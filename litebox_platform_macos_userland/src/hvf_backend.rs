// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Hypervisor.framework guest backend: unchanged stock AArch64 Linux code
//! executed at EL0 on real vCPUs, dispatched into the existing Linux shim.
//!
//! Shape:
//!
//! * One process-global, permission-mirrored [`HvfAddressSpace`].  The Linux
//!   shim already runs every guest process's threads in one flat address
//!   space at guest VA == host VA (pre-`exec` fork families take turns by
//!   parking their private memory), and it dereferences guest pointers
//!   directly, so the backend mirrors every guest mapping into the host view
//!   with host permissions = guest permissions minus EXECUTE.
//! * A bounded pool of owner lanes (see [`crate::hvf_vcpu`]).  vCPUs are
//!   interchangeable execution engines: a guest thread's complete
//!   architectural state lives in its `PtRegs` plus a per-thread FP/TLS
//!   context, so any lane can run any thread.  A thread acquires a lane per
//!   run, runs until the next exit (syscall, fault, kick, or time-slice
//!   timer), and releases it, so more guest threads than vCPUs are fine and no
//!   compute-bound thread can starve the others.
//! * Interrupts: [`HvfThreadSlot`] records a pending interrupt and kicks the
//!   lane the thread is currently running on, under one lock, so a kick can
//!   never be lost between "checked for pending" and "entered the guest" (the
//!   lane latches kicks that land while it is still entering).
//! * Every EL0 exception is vectored by the EL1 monitor into one `HVC` exit;
//!   `ESR_EL1` says what happened: `SVC` becomes `EnterShim::syscall`, `WFx`
//!   a yield, everything else `EnterShim::exception`.  A kick becomes
//!   `EnterShim::interrupt`; a timer slice simply re-queues the thread.

use core::cell::RefCell;
use core::fmt;
use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use crate::diagnostics_counters::{RankedMutex, RankedRwLock};
use std::time::{Duration, Instant};

use litebox::mm::domain::GuestVaDomain;
use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, GuestAccessPreparation,
    MemoryRegionPermissions, PermissionUpdateError, RemapError, SharedPageIoError,
};
use litebox::shim::{
    ContinueOperation, EnterShim, Exception, ExceptionInfo, WxFlipOutcome, WxFlipRequest,
};
use litebox::utils::ids::{FamilyId, VmViewId};
use litebox_common_linux::PtRegs;

use crate::hvf::{
    HvfArchitecturalState, HvfEl1State, HvfError, HvfSimd128, HvfVcpuCancellation, HvfVcpuExit,
    process_hvf_vm,
};
use crate::hvf_memory::{
    ANY_FILE_WINDOW_EVER, ANY_HOST_REDIRECT_EVER, FILE_COW_COUNTERS, FILE_ORIGINS, FileOrigin,
    FileOriginKey, FileOriginState, FileWindow, HostAccessEntry, HostAliasState, HvfAddressSpace,
    HvfGuestPermissions, HvfMemory, MAX_FILE_ORIGIN_PAGES, PageKind, PromoteTarget,
    HvfMemoryError, HvfRangeMutation, HvfSharedBackingKey, HvfVcpuMemorySnapshot,
    HvfVcpuParticipant, HvfVcpuRunAttachment, fallible_read_u64, file_cow_count,
    file_origin_adjust, next_file_origin_gva, process_hvf_memory,
};
use crate::diagnostics_counters::{
    GR_COUNTERS, GrSite, gr_stale_skips_round,
};
use litebox::platform::page_mgmt::CowAllocationError;
use crate::hvf_vcpu::{
    HvfBoundVcpu, HvfExitFp, HvfFpDeposit, HvfGuestFpClaim, HvfGuestRegisterCell, HvfVcpuExitState,
    HvfVcpuLane, HvfVcpuLaneCancellation, HvfVcpuLaneError, HvfVcpuLaneHandle, HvfVcpuRegistry,
    HvfVcpuRunReservation, HvfVcpuRunResult, RunControl,
};

/// Best-effort, bounded AAPCS64 frame-pointer walk from the faulting
/// frame's own `x29`, populating `ExceptionInfo::backtrace` for this
/// backend's direct-guest and monitor-relayed exception paths (the only
/// paths that call this; the legacy native-execution backend's own
/// `ExceptionInfo` sites in `lib.rs`/`guest.rs` stay empty by design --
/// see their own comments). Diagnostic only: never changes guest-visible
/// behavior, never panics, and treats every frame-pointer value read from
/// guest memory as untrusted, possibly-adversarial data -- see this
/// project's own `chromium-fd-ownership-lr-degenerate-disassembly-proof`
/// row for why the single register-only `x30` this crate already logs can
/// be degenerate (equal to the fault PC itself) and a real chain walk is
/// needed to see past it.
///
/// Each step reads the AAPCS64 frame-record pair `[fp]` (the caller's own
/// saved `x29`) and `[fp+8]` (the return address into that caller) via
/// `hvf_memory::fallible_read_u64` -- the same already-production fallible
/// primitive `hvf_memory.rs`'s own alias-race detection already uses for
/// guest-computed addresses, safe for any address per that primitive's own
/// contract (`read_u64_fallible`'s doc: valid for reads, or a pointer
/// guaranteed to be in non-Rust memory -- true of the whole guest VA range
/// this walk can ever reach, since it never leaves guest-owned address
/// space). A bad chain therefore just fails the read and stops the walk;
/// it can never touch host-owned Rust memory. The walk also stops --
/// again, without panicking -- the instant the pointer is null or not
/// 16-byte aligned (the AAPCS64 stack-alignment requirement, used here
/// only as a cheap corruption check, not because misaligned reads are
/// themselves unsafe), or the chain fails to move strictly to a higher
/// address (guards a cyclic/self-referential chain independent of the
/// hard frame cap); `FrameBacktrace::MAX_FRAMES` bounds the loop
/// regardless of whether any of those checks ever trip.
/// Whether the one consumer of [`ExceptionInfo::backtrace`] can see it: the shim's debug-level
/// guest-fault log (see `EnterShim::exception` in `litebox_shim_linux`). The field is documented
/// as purely diagnostic and `EMPTY` is always valid, so the frame walk -- up to
/// `FrameBacktrace::MAX_FRAMES` fallible guest reads per exception exit, on every exception exit,
/// including the ones a guest takes on purpose -- is only paid when that log is enabled. Kept in
/// sync with the shim's own gate by targeting the module that owns the log line.
fn exception_backtrace_wanted() -> bool {
    litebox_util_log::log_enabled!(target: "litebox_shim_linux", litebox_util_log::Level::Debug)
}

fn capture_frame_backtrace(fp0: usize) -> litebox::shim::FrameBacktrace {
    let mut frames = [0u64; litebox::shim::FrameBacktrace::MAX_FRAMES];
    let mut count = 0usize;
    let mut fp = fp0;
    while count < litebox::shim::FrameBacktrace::MAX_FRAMES {
        if fp == 0 || fp % 16 != 0 {
            break;
        }
        let Some(saved_fp) = fallible_read_u64(fp) else {
            break;
        };
        let Some(lr_slot) = fp.checked_add(8) else {
            break;
        };
        let Some(return_addr) = fallible_read_u64(lr_slot) else {
            break;
        };
        if return_addr == 0 {
            break;
        }
        frames[count] = return_addr;
        count += 1;
        let saved_fp = usize::try_from(saved_fp).unwrap_or(usize::MAX);
        if saved_fp <= fp {
            break;
        }
        fp = saved_fp;
    }
    litebox::shim::FrameBacktrace::from_frames(&frames[..count])
}

const PAGE_SIZE: usize = 16 * 1024;
/// Guest range the shim may use, mirrored from `lib.rs`'s `GUEST_ADDR_MIN/MAX`.
const GUEST_ADDR_MIN: usize = 0x0100_0000_0000;
const GUEST_ADDR_MAX: usize = 0x0000_4000_0000_0000;
/// One guest-executable page holding the `rt_sigreturn` trampoline.  Reported
/// to the shim as reserved so its own allocator never places anything there.
const SIGRETURN_TRAMPOLINE_GVA: usize = GUEST_ADDR_MAX - PAGE_SIZE;
/// `movz x8, #139` (`__NR_rt_sigreturn`); `svc #0`.
const SIGRETURN_TRAMPOLINE: [u32; 2] = [0xd280_1168, 0xd400_0001];
/// Two guest pages right below the trampoline: the vDSO ELF image (guest
/// READ|EXECUTE) at `VDSO_GVA`, then its clock data page (guest READ, written
/// by the host) at `VDSO_GVA + PAGE_SIZE` -- the text finds the data page as
/// "its own page plus one". Reported to the shim as reserved together with
/// the trampoline; see [`crate::vdso`].
const VDSO_GVA: usize = SIGRETURN_TRAMPOLINE_GVA - 2 * PAGE_SIZE;
const LANE_QUEUE_CAPACITY: usize = 16;
/// Base GVA and per-worker stride for [`hvf_scheduler_scaling_probe`]'s
/// disjoint per-thread compute pages. Placed well clear of both
/// `GUEST_ADDR_MIN` and the trampoline/lane-starvation scratch page near
/// `GUEST_ADDR_MAX`, with a 1 MiB stride so up to eight single-page workers
/// never share a page.
const SCALING_PROBE_BASE_GVA: usize = GUEST_ADDR_MIN + 0x1000_0000;
const SCALING_PROBE_STRIDE: usize = 0x0010_0000;
const LANE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
/// Apple Silicon's generic timer runs at 24 MHz and `mach_absolute_time`
/// reads the same counter the guest sees as `CNTVCT_EL0` (offset zero).
const TIMER_TICKS_PER_SECOND: u64 = 24_000_000;
/// One guest time slice before a running thread is re-queued for fairness.
const TIME_SLICE: Duration = Duration::from_millis(10);
/// Bound on one synchronous shootdown (kick running lanes, synchronize idle
/// ones, pump acknowledgements) after a mapping mutation.  Expiry is logged,
/// never fatal: the retirement simply stays deferred.
const SHOOTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const SHOOTDOWN_POLL: Duration = Duration::from_micros(50);
const LANE_REPLACEMENT_POLL: Duration = Duration::from_millis(10);
/// Bound on consecutive attach/run races a single `run_thread` iteration will
/// retry before treating it as a genuine, non-recoverable failure instead of
/// expected concurrent-mutation contention.
const ATTACHMENT_RACE_RETRY_LIMIT: u32 = 1000;
/// Bound on consecutive memory-abort reruns attributed to a stale view before
/// the fault is delivered to the guest regardless.
const STALE_VIEW_RERUN_LIMIT: u32 = 64;
/// Bound on consecutive `WxFlipOutcome::AliasConflictRefused` reruns on the same guest exit
/// before falling through to `try_resolve_cow_fault`/real fault delivery regardless. A legitimate
/// mmap/mprotect/munmap race resolves within a handful of reruns; a page that is refused because
/// it is still only lineage-inherited (never independently claimed by this view) never resolves
/// by rerunning alone and needs `try_resolve_cow_fault`'s own materialization, exactly like a
/// `HostFailure` already gets -- this bound is what turns that into a bounded number of free
/// retries instead of an unconditional, indefinite one.
const ALIAS_CONFLICT_RERUN_LIMIT: u32 = 64;

/// GSIGSEGV2: per-thread "attempts on one fault" cells for the two stale-translation recovery
/// arms, keyed by `(page, translation_generation, count)` -- see
/// [`HvfBackend::fault_repeat_count`] for why the page alone is the wrong identity.
thread_local! {
    static WRITABLE_NOW_RESUMES: core::cell::Cell<(usize, u64, u32)> =
        const { core::cell::Cell::new((usize::MAX, 0, 0)) };
    static REPAIR_RESUMES: core::cell::Cell<(usize, u64, u32)> =
        const { core::cell::Cell::new((usize::MAX, 0, 0)) };
}

/// Largest range `materialize_inherited_range` walks page by page (4 GiB of 16 KiB pages).
const MATERIALIZE_PAGE_BOUND: usize = 1 << 18;
const EC_SHIFT: u64 = 26;
const EC_MASK: u64 = 0x3f;
const EC_WFX: u64 = 0x01;
const EC_SVC64: u64 = 0x15;
const EC_HVC64: u64 = 0x16;
const EC_BRK64: u64 = 0x3c;
/// ESR_EL1 exception classes for a stage-1 abort taken from a lower EL: an
/// instruction fetch and a data access respectively. `dispatch_monitor_exit`
/// already tests both together via its `is_abort` match; `classify_wx_fault`
/// needs to distinguish them (a fetch always wants EXECUTE; a data access's
/// direction depends on the ESR `WnR` bit below).
const EC_INSTRUCTION_ABORT_LOWER_EL: u64 = 0x20;
const EC_DATA_ABORT_LOWER_EL: u64 = 0x24;
/// ESR_EL1\[5:0\]: the Data/Instruction Fault Status Code. The permission-fault
/// codes are `0b0011LL` for translation level `LL` (ARM DDI 0487, ESR_EL1.DFSC/IFSC);
/// masking off the level bits leaves this fixed pattern.
const ESR_FSC_PERMISSION_FAULT: u64 = 0x0c;
const ESR_FSC_PERMISSION_FAULT_MASK: u64 = 0x3c;
/// DFSC/IFSC (`ESR_ELx` bits `[5:2]`, ignoring the translation-level bits `[1:0]`) for a
/// translation fault at any level -- the class the fork-COW fault classifier
/// (`try_resolve_cow_fault`) services: a per-view address space with no physical mapping at all
/// yet for a page its family logically owns by lineage.
const ESR_FSC_TRANSLATION_FAULT: u64 = 0x04;
const ESR_FSC_TRANSLATION_FAULT_MASK: u64 = 0x3c;
/// ESR_EL1\[6\]: Write-not-Read, valid for a Data Abort. Set means the guest's
/// faulting access was a write.
const ESR_WNR: u64 = 1 << 6;
const HVC_IMMEDIATE_MASK: u64 = 0xffff;
const MONITOR_HVC_IMMEDIATE: u64 = 0x4c42;
/// Entry PC of the lower-EL AArch64 synchronous vector. The monitor's first
/// instruction there is its HVC to the host; an authenticated kick can stop the
/// vCPU immediately before that instruction executes.
const MONITOR_LOWER_EL_SYNC_OFFSET: u64 = 0x400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaneReplacementFailure {
    index: usize,
    generation: u64,
    stage: &'static str,
}

struct LaneMaintenanceFailure {
    failure: LaneReplacementFailure,
    source: HvfBackendError,
}

#[derive(Debug)]
pub enum HvfBackendError {
    Hvf(HvfError),
    Memory(HvfMemoryError),
    Lane(HvfVcpuLaneError),
    AlreadyInstalled,
    NotInstalled,
    LaneAcquisitionTimeout,
    LaneTicketExhausted,
    LanePoolCorrupt {
        index: usize,
    },
    LaneNotReusable {
        index: usize,
    },
    LaneReplacementFailed {
        index: usize,
        generation: u64,
        stage: &'static str,
    },
    LaneMaintenanceThread(std::io::Error),
    Trampoline(&'static str),
    Vdso(&'static str),
    /// An exit the dispatch loop cannot classify (a malformed/unknown HVF
    /// SDK exit, or an exception taken outside the EL1 monitor / not the
    /// monitor's own `HVC`). `source_pc` is the guest architectural PC at
    /// the moment of that exit when the caller has one available (the main
    /// dispatch loop always does, via `HvfArchitecturalState::pc`), so the
    /// resulting fatal-failure message names both the exit's own syndrome
    /// (already inside `HvfVcpuExit`'s `Debug` output) and where in the
    /// guest it happened, rather than only the former.
    UnexpectedExit {
        exit: HvfVcpuExit,
        source_pc: Option<u64>,
    },
    /// [`HvfBackend::space_for_view`] was asked to mint a brand-new
    /// per-`VmViewId` address space (no such space exists yet for this view).
    /// Deliberately refused rather than attempted: whether a second
    /// [`HvfAddressSpace`]'s own `map_range`/`claim_with` calls at the same
    /// reserved trampoline GVA [`HvfBackend`] already holds forever in
    /// `default_space` are physically independent per space (their own
    /// `HvfMemoryError::IpaOwnership`/claim bookkeeping is per-space, but
    /// whether the underlying host-mirrored page each claim installs can
    /// safely coexist with `default_space`'s permanent claim at the same GVA
    /// has not been verified) is exactly the open design question a future
    /// change must resolve before this can be implemented safely.
    ViewSpaceCreationUnsupported,
    /// An in-repo HVF witness could not set up or could not observe the condition it exists
    /// to prove. Carries a static message rather than a per-probe error type so every probe
    /// reports the same way.
    Witness(&'static str),
}

impl fmt::Display for HvfBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::Memory(error) => write!(f, "{error}"),
            Self::Lane(error) => write!(f, "{error}"),
            Self::AlreadyInstalled => write!(f, "the HVF guest backend is already installed"),
            Self::NotInstalled => write!(f, "the HVF guest backend is not installed"),
            Self::LaneAcquisitionTimeout => {
                write!(f, "timed out waiting for a free HVF vCPU lane")
            }
            Self::LaneTicketExhausted => {
                write!(f, "the HVF vCPU lane ticket sequence is exhausted")
            }
            Self::LanePoolCorrupt { index } => {
                write!(
                    f,
                    "the HVF vCPU lane pool rejected duplicate or invalid lane {index}"
                )
            }
            Self::LaneNotReusable { index } => {
                write!(
                    f,
                    "HVF vCPU lane {index} left checkout without reaching reusable idle state"
                )
            }
            Self::LaneReplacementFailed {
                index,
                generation,
                stage,
            } => write!(
                f,
                "HVF vCPU lane {index} generation {generation} failed replacement while {stage}"
            ),
            Self::LaneMaintenanceThread(error) => {
                write!(
                    f,
                    "failed to start the HVF lane-maintenance thread: {error}"
                )
            }
            Self::Trampoline(message) => {
                write!(
                    f,
                    "failed to install the guest sigreturn trampoline: {message}"
                )
            }
            Self::Vdso(message) => {
                write!(f, "failed to install the guest vDSO: {message}")
            }
            Self::UnexpectedExit { exit, source_pc } => match source_pc {
                Some(pc) => write!(
                    f,
                    "the HVF vCPU returned an exit the backend cannot classify at guest PC {pc:#x}: {exit:?}"
                ),
                None => write!(
                    f,
                    "the HVF vCPU returned an exit the backend cannot classify: {exit:?}"
                ),
            },
            Self::ViewSpaceCreationUnsupported => write!(
                f,
                "creating a new per-view HVF address space is not yet supported"
            ),
            Self::Witness(message) => write!(f, "HVF witness failed: {message}"),
        }
    }
}

impl std::error::Error for HvfBackendError {}

impl From<HvfError> for HvfBackendError {
    fn from(value: HvfError) -> Self {
        Self::Hvf(value)
    }
}

impl From<HvfMemoryError> for HvfBackendError {
    fn from(value: HvfMemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<HvfVcpuLaneError> for HvfBackendError {
    fn from(value: HvfVcpuLaneError) -> Self {
        Self::Lane(value)
    }
}

// ---------------------------------------------------------------------------
// Per-thread guest context.
// ---------------------------------------------------------------------------

/// The parts of a guest thread's architectural state that do not live in its
/// `PtRegs`: the vector file and the thread pointer.  Zero is the correct
/// initial value for a fresh thread (cleared vector file, default rounding
/// mode, no TLS), matching the native backend.
///
/// FXR resident-register cache: the integer file (`PtRegs`) and `tpidr_el0` are refreshed by
/// every exit read, so they are always current here. The vector file is read lazily: after a
/// run it stays resident in the lane's vCPU ([`FpLocation::Lane`]) and `fp` is only
/// authoritative once materialized. `fp` is therefore private to this module and reached only
/// through [`Self::materialized_fp`] / [`Self::set_fp`] / the run-input and exit-absorb steps
/// of `run_thread` -- no path can read a stale vector file.
struct HvfThreadContext {
    fp: litebox::platform::FpSimdState64,
    fp_location: FpLocation,
    tpidr_el0: u64,
    /// This thread's SIMD/FP custody cell (identity + deposit mailbox), created at its first run.
    cell: Option<Arc<HvfGuestRegisterCell>>,
    /// `cell`'s deposit count when this thread last looked at its mailbox.
    deposits_seen: u64,
    /// The lane `(index, generation)` this thread last ran on: the lane whose resident cache is
    /// closest to this thread's state, preferred by the pool.
    last_lane: Option<(usize, u64)>,
    /// BCORE-4: this thread's own vCPU. `None` for a thread that runs on the lane pool, which
    /// is every thread unless `LITEBOX_HVF_BOUND=1` and the bind trigger fired.
    bound: Option<BoundThread>,
}

/// FXR: where a guest thread's authoritative SIMD/FP file is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FpLocation {
    /// [`HvfThreadContext::fp`].
    Host,
    /// Resident in lane `index`'s vCPU (generation `generation`) under residency `seq`;
    /// `host_valid` when `fp` holds an identical copy (materialized without the lane giving the
    /// file up).
    Lane {
        index: usize,
        generation: u64,
        seq: u64,
        host_valid: bool,
    },
}

impl HvfThreadContext {
    const fn new() -> Self {
        Self {
            fp: litebox::platform::FpSimdState64 {
                v: [0; 32],
                fpsr: 0,
                fpcr: 0,
            },
            fp_location: FpLocation::Host,
            tpidr_el0: 0,
            cell: None,
            deposits_seen: 0,
            last_lane: None,
            bound: None,
        }
    }

    const fn fp_host_valid(&self) -> bool {
        matches!(
            self.fp_location,
            FpLocation::Host | FpLocation::Lane { host_valid: true, .. }
        )
    }

    /// The lane `(index, generation)` to ask the pool for: the one holding the vector file, else
    /// the one this thread last ran on.
    const fn preferred_lane(&self) -> Option<(usize, u64)> {
        match self.fp_location {
            FpLocation::Lane {
                index, generation, ..
            } => Some((index, generation)),
            FpLocation::Host => self.last_lane,
        }
    }

    fn cell(&mut self) -> Arc<HvfGuestRegisterCell> {
        Arc::clone(self.cell.get_or_insert_with(HvfGuestRegisterCell::new))
    }

    /// Replaces the vector file (sigreturn, ptrace resume, clone-child setup): the host copy is
    /// authoritative from here; any resident copy is superseded.
    fn set_fp(&mut self, state: &litebox::platform::FpSimdState64) {
        self.fp = *state;
        self.fp_location = FpLocation::Host;
    }

    fn apply_deposit(&mut self, deposit: HvfFpDeposit) {
        let Some(fp) = deposit.fp else {
            fatal(
                "materializing a guest thread's SIMD/FP registers",
                &HvfBackendError::Lane(HvfVcpuLaneError::FpResidency {
                    lane_generation: deposit.lane_generation,
                    claimed_seq: Some(deposit.seq),
                }),
            );
        };
        self.fp = host_fp_state(&fp);
        self.fp_location = match self.fp_location {
            FpLocation::Lane {
                index,
                generation,
                seq,
                ..
            } if deposit.still_resident => FpLocation::Lane {
                index,
                generation,
                seq,
                host_valid: true,
            },
            _ => FpLocation::Host,
        };
        crate::diagnostics_counters::record_resident(
            crate::diagnostics_counters::RESIDENT_GUEST_DEPOSITS_ABSORBED,
            1,
        );
    }

    /// Takes whatever the lanes deposited since the last look: the deposit for this thread's
    /// current residency (if any) is absorbed, every other one is stale. One atomic load when
    /// nothing arrived.
    fn absorb_deposits(&mut self) {
        let Some(cell) = self.cell.as_ref() else {
            return;
        };
        let count = cell.deposit_count();
        if count == self.deposits_seen {
            return;
        }
        self.deposits_seen = count;
        let (deposit, stale) = match self.fp_location {
            FpLocation::Lane {
                generation, seq, ..
            } => cell.take(generation, seq),
            FpLocation::Host => (None, cell.discard_all()),
        };
        if stale != 0 {
            crate::diagnostics_counters::record_resident(
                crate::diagnostics_counters::RESIDENT_GUEST_DEPOSITS_STALE,
                stale as u64,
            );
        }
        if let Some(deposit) = deposit {
            self.apply_deposit(deposit);
        }
    }

    /// Makes `fp` authoritative: absorbs a deposit that already arrived, or asks the lane holding
    /// the file to hand a copy back and waits for it. A lane can always answer (it hands the file
    /// back before anything could overwrite it, and when it closes); a lost file or a lane that
    /// never answers is fatal rather than a silently wrong vector file.
    fn materialize_fp(&mut self, for_run: bool) {
        self.absorb_deposits();
        let FpLocation::Lane {
            index,
            generation,
            seq,
            host_valid: false,
        } = self.fp_location
        else {
            return;
        };
        let cell = self.cell();
        let started = crate::diagnostics_counters::ticks();
        let deadline = Instant::now() + FP_MATERIALIZE_TIMEOUT;
        crate::diagnostics_counters::record_resident(
            crate::diagnostics_counters::RESIDENT_GUEST_MATERIALIZE_REQUESTS,
            1,
        );
        if for_run {
            crate::diagnostics_counters::record_resident(
                crate::diagnostics_counters::RESIDENT_GUEST_MATERIALIZE_FOR_RUN,
                1,
            );
        }
        let mut asked_at: Option<Instant> = None;
        loop {
            // Ask again only while no request has reached the lane's queue (it was closing, being
            // replaced, or its queue was full), or after a long silence: one admitted request is
            // answered by the owner, and re-asking every slice would fill the lane's bounded queue
            // (and refuse its lease holder's next run) whenever the owner is slow to get a CPU.
            let due = asked_at.is_none_or(|at| at.elapsed() >= FP_MATERIALIZE_REASK);
            if due
                && let Some(backend) = active()
                && backend.request_fp_materialization(index, generation, &cell, seq)
            {
                asked_at = Some(Instant::now());
            }
            // Counted before the mailbox is looked at, so anything deposited later is seen by the
            // next `absorb_deposits`.
            self.deposits_seen = cell.deposit_count();
            let slice = (Instant::now() + FP_MATERIALIZE_RETRY).min(deadline);
            let (deposit, stale) = cell.wait_take(generation, seq, slice);
            if stale != 0 {
                crate::diagnostics_counters::record_resident(
                    crate::diagnostics_counters::RESIDENT_GUEST_DEPOSITS_STALE,
                    stale as u64,
                );
            }
            if let Some(deposit) = deposit {
                crate::diagnostics_counters::record_guest_materialize_wait(
                    crate::diagnostics_counters::ticks().wrapping_sub(started),
                );
                self.apply_deposit(deposit);
                return;
            }
            if Instant::now() >= deadline {
                fatal(
                    "waiting for a vCPU lane to hand back a guest thread's SIMD/FP registers",
                    &HvfBackendError::Lane(HvfVcpuLaneError::OperationTimeout),
                );
            }
        }
    }

    /// The authoritative vector file (materializing it first when it is resident in a lane).
    fn materialized_fp(&mut self) -> litebox::platform::FpSimdState64 {
        self.materialize_fp(false);
        self.fp
    }

    /// The run input for a run on lane `lane` (`(index, generation)`): the architectural state
    /// to install (`ctx`'s integer file, `tpidr_el0`, and the vector file when the host holds
    /// it) and the SIMD/FP claim. A vector file resident in a different lane is materialized
    /// first, so a run never needs a file its lane cannot provide.
    fn run_input(
        &mut self,
        ctx: &PtRegs,
        lane: (usize, u64),
    ) -> (HvfArchitecturalState, HvfGuestFpClaim, Arc<HvfGuestRegisterCell>) {
        self.absorb_deposits();
        if let FpLocation::Lane {
            index,
            generation,
            host_valid: false,
            ..
        } = self.fp_location
            && (index, generation) != lane
        {
            self.materialize_fp(true);
        }
        let resident_seq = match self.fp_location {
            FpLocation::Lane {
                index,
                generation,
                seq,
                ..
            } if (index, generation) == lane => Some(seq),
            _ => None,
        };
        let claim = HvfGuestFpClaim {
            resident_seq,
            host_valid: self.fp_host_valid(),
        };
        let cell = self.cell();
        (architectural_state(ctx, self), claim, cell)
    }

    /// Takes a run's exit state in: `tpidr_el0` always (the exit read includes it); the vector
    /// file per the result's [`HvfExitFp`].
    fn absorb_exit(
        &mut self,
        state: &HvfArchitecturalState,
        fp: HvfExitFp,
        lane: (usize, u64),
    ) {
        self.tpidr_el0 = state.tpidr_el0;
        self.last_lane = Some(lane);
        match fp {
            HvfExitFp::Materialized => {
                self.fp = host_fp_state(&crate::hvf::HvfGuestFp::of(state));
                self.fp_location = FpLocation::Host;
            }
            HvfExitFp::Resident {
                lane_generation,
                seq,
            } => {
                self.fp_location = FpLocation::Lane {
                    index: lane.0,
                    generation: lane_generation,
                    seq,
                    host_valid: false,
                };
            }
        }
    }
}

/// Bound on one guest thread's wait for a lane to hand its SIMD/FP file back (the lanes' own
/// command bound).
const FP_MATERIALIZE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often that wait looks again for a lane to ask (while no request was admitted).
const FP_MATERIALIZE_RETRY: Duration = Duration::from_millis(10);
/// How long an admitted request is trusted before it is sent again.
const FP_MATERIALIZE_REASK: Duration = Duration::from_secs(1);

fn host_fp_state(fp: &crate::hvf::HvfGuestFp) -> litebox::platform::FpSimdState64 {
    let mut host = litebox::platform::FpSimdState64 {
        v: [0; 32],
        fpsr: 0,
        fpcr: 0,
    };
    for (destination, source) in host.v.iter_mut().zip(fp.q.iter()) {
        *destination = u128::from_le_bytes(source.bytes);
    }
    host.fpcr = u32::try_from(fp.fpcr & 0xffff_ffff).unwrap_or(0);
    host.fpsr = u32::try_from(fp.fpsr & 0xffff_ffff).unwrap_or(0);
    host
}

thread_local! {
    static HVF_THREAD: RefCell<HvfThreadContext> = const { RefCell::new(HvfThreadContext::new()) };
}

/// The guest thread's vector file for the shim (signal frames, clone/fork capture, ptrace
/// stops): materialized from its lane first when it is resident there.
pub(crate) fn thread_fp_state() -> litebox::platform::FpSimdState64 {
    HVF_THREAD.with(|context| context.borrow_mut().materialized_fp())
}

pub(crate) fn set_thread_fp_state(state: &litebox::platform::FpSimdState64) {
    HVF_THREAD.with(|context| context.borrow_mut().set_fp(state));
}

pub(crate) fn thread_tpidr_el0() -> usize {
    HVF_THREAD.with(|context| usize::try_from(context.borrow().tpidr_el0).unwrap_or(0))
}

pub(crate) fn set_thread_tpidr_el0(value: usize) {
    HVF_THREAD.with(|context| context.borrow_mut().tpidr_el0 = value as u64);
}

/// Per-thread interrupt state shared with [`crate::ThreadHandle`], so an
/// interrupt aimed at a thread from any other thread reaches the vCPU it is
/// running on (or is delivered before its next entry).
pub(crate) struct HvfThreadSlot {
    pending: AtomicBool,
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_THREAD_SLOT`]) -- `kick()` holds it
    /// across the cancellation's SDK call, and the run loop holds it across the lane's
    /// `reserve_run`, so it is both a host-call and a lock-acquisition site.
    current: RankedMutex<Option<HvfVcpuLaneCancellation>>,
}

impl HvfThreadSlot {
    pub(crate) const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            current: RankedMutex::new(None, crate::diagnostics_counters::RANK_THREAD_SLOT),
        }
    }

    /// Records an interrupt and kicks the lane this thread is currently
    /// running on, if any.  Holding `current` across the kick is what makes
    /// the kick target exactly this thread's run: the run loop only clears
    /// `current` (under the same lock) after its run has returned.
    pub(crate) fn kick(&self) {
        self.pending.store(true, Ordering::Release);
        if let Some(backend) = active() {
            backend.available.notify_all();
        }
        let current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cancellation) = current.as_ref() {
            let _ = cancellation.request();
        }
    }

    fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }
}

// ---------------------------------------------------------------------------
// Backend.
// ---------------------------------------------------------------------------

struct LaneGeneration {
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_LANE`]) -- the lane object is moved
    /// out under this lock during lane replacement, and the replacement path waits on the
    /// maintenance condvar (see `LANE_REPLACEMENT_POLL`) with nothing else held.
    lane: RankedMutex<Option<HvfVcpuLane>>,
    handle: HvfVcpuLaneHandle,
    /// The view this lane's participant is currently registered against
    /// (`None` for [`HvfBackend::default_space`]), paired with the
    /// participant handle itself. Both must always change together --
    /// [`HvfBackend::ensure_lane_attached_to_view`] is the only place that
    /// migrates a lane between spaces, and it updates both fields atomically
    /// under this one lock.
    ///
    /// The participant is `None` only for the transient instant inside
    /// [`HvfBackend::ensure_lane_attached_to_view`]'s own critical section
    /// where it has been moved out to pass by value into
    /// `HvfAddressSpace::migrate_vcpu_participant`: that function is CALLED
    /// with this lock held (see its own doc comment), so the `None` is
    /// observable only to a thread that already holds it -- no other reader
    /// can ever observe `None` here. Every other reader treats `None` as a
    /// logic error (a lane whose only participant registration was lost to
    /// a migration failure, which the caller must treat as fatal to this
    /// lane generation, not silently skipped).
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_PARTICIPANT`]).
    participant: RankedMutex<(Option<VmViewId>, Option<HvfVcpuParticipant>)>,
    /// hvf-lane-view-affinity: lock-free mirror of `participant.0` as a [`view_tag`] key, for
    /// the lane pool's handout choice ([`preferred_free_lane`]). Written only where
    /// `participant.0` is written (construction, and the migrate arm of
    /// [`HvfBackend::ensure_lane_attached_to_view`], under that same lock) and read under the
    /// pool lock WITHOUT taking `participant`, so the pool never acquires a lock that
    /// `ensure_lane_attached_to_view` holds across an exclusive VM operation. A stale value can
    /// only cost one migration: `ensure_lane_attached_to_view` still decides from
    /// `participant.0` itself.
    view_tag: AtomicU64,
    /// T1b (hvf-kick-only-lanes-in-mutated-space): lock-free mirror of `participant.1`'s
    /// [`HvfVcpuParticipant::address_space`], keyed by address-space id the way `view_tag` is keyed
    /// by view id. A mutation kicks only the lanes whose tag is the space it just mutated, so one
    /// process's `Protect`/`Unmap` no longer cancels the runs of every other process's lanes
    /// (today: one kick request per lane in the VM -- 11 per round).
    ///
    /// Written exactly where the participant itself is replaced and always under `participant`:
    /// `create_lane_generation` (construction) and the migrate arm of
    /// [`HvfBackend::ensure_lane_attached_to_view`]. Read with Acquire by `kick_lanes` with no lock
    /// at all. Correctness (invariant 4): a lane can be *in flight* in a space `S` only after
    /// `attach` + `submit` in `S`, and this tag's store is sequenced before that attach on the same
    /// thread; `submit` publishes `in_flight` under `S`'s `cell.state`, which the mutating thread
    /// acquires before it mints the retirement, so its Acquire load of this tag reads `S` (or a
    /// later value, which requires the lane to have finished that run and migrated with a departing
    /// acknowledgement). A lane of another space is not a participant `S`'s retirement requires and
    /// holds no stale `S` translation (different root), so skipping it is safe -- and a tag that is
    /// somehow stale costs only exit latency, never correctness: that lane still re-attaches at its
    /// next exit, and a run on a stale root is rerun rather than delivered.
    space_tag: AtomicU64,
}

/// The address space [`HvfBackend::space_for_view`] resolved for a given
/// call: either a plain borrow of [`HvfBackend::default_space`] (the common
/// case today) or a shared, refcounted handle onto one view's own space.
/// `Deref`s to `&HvfAddressSpace` so a caller need not care which case it
/// got.
enum ResolvedSpace<'a> {
    Default(&'a HvfAddressSpace),
    View(Arc<HvfAddressSpace>),
}

impl core::ops::Deref for ResolvedSpace<'_> {
    type Target = HvfAddressSpace;

    fn deref(&self) -> &HvfAddressSpace {
        match self {
            Self::Default(space) => space,
            Self::View(space) => space,
        }
    }
}

enum LaneSlotState {
    Ready(Arc<LaneGeneration>),
    Retiring(Arc<LaneGeneration>),
    Replacing { old_generation: u64 },
    Failed(LaneReplacementFailure),
}

struct PooledLane {
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_LANE_SLOT`]); taken by the pool
    /// hand-out while [`HvfBackend::free`] is held and by lane replacement, never across a wait.
    state: RankedMutex<LaneSlotState>,
}

struct LaneMaintenance {
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_LANE_MAINTENANCE`]); waited on through
    /// `wake` by the maintenance thread, so the park is a named `wait_while_holding` site.
    requested: RankedMutex<bool>,
    wake: Condvar,
    /// CLASS A: same rank as `requested` (the two are never held at the same time except by
    /// [`HvfBackend::lane_maintenance`]'s own hand-off, which takes them in this order).
    owner: RankedMutex<Option<std::thread::JoinHandle<()>>>,
}

struct SharedInitialization {
    initialized: HashMap<usize, Vec<Range<usize>>>,
    in_progress: HashMap<usize, Vec<Range<usize>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationKind {
    /// A new mapping: nothing can be stale, no shootdown.
    Map,
    /// Permissions changed on existing pages.
    Protect,
    /// Existing pages removed.
    Unmap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreeLane {
    index: usize,
    generation: u64,
    /// The lane's [`LaneGeneration::view_tag`] when it was returned to the pool. Exact while the
    /// lane sits in the free list: only a lease holder (`ensure_lane_attached_to_view`) or the
    /// lane-repair path (which replaces the generation outright) ever changes a lane's view.
    view_tag: u64,
}

/// hvf-lane-view-affinity: the lane pool's affinity key for a guest view -- the raw `VmViewId`,
/// or `0` for [`HvfBackend::default_space`] (`VmViewId` is `NonZeroU64`-backed, so the two never
/// collide).
fn view_tag(view: Option<VmViewId>) -> u64 {
    view.map_or(0, |view| view.get().get())
}

/// hvf-lane-view-affinity: the free-list position [`HvfBackend::acquire_lane_inner`] serves to
/// the one ticket it is serving, for a thread whose view has affinity key `view_tag`: a free lane
/// whose participant is already registered in that view if there is one -- FXR first the lane this
/// thread last ran on, else (T2c) the MOST recently released lane of this view -- and only when no
/// lane of this view is free, the deque's front; `None` only when no lane is free. Ticket fairness
/// is untouched -- this only chooses WHICH idle lane the served ticket gets. The point: with
/// several views interleaving, a lane last run by another view made
/// `ensure_lane_attached_to_view` migrate its participant (two exclusive VM operations, serialized
/// behind every other process's mapping mutation) and the fresh participant then forced a
/// synchronization monitor trip (a second `hv_vcpu_run`) before the real run -- on most syscalls
/// of a multi-process desktop (52-55% of runs measured). Any lane of this own view avoids both.
///
/// Which lane of the view is chosen changed with T2c: it was the least recently released one (the
/// deque's front, the pre-existing LRU choice) and is now the most recently released one (LIFO
/// within the view, hence `rposition` over a deque whose two release sites both push to the back).
/// LIFO pairs a thread with the lane whose owner thread is most likely still spinning for work
/// (see `AdaptiveSpin` in hvf_vcpu.rs) instead of parked, which is worth more than the register
/// cache warmth LRU was guessing at. Safety-neutral either way: both choices are a lane of the
/// same view, so no participant migration is introduced.
///
/// FXR: within the view, the lane this thread last ran on (`preferred`, `(index, generation)`)
/// comes first when it is free: its resident-register cache already holds most of this thread's
/// state (and usually its SIMD/FP file), so the run installs a few registers instead of the full
/// file. Only a lane of the same view is preferred -- crossing views costs a participant
/// migration, far more than a full install.
fn preferred_free_lane(
    free: &VecDeque<FreeLane>,
    view_tag: u64,
    preferred: Option<(usize, u64)>,
) -> Option<usize> {
    if let Some((index, generation)) = preferred
        && let Some(position) = free.iter().position(|lane| {
            lane.index == index && lane.generation == generation && lane.view_tag == view_tag
        })
    {
        return Some(position);
    }
    // T2c: with no lane of its own free, the most recently released lane of this view comes
    // first. Release pushes to the back, so this is LIFO within the view: the lane a thread just
    // handed back is the one whose owner is most likely still spinning for work (see
    // `AdaptiveSpin` in hvf_vcpu.rs), and reusing it also avoids a participant migration.
    free.iter()
        .rposition(|lane| lane.view_tag == view_tag)
        .or_else(|| (!free.is_empty()).then_some(0))
}

/// Ticket-ordered free-list state: a lane index is served to whichever
/// waiter's own ticket equals `next_serving`, so an acquire admitted after a
/// longer-waiting one can never barge ahead of it, regardless of `Condvar`
/// wakeup order.
struct LanePool {
    free: VecDeque<FreeLane>,
    checked_out: usize,
    retiring: usize,
    failure: Option<LaneReplacementFailure>,
    canceled_tickets: BTreeSet<u64>,
    next_ticket: u64,
    next_serving: u64,
}

/// Per-backend fault-classification counters, for the periodic debug
/// counters and as a live witness that every category of exception exit is
/// actually being taken (not merely reachable). `fatal_faults` is not here:
/// [`fatal`] is a free function with no backend handle at some of its call
/// sites (e.g. before process-global publication), so it uses its own
/// process-global counter instead.
#[derive(Default)]
struct HvfExceptionCounters {
    raw_exception_exits: std::sync::atomic::AtomicU64,
    stale_view_reruns: std::sync::atomic::AtomicU64,
    wx_service_requests: std::sync::atomic::AtomicU64,
    wx_service_settled: std::sync::atomic::AtomicU64,
    wx_service_refaulted: std::sync::atomic::AtomicU64,
    /// No producer yet -- reserved for the cross-crate `GuestVaDomain`-view-level conflict
    /// detector `hvf-wx-custody-crosscrate-commit-and-ledger` will add. Provably `0` today,
    /// which is exactly the value every consuming witness of the
    /// `wx_service_requests == wx_service_settled + wx_service_refaulted +
    /// wx_alias_conflict_refusals` invariant wants.
    wx_alias_conflict_refusals: std::sync::atomic::AtomicU64,
    in_flight: std::sync::atomic::AtomicI64,
    /// Times the per-mutation quarantine pump (see
    /// [`HvfBackend::pump_quarantine`]) actually ran `retry_quarantined_resources`
    /// because outstanding quarantine was observed.
    quarantine_pump_runs: std::sync::atomic::AtomicU64,
    /// Sum of every resource kind [`HvfQuarantineRetryReport`] reported
    /// released across every pump run.
    quarantine_pump_reclaimed: std::sync::atomic::AtomicU64,
    /// Sum of [`HvfQuarantineRetryReport::permanent_entries_observed`]
    /// across every pump run.
    quarantine_permanent_failures: std::sync::atomic::AtomicU64,
    /// wx-service-latency-measurement: count/sum/max nanoseconds of W^X service latency (from
    /// just before [`HvfBackend::classify_wx_fault`] through the guest resuming), across every
    /// request this vCPU resumed for on its own -- i.e. every [`WxFlipOutcome::Committed`],
    /// [`WxFlipOutcome::StaleGeneration`], and bounded-retry [`WxFlipOutcome::AliasConflictRefused`]
    /// (see [`HvfBackend::dispatch_monitor_exit`]'s WX-fault arm). A [`WxFlipOutcome::HostFailure`],
    /// or an alias-conflict refusal that exhausts its own rerun bound, falls through to ordinary
    /// guest-signal delivery instead of resuming here, so it contributes no sample -- this is
    /// service latency for the resumed-in-place path specifically, not every classified fault.
    wx_service_latency_count: std::sync::atomic::AtomicU64,
    wx_service_latency_sum_ns: std::sync::atomic::AtomicU64,
    wx_service_latency_max_ns: std::sync::atomic::AtomicU64,
    /// Log2(nanoseconds)-scale histogram of the same samples; see
    /// [`crate::diagnostics_counters::latency_bucket_index`].
    wx_service_latency_buckets:
        [std::sync::atomic::AtomicU64; crate::diagnostics_counters::LATENCY_BUCKETS],
}

/// One coherent, generation-bound snapshot of every hardware-exception counter that
/// participates in either of the row's two invariant equations, loaded in one pass (all
/// `Acquire`, so a concurrent increment mid-snapshot is never torn):
///
/// * `raw_exception_exits == stale_view_reruns + wx_service_requests + guest_faults_serviced +
///   guest_faults_delivered + fatal_faults`
/// * `wx_service_requests == wx_service_settled + wx_service_refaulted +
///   wx_alias_conflict_refusals`, with `in_flight == 0` at any settled/quiescent point.
///
/// `generation` is tagged from [`HvfBackend::mutations`], the existing per-mutation epoch marker
/// -- the natural "runner generation" this snapshot was taken against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HvfExceptionCountersSnapshot {
    pub(crate) raw_exception_exits: u64,
    pub(crate) stale_view_reruns: u64,
    pub(crate) wx_service_requests: u64,
    pub(crate) wx_service_settled: u64,
    pub(crate) wx_service_refaulted: u64,
    pub(crate) wx_alias_conflict_refusals: u64,
    pub(crate) guest_faults_serviced: u64,
    pub(crate) guest_faults_delivered: u64,
    pub(crate) fatal_faults: u64,
    pub(crate) in_flight: i64,
    pub(crate) generation: u64,
    /// The raw `TaskInstanceId` value (never reconstructed as a `TaskInstanceId` itself -- that
    /// type's constructor is deliberately mint-only, see `litebox::utils::ids`) most recently
    /// delivered to, per [`DELIVERED_TASK_RING`]. `None` marks an empty slot.
    pub(crate) delivered_task_ring: [Option<core::num::NonZeroU64>; DELIVERED_TASK_RING_LEN],
    /// See [`HvfExceptionCounters::quarantine_pump_runs`].
    pub(crate) quarantine_pump_runs: u64,
    /// See [`HvfExceptionCounters::quarantine_pump_reclaimed`].
    pub(crate) quarantine_pump_reclaimed: u64,
    /// See [`HvfExceptionCounters::quarantine_permanent_failures`].
    pub(crate) quarantine_permanent_failures: u64,
    /// See [`HvfExceptionCounters::wx_service_latency_count`].
    pub(crate) wx_service_latency_count: u64,
    /// See [`HvfExceptionCounters::wx_service_latency_sum_ns`].
    pub(crate) wx_service_latency_sum_ns: u64,
    /// See [`HvfExceptionCounters::wx_service_latency_max_ns`].
    pub(crate) wx_service_latency_max_ns: u64,
    /// See [`HvfExceptionCounters::wx_service_latency_buckets`].
    pub(crate) wx_service_latency_buckets: [u64; crate::diagnostics_counters::LATENCY_BUCKETS],
}

/// Process-global lifecycle-residual counters read by the `macos-hvf-thread-process-lifecycle`
/// umbrella acceptance witness: a live guest thread/process workload (clone/fork/vfork/exec/
/// wait/exit, repeated) must leave every one of these back at its pre-workload value once every
/// spawned task has exited and been reaped and every retirement/quarantine cycle it triggered has
/// settled. See [`hvf_lifecycle_residual_snapshot`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HvfLifecycleResidualSnapshot {
    /// Lanes/vCPUs with a live owner task attached. See [`HvfVcpuRegistry::active`].
    pub active_lanes: u32,
    /// Lanes/vCPUs abandoned by their owner but not yet reclaimed by the vCPU reaper. See
    /// [`HvfVcpuRegistry::custodial`].
    pub custodial_lanes: u32,
    /// Retired custody generations awaiting every participant's TLBI acknowledgement before their
    /// backing resources may be reused. See [`HvfMemoryUsage::retired_generations`].
    pub retired_generations: usize,
    /// Live per-lineage mirrored address spaces. See [`HvfMemoryUsage::address_spaces`].
    pub address_spaces: usize,
    /// Live `HostSlotArena` entries. See [`HvfMemoryUsage::host_slots`].
    pub host_slots: usize,
    /// Live `DataMapping`/backing objects. See [`HvfMemoryUsage::backing_objects`].
    pub backing_objects: usize,
    /// Alias-page quarantine reservations awaiting reclaim. See
    /// [`HvfMemoryUsage::alias_quarantine_reservations`].
    pub alias_quarantine_reservations: usize,
    /// Data-page quarantine reservations awaiting reclaim. See
    /// [`HvfMemoryUsage::data_quarantine_reservations`].
    pub data_quarantine_reservations: usize,
    /// Every still-outstanding quarantined resource of any kind. See
    /// [`HvfMemoryUsage::quarantined_resources`].
    pub quarantined_resources: usize,
    /// Total outstanding retirement rows summed across every live address space. See
    /// [`crate::hvf_memory::HvfMemory::total_rows_pending`] (`PageSettlementReceipt::rows_pending`,
    /// folded in by `diagnostics-counter-readout-surface-remaining-sources`).
    pub page_settlement_rows_pending: usize,
    /// Process-global shared backing objects still pinned by their key. See
    /// [`HvfMemoryUsage::pinned_shared_backings`].
    pub pinned_shared_backings: usize,
    /// Pages claimed across every live address space, against
    /// `HvfMemoryLimits::max_claimed_pages`. See [`HvfMemoryUsage::claimed_pages`]. Published
    /// (with `live_data_pages`) so a long-running witness can watch the fork-COW retention
    /// `reap_fork_cow_retention` bounds -- both climbed monotonically to their limits under a
    /// Chromium spawn storm before it existed.
    pub claimed_pages: usize,
    /// Claimed pages with a live stage-two data mapping, against
    /// `HvfMemoryLimits::max_live_data_pages`. See [`HvfMemoryUsage::live_data_pages`].
    pub live_data_pages: usize,
    /// Shared read-only file origins alive in the registry (`hvf_memory::FILE_ORIGINS`), each
    /// referenced by at least one window record or file alias; back to baseline once every
    /// space that mapped a file privately is destroyed.
    pub file_origin_objects: usize,
    /// Live private-file window records across every space (a split adds one).
    pub file_windows_live: usize,
    /// Live read-only file aliases onto origin pages across every space.
    pub file_alias_pages_live: usize,
    /// BCORE-1: vCPUs a guest thread created and drives on its own host thread. Back to 0 once
    /// every guest thread that took one has exited -- `unbind_current_thread` is the only
    /// releaser, and it runs from the shim's thread-exit path and from `run_thread`'s return.
    pub bound_vcpus: u32,
    /// BCORE-1: bound vCPUs no thread can destroy any more (an owner unwound past its own
    /// vCPU). Permanent and expected to be 0: a nonzero value means a vCPU leaked out of the
    /// bound path and the VM's own cap is smaller from here on.
    pub lost_vcpus: u32,
}

/// Decrements [`HvfExceptionCounters::in_flight`] on every return path out of
/// exception dispatch (syscall, WFx, stale rerun, WX-resolved, or delivered
/// to the shim) without having to touch each return statement individually.
struct InFlightExceptionGuard<'a>(&'a std::sync::atomic::AtomicI64);

impl<'a> InFlightExceptionGuard<'a> {
    fn new(in_flight: &'a std::sync::atomic::AtomicI64) -> Self {
        in_flight.fetch_add(1, Ordering::Relaxed);
        Self(in_flight)
    }
}

impl Drop for InFlightExceptionGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct HvfBackend {
    memory: &'static HvfMemory,
    /// The address space used for every pre-view/bring-up path and as the
    /// fallback whenever a call site has no [`VmViewId`] to resolve (kept
    /// exactly as the single space this backend used before per-view
    /// isolation existed).
    default_space: HvfAddressSpace,
    /// The mirrored space every shared file origin is claimed in (see
    /// `hvf_memory::FILE_ORIGINS`): never passed to `attach_vcpu`, never the target of
    /// `ensure_lane_attached_to_view`, so no vCPU root ever carries an origin descriptor;
    /// windows alias its pages by IPA and host redirects use its permanent host mirror. Created
    /// with the backend (one of `max_address_spaces`, permanently) unless
    /// `LITEBOX_HVF_NO_FILE_COW=1`, in which case every private file mapping keeps taking the
    /// memcpy path.
    origin_space: Option<HvfAddressSpace>,
    /// One additional mirrored address space per `VmViewId` that has ever
    /// needed real isolation from `default_space`, created lazily by
    /// [`Self::space_for_view`]. Bounded the same way `default_space` itself
    /// is: `create_mirrored_address_space` enforces
    /// `HvfMemoryLimits::max_address_spaces` (254) internally.
    /// CLASS C: read-mostly (every guest exit resolves its view's space here), so a reader
    /// lock: a `Mutex` made one address-space lookup at a time process-wide, measured 0.354
    /// thread-seconds per wall-second of waiters at idle (`prepare_guest_access+192`).
    /// Writes (create on first use, remove on release) stay exclusive.
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_VIEW_SPACES`]).
    view_spaces: RankedRwLock<HashMap<VmViewId, Arc<HvfAddressSpace>>>,
    /// Views already permanently retired at the domain level (see
    /// [`Self::release_view_space`]) whose own [`Self::view_spaces`] entry has not yet been
    /// destroyed -- [`HvfAddressSpace::destroy`] refused at least once, or a live descendant still
    /// held an unpromoted COW alias possibly sourced from this view (see
    /// [`Self::family_blocks_release`]), so the entry stays reachable here for a later retry
    /// instead of being dropped unreachable-but-still-alive. Each entry's own [`FamilyId`] is
    /// captured once, by the caller, before the view is unregistered from the domain -- see
    /// [`GuestVaDomain::family_of_view`]'s own doc comment for why a fresh per-retry lookup by
    /// [`VmViewId`] alone cannot work here.
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_VIEW_RETIREMENT`]). Taken by
    /// [`Self::release_view_space`]'s deferral arm and by the reap paths, i.e. around a space's
    /// `destroy()`, which joins the VM operation gate -- so it is exactly the "held across the
    /// FIFO" shape the rank exists to name.
    pending_view_retirement: RankedMutex<Vec<(VmViewId, Option<FamilyId>)>>,
    registry: HvfVcpuRegistry,
    el1: HvfEl1State,
    lanes: Vec<PooledLane>,
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_LANE_POOL`]). A guest thread parks on
    /// [`Self::available`] while holding it when no lane is free, which is the one condvar wait on
    /// the per-syscall path; it is also taken by every mutation's shootdown.
    free: RankedMutex<LanePool>,
    available: Condvar,
    /// Step GF (b): guest threads parked inside [`Self::acquire_lane_inner`] right now, i.e.
    /// genuinely waiting for a lane rather than running one. A thread holding a sticky lease
    /// reads this (one relaxed load per run) and gives its lane back as soon as it is non-zero,
    /// which is what keeps stickiness from starving a waiter: the pool's strict FIFO ticket
    /// order is bypassed only while nobody is queued.
    lane_waiters: AtomicUsize,
    /// Step GF (b): bumped whenever something needs every retained lane back -- a mapping
    /// shootdown (which can only synchronize a lane it can take out of the pool) or lane
    /// maintenance. A sticky lease records the epoch it was taken at and is given back at the
    /// holder's next loop top once this has moved.
    lane_yield_epoch: AtomicU64,
    /// Step GF (fix-up): one bit per lane index, set exactly while that lane's checkout is parked
    /// in some thread's [`RETAINED_LANE`] and cleared the moment it is not. This is what lets a
    /// shootdown tell the two reasons a lane can be checked out apart: "a thread is keeping it
    /// between runs" (which the shootdown can only reach by asking that thread to give it back)
    /// versus "a thread is mid-run on it" (which the shootdown simply has to wait out). Before
    /// this existed, every unreachable lane bumped [`Self::lane_yield_epoch`], and a bump revokes
    /// *every* retained lease process-wide -- so a shootdown storm switched stickiness off for
    /// every thread, not just the ones holding a lane the shootdown needed.
    retained_lanes: AtomicU64,
    lane_maintenance: LaneMaintenance,
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_PARTICIPANT_RECOVERY`]); it serializes
    /// the lane-participant recovery sweep, which takes each lane's participant (ranked above it)
    /// and the memory manager's locks while held.
    participant_recovery: RankedMutex<()>,
    trampoline: Range<usize>,
    /// The vDSO image page followed by its clock data page; see [`crate::vdso`].
    vdso: Range<usize>,
    /// The clock data page's host-writable storage address and the values last published
    /// there; one mutex serializes the shim's epoch hand-over against the periodic realtime
    /// refresher (see [`Self::publish_vdso_clock`]).
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_VDSO_CLOCK`]); it serializes the
    /// shim's epoch hand-over against the periodic realtime refresher, both of which write the
    /// clock page the guest reads without a lock, so it is held across that host write.
    vdso_clock: RankedMutex<VdsoClock>,
    /// CLASS A: ranked ([`crate::diagnostics_counters::RANK_SHARED_INIT`]); a second thread waits
    /// on [`Self::shared_initialization_changed`] while holding it, so the park is a named
    /// `wait_while_holding` site rather than an invisible one.
    shared_initialization: RankedMutex<SharedInitialization>,
    shared_initialization_changed: Condvar,
    /// Running count of settled mutations, for the periodic debug counters.
    mutations: std::sync::atomic::AtomicU64,
    /// BCORE-4: one entry per live bound vCPU, so a mutation's settle can kick them exactly
    /// the way it kicks running lanes. Only ever non-empty with `LITEBOX_HVF_BOUND=1`.
    bound_entries: Mutex<Vec<Arc<BoundEntry>>>,
    /// Lazy write-xor-execute emulation for a guest `mprotect(RWX)`; see
    /// [`WxToggle`]'s own doc comment.
    wx_toggle: WxToggle,
    /// Fault-classification counters; see [`HvfExceptionCounters`].
    exception_counters: HvfExceptionCounters,
}

/// What the host publishes into the vDSO clock data page; see [`crate::vdso`].
struct VdsoClock {
    /// Host-writable address of the clock data page (`HvfAddressSpace::host_storage_address`);
    /// `0` until [`HvfBackend::install_vdso`] has run.
    storage: usize,
    values: crate::vdso::ClockValues,
}

// -- step GF (b): lane stickiness -----------------------------------------
//
// Why this exists. The G inventory (step G, `.gm/syscall-bench/steps/G/inventory.md` §7 and the
// 2026-09-29 re-measurement under `.gm/syscall-bench/steps/GF/`) credits 71-76 % of the
// X-connected spaces' runnable-not-running time to `r2_view_attach` and 9-15 % to
// `r1_lane_wait`, and both are the same thing: the pooled path hands the lane back to
// [`HvfBackend::free`] at the end of every single run, so the next run of the same thread has to
// take a ticket, wait its turn, and -- whenever the lane it gets is registered in a different
// view -- migrate it (`HvfBackend::ensure_lane_attached_to_view`, two participant operations and
// a fresh address-space attachment), measured at 10.4 ms mean per migration on the desktop.
//
// What it does. A thread whose run ended keeps the checkout in [`RETAINED_LANE`] instead, so the
// next run reuses `slot.current`'s whole attachment: no pool round trip, no migration, no
// re-attach. The invariant that makes that safe is single and applies to every case below:
//
// > **A thread may hold a lane only while it is making progress towards its next run.**
//
// Five things enforce it:
//
// * **a waiter** -- [`HvfBackend::lane_waiters`] is non-zero, so the pool's strict FIFO ticket
//   order is bypassed only while nobody is queued;
// * **a host wait** -- [`release_retained_lane`] runs before this thread blocks on any host
//   primitive it can be parked on: the platform park ([`RawMutex::block_inner`], which every
//   ulock wait -- interruptible guest wait, vfork park, shim lock -- goes through), the
//   exclusive-VM-operation admission FIFO (`HvfVm::wait_for_operation_state`, the desktop's
//   single largest blocked wait), and a contended [`crate::diagnostics_counters::RankedMutex`].
//   A thread parked in one of these cannot give its lane back at a loop top, and the shim's
//   dispatch -- which runs *while* the lease is retained -- blocks on them for milliseconds at a
//   time, so covering them is not hygiene: it is the difference between holding a lane across a
//   host I/O wait and not;
// * **a shootdown or lane maintenance** -- [`HvfBackend::lane_yield_epoch`] moved. Note the one
//   case this cannot cover: the shootdown's own caller is the mutating thread, which retains the
//   lane it is now trying to acquire and has no loop top until the shootdown returns, so
//   [`HvfBackend::shootdown`] releases its own lease up front instead of asking itself for it;
// * **the retention bounds** -- [`LANE_STICKY_MAX_RUNS`] consecutive runs, or
//   [`lane_sticky_max_hold`] of wall clock, whichever comes first. Both are real: the run count
//   is carried from one retain to the next (it is incremented on the lease the thread is actually
//   still holding, not on a throwaway copy), and the deadline is stamped when the lease is taken.
//   They are the backstop for a thread that never blocks and never sees a waiter, including a
//   thread blocked on a host primitive this list does not know about -- which bounds the hold but
//   cannot release it mid-block, so the site list above is not optional;

/// How many consecutive runs one retained lease may serve. Nothing but this stands between a
/// guest thread that never blocks and the rest of the process's threads if
/// [`HvfBackend::lane_waiters`] were ever wrong; at ~10 us per short syscall it bounds a
/// waiter-free hold to well under a millisecond.
///
/// Step GF (fix-up): this cap was dead code on arrival -- `retain_lane` stored `0` on every call
/// and `take_retained_lane` incremented a copy whose struct was dropped with the lease moved out
/// of it, so no lease ever reached 64 runs and `lane_sticky.released_cap` was structurally 0.
/// [`Self::take_retained_lane`] now returns the incremented count so the caller can carry it into
/// the next [`retain_lane`].
const LANE_STICKY_MAX_RUNS: u32 = 64;

/// Default for [`lane_sticky_max_hold`]: one guest time slice.
const LANE_STICKY_MAX_HOLD_US: u64 = 10_000;

/// Step GF (fix-up): the wall-clock half of the retention bound -- a lease is given back at the
/// holder's next loop top once this much wall time has passed since it was taken, whatever the
/// run count says. Two things it buys that the run count cannot: it names the bound the PRD row
/// actually words ("until it blocks or its 10 ms slice expires"), and it catches a lease held
/// across one very long iteration (a multi-millisecond shim dispatch), which a run count of 64
/// never would. Override with `LITEBOX_HVF_LANE_STICKY_US`.
fn lane_sticky_max_hold() -> Duration {
    static HOLD: OnceLock<Duration> = OnceLock::new();
    *HOLD.get_or_init(|| {
        let us = std::env::var("LITEBOX_HVF_LANE_STICKY_US")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(LANE_STICKY_MAX_HOLD_US);
        Duration::from_micros(us)
    })
}

/// A lane checkout a guest thread is keeping from one run to the next.
struct RetainedLane {
    lease: LaneLease<'static>,
    /// Consecutive runs this lease has served so far.
    runs: u32,
    /// [`HvfBackend::lane_yield_epoch`] when the lease was taken.
    epoch: u64,
    /// Step GF (fix-up): wall-clock deadline stamped when the lease was taken, so a lease held
    /// across one long iteration is not also held across the next.
    deadline: Instant,
}

thread_local! {
    /// Step GF (b): the calling guest thread's retained lane, if any. One per host thread, and a
    /// host thread runs one guest thread at a time, so there is no keying to do.
    static RETAINED_LANE: RefCell<Option<RetainedLane>> = const { RefCell::new(None) };
}

/// Step GF (b): asks every thread holding a retained lane to give it back at its next loop top.
/// Called by a mapping shootdown that could not take a lane out of the pool (it must synchronize
/// that lane, and a checked-out lane is invisible to it) and by lane maintenance.
fn bump_lane_yield_epoch() {
    if let Some(backend) = active() {
        backend.lane_yield_epoch.fetch_add(1, Ordering::SeqCst);
    }
}

/// Step GF (b): hands the calling thread's retained lane back to the pool, if it has one.
///
/// The one entry point for every "this thread is about to stop iterating" case: before a platform
/// wait ([`RawMutex::block_inner`]), before the exclusive-VM-operation admission wait
/// (`HvfVm::wait_for_operation_state`), before a contended `RankedMutex`, and when the thread
/// leaves [`HvfBackend::run_thread`] altogether. Safe to call from any thread at any time -- it is
/// a no-op when nothing is retained, and a retained lane is never mid-attachment (the attachment is
/// consumed by the run that just returned) so it is always immediately releasable.
pub(crate) fn release_retained_lane(reason: usize) {
    let Some(retained) = RETAINED_LANE.with(|cell| cell.borrow_mut().take()) else {
        return;
    };
    // The lease's own backend, not `active()`: a lease is only ever retained on the backend it was
    // taken from (`run_thread_loop` filters `active()` against `self` before retaining), so this
    // is exact and cannot clear a bit on some other backend's mask.
    retained.lease.backend.clear_retained_lane(retained.lease.index());
    crate::diagnostics_counters::record_lane_sticky(reason);
    drop(retained.lease);
}

/// Step GF (b): stores `lease` as this thread's retained lane, carrying the run count `runs`
/// forward from the lease's previous retention (0 for a lease just taken from the pool).
fn retain_lane(lease: LaneLease<'static>, runs: u32, epoch: u64, deadline: Instant) {
    lease.backend.set_retained_lane(lease.index());
    RETAINED_LANE.with(|cell| {
        *cell.borrow_mut() = Some(RetainedLane {
            lease,
            runs,
            epoch,
            deadline,
        });
    });
}

impl HvfBackend {
    /// Step GF (fix-up): records that lane `index` is now parked in some thread's
    /// [`RETAINED_LANE`]. See [`Self::retained_lanes`].
    fn set_retained_lane(&self, index: usize) {
        if index < u64::BITS as usize {
            self.retained_lanes.fetch_or(1 << index, Ordering::SeqCst);
        }
    }

    /// Step GF (fix-up): the converse of [`Self::set_retained_lane`].
    fn clear_retained_lane(&self, index: usize) {
        if index < u64::BITS as usize {
            self.retained_lanes.fetch_and(!(1 << index), Ordering::SeqCst);
        }
    }

    /// Step GF (fix-up): whether lane `index` is currently parked in some thread's
    /// [`RETAINED_LANE`] rather than merely checked out by a thread mid-run.
    fn lane_is_retained(&self, index: usize) -> bool {
        index < u64::BITS as usize && self.retained_lanes.load(Ordering::SeqCst) & (1 << index) != 0
    }

    /// Step GF (b): takes this thread's retained lane back for one more run, or `None` when the
    /// thread has none or must not keep it (see the module comment for the release cases). The
    /// returned [`RetainedLane::runs`] is already incremented, so the caller can carry it into the
    /// next [`retain_lane`] -- that carry is what makes [`LANE_STICKY_MAX_RUNS`] reachable.
    fn take_retained_lane(&self) -> Option<RetainedLane> {
        if !crate::diagnostics_counters::lane_sticky_enabled() {
            return None;
        }
        let mut retained = RETAINED_LANE.with(|cell| cell.borrow_mut().take())?;
        use crate::diagnostics_counters::{
            LANE_STICKY_RELEASED_CAP, LANE_STICKY_RELEASED_TIME, LANE_STICKY_RELEASED_WAITERS,
            LANE_STICKY_RELEASED_YIELD,
        };
        let waiters = self.lane_waiters.load(Ordering::Relaxed) != 0;
        let yielded = self.lane_yield_epoch.load(Ordering::Acquire) != retained.epoch;
        let capped = retained.runs >= LANE_STICKY_MAX_RUNS;
        let expired = Instant::now() >= retained.deadline;
        let reason = if waiters {
            Some(LANE_STICKY_RELEASED_WAITERS)
        } else if yielded {
            Some(LANE_STICKY_RELEASED_YIELD)
        } else if capped {
            Some(LANE_STICKY_RELEASED_CAP)
        } else if expired {
            Some(LANE_STICKY_RELEASED_TIME)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.clear_retained_lane(retained.lease.index());
            crate::diagnostics_counters::record_lane_sticky(reason);
            drop(retained.lease);
            return None;
        }
        retained.runs = retained.runs.saturating_add(1);
        Some(retained)
    }
}

/// Affine custody of one index removed from [`LanePool::free`]. A checkout can
/// move to a worker thread, but it cannot be copied or forgotten accidentally;
/// every return is also checked against the lane owner's quiescent state.
struct LaneLease<'backend> {
    backend: &'backend HvfBackend,
    index: usize,
    generation: Arc<LaneGeneration>,
    return_to_pool: bool,
}

impl LaneLease<'_> {
    const fn index(&self) -> usize {
        self.index
    }

    fn lane(&self) -> &LaneGeneration {
        &self.generation
    }

    /// Step GF (b): rebinds this checkout to a `&'static` backend so it can outlive the
    /// `&self` borrow it was taken under and be kept in [`RETAINED_LANE`] from one run to the
    /// next. The checkout is affine either way -- this moves it rather than dropping it, so the
    /// lane is never returned to the pool here.
    fn with_backend(self, backend: &'static HvfBackend) -> LaneLease<'static> {
        let this = core::mem::ManuallyDrop::new(self);
        LaneLease {
            backend,
            index: this.index,
            generation: Arc::clone(&this.generation),
            return_to_pool: this.return_to_pool,
        }
    }

    fn retire(mut self) {
        let generation = self.generation.handle.generation();
        let requested = self
            .generation
            .lane
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|lane| {
                lane.request_retirement();
                true
            });
        let mut pool = self
            .backend
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut slot = self.backend.lanes[self.index]
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retiring = pool.retiring.checked_add(1);
        let valid = requested
            && pool.failure.is_none()
            && !pool.free.iter().any(|free| free.index == self.index)
            && pool.checked_out != 0
            && retiring.is_some()
            && matches!(
                &*slot,
                LaneSlotState::Ready(current)
                    if current.handle.generation() == generation
                        && Arc::ptr_eq(current, &self.generation)
            );
        if valid {
            let Some(retiring) = retiring else {
                unreachable!();
            };
            *slot = LaneSlotState::Retiring(Arc::clone(&self.generation));
            pool.checked_out -= 1;
            pool.retiring = retiring;
            self.return_to_pool = false;
        }
        drop(slot);
        drop(pool);
        if !valid {
            fatal(
                "retiring a vCPU lane generation",
                &HvfBackendError::LanePoolCorrupt { index: self.index },
            );
        }
        let backend = self.backend;
        drop(self);
        backend.request_lane_maintenance();
    }
}

impl Drop for LaneLease<'_> {
    fn drop(&mut self) {
        if !self.return_to_pool {
            return;
        }
        if !self.generation.handle.is_reusable() {
            fatal(
                "returning a non-quiescent vCPU lane to the pool",
                &HvfBackendError::LaneNotReusable { index: self.index },
            );
        }
        self.backend.release_lane(self.index, &self.generation);
    }
}

/// Extends a lane checkout with the exact cancellation capability and run
/// reservation installed for this thread. Its destructor clears thread
/// authority, settles any unsubmitted reservation, and only then returns a
/// reusable lane to the pool or retires a non-reusable generation.
struct ActiveThreadLaneLease<'backend, 'slot> {
    lease: Option<LaneLease<'backend>>,
    slot: &'slot HvfThreadSlot,
    cancellation: Option<HvfVcpuLaneCancellation>,
    reservation: Option<HvfVcpuRunReservation>,
}

impl<'backend, 'slot> ActiveThreadLaneLease<'backend, 'slot> {
    const fn new(lease: LaneLease<'backend>, slot: &'slot HvfThreadSlot) -> Self {
        Self {
            lease: Some(lease),
            slot,
            cancellation: None,
            reservation: None,
        }
    }

    fn index(&self) -> usize {
        self.lease.as_ref().map_or(usize::MAX, LaneLease::index)
    }

    fn lane(&self) -> &LaneGeneration {
        self.lease.as_ref().map(LaneLease::lane).unwrap_or_else(|| {
            fatal(
                "accessing a released vCPU lane checkout",
                &HvfBackendError::LanePoolCorrupt { index: usize::MAX },
            )
        })
    }

    fn install(
        &mut self,
        reservation: HvfVcpuRunReservation,
        cancellation: HvfVcpuLaneCancellation,
    ) {
        if self.cancellation.is_some() || self.reservation.is_some() {
            fatal(
                "installing duplicate vCPU run authority",
                &HvfBackendError::LanePoolCorrupt {
                    index: self.index(),
                },
            );
        }
        self.cancellation = Some(cancellation);
        self.reservation = Some(reservation);
    }

    /// Clears everything that makes THIS THREAD the lane's authority: the cancellation
    /// capability installed in the thread's slot first, then any run reservation it has not
    /// submitted -- deliberately in that order, so no new interrupt can acquire stale authority
    /// while the reservation is being cancelled. [`Drop`] and [`Self::settle_keeping_lane`]
    /// share it, so "end the run" means exactly one thing.
    fn clear_authority(&mut self) {
        if let Some(expected) = self.cancellation.take() {
            let mut current = self
                .slot
                .current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !current
                .as_ref()
                .is_some_and(|installed| installed.is_same_run(&expected))
            {
                drop(current);
                fatal(
                    "clearing a vCPU run cancellation capability",
                    &HvfBackendError::LanePoolCorrupt {
                        index: self.index(),
                    },
                );
            }
            *current = None;
        }
        drop(self.reservation.take());
    }

    /// Ends the run exactly as [`Drop`] does, but hands the checkout back to the caller instead
    /// of returning the lane to the pool (step GF (b) lane stickiness). `None` means the lane
    /// generation was no longer reusable, in which case [`LaneLease::retire`] has already run.
    fn settle_keeping_lane(&mut self) -> Option<LaneLease<'backend>> {
        self.clear_authority();
        let lease = self.lease.take()?;
        if lease.generation.handle.is_reusable() {
            Some(lease)
        } else {
            crate::diagnostics_counters::record_lane_sticky(
                crate::diagnostics_counters::LANE_STICKY_RELEASED_RETIRE,
            );
            lease.retire();
            None
        }
    }

    fn take_reservation(&mut self) -> HvfVcpuRunReservation {
        self.reservation.take().unwrap_or_else(|| {
            fatal(
                "submitting a missing vCPU run reservation",
                &HvfBackendError::LanePoolCorrupt {
                    index: self.index(),
                },
            )
        })
    }
}

impl Drop for ActiveThreadLaneLease<'_, '_> {
    fn drop(&mut self) {
        self.clear_authority();

        let Some(lease) = self.lease.take() else {
            return;
        };
        if lease.generation.handle.is_reusable() {
            drop(lease);
        } else {
            lease.retire();
        }
    }
}

struct OwnedGuestRange<'backend> {
    backend: &'backend HvfBackend,
    range: Range<usize>,
    armed: bool,
}

impl<'backend> OwnedGuestRange<'backend> {
    fn new(backend: &'backend HvfBackend, range: Range<usize>) -> Self {
        Self {
            backend,
            range,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for OwnedGuestRange<'_> {
    fn drop(&mut self) {
        if self.armed {
            let cleaned = self.backend.mutate_with_retry(
                &self.backend.default_space,
                MutationKind::Unmap,
                || self.backend.default_space.unmap_range(self.range.clone(), false),
            );
            if !matches!(cleaned, Ok(true)) {
                fatal(
                    "cleaning up an owned HVF guest range",
                    &HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting),
                );
            }
        }
    }
}

struct ProbeWorker<T> {
    index: usize,
    stop: std::sync::Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<T, HvfVcpuLaneError>>>,
}

impl<T> ProbeWorker<T> {
    fn join(mut self) -> std::thread::Result<Result<T, HvfVcpuLaneError>> {
        match self.thread.take() {
            Some(thread) => thread.join(),
            None => Err(Box::new("HVF probe worker was already joined")),
        }
    }
}

impl<T> Drop for ProbeWorker<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl fmt::Debug for HvfBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfBackend")
            .field("address_space", &self.default_space.id())
            .field("lanes", &self.lanes.len())
            .field("registry", &self.registry)
            .field("trampoline", &self.trampoline)
            .field("vdso", &self.vdso)
            .finish_non_exhaustive()
    }
}

static HVF_BACKEND: OnceLock<HvfBackend> = OnceLock::new();
// CLASS A: ranked ([`crate::diagnostics_counters::RANK_BACKEND_INSTALL`]) -- it serializes
// backend installation, which creates the VM, every lane vCPU and the vDSO: host calls, and
// never anything that can take this lock again, so it is the order's bottom.
static HVF_BACKEND_INSTALL: RankedMutex<()> =
    RankedMutex::new((), crate::diagnostics_counters::RANK_BACKEND_INSTALL);

/// The installed backend, if the runner selected HVF execution.
pub(crate) fn active() -> Option<&'static HvfBackend> {
    HVF_BACKEND.get()
}

/// Reads [`HvfBackend::lifecycle_residual_snapshot`] for the installed backend, or `None` when
/// HVF execution was not selected for this process (the native backend has none of these
/// resources). The `macos-hvf-thread-process-lifecycle` umbrella acceptance witness reads this
/// once before a workload and once after every task it spawned has exited and been reaped,
/// comparing every field for exact convergence back to the pre-workload snapshot.
pub fn hvf_lifecycle_residual_snapshot() -> Option<HvfLifecycleResidualSnapshot> {
    active().map(HvfBackend::lifecycle_residual_snapshot)
}

/// Live witness that the already-installed HVF backend keeps working with the
/// Seatbelt sandbox up: acquires a pooled lane, runs one real
/// `hv_vcpu_run` round-trip through the EL1 monitor (the same `HVC`-dispatch
/// path every guest syscall uses), and confirms the exit is the expected
/// monitor `HVC`. `hv_vcpu_run`/`hv_vm_map`/etc. are not syscalls, so Seatbelt
/// (which mediates named *operations*, not arbitrary Mach traps) has no
/// policy rule that could deny them either way -- this proves that
/// empirically rather than assuming it, matching how the rest of this module
/// treats every other host-boundary interaction.
///
/// # Errors
///
/// Returns the backend's typed error if no lane is available, the vCPU
/// cannot be attached, or the run does not return the expected monitor exit.
pub fn hvf_sandbox_probe() -> Result<(), HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lease = backend.acquire_lane()?;
    let outcome = (|| {
        let lane = lease.lane();
        let attachment = {
            let participant = lane
                .participant
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            backend.default_space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?
        };
        let state = spin_probe_state(backend.trampoline_address());
        let run = lane.handle.run(attachment, &state)?;
        let hvc = matches!(run.state, HvfVcpuExitState::LowerElMonitor(_))
            && matches!(
                run.exit,
                HvfVcpuExit::Exception(exception)
                    if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_HVC64
                        && exception.syndrome & HVC_IMMEDIATE_MASK == MONITOR_HVC_IMMEDIATE
            );
        if hvc {
            Ok(())
        } else {
            let state = match &run.state {
                HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => {
                    state
                }
            };
            Err(HvfBackendError::UnexpectedExit {
                exit: run.exit,
                source_pc: Some(state.pc),
            })
        }
    })();
    drop(lease);
    outcome
}

/// A minimal, diagnostic-only [`EnterShim`] for [`hvf_vtimer_monitor_race_probe`].
///
/// The `EC_WFX` arm of `dispatch_monitor_exit` -- the one this probe's
/// constructed-combination tier deliberately routes through -- never calls any
/// shim method (it only advances `ctx.pc` and yields). These bodies exist
/// solely so a concrete `&dyn EnterShim` can be constructed at all; actually
/// reaching one would mean this probe's own construction is wrong, not that
/// the fix under test is wrong, so they fail loudly instead of pretending to
/// behave like a real shim.
struct HvfVtimerRaceNullShim;

impl EnterShim for HvfVtimerRaceNullShim {
    type ExecutionContext = PtRegs;
    fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        unreachable!("hvf_vtimer_monitor_race_probe: its EC_WFX exit never calls EnterShim::init")
    }
    fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        unreachable!("hvf_vtimer_monitor_race_probe: its EC_WFX exit never calls EnterShim::syscall")
    }
    fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
        unreachable!("hvf_vtimer_monitor_race_probe: its EC_WFX exit never calls EnterShim::exception")
    }
    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        unreachable!("hvf_vtimer_monitor_race_probe: its EC_WFX exit never calls EnterShim::interrupt")
    }
}

/// Report for [`hvf_vtimer_monitor_race_probe`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfVtimerMonitorRaceReport {
    /// Attempts spent genuinely trying to win the real micro-architectural race
    /// (a real EL0 `SVC` raced against a virtual-timer deadline) before this
    /// probe's own bounded budget ran out.
    pub race_attempts: u32,
    /// True if one of those real attempts actually landed
    /// `(VtimerActivated, LowerElMonitor)` at `MONITOR_LOWER_EL_SYNC_OFFSET` --
    /// the exact SDK-level condition this row's own live evidence witnessed
    /// twice during real interactive use, reproduced here from a real
    /// `hv_vcpu_run` round trip rather than only constructed.
    pub real_race_won: bool,
    /// `HvfBackend::dispatch` -- the exact function this row's fatal abort
    /// lives in -- was called with the witnessed `(VtimerActivated,
    /// LowerElMonitor)` combination at `MONITOR_LOWER_EL_SYNC_OFFSET`,
    /// constructed directly (the row's own live evidence already
    /// independently proved this is a real, reachable SDK output; this tier
    /// tests the only thing actually in question -- whether `dispatch`'s
    /// routing for it is correct -- deterministically rather than only when
    /// the real race happens to land), and returned normally.
    ///
    /// Always `true` when this report exists: `dispatch` aborting the process
    /// on this combination is exactly the bug this row is about, and an abort
    /// takes the whole process down immediately (no unwind, no `Result`) --
    /// so there is no failure value to encode here. Seeing this report at all,
    /// for either tier, already is the pass signal.
    pub constructed_dispatch_returned: bool,
    /// The `state.pc` both tiers exercised (`MONITOR_LOWER_EL_SYNC_OFFSET`),
    /// so the report is self-describing without cross-checking the source.
    pub source_pc: u64,
}

/// Deliberately, repeatably reproduces the exact `(HvfVcpuExit::VtimerActivated,
/// HvfVcpuExitState::LowerElMonitor)` combination at `MONITOR_LOWER_EL_SYNC_OFFSET`
/// behind `hvf-vtimeractivated-lowerelmonitor-exit-aborts-runner` (live-witnessed
/// twice during real interactive VNC keyboard input, both times ending the runner
/// via `std::process::abort()`), and proves `HvfBackend::dispatch` no longer
/// aborts the process on it.
///
/// Two tiers, both exercised every run:
///
/// 1. A bounded number of genuine attempts to win the real race: a real EL0
///    `SVC` through the guest-executable sigreturn trampoline
///    ([`spin_probe_state`]), raced via [`HvfVcpuLaneHandle::run_with_deadline`]
///    against a virtual-timer deadline swept a few ticks around the read of
///    `CNTVCT_EL0` taken just before each call. The window this needs to land
///    in -- between the monitor's sync-vector entry and its own single `HVC`
///    instruction -- is a handful of hardware cycles wide, well under one
///    24MHz tick, so what actually gives different attempts a real chance is
///    the host-side scheduling jitter around each `hv_vcpu_run` round trip
///    (itself real, variable wall-clock work) -- the same kind of jitter real
///    interactive load supplied in production, not a hand-tuned exact offset.
/// 2. A deterministic construction of the exact witnessed combination -- a
///    plain [`HvfVcpuRunResult`] literal, no SDK round trip -- fed straight
///    into `dispatch()`. This is not a fallback of last resort: it is run
///    every time specifically because the race above is expected to often
///    miss on a quiet, unloaded diagnostic host (unlike the real desktop
///    session this row's evidence came from), and this row's own live
///    evidence already independently proved the SDK really does produce this
///    combination -- so what's actually in question, and all this tier
///    exists to test, is whether `dispatch()`'s routing for it is correct.
///
/// # Errors
///
/// Returns the backend's typed error if no lane is available or the vCPU
/// cannot be attached. Never returns an error for the condition under test:
/// if `dispatch()` still aborted, the whole process would already be gone
/// before either tier could return anything at all -- there is no in-band
/// failure to represent.
pub fn hvf_vtimer_monitor_race_probe() -> Result<HvfVtimerMonitorRaceReport, HvfBackendError> {
    const RACE_ATTEMPT_BOUND: u32 = 4_000;
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lease = backend.acquire_lane()?;
    let outcome = (|| {
        let lane = lease.lane();
        let attach = || -> Result<HvfVcpuRunAttachment, HvfBackendError> {
            let participant = lane
                .participant
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(backend
                .default_space
                .attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?)
        };

        // Tier 1: genuinely try to win the real race.
        let mut race_attempts = 0u32;
        let mut real_race_won = false;
        while race_attempts < RACE_ATTEMPT_BOUND {
            race_attempts += 1;
            let state = spin_probe_state(backend.trampoline_address());
            let now: u64;
            // SAFETY: the same EL0-permitted `CNTVCT_EL0` read `time_slice_deadline`
            // already performs elsewhere in this file.
            unsafe {
                core::arch::asm!("isb", "mrs {counter}, cntvct_el0", counter = out(reg) now, options(nomem, nostack));
            }
            let deadline = now.wrapping_add(u64::from(race_attempts % 5));
            let run = lane.handle.run_with_deadline(attach()?, &state, deadline)?;
            if matches!(run.exit, HvfVcpuExit::VtimerActivated)
                && matches!(
                    run.state,
                    HvfVcpuExitState::LowerElMonitor(inner)
                        if inner.pc == MONITOR_LOWER_EL_SYNC_OFFSET
                )
            {
                real_race_won = true;
                break;
            }
            // Every other outcome (a clean DirectGuest VtimerActivated that missed the
            // `SVC` entirely, or a real Exception/HVC `LowerElMonitor` exit where the
            // `HVC` won the race) is not this row's own combination. Nothing here needs
            // unwinding for either: a `DirectGuest` exit never touched the monitor, and
            // an ordinary monitor `HVC` exit is exactly what `dispatch_monitor_exit`
            // already handles correctly elsewhere (`(Exception, LowerElMonitor)` with the
            // monitor's own HVC syndrome) -- this probe simply does not act on it, and
              // the next attempt mints an entirely fresh EL0 entry state regardless.
        }

        // Tier 2: construct the exact witnessed combination and prove `dispatch()`
        // routes it without aborting.
        let mut monitor_state = HvfArchitecturalState::default();
        monitor_state.pc = MONITOR_LOWER_EL_SYNC_OFFSET;
        monitor_state.cpsr = 0x3c5; // EL1h, matching every other real monitor-state construction in this file.
        monitor_state.spsr_el1 = 0xa000_0000; // The EL0t state the monitor's own entry would have saved.
        monitor_state.esr_el1 = EC_WFX << EC_SHIFT; // Routes dispatch_monitor_exit to its side-effect-free EC_WFX arm.
        let constructed_run = HvfVcpuRunResult {
            exit: HvfVcpuExit::VtimerActivated,
            state: HvfVcpuExitState::LowerElMonitor(monitor_state),
            run_epoch: 0,
            run_wall_ns: 0,
            owner_ns: 0,
            owner_gate_locks: 0,
            owner_wake_ticks: 0,
            owner_end_ticks: 0,
            replied_at_ticks: 0,
            fp: HvfExitFp::Materialized,
        };
        let slot = HvfThreadSlot::new();
        let snapshot = backend.default_space.vcpu_snapshot()?;
        let shim = HvfVtimerRaceNullShim;
        let mut ctx = PtRegs::default();
        let mut stale_view_reruns = 0u32;
        let mut alias_conflict_reruns = 0u32;
        // Calling `dispatch()` at all and reaching the line after it is itself the
        // entire proof: the pre-fix code path for this exact combination was
        // `fatal()` -> `std::process::abort()`, which ends the process with no
        // unwind and no `Result` -- there is no code path back here if that still
        // happens.
        let _disposition = backend.dispatch(
            &shim,
            &mut ctx,
            &slot,
            &constructed_run,
            &snapshot,
            &mut stale_view_reruns,
            &mut alias_conflict_reruns,
            &backend.default_space,
            None,
        );

        Ok(HvfVtimerMonitorRaceReport {
            race_attempts,
            real_race_won,
            constructed_dispatch_returned: true,
            source_pc: MONITOR_LOWER_EL_SYNC_OFFSET,
        })
    })();
    drop(lease);
    outcome
}

/// BCORE-3: the bound-vCPU host-signal fast path, exercised for real.
///
/// The branch shipped but had never executed in any test: `setitimer` is `ENOSYS` in the shim,
/// so no guest ever produced the `SIGALRM` that would make [`crate::host_signals_pending`]
/// true, and `bound.host_signal_fastpath` was 0 in every run ever taken. This witness supplies
/// the missing half from the host side, which is where the missing producer actually lives: a
/// real bound vCPU (not a lane) runs a real spinning guest, so its exits really are
/// `VtimerActivated`, and a real `pthread_kill(SIGALRM)` -- handled by the production handler
/// (`crate::async_signal_handler`) and recorded in the same per-thread bitmap the production
/// timer path writes -- makes that word nonzero between two of those exits.
///
/// Asserted, all at once:
/// * the bound path engaged (`bound.runs` moved) and really took `VtimerActivated` exits;
/// * at least one of them had NO host signal pending, so the control arm (`yield_now` +
///   resume) is what ran then;
/// * at least one had one pending, `bound.host_signal_fastpath` moved, and
///   `EnterShim::interrupt` was genuinely called -- i.e. the shipped branch executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfBoundHostSignalReport {
    /// Bound-loop iterations this witness drove.
    pub iterations: u32,
    /// Iterations on which the thread had no bound vCPU (it fell through to the pool).
    pub unbound_iterations: u32,
    /// Bound runs taken (`bound.runs` delta).
    pub bound_runs: u64,
    /// `VtimerActivated` exits on the bound vCPU (`bound.vtimer_exits` delta).
    pub vtimer_exits: u64,
    /// Of those, the ones with no host signal pending yet: the control arm.
    pub vtimer_exits_without_signal: u64,
    /// `bound.host_signal_fastpath` delta -- the branch under test.
    pub host_signal_fastpath: u64,
    /// `EnterShim::interrupt` calls that branch actually made.
    pub shim_interrupts: u64,
    /// The host signal used to make `host_signals_pending()` true.
    pub signal: i32,
    /// Phase 1, measured: wall time between two consecutive `VtimerActivated` exits of the
    /// spinning guest, in milliseconds -- i.e. how long a bound vCPU will run guest code that
    /// never exits on its own before the slice preempts it. Zero when the guest took fewer
    /// than two vtimer exits.
    pub spin_slice_ms: u64,
    /// Phase 2: the kick aimed at the reserved (not yet running) bound vCPU really was latched,
    /// i.e. the debit below is real.
    pub teardown_latched_kick: bool,
    /// Phase 2: debits charged by that teardown-phase kick.
    pub teardown_kicks_issued: u64,
    /// Phase 2: of those, the ones `unbind`'s `terminalize` reported as abandoned instead of
    /// dropping. Must be nonzero: reaching this counter at all is what the fix-up is for.
    pub teardown_kicks_abandoned: u64,
    /// Phase 2: stale debits that same `terminalize` reported as expired.
    pub teardown_kicks_expired_terminal: u64,
    /// `bound.live` after all three phases: every bound vCPU this witness created is gone.
    pub bound_live_after: u64,
    /// Phase 3: the `Drop` arm really was reached with a kick outstanding (bound, reserved,
    /// and the kick latched rather than refused).
    pub drop_armed: bool,
    /// Phase 3a: the participant was deregistered before the drop, so the destructor was left
    /// with exactly the vCPU and the ledger -- this arm isolates that half of the teardown.
    pub drop_deregistered: bool,
    /// Phase 3a: the `BoundThread` really left the thread-local, so `Drop for HvfBoundVcpu`
    /// ran (no `unbind`, no `unbind_current_thread`).
    pub drop_ran: bool,
    /// Phase 3: debits charged by the kick that was outstanding at the drop.
    pub drop_kicks_issued: u64,
    /// Phase 3: of those, the ones `Drop`'s `terminalize` reported as abandoned.
    pub drop_kicks_abandoned: u64,
    /// Phase 3: stale debits that same `terminalize` reported as expired.
    pub drop_kicks_expired_terminal: u64,
    /// Phase 3: `bound.unbinds_drop` delta -- the destructor's own teardown counter.
    pub drop_unbinds_drop: u64,
    /// Phase 3: `bound.lost` delta. Must be 0: the destructor destroyed the vCPU.
    pub drop_lost: u64,
    /// Phase 3a: `bound_entries` rows left behind after the drop. Must be 0: a destroyed vCPU
    /// must not stay in the list the mutation kick rounds and the eviction pick walk.
    pub drop_entries_left: u64,
    /// Phase 3b: the `BoundThread` fell with its participant STILL IN PLACE -- the shape an
    /// unwinding owner thread produces, and the one phase 3a cannot see.
    pub drop_undo_ran: bool,
    /// Phase 3b: the stranded-record sweep ran on the space afterwards.
    pub drop_undo_swept: bool,
    /// Phase 3b: records that sweep had to REMOVE. Must be 0: `Drop` discharged the
    /// participant, so a record that `begin_destroy` would refuse on was never left behind.
    pub drop_undo_sweep_removed: u64,
    /// Phase 4: a participant record was deliberately stranded -- the owner marked stopped and
    /// the handle dropped without deregistration, which is the state no teardown of the vCPU
    /// itself can repair.
    pub sweep_armed: bool,
    /// Phase 4: the sweep ran on the space.
    pub sweep_ran: bool,
    /// Phase 4: records the sweep removed. Must be >= 1: this is what makes an address space
    /// destroyable again after any teardown that failed to deregister.
    pub sweep_removed: u64,
}

/// A minimal, diagnostic-only [`EnterShim`] for [`hvf_bound_host_signal_probe`].
///
/// The guest is a bare `b .` spin, so its only exit is the vtimer and the only shim method the
/// fast path can reach is `interrupt`. Any other one would mean this witness's own construction
/// is wrong, so they end the loop instead of pretending to be a real shim.
struct HvfBoundHostSignalShim {
    interrupts: AtomicU64,
}

impl EnterShim for HvfBoundHostSignalShim {
    type ExecutionContext = PtRegs;
    fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Resume
    }
    fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Terminate
    }
    fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
        ContinueOperation::Terminate
    }
    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        self.interrupts.fetch_add(1, Ordering::Relaxed);
        ContinueOperation::Resume
    }
}

pub fn hvf_bound_host_signal_probe() -> Result<HvfBoundHostSignalReport, HvfBackendError> {
    use crate::diagnostics_counters as dc;
    const ITERATION_BOUND: u32 = 4_000;
    /// Re-delivery period: far shorter than one time slice, so the vtimer exit that follows the
    /// first delivery already sees a nonzero pending word.
    const SIGNAL_PERIOD: Duration = Duration::from_millis(2);
    const SIGNAL: libc::c_int = libc::SIGALRM;
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    if !bound_enabled() {
        return Err(HvfBackendError::Witness(
            "LITEBOX_HVF_BOUND=1 is not set, so the bound-vCPU host-signal fast path never runs",
        ));
    }
    // The production handler, for the signal the helper thread sends below.
    crate::install_async_signal_handlers();
    // A page holding `b .`: a guest that spins until the vtimer fires, so every exit is a
    // `VtimerActivated` one. Mapped here, on the thread that installed the backend, with the
    // same recipe `hvf_lane_starvation_probe` uses; only the bound run itself needs its own
    // thread (it needs a `ThreadHandle` registration, and `run_with_handle` refuses to nest).
    let spin_range = backend.trampoline.end..backend.trampoline.end + PAGE_SIZE;
    let mapped = backend.default_space.map_range(
        spin_range.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        false,
        false,
    )?;
    let spin_mapping = OwnedGuestRange::new(backend, spin_range.clone());
    backend.default_space.defer_retirement(mapped.retirement)?;
    let spin_instruction: u32 = 0x1400_0000; // `b .`
    // SAFETY: `spin_range` was just mapped read/write in the mirrored host view and nothing else
    // references it yet.
    unsafe {
        core::ptr::copy_nonoverlapping(
            spin_instruction.to_le_bytes().as_ptr(),
            spin_range.start as *mut u8,
            4,
        );
    }
    let executable = backend.default_space.protect_range(
        spin_range.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
    )?;
    backend.default_space.defer_retirement(executable.retirement)?;
    backend.default_space.pump_retirements()?;
    let runs_before = dc::bound_stat_total(dc::BOUND_RUNS);
    let vtimer_before = dc::bound_stat_total(dc::BOUND_VTIMER_EXITS);
    let fastpath_before = dc::bound_stat_total(dc::BOUND_HOST_SIGNAL_FASTPATH);
    let witness = std::thread::Builder::new()
        .name("litebox-hvf-bound-host-signal".to_owned())
        .spawn(move || -> Result<HvfBoundHostSignalReport, HvfBackendError> {
            crate::ThreadHandle::run_with_handle(|| {
                // SIGALRM has to be deliverable on THIS thread: `block_guest_signals` blocks it
                // on threads that can never record one, and this thread is about to be able to.
                //
                // SAFETY: `sigemptyset`/`sigaddset` initialize `set` before `pthread_sigmask`
                // reads it; unblocking a signal has no further precondition.
                unsafe {
                    let mut set: libc::sigset_t = core::mem::zeroed();
                    libc::sigemptyset(&raw mut set);
                    libc::sigaddset(&raw mut set, SIGNAL);
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, core::ptr::null_mut());
                }
                let shim = HvfBoundHostSignalShim {
                    interrupts: AtomicU64::new(0),
                };
                let mut ctx = PtRegs::default();
                ctx.pc = spin_range.start;
                // EL0t with DAIF clear, so the vtimer interrupt is actually taken.
                ctx.pstate = 0xa000_0000;
                let slot = HvfThreadSlot::new();
                let stop = Arc::new(AtomicBool::new(false));
                // Held back until the control observation below has been made: the witness wants
                // a vtimer exit with NO host signal pending first, to prove the two arms differ.
                let go = Arc::new(AtomicBool::new(false));
                let killer = {
                    let stop = Arc::clone(&stop);
                    let go = Arc::clone(&go);
                    // `pthread_t` is an opaque pointer, carried as `usize` so it is `Send`. The
                    // thread it names is this one, which outlives the sender (joined below).
                    let target = unsafe { libc::pthread_self() } as usize;
                    std::thread::Builder::new()
                        .name("litebox-hvf-bound-host-signal-sender".to_owned())
                        .spawn(move || {
                            while !stop.load(Ordering::Relaxed) {
                                if go.load(Ordering::Relaxed) {
                                    // SAFETY: `target` is this witness thread's own `pthread_t`,
                                    // still live (the sender is joined before this scope ends).
                                    unsafe {
                                        libc::pthread_kill(target as libc::pthread_t, SIGNAL)
                                    };
                                }
                                std::thread::sleep(SIGNAL_PERIOD);
                            }
                        })
                };
                // Bind on the very first iteration: the trigger counts exits in a window, and
                // this witness wants the bound path, not the pooled one.
                let mut streak = (Instant::now(), BOUND_TRIGGER_EXITS - 1);
                let mut iterations = 0u32;
                let mut unbound_iterations = 0u32;
                let mut vtimer_exits_without_signal = 0u64;
                let mut first_slice_at: Option<Instant> = None;
                let mut last_slice_at: Option<Instant> = None;
                let mut slice_ends = 0u64;
                let mut last_vtimer = vtimer_before;
                let outcome = loop {
                    if iterations >= ITERATION_BOUND {
                        break Err(HvfBackendError::Witness(
                            "the bound vCPU never took a vtimer exit with a host signal pending",
                        ));
                    }
                    iterations += 1;
                    match backend.bound_iteration(&shim, &mut ctx, &slot, None, &mut streak) {
                        BoundOutcome::Ran(ContinueOperation::Terminate) => break Err(
                            HvfBackendError::Witness("the bound run asked the loop to terminate"),
                        ),
                        BoundOutcome::Ran(_) => {
                            let vtimer = dc::bound_stat_total(dc::BOUND_VTIMER_EXITS);
                            let fastpath = dc::bound_stat_total(dc::BOUND_HOST_SIGNAL_FASTPATH);
                            if vtimer != last_vtimer {
                                last_vtimer = vtimer;
                                // BCORE2-FX: the clock of the slice. Two consecutive vtimer
                                // exits of a guest that never exits on its own (`b .`) are one
                                // full slice apart, so the gap between them is the number the
                                // bound path's preemption claim rests on -- measured, not
                                // asserted from the code.
                                if slice_ends == 0 {
                                    first_slice_at = Some(Instant::now());
                                } else {
                                    last_slice_at = Some(Instant::now());
                                }
                                slice_ends += 1;
                                if fastpath == fastpath_before {
                                    vtimer_exits_without_signal += 1;
                                    // One control observation is enough: from here the signal
                                    // flows, so the next vtimer exit is the one under test.
                                    go.store(true, Ordering::Release);
                                }
                            }
                            if fastpath != fastpath_before {
                                break Ok(());
                            }
                        }
                        BoundOutcome::Unbound => unbound_iterations += 1,
                    }
                };
                stop.store(true, Ordering::Release);
                if let Ok(killer) = killer {
                    let _ = killer.join();
                }
                // Give the vCPU back on the thread that owns it, through the same teardown the
                // shim's thread-exit path uses (`unbind`, which terminalizes the kick ledger).
                backend.unbind_current_thread(dc::BOUND_UNBINDS_EXIT);
                // -- Phase 2: the teardown discharger -------------------------------------
                //
                // `unbind`/`Drop` terminalizing a bound vCPU's control is what makes
                // `kicks_abandoned` / `kicks_expired_terminal` reachable at all (before that
                // fix-up they were structurally 0: a vCPU destroyed while a kick was still
                // outstanding dropped the debit in silence). Deterministic construction of
                // exactly that state: reserve a run (the control is then `Reserved`), which is a
                // phase a kick is *latched* against -- an SDK-free debit that only the run's own
                // `consume_latched` or a `terminalize` can discharge -- kick it, and unbind
                // without ever running it. The debit must surface as `kicks_abandoned`, and the
                // latched attempt must be completed with `Terminalized` rather than left for a
                // run that will never happen.
                let issued_before = dc::bound_stat_total(dc::BOUND_KICKS_ISSUED);
                let abandoned_before = dc::bound_stat_total(dc::BOUND_KICKS_ABANDONED);
                let terminal_before = dc::bound_stat_total(dc::BOUND_KICKS_EXPIRED_TERMINAL);
                let teardown_bound = backend.bind_current_thread(None);
                let latched = if teardown_bound {
                    HVF_THREAD.with(|context| {
                        let context = context.borrow();
                        let Some(bound) = context.bound.as_ref() else {
                            return false;
                        };
                        // `Reserved` is what makes `request_kick` latch rather than refuse.
                        let Ok(_epoch) = bound.vcpu.reserve_run() else {
                            return false;
                        };
                        bound
                            .entry
                            .control
                            .request_kick(
                                bound.entry.generation,
                                &bound.entry.cancellation,
                                None,
                            )
                            .is_ok()
                    })
                } else {
                    false
                };
                backend.unbind_current_thread(dc::BOUND_UNBINDS_EXIT);
                let teardown_issued =
                    dc::bound_stat_total(dc::BOUND_KICKS_ISSUED) - issued_before;
                let teardown_abandoned =
                    dc::bound_stat_total(dc::BOUND_KICKS_ABANDONED) - abandoned_before;
                let teardown_expired_terminal =
                    dc::bound_stat_total(dc::BOUND_KICKS_EXPIRED_TERMINAL) - terminal_before;
                // -- Phase 3a: the `Drop` arm, ledger half --------------------------------
                //
                // `unbind` is the orderly teardown; `Drop for HvfBoundVcpu` is the containment
                // of last resort for an owner thread that unwinds past its own vCPU (a panic, a
                // TLS destructor). It has to discharge the ledger the same way, destroy the
                // vCPU, give the registry slot back and take its `BoundEntry` out of the
                // backend's list -- otherwise an unwound thread leaves a dead generation behind
                // for every later mutation kick round to walk. Same deterministic state as
                // phase 2 (reserve, so a kick latches), but here nothing calls `unbind`: the
                // `BoundThread` leaves the thread-local and falls.
                //
                // This arm deregisters the participant by hand first (`drop_deregistered`), so
                // it isolates the vCPU/ledger half. The half an unwinding owner cannot do for
                // itself -- discharging the participant -- is phase 3b's.
                let drop_issued_before = dc::bound_stat_total(dc::BOUND_KICKS_ISSUED);
                let drop_abandoned_before = dc::bound_stat_total(dc::BOUND_KICKS_ABANDONED);
                let drop_terminal_before = dc::bound_stat_total(dc::BOUND_KICKS_EXPIRED_TERMINAL);
                let drops_before = dc::bound_stat_total(dc::BOUND_UNBINDS_DROP);
                let lost_before = dc::bound_stat_total(dc::BOUND_LOST);
                let drop_setup = if backend.bind_current_thread(None) {
                    HVF_THREAD.with(|context| {
                        let mut context = context.borrow_mut();
                        let Some(bound) = context.bound.as_mut() else {
                            return None;
                        };
                        // `Reserved` is what makes `request_kick` latch rather than refuse.
                        let Ok(_epoch) = bound.vcpu.reserve_run() else {
                            return None;
                        };
                        let latched = bound
                            .entry
                            .control
                            .request_kick(bound.entry.generation, &bound.entry.cancellation, None)
                            .is_ok();
                        bound.vcpu.stop_owner();
                        let deregistered = match bound.participant.take() {
                            Some(mut participant) => bound
                                .space
                                .get(backend)
                                .deregister_vcpu_participant(&mut participant)
                                .is_ok(),
                            None => false,
                        };
                        Some((latched, deregistered))
                    })
                } else {
                    None
                };
                // The destructor runs here, at the end of this statement, when the taken
                // `BoundThread` falls out of the temporary.
                let drop_ran = HVF_THREAD
                    .with(|context| context.borrow_mut().bound.take())
                    .is_some();
                let drop_armed = drop_setup.is_some_and(|(latched, _)| latched);
                let drop_deregistered = drop_setup.is_some_and(|(_, deregistered)| deregistered);
                let drop_kicks_issued =
                    dc::bound_stat_total(dc::BOUND_KICKS_ISSUED) - drop_issued_before;
                let drop_kicks_abandoned =
                    dc::bound_stat_total(dc::BOUND_KICKS_ABANDONED) - drop_abandoned_before;
                let drop_kicks_expired_terminal =
                    dc::bound_stat_total(dc::BOUND_KICKS_EXPIRED_TERMINAL) - drop_terminal_before;
                let drop_unbinds_drop =
                    dc::bound_stat_total(dc::BOUND_UNBINDS_DROP) - drops_before;
                let drop_lost = dc::bound_stat_total(dc::BOUND_LOST) - lost_before;
                let drop_entries_left = backend
                    .bound_entries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len() as u64;
                // -- Phase 3b: the `Drop` arm as an unwind really leaves it ---------------
                //
                // The participant stays in place: the destructor is handed exactly what an
                // unwinding owner thread hands it -- `vcpu` declared before `participant`, so
                // the vCPU is destroyed first and only then would the handle's own destructor
                // mark the capability `PARTICIPANT_ABANDONED`, leaving the RECORD in the
                // address space. `begin_destroy` refuses with `AddressSpaceBusy` while that
                // map is non-empty, so one unwound owner would strand the space for the life
                // of the process. Run the same repair `begin_destroy` now performs, as an
                // observation: it must find NOTHING to repair, which is the assertion that
                // `Drop for BoundThread` really discharged the participant.
                let _drop_undo_setup = if backend.bind_current_thread(None) {
                    HVF_THREAD.with(|context| {
                        let context = context.borrow();
                        let Some(bound) = context.bound.as_ref() else {
                            return false;
                        };
                        bound.vcpu.reserve_run().is_ok()
                            && bound
                                .entry
                                .control
                                .request_kick(
                                    bound.entry.generation,
                                    &bound.entry.cancellation,
                                    None,
                                )
                                .is_ok()
                    })
                } else {
                    false
                };
                let drop_undo_ran = HVF_THREAD
                    .with(|context| context.borrow_mut().bound.take())
                    .is_some();
                let (drop_undo_swept, drop_undo_sweep_removed) =
                    match backend.default_space.recover_stopped_vcpu_participants() {
                        Ok(receipts) => (true, receipts.iter().filter(|r| r.removed).count() as u64),
                        Err(_) => (false, u64::MAX),
                    };
                // -- Phase 4: the strand the sweep exists to repair ----------------------
                //
                // Deliberately strand a record the way a teardown that never deregistered
                // would: mark the owner stopped, drop the handle WITHOUT deregistering it (its
                // destructor only marks the capability abandoned), then unbind -- which by then
                // has nothing left to discharge. This is the state no vCPU teardown can repair
                // on its own, so the sweep has to: it must find and remove the record, which is
                // what lets `begin_destroy` destroy the space again.
                let mut sweep_armed = false;
                if backend.bind_current_thread(None) {
                    sweep_armed = HVF_THREAD.with(|context| {
                        let mut context = context.borrow_mut();
                        let Some(bound) = context.bound.as_mut() else {
                            return false;
                        };
                        bound.vcpu.stop_owner();
                        // Dropped here, underegistered: the capability becomes ABANDONED.
                        bound.participant.take().is_some()
                    });
                    backend.unbind_current_thread(dc::BOUND_UNBINDS_EXIT);
                }
                let (sweep_ran, sweep_removed) =
                    match backend.default_space.recover_stopped_vcpu_participants() {
                        Ok(receipts) => (true, receipts.iter().filter(|r| r.removed).count() as u64),
                        Err(_) => (false, 0),
                    };
                let report = HvfBoundHostSignalReport {
                    iterations,
                    unbound_iterations,
                    bound_runs: dc::bound_stat_total(dc::BOUND_RUNS) - runs_before,
                    vtimer_exits: dc::bound_stat_total(dc::BOUND_VTIMER_EXITS) - vtimer_before,
                    vtimer_exits_without_signal,
                    host_signal_fastpath: dc::bound_stat_total(dc::BOUND_HOST_SIGNAL_FASTPATH)
                        - fastpath_before,
                    shim_interrupts: shim.interrupts.load(Ordering::Relaxed),
                    signal: SIGNAL,
                    spin_slice_ms: match (first_slice_at, last_slice_at, slice_ends) {
                        (Some(first), Some(last), ends) if ends >= 2 => u64::try_from(
                            last.duration_since(first).as_millis() / u128::from((ends - 1).max(1)),
                        )
                        .unwrap_or(u64::MAX),
                        _ => 0,
                    },
                    teardown_latched_kick: latched,
                    teardown_kicks_issued: teardown_issued,
                    teardown_kicks_abandoned: teardown_abandoned,
                    teardown_kicks_expired_terminal: teardown_expired_terminal,
                    bound_live_after: dc::bound_stat_total(dc::BOUND_LIVE),
                    drop_armed,
                    drop_deregistered,
                    drop_ran,
                    drop_kicks_issued,
                    drop_kicks_abandoned,
                    drop_kicks_expired_terminal,
                    drop_unbinds_drop,
                    drop_lost,
                    drop_entries_left,
                    drop_undo_ran,
                    drop_undo_swept,
                    drop_undo_sweep_removed,
                    sweep_armed,
                    sweep_ran,
                    sweep_removed,
                };
                outcome.map(|()| report)
            })
        })
        .map_err(|_| HvfBackendError::Witness("spawning the bound host-signal witness thread"))?;
    let report = witness
        .join()
        .map_err(|_| HvfBackendError::Witness("the bound host-signal witness thread panicked"))??;
    // The spin page stays mapped on purpose. This is a short-lived diagnostic process that
    // exits immediately after the report, and asking `unmap_range` for a page at the very top
    // of the guest address space answers `changed = false` here -- which `OwnedGuestRange`'s
    // destructor escalates to a `fatal` (the same destructor
    // `hvf_lane_starvation_probe` never reaches, since that probe fails earlier). Leaving the
    // page mapped keeps a passed witness from being reported as a fatal backend failure.
    spin_mapping.disarm();
    if report.vtimer_exits == 0 {
        return Err(HvfBackendError::Witness(
            "the bound vCPU never took a VtimerActivated exit",
        ));
    }
    if report.host_signal_fastpath == 0 || report.shim_interrupts == 0 {
        return Err(HvfBackendError::Witness(
            "a pending host signal did not turn a bound vtimer exit into EnterShim::interrupt",
        ));
    }
    if !report.teardown_latched_kick
        || report.teardown_kicks_issued == 0
        || report.teardown_kicks_abandoned + report.teardown_kicks_expired_terminal == 0
    {
        return Err(HvfBackendError::Witness(
            "unbinding a bound vCPU with a kick outstanding did not report the debit: `terminalize` is not discharging it",
        ));
    }
    if report.bound_live_after != 0 {
        return Err(HvfBackendError::Witness(
            "a bound vCPU survived the witness's own teardown",
        ));
    }
    if !report.drop_armed
        || !report.drop_deregistered
        || !report.drop_ran
        || report.drop_unbinds_drop == 0
        || report.drop_lost != 0
        || report.drop_entries_left != 0
        || report.drop_kicks_issued == 0
        || report.drop_kicks_abandoned + report.drop_kicks_expired_terminal == 0
    {
        return Err(HvfBackendError::Witness(
            "dropping a bound vCPU with a kick outstanding did not report the debit: `Drop` is not terminalizing it",
        ));
    }
    // Phase 3b: the participant was left in place, so this is the only arm that can see whether
    // the unwind teardown discharges it. A record left behind keeps `begin_destroy` at
    // `AddressSpaceBusy` for the life of the process.
    if !report.drop_undo_ran || !report.drop_undo_swept || report.drop_undo_sweep_removed != 0 {
        return Err(HvfBackendError::Witness(
            "dropping a bound vCPU left its participant record in the address space: the unwind teardown does not discharge it",
        ));
    }
    // Phase 4: the sweep is what repairs a record no vCPU teardown can. If it cannot remove a
    // deliberately stranded one, a space stays undestroyable -- and its stage-2 pages stay
    // charged against the live-data budget -- forever.
    if !report.sweep_armed || !report.sweep_ran || report.sweep_removed == 0 {
        return Err(HvfBackendError::Witness(
            "the stranded-participant sweep did not remove a deliberately stranded record: an address space would stay undestroyable",
        ));
    }
    Ok(report)
}

/// Live, process-terminal-scale witness (it runs for slightly over
/// [`LANE_ACQUIRE_TIMEOUT`]) that `HvfBackend::acquire_lane`'s 60-second
/// deadline is a genuine bound under real starvation, not dead code: every
/// pooled lane is occupied with a real spinning guest run on its own thread,
/// a fresh acquire is issued against the exhausted pool, and the call must
/// block for approximately the full deadline before returning the typed
/// [`HvfBackendError::LaneAcquisitionTimeout`] -- neither hanging forever nor
/// returning early. Every occupying run is then stopped through authenticated
/// cancellation or the cooperative VTimer fallback, and the pool is proven to
/// return to exactly its baseline free count.
///
/// # Errors
///
/// Returns the backend's typed error if the spin page cannot be mapped, a
/// lane cannot be occupied, the timeout does not fire within a bounded
/// margin past the deadline, or the pool fails to drain back to baseline.
pub fn hvf_lane_starvation_probe() -> Result<HvfLaneStarvationReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let spin_range = backend.trampoline.end..backend.trampoline.end + PAGE_SIZE;
    let mapped = backend.default_space.map_range(
        spin_range.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        false,
        false,
    )?;
    let _spin_mapping = OwnedGuestRange::new(backend, spin_range.clone());
    backend.default_space.defer_retirement(mapped.retirement)?;
    // `b .`: spins in place until canceled.
    let spin_instruction: u32 = 0x1400_0000;
    // SAFETY: `spin_range` was just mapped read/write in the mirrored host
    // view and nothing else references it yet.
    unsafe {
        core::ptr::copy_nonoverlapping(
            spin_instruction.to_le_bytes().as_ptr(),
            spin_range.start as *mut u8,
            4,
        );
    }
    let executable = backend.default_space.protect_range(
        spin_range.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
    )?;
    backend.default_space.defer_retirement(executable.retirement)?;
    backend.default_space.pump_retirements()?;

    let lane_count = backend.lanes.len();
    let outcome = (|| {
        let mut occupied: Vec<ProbeWorker<HvfVcpuRunResult>> = Vec::new();
        occupied
            .try_reserve_exact(lane_count)
            .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
        for _ in 0..lane_count {
            let lease = backend.acquire_lane()?;
            let index = lease.index();
            let lane = lease.lane();
            let attachment = {
                let participant = lane
                    .participant
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                backend.default_space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?
            };
            let state = spin_probe_state(spin_range.start);
            let handle = lane.handle.clone();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let worker_stop = std::sync::Arc::clone(&stop);
            let thread = std::thread::Builder::new()
                .name("litebox-hvf-lane-starvation-occupier".to_owned())
                .spawn(move || {
                    let lane = lease.lane();
                    // time-slicing: no single `hv_vcpu_run`/command round trip
                    // is held open anywhere near `COMMAND_WAIT_TIMEOUT` (30s),
                    // so the lane can genuinely stay occupied for the full 60s
                    // `LANE_ACQUIRE_TIMEOUT` this witness needs, exactly as a
                    // real long-running compute-bound guest thread would.
                    // `backend` is `&'static`, so re-attaching across time
                    // slices from inside this thread needs no extra lifetime
                    // plumbing.
                    let mut attachment = attachment;
                    let mut state = state;
                    loop {
                        let deadline = time_slice_deadline();
                        let run = handle.run_with_deadline(attachment, &state, deadline)?;
                        match (run.exit, run.state) {
                            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(next)) => {
                                if worker_stop.load(Ordering::Acquire) {
                                    return Ok(run);
                                }
                                state = next;
                                attachment = {
                                    let participant = lane
                                        .participant
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    backend.default_space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?
                                };
                            }
                            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_)) => {
                                return Ok(run);
                            }
                            _ => return Err(invalid_run_state(&run)),
                        }
                    }
                })
                .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
            occupied.push(ProbeWorker {
                index,
                stop,
                thread: Some(thread),
            });
        }
        // Every lane is now genuinely held (popped from the free list, with a
        // real run in progress on it) rather than merely marked busy, so this
        // acquire has no lane to receive even if scheduling is adversarial.
        let started = Instant::now();
        let starved = backend.acquire_lane();
        let elapsed = started.elapsed();
        let timed_out = matches!(starved, Err(HvfBackendError::LaneAcquisitionTimeout));
        // Bounded margin (not exact equality) for scheduling jitter around a
        // real wall-clock deadline; still tight enough to prove the const is
        // honored rather than, say, a near-zero or unbounded wait.
        let timing_bounded = elapsed >= LANE_ACQUIRE_TIMEOUT
            && elapsed < LANE_ACQUIRE_TIMEOUT.saturating_add(Duration::from_secs(10));
        if let Ok(lease) = starved {
            // Should not happen given every lane is genuinely held, but leave
            // no lane silently checked out if it somehow does.
            drop(lease);
        }

        let mut cancel_errors: Vec<String> = Vec::new();
        let mut cancellations = Vec::new();
        for worker in &occupied {
            let cancellation = backend.current_lane_handle(worker.index)?.cancellation();
            let cancellation_stop = std::sync::Arc::clone(&worker.stop);
            match std::thread::Builder::new()
                .name("litebox-hvf-lane-starvation-canceller".to_owned())
                .spawn(move || {
                    let result = cancellation.cancel();
                    if result.is_err() {
                        cancellation_stop.store(true, Ordering::Release);
                    }
                    result
                }) {
                Ok(thread) => {
                    cancellations.push((std::sync::Arc::clone(&worker.stop), thread));
                }
                Err(error) => {
                    worker.stop.store(true, Ordering::Release);
                    cancel_errors.push(format!("failed to spawn cancellation thread: {error}"));
                }
            }
        }
        for (stop, cancellation) in cancellations {
            match cancellation.join() {
                Ok(Ok(_)) => {}
                Ok(Err(
                    HvfVcpuLaneError::CancellationTooLate { .. } | HvfVcpuLaneError::VcpuNotRunning,
                )) => {}
                Ok(Err(error)) => cancel_errors.push(format!("{error}")),
                Err(_) => {
                    stop.store(true, Ordering::Release);
                    cancel_errors.push("cancellation thread panicked".to_owned());
                }
            }
        }
        let mut run_errors: Vec<String> = Vec::new();
        for worker in occupied {
            let stop = std::sync::Arc::clone(&worker.stop);
            match worker.join() {
                Ok(Ok(run)) => {
                    let clean = matches!(
                        (run.exit, run.state),
                        (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
                    ) || stop.load(Ordering::Acquire)
                        && matches!(
                            (run.exit, run.state),
                            (
                                HvfVcpuExit::VtimerActivated,
                                HvfVcpuExitState::DirectGuest(_)
                            )
                        );
                    if !clean {
                        run_errors.push(format!("unexpected exit: {:?}", run.exit));
                    }
                }
                Ok(Err(error)) => run_errors.push(format!("{error}")),
                Err(_) => run_errors.push("occupier thread panicked".to_owned()),
            }
        }
        let pool_at_baseline = {
            let pool = backend
                .free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            lane_pool_at_baseline(&pool, lane_count)
        };
        Ok(HvfLaneStarvationReport {
            lane_count,
            timed_out,
            timing_bounded,
            elapsed_millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            occupying_runs_stopped_cleanly: cancel_errors.is_empty() && run_errors.is_empty(),
            cancel_errors,
            run_errors,
            pool_at_baseline,
        })
    })();
    outcome
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfLaneStarvationReport {
    pub lane_count: usize,
    pub timed_out: bool,
    pub timing_bounded: bool,
    pub elapsed_millis: u64,
    /// Every occupying run stopped through either an authenticated cancellation
    /// or the cooperative VTimer fallback, without an owner-lane error.
    pub occupying_runs_stopped_cleanly: bool,
    pub cancel_errors: Vec<String>,
    pub run_errors: Vec<String>,
    pub pool_at_baseline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfLaneReplacementReport {
    pub lane_count: usize,
    pub lane_index: usize,
    pub retired_generation: u64,
    pub replacement_generation: u64,
    pub old_generation_non_reusable: bool,
    pub cancellation_authority_cleared: bool,
    pub owner_reaped_and_slot_replaced: bool,
    pub replacement_hvc_verified: bool,
    pub pool_at_baseline: bool,
}

/// Deterministically exercises the installed backend's complete generational
/// lane-replacement path. Every pooled generation is checked out so that, once
/// one target is made non-reusable and retired through
/// [`ActiveThreadLaneLease`], the next ordinary acquisition can only receive a
/// newer generation published into that exact slot.
///
/// # Errors
///
/// Returns the backend's typed error if the pool does not begin or end at its
/// exact baseline, run authority is not cleared, retirement or replacement does
/// not preserve the target slot's identity, or the replacement cannot execute
/// the normal monitor-HVC path.
pub fn hvf_lane_replacement_probe() -> Result<HvfLaneReplacementReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lane_count = backend.lanes.len();
    {
        let pool = backend
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !lane_pool_at_baseline(&pool, lane_count) {
            return Err(HvfBackendError::LanePoolCorrupt { index: usize::MAX });
        }
    }

    let mut held = Vec::new();
    held.try_reserve_exact(lane_count)
        .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
    for _ in 0..lane_count {
        held.push(backend.acquire_lane()?);
    }
    let target = held
        .pop()
        .ok_or(HvfBackendError::LanePoolCorrupt { index: usize::MAX })?;
    let lane_index = target.index();
    let retired_generation = target.lane().handle.generation();

    let slot = HvfThreadSlot::new();
    let mut active = ActiveThreadLaneLease::new(target, &slot);
    {
        let mut current = slot
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_some() {
            return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
        }
        let reservation = active.lane().handle.reserve_run()?;
        let cancellation = reservation.cancellation();
        active.install(reservation, cancellation.clone());
        *current = Some(cancellation);
    }

    let retirement_requested = active
        .lane()
        .lane
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_some_and(|lane| {
            lane.request_retirement();
            true
        });
    let old_generation_non_reusable = retirement_requested && !active.lane().handle.is_reusable();

    // This is the behavior under witness: clear the exact thread authority,
    // settle the still-unsubmitted reservation, and select retirement rather
    // than the ordinary reusable-lane return path.
    drop(active);
    let cancellation_authority_cleared = slot
        .current
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_none();
    if !old_generation_non_reusable || !cancellation_authority_cleared {
        return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
    }

    // Every other slot remains checked out in `held`; successful acquisition
    // therefore requires maintenance to reap and replace this exact slot.
    let replacement = backend.acquire_lane()?;
    let replacement_generation = replacement.lane().handle.generation();
    let owner_reaped_and_slot_replaced =
        replacement.index() == lane_index && replacement_generation > retired_generation;
    if !owner_reaped_and_slot_replaced {
        return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
    }

    let run = {
        let lane = replacement.lane();
        let attachment = {
            let participant = lane
                .participant
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            backend.default_space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?
        };
        let state = spin_probe_state(backend.trampoline_address());
        lane.handle.run(attachment, &state)?
    };
    let replacement_hvc_verified = matches!(run.state, HvfVcpuExitState::LowerElMonitor(_))
        && matches!(
            run.exit,
            HvfVcpuExit::Exception(exception)
                if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_HVC64
                    && exception.syndrome & HVC_IMMEDIATE_MASK == MONITOR_HVC_IMMEDIATE
        );
    if !replacement_hvc_verified {
        let state = match &run.state {
            HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => state,
        };
        return Err(HvfBackendError::UnexpectedExit {
            exit: run.exit,
            source_pc: Some(state.pc),
        });
    }

    drop(replacement);
    drop(held);
    let pool_at_baseline = {
        let pool = backend
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lane_pool_at_baseline(&pool, lane_count)
    };
    if !pool_at_baseline {
        return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
    }

    Ok(HvfLaneReplacementReport {
        lane_count,
        lane_index,
        retired_generation,
        replacement_generation,
        old_generation_non_reusable,
        cancellation_authority_cleared,
        owner_reaped_and_slot_replaced,
        replacement_hvc_verified,
        pool_at_baseline,
    })
}

/// Number of queue-to-wake trials [`hvf_scheduler_latency_probe`] measures.
const SCHEDULER_LATENCY_TRIALS: usize = 2000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSchedulerLatencyReport {
    pub lane_count: usize,
    pub trials: usize,
    pub p50_nanos: u64,
    pub p99_nanos: u64,
    pub max_nanos: u64,
    pub min_nanos: u64,
    pub mean_nanos: u64,
    /// Whether the trailing half of the sample is not systematically slower
    /// than the leading half (a coarse, cheap growth check: unbounded
    /// wakeup latency would show up as a rising trend across trials).
    pub no_growth_trend: bool,
    pub pool_at_baseline: bool,
}

/// Live witness measuring the real wall-clock latency from "a lane is handed
/// back to the pool" (`release_lane`, the moment `acquire_lane`'s `Condvar`
/// is notified) to "a concurrently blocked waiter wakes and observes it"
/// (`acquire_lane` returning), across many trials. This is the queue/wakeup
/// path `HvfBackend::run_thread` depends on for every guest syscall return
/// and every VTimer re-queue, so its latency distribution bounds how quickly
/// an idle lane picks up newly queued guest work.
///
/// One lane is held out of the pool as a dedicated "server": each trial
/// spawns a fresh waiter thread that blocks in `acquire_lane` (the pool is
/// otherwise fully free, so the waiter always contends on the `Condvar`
/// rather than an already-idle fast path), the main thread times a short
/// settle, releases the held-out lane, and the waiter reports the elapsed
/// time from just before `release_lane` to its own `acquire_lane` return.
/// p50/p99/max/min/mean are reported in nanoseconds; a monotonic bound is
/// not asserted (real OS scheduling jitter varies by load) but growth across
/// the trial sequence would indicate an unbounded/leaking wakeup path, which
/// this checks for directly.
///
/// # Errors
///
/// Returns the backend's typed error if no lane is available or a waiter
/// thread cannot be spawned or joined.
pub fn hvf_scheduler_latency_probe() -> Result<HvfSchedulerLatencyReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lane_count = backend.lanes.len();
    // Hold every lane but one out of the pool for the duration of the probe,
    // so each trial's waiter genuinely blocks on the `Condvar` (a free lane
    // elsewhere in the pool would let `acquire_lane` return immediately
    // without ever reaching the wait path this probe measures).
    let mut held = Vec::new();
    for _ in 0..lane_count.saturating_sub(1) {
        held.push(backend.acquire_lane()?);
    }
    let mut samples = Vec::with_capacity(SCHEDULER_LATENCY_TRIALS);
    let outcome: Result<(), HvfBackendError> = (|| {
        for _ in 0..SCHEDULER_LATENCY_TRIALS {
            let served = backend.acquire_lane()?;
            let start_barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let waiter_barrier = std::sync::Arc::clone(&start_barrier);
            let thread = std::thread::Builder::new()
                .name("litebox-hvf-scheduler-latency-waiter".to_owned())
                .spawn(move || {
                    waiter_barrier.wait();
                    let started = Instant::now();
                    let index = backend.acquire_lane();
                    let elapsed = started.elapsed();
                    (index, elapsed)
                })
                .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
            start_barrier.wait();
            // A short, fixed settle so the waiter thread has genuinely
            // reached `acquire_lane`'s wait before the lane is released;
            // this is scheduling slack for the waiter to start, not part of
            // the measured interval (the waiter's own `Instant::now()` is
            // taken after the barrier, immediately before it calls
            // `acquire_lane`).
            std::thread::sleep(Duration::from_micros(200));
            drop(served);
            let (lease, elapsed) = thread
                .join()
                .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
            drop(lease?);
            samples.push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        }
        Ok(())
    })();
    drop(held);
    outcome?;

    // Trend check first, over trial order (the sequence as collected, before
    // sorting destroys that order): compare the mean of the first half of
    // the run to the mean of the second half. A genuinely bounded wakeup
    // path shows no systematic rise as the process keeps running; this
    // rejects only a clear rise (second half more than 50% above the
    // first), tolerant of ordinary jitter.
    let no_growth_trend = if samples.len() < 20 {
        true
    } else {
        let half = samples.len() / 2;
        let mean_of = |slice: &[u64]| -> u128 {
            slice.iter().map(|&value| u128::from(value)).sum::<u128>() / slice.len() as u128
        };
        let first_half_mean = mean_of(&samples[..half]);
        let second_half_mean = mean_of(&samples[half..]);
        second_half_mean <= first_half_mean.saturating_mul(3) / 2 + 1
    };

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let n = sorted.len().max(1);
    let percentile = |p: usize| sorted[(n.saturating_mul(p) / 100).min(n - 1)];
    let min_nanos = *sorted.first().unwrap_or(&0);
    let max_nanos = *sorted.last().unwrap_or(&0);
    let mean_nanos = if sorted.is_empty() {
        0
    } else {
        u64::try_from(sorted.iter().map(|&value| u128::from(value)).sum::<u128>() / n as u128)
            .unwrap_or(u64::MAX)
    };
    let pool = backend
        .free
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pool_at_baseline = lane_pool_at_baseline(&pool, lane_count);
    drop(pool);
    Ok(HvfSchedulerLatencyReport {
        lane_count,
        trials: sorted.len(),
        p50_nanos: percentile(50),
        p99_nanos: percentile(99),
        max_nanos,
        min_nanos,
        mean_nanos,
        no_growth_trend,
        pool_at_baseline,
    })
}

/// Wall-clock budget each concurrency level runs for in
/// [`hvf_scheduler_scaling_probe`].
const SCALING_RUN_DURATION: Duration = Duration::from_millis(1500);
/// `add x0, x0, #1` ; `b <self>` : an unbounded ALU loop that genuinely
/// retires instructions each pass (unlike `hvf_lane_starvation_probe`'s
/// `b .`, which never advances architectural state), so time-sliced re-entry
/// counts below are real compute progress, not mere occupancy.
const COMPUTE_LOOP: [u32; 2] = [0x9100_0000, 0x1400_0000];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSchedulerScalingLevel {
    pub concurrency: usize,
    /// Total VTimer time-slice re-entries observed across all threads at
    /// this concurrency, summed -- the scheduler's own unit of guest compute
    /// progress, independent of host clock-source quirks.
    pub total_slices: u64,
    pub elapsed_millis: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HvfSchedulerScalingReport {
    pub lane_count: usize,
    pub levels: Vec<HvfSchedulerScalingLevel>,
    /// `levels[i].total_slices` throughput relative to the N=1 level, i.e.
    /// the measured speedup at each concurrency (near-`N` up to the lane
    /// count would indicate concurrent, non-serialized progress).
    pub speedup: Vec<f64>,
    pub pool_at_baseline: bool,
}

/// Live witness measuring real wall-clock scaling of independent,
/// non-yielding compute-bound guest threads: for each concurrency level in
/// `1, 2, 4, ..` up to the lane pool's own size, `concurrency` guest threads
/// each spin an unbounded ALU loop ([`COMPUTE_LOOP`]) on their own disjoint
/// mapped page for a fixed wall-clock budget, re-attaching after each VTimer
/// slice exit exactly as `HvfBackend::run_thread` does in production. The
/// summed slice count at each level is the scheduler's own throughput unit;
/// near-linear growth with `concurrency` (up to the real core/lane count) is
/// the direct live proof that independent vCPUs make concurrent progress on
/// real cores rather than serializing behind a shared lock -- the clearest
/// evidence for the "no global lock across `hv_vcpu_run`" invariant, since a
/// held lock would flatten this curve regardless of core count.
///
/// # Errors
///
/// Returns the backend's typed error if a scratch page cannot be mapped, a
/// lane cannot be occupied, or an occupier thread cannot be spawned/joined.
pub fn hvf_scheduler_scaling_probe() -> Result<HvfSchedulerScalingReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lane_count = backend.lanes.len();
    let mut levels_to_run: Vec<usize> = [1usize, 2, 4, 8]
        .into_iter()
        .filter(|&n| n <= lane_count)
        .collect();
    if levels_to_run.is_empty() {
        levels_to_run.push(lane_count.max(1));
    }

    let mut levels = Vec::with_capacity(levels_to_run.len());
    for &concurrency in &levels_to_run {
        let mut ranges = Vec::with_capacity(concurrency);
        let mut owned_ranges = Vec::with_capacity(concurrency);
        for slot in 0..concurrency {
            let base = SCALING_PROBE_BASE_GVA + slot * SCALING_PROBE_STRIDE;
            let range = base..base + PAGE_SIZE;
            let mapped = backend.default_space.map_range(
                range.clone(),
                HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                false,
                false,
            )?;
            let owned = OwnedGuestRange::new(backend, range.clone());
            backend.default_space.defer_retirement(mapped.retirement)?;
            let mut bytes = [0u8; COMPUTE_LOOP.len() * 4];
            for (index, instruction) in COMPUTE_LOOP.iter().enumerate() {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&instruction.to_le_bytes());
            }
            // SAFETY: `range` was just mapped read/write in the mirrored
            // host view and nothing else references it yet.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), range.start as *mut u8, bytes.len());
            }
            let executable = backend.default_space.protect_range(
                range.clone(),
                HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            )?;
            backend.default_space.defer_retirement(executable.retirement)?;
            ranges.push(range);
            owned_ranges.push(owned);
        }
        backend.default_space.pump_retirements()?;

        let mut occupied: Vec<ProbeWorker<u64>> = Vec::with_capacity(concurrency);
        for range in &ranges {
            let lease = backend.acquire_lane()?;
            let index = lease.index();
            let lane = lease.lane();
            let attachment = {
                let participant = lane
                    .participant
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                backend.default_space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?
            };
            let state = spin_probe_state(range.start);
            let handle = lane.handle.clone();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let worker_stop = std::sync::Arc::clone(&stop);
            let thread = std::thread::Builder::new()
                .name("litebox-hvf-scheduler-scaling-worker".to_owned())
                .spawn(move || -> Result<u64, HvfVcpuLaneError> {
                    let lane = lease.lane();
                    let mut attachment = attachment;
                    let mut state = state;
                    let deadline = Instant::now() + SCALING_RUN_DURATION;
                    let mut slices = 0u64;
                    loop {
                        let vtimer_deadline = time_slice_deadline();
                        let run = handle.run_with_deadline(attachment, &state, vtimer_deadline)?;
                        match (run.exit, run.state) {
                            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(next)) => {
                                slices += 1;
                                if worker_stop.load(Ordering::Acquire) || Instant::now() >= deadline
                                {
                                    // Cooperative stop: the loop simply
                                    // declines to re-enter after this slice
                                    // rather than needing a cross-thread
                                    // cancel, which keeps every worker's
                                    // timing symmetric across concurrency
                                    // levels.
                                    return Ok(slices);
                                }
                                state = next;
                                attachment = {
                                    let participant = lane
                                        .participant
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    backend.default_space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))?
                                };
                            }
                            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_)) => {
                                return Ok(slices);
                            }
                            _ => return Err(invalid_run_state(&run)),
                        }
                    }
                })
                .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
            occupied.push(ProbeWorker {
                index,
                stop,
                thread: Some(thread),
            });
        }

        let started = Instant::now();
        let mut total_slices = 0u64;
        let mut join_errors: Vec<String> = Vec::new();
        for worker in occupied {
            match worker.join() {
                Ok(Ok(slices)) => total_slices += slices,
                Ok(Err(error)) => join_errors.push(format!("{error}")),
                Err(_) => join_errors.push("scaling worker thread panicked".to_owned()),
            }
        }
        let elapsed = started.elapsed();
        drop(owned_ranges);
        if !join_errors.is_empty() {
            litebox_util_log::warn!(
                concurrency:? = concurrency, errors:? = join_errors;
                "HVF scheduler scaling probe worker error"
            );
        }
        levels.push(HvfSchedulerScalingLevel {
            concurrency,
            total_slices,
            elapsed_millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        });
    }

    let baseline_throughput = levels.first().map_or(0.0, |level| {
        if level.elapsed_millis == 0 {
            0.0
        } else {
            level.total_slices as f64 / level.elapsed_millis as f64
        }
    });
    let speedup = levels
        .iter()
        .map(|level| {
            if level.elapsed_millis == 0 || baseline_throughput == 0.0 {
                0.0
            } else {
                (level.total_slices as f64 / level.elapsed_millis as f64) / baseline_throughput
            }
        })
        .collect();

    let pool = backend
        .free
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pool_at_baseline = lane_pool_at_baseline(&pool, lane_count);
    drop(pool);

    Ok(HvfSchedulerScalingReport {
        lane_count,
        levels,
        speedup,
        pool_at_baseline,
    })
}

fn advance_canceled_tickets(pool: &mut LanePool) -> Result<(), HvfBackendError> {
    pool.canceled_tickets
        .retain(|ticket| *ticket >= pool.next_serving);
    while pool.canceled_tickets.remove(&pool.next_serving) {
        pool.next_serving = pool
            .next_serving
            .checked_add(1)
            .ok_or(HvfBackendError::LaneTicketExhausted)?;
    }
    Ok(())
}

fn lane_pool_at_baseline(pool: &LanePool, lane_count: usize) -> bool {
    pool.failure.is_none()
        && pool.canceled_tickets.is_empty()
        && pool.checked_out == 0
        && pool.retiring == 0
        && pool.next_serving == pool.next_ticket
        && pool.free.len() == lane_count
        && (0..lane_count)
            .all(|index| pool.free.iter().filter(|free| free.index == index).count() == 1)
}

fn lane_replacement_error(failure: LaneReplacementFailure) -> HvfBackendError {
    HvfBackendError::LaneReplacementFailed {
        index: failure.index,
        generation: failure.generation,
        stage: failure.stage,
    }
}

fn invalid_run_state(run: &HvfVcpuRunResult) -> HvfVcpuLaneError {
    let state = match &run.state {
        HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => state,
    };
    HvfVcpuLaneError::InvalidExecutionState {
        exit: run.exit,
        state: state.into(),
    }
}

/// A minimal architectural state whose PC is the guest-executable sigreturn
/// trampoline (`svc #0`), the one guest page every HVF backend installation
/// already guarantees is mapped RX -- so this witness needs no address space
/// of its own and cannot race any real guest thread's own mappings.
fn spin_probe_state(pc: usize) -> HvfArchitecturalState {
    let mut state = HvfArchitecturalState::default();
    state.pc = pc as u64;
    state.cpsr = 0xa000_0000;
    state.sp_el0 = 0;
    state.sp_el1 = 0;
    state
}

/// Installs the process-global HVF backend.  Must run before the shim maps
/// anything: every later page-management call is routed through it.
pub(crate) fn install() -> Result<&'static HvfBackend, HvfBackendError> {
    // CLASS A: rank-checked but NOT registered (see `RankedMutex::lock_unregistered`). The only
    // waits inside this body are the vCPU creation barriers, one pair per lane, and no other
    // thread can contend for this lock while it is held -- installation is a one-shot transition
    // that runs before the backend is published.
    let _installation = HVF_BACKEND_INSTALL
        .lock_unregistered()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if HVF_BACKEND.get().is_some() {
        return Err(HvfBackendError::AlreadyInstalled);
    }
    let backend = HvfBackend::create()?;
    litebox_util_log::info!(
        lanes:? = backend.lanes.len(),
        capacity:? = backend.registry.capacity(),
        trampoline:? = backend.trampoline.start;
        "HVF guest backend installed: unchanged stock code will execute on real vCPUs"
    );
    match HVF_BACKEND.set(backend) {
        Ok(()) => {}
        Err(_backend) => fatal(
            "publishing the process-global HVF backend",
            &HvfBackendError::AlreadyInstalled,
        ),
    }
    let backend = HVF_BACKEND.get().unwrap_or_else(|| {
        fatal(
            "recovering the process-global HVF backend after publication",
            &HvfBackendError::NotInstalled,
        )
    });
    if let Err(error) = backend.start_lane_maintenance() {
        // Publication is a process-global one-way transition: `active()` may
        // already have handed this backend to another thread, so a maintenance
        // owner that cannot be established is not a recoverable installation
        // error.  Abort instead of returning an error that could invite a
        // native fallback while `HVF_BACKEND` remains permanently installed.
        fatal(
            "starting lane maintenance after publishing the HVF backend",
            &error,
        );
    }
    if let Err(error) = backend.start_vdso_clock_refresher() {
        // Same one-way reasoning: without the refresher the vDSO's `CLOCK_REALTIME` would
        // silently drift away from the host's, and the guest is already promised a vDSO.
        fatal(
            "starting the vDSO clock refresher after publishing the HVF backend",
            &HvfBackendError::LaneMaintenanceThread(error),
        );
    }
    // `wx-latency-readout`: `LITEBOX_HVF_DIAG_INTERVAL=<secs>` opt-in periodic debug readout of
    // the wx-service-latency counters -- mirrors `LITEBOX_HVF_LANES`'s own env-var handling in
    // `HvfBackend::create` immediately above (unset by default; an unparsable value is ignored
    // with a warning rather than refusing to start). Lives here rather than in `create` because
    // the readout thread needs `&'static self`, available only once `backend` is this process's
    // published, process-global `'static` reference -- see `start_diagnostics_readout`'s own doc
    // comment for what the periodic line contains and why it exists alongside the pre-existing
    // always-on `counters_publisher` mmap-file surface. Never fatal on failure to start: purely
    // additive diagnostics, not load-bearing for guest execution.
    let requested_diag_interval_secs = std::env::var("LITEBOX_HVF_DIAG_INTERVAL")
        .ok()
        .and_then(|raw| match raw.trim().parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => {
                litebox_util_log::warn!(raw:? = raw; "LITEBOX_HVF_DIAG_INTERVAL is not a number; ignoring");
                None
            }
        });
    match requested_diag_interval_secs {
        None => {}
        Some(0) => {
            litebox_util_log::warn!(
                "LITEBOX_HVF_DIAG_INTERVAL=0 has no periodic interval; ignoring"
            );
        }
        Some(interval_secs) => {
            match backend.start_diagnostics_readout(Duration::from_secs(interval_secs)) {
                Ok(()) => {
                    litebox_util_log::info!(
                        interval_secs;
                        "LITEBOX_HVF_DIAG_INTERVAL override in effect: periodic wx-service-latency readout started"
                    );
                }
                Err(error) => {
                    litebox_util_log::warn!(
                        error:? = error, interval_secs;
                        "starting the LITEBOX_HVF_DIAG_INTERVAL readout thread failed; continuing without it"
                    );
                }
            }
        }
    }
    Ok(backend)
}

impl HvfBackend {
    fn create() -> Result<Self, HvfBackendError> {
        // CLASS A: the lock inventory is checked before any lock in this file can be taken, in
        // every build, so a lock added without a rank is reported instead of silently invisible.
        crate::diagnostics_counters::lock_inventory_selfcheck();
        let memory = process_hvf_memory()?;
        let default_space = memory.create_mirrored_address_space()?;
        // Created eagerly (not on the first origin) so the lifecycle residual witness sees the
        // same `address_spaces` before and after a workload that maps files privately.
        let origin_space = if file_cow_disabled() {
            None
        } else {
            Some(memory.create_mirrored_address_space()?)
        };
        let registry = HvfVcpuRegistry::process()?;
        let snapshot = default_space.vcpu_snapshot()?;
        let el1 = HvfEl1State::linux_user(
            snapshot.synchronization_ttbr0_el1,
            snapshot.regime.tcr_el1,
            u64::from(snapshot.regime.mair_attr0),
        );
        let parallelism = std::thread::available_parallelism().map_or(1, |n| n.get());
        // `LITEBOX_HVF_LANES=<n>` caps the vCPU lane pool below the host's
        // parallelism. A diagnostic knob, not a tuning one: a single lane
        // serializes all guest execution, which is the cleanest way to tell
        // a genuine multi-core race (vanishes at 1) from a timing-independent
        // bug (persists at 1) without touching any other code path. Values
        // outside [1, parallelism] are clamped; unparsable values are ignored
        // with a warning rather than refusing to start.
        let requested_lanes = std::env::var("LITEBOX_HVF_LANES")
            .ok()
            .and_then(|raw| match raw.trim().parse::<usize>() {
                Ok(n) => Some(n),
                Err(_) => {
                    litebox_util_log::warn!(raw:? = raw; "LITEBOX_HVF_LANES is not a number; ignoring");
                    None
                }
            })
            .map(|n| n.clamp(1, parallelism.max(1)));
        let lane_count = requested_lanes
            .unwrap_or(parallelism)
            .max(1)
            .min(usize::try_from(registry.capacity()).unwrap_or(1));
        let (numer, denom) = crate::vdso::host_timebase().map_err(HvfBackendError::Vdso)?;
        if requested_lanes.is_some() {
            litebox_util_log::warn!(lane_count, parallelism; "LITEBOX_HVF_LANES override in effect");
        }
        // FXR / T2a: the verify knob makes every run pay a full 74-register readback (and every
        // exit a SIMD capture); say so once, so a slow run is never mistaken for a regression.
        if crate::hvf::state_verify_enabled() {
            let readback_registers = 74_u32;
            litebox_util_log::warn!(
                readback_registers;
                "LITEBOX_HVF_VERIFY_STATE=1: every vCPU register install is read back and compared (diagnostics only, slow)"
            );
        }
        // BCORE: a bound vCPU is a real architectural change to the run path (no lane
        // hand-off, no owner thread), so say so once at startup -- a bound run's counters are
        // otherwise indistinguishable from a very fast pooled one.
        if bound_enabled() {
            crate::diagnostics_counters::add_stat(crate::diagnostics_counters::BOUND_ENABLED, 1);
            litebox_util_log::warn!(
                trigger_exits:? = BOUND_TRIGGER_EXITS, reserve:? = crate::hvf_vcpu::BOUND_RESERVE;
                "LITEBOX_HVF_BOUND=1: a hot guest thread takes a vCPU of its own instead of a pooled lane"
            );
        }
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(lane_count)
            .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
        let mut free = Vec::new();
        free.try_reserve_exact(lane_count)
            .map_err(|_| HvfBackendError::Lane(HvfVcpuLaneError::RegistryAccounting))?;
        for index in 0..lane_count {
            let generation = Self::create_lane_generation(&registry, &default_space, None, el1)?;
            free.push(FreeLane {
                index,
                generation: generation.handle.generation(),
                view_tag: generation.view_tag.load(Ordering::Relaxed),
            });
            lanes.push(PooledLane {
                state: RankedMutex::new(
                    LaneSlotState::Ready(generation),
                    crate::diagnostics_counters::RANK_LANE_SLOT,
                ),
            });
        }
        let backend = Self {
            memory,
            default_space,
            origin_space,
            view_spaces: RankedRwLock::new(
                HashMap::new(),
                crate::diagnostics_counters::RANK_VIEW_SPACES,
            ),
            pending_view_retirement: RankedMutex::new(
                Vec::new(),
                crate::diagnostics_counters::RANK_VIEW_RETIREMENT,
            ),
            registry,
            el1,
            lanes,
            free: RankedMutex::new(
                LanePool {
                free: VecDeque::from(free),
                checked_out: 0,
                retiring: 0,
                failure: None,
                canceled_tickets: BTreeSet::new(),
                next_ticket: 0,
                next_serving: 0,
                },
                crate::diagnostics_counters::RANK_LANE_POOL,
            ),
            available: Condvar::new(),
            lane_waiters: AtomicUsize::new(0),
            lane_yield_epoch: AtomicU64::new(0),
            retained_lanes: AtomicU64::new(0),
            lane_maintenance: LaneMaintenance {
                requested: RankedMutex::new(
                    false,
                    crate::diagnostics_counters::RANK_LANE_MAINTENANCE,
                ),
                wake: Condvar::new(),
                owner: RankedMutex::new(
                    None,
                    crate::diagnostics_counters::RANK_LANE_MAINTENANCE,
                ),
            },
            participant_recovery: RankedMutex::new(
                (),
                crate::diagnostics_counters::RANK_PARTICIPANT_RECOVERY,
            ),
            trampoline: SIGRETURN_TRAMPOLINE_GVA..SIGRETURN_TRAMPOLINE_GVA + PAGE_SIZE,
            vdso: VDSO_GVA..VDSO_GVA + 2 * PAGE_SIZE,
            vdso_clock: RankedMutex::new(
                VdsoClock {
                    storage: 0,
                    values: crate::vdso::ClockValues {
                        numer,
                        denom,
                        mono_epoch_ns: 0,
                        real_offset_ns: crate::vdso::host_real_offset_ns(),
                    },
                },
                crate::diagnostics_counters::RANK_VDSO_CLOCK,
            ),
            shared_initialization: RankedMutex::new(
                SharedInitialization {
                    initialized: HashMap::new(),
                    in_progress: HashMap::new(),
                },
                crate::diagnostics_counters::RANK_SHARED_INIT,
            ),
            shared_initialization_changed: Condvar::new(),
            mutations: std::sync::atomic::AtomicU64::new(0),
            // CLASS A: cannot block -- this `Vec` is pushed and removed under the bound-vCPU knob
            // only (`LITEBOX_HVF_BOUND=1`, off by default), always for a handful of instructions,
            // and never across another lock, a wait or a host call: the `BoundEntry` it names is
            // signalled through an `AtomicBool`, not through this lock.
            bound_entries: Mutex::new(Vec::new()),
            wx_toggle: WxToggle::default(),
            exception_counters: HvfExceptionCounters::default(),
        };
        backend.install_trampoline()?;
        backend.install_vdso()?;
        Ok(backend)
    }

    fn create_lane_generation(
        registry: &HvfVcpuRegistry,
        space: &HvfAddressSpace,
        view: Option<VmViewId>,
        el1: HvfEl1State,
    ) -> Result<Arc<LaneGeneration>, HvfBackendError> {
        let lane = registry.create_lane(LANE_QUEUE_CAPACITY)?;
        let handle = lane.handle();
        handle.initialize_el1(el1)?;
        handle.set_vtimer(true, 0)?;
        let participant = space.register_vcpu_participant(handle.participant_capability()?)?;
        // T1b: the lane's space tag starts as the space this participant was just registered in
        // (see `LaneGeneration::space_tag`).
        let space_tag = participant.address_space().value();
        Ok(Arc::new(LaneGeneration {
            lane: RankedMutex::new(Some(lane), crate::diagnostics_counters::RANK_LANE),
            handle,
            participant: RankedMutex::new(
                (view, Some(participant)),
                crate::diagnostics_counters::RANK_PARTICIPANT,
            ),
            view_tag: AtomicU64::new(view_tag(view)),
            space_tag: AtomicU64::new(space_tag),
        }))
    }

    /// Pure query: whether `view` already has its own independent, per-view [`HvfAddressSpace`]
    /// recorded in [`Self::view_spaces`]. Unlike [`Self::space_for_view`], a miss never creates
    /// one -- this never takes the memory manager's own locks and never mutates
    /// [`Self::view_spaces`]. A view that has never reached [`Self::space_for_view`]'s miss
    /// branch (never had a guest instruction dispatched under it through this backend) reads
    /// `false`, matching `space_for_view`'s own "no entry yet" case exactly.
    pub(crate) fn has_view_space(&self, view: VmViewId) -> bool {
        self.view_spaces
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&view)
    }

    /// Resolves the [`HvfAddressSpace`] a `view` should be handled against.
    ///
    /// `None` (the pre-view/bring-up case, and the recorded view of every
    /// lane that has never been migrated) always resolves to
    /// [`Self::default_space`] directly -- no lock, no allocation.
    ///
    /// `Some(view)` first checks [`Self::view_spaces`] for an already-created
    /// space for that view. On a miss, this currently refuses rather than
    /// creating one: see [`HvfBackendError::ViewSpaceCreationUnsupported`]'s
    /// own documentation for exactly why minting a second address space and
    /// installing the sigreturn trampoline into it (the way `default_space`
    /// got its own copy in [`Self::install_trampoline`]) is not yet known to
    /// be safe to do while `default_space` still holds its own permanent
    /// claim at the identical GVA. No call site passes `Some(view)` today, so
    /// this arm is presently unreachable in practice; it exists so
    /// [`Self::ensure_lane_attached_to_view`] and the lane-repair path have a
    /// single, correct place to resolve a recorded view once a future change
    /// starts populating `view_spaces`.
    fn space_for_view(&self, view: Option<VmViewId>) -> Result<ResolvedSpace<'_>, HvfBackendError> {
        let Some(view) = view else {
            return Ok(ResolvedSpace::Default(&self.default_space));
        };
        {
            let spaces = self
                .view_spaces
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(space) = spaces.get(&view) {
                return Ok(ResolvedSpace::View(Arc::clone(space)));
            }
        }
        // No entry yet: create one outside the lock (space creation itself takes the memory
        // manager's own locks and must never be attempted while `view_spaces` is held), then
        // race to publish it. `alias_trampoline_stage1` gives the fresh space the identical
        // sigreturn-trampoline content `default_space` holds permanently, at the same fixed GVA,
        // without a second independent claim at that GVA (the open question
        // `ViewSpaceCreationUnsupported` used to document -- resolved by aliasing instead of
        // reclaiming) -- and the same for the two vDSO pages, so every view reads the one clock
        // data page the host keeps current.
        let created = self.memory.create_mirrored_address_space()?;
        let permanent = [self.trampoline.start, self.vdso.start, self.vdso.start + PAGE_SIZE];
        if let Err(error) = permanent
            .iter()
            .try_for_each(|&gva| created.alias_trampoline_stage1(&self.default_space, gva))
        {
            let _ = created.destroy();
            return Err(error.into());
        }
        let new_space = Arc::new(created);
        let mut spaces = self
            .view_spaces
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match spaces.entry(view) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                // Lost the race to a concurrent creator for the same view: tear down this one's
                // now-redundant space and use theirs instead, rather than leaking a second live
                // address space nothing will ever reference again.
                let winner = Arc::clone(entry.get());
                drop(spaces);
                if let Ok(space) = Arc::try_unwrap(new_space) {
                    let _ = space.destroy();
                }
                Ok(ResolvedSpace::View(winner))
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&new_space));
                // T1f-a: one per-view address space minted (F5's churn numerator).
                crate::diagnostics_counters::record_view_space(
                    crate::diagnostics_counters::VIEW_SPACE_CREATED,
                );
                Ok(ResolvedSpace::View(new_space))
            }
        }
    }

    /// Retires `view`'s own per-view mirrored [`HvfAddressSpace`], if [`Self::space_for_view`]
    /// ever created one for it, once every obstruction [`HvfAddressSpace::destroy`] itself checks
    /// for (a live vCPU participant still registered against it, an unacknowledged retirement row,
    /// a lineage page still pinned for a live descendant, ...) has cleared, AND once
    /// [`Self::family_blocks_release`] no longer names a live descendant view that might still
    /// resolve its own fork-COW custody back to `view` (checked first, ahead of even attempting
    /// `destroy()`: `destroy()` itself has no visibility into another view's own space at all).
    ///
    /// Callable only once `view` is already permanently retired at the domain level (`view` will
    /// never again be `current_guest_view()` for any live task) -- today that means the shim's own
    /// exit path, right after it calls `GuestVaDomain::unregister_view`. A `destroy()` failure here
    /// therefore only ever means "not yet, some obstruction has not cleared" (most commonly: the
    /// lane that last ran this view has not been reused for a different view since, so its
    /// participant registration is still live in `state.participants`) -- never "still logically in
    /// use". A space that is not yet safe stays in [`Self::view_spaces`], reachable for a later
    /// retry alongside every other view still awaiting one, rather than being dropped unreachable-
    /// but-still-alive: an earlier attempt at this exact mechanism removed the `view_spaces` entry
    /// and ignored `destroy()`'s own refusal, permanently orphaning a fully-live address space that
    /// still held its permanent host-slot mirror -- wedging every later mirrored claim at the same
    /// GVA (`HvfMemoryError::MirrorSlotShared`) since nothing could ever reach it again to retry.
    /// Every candidate this call retries was, by the same reasoning, already permanently retired
    /// whenever it was first queued, so retrying it here is exactly as safe as it was the first
    /// time -- retirement only ever removes participants/rows from a dead view, never adds them.
    pub(crate) fn release_view_space(
        &self,
        view: VmViewId,
        family: Option<FamilyId>,
        domain: &GuestVaDomain,
    ) {
        let _origin =
            crate::diagnostics_counters::enter_origin(crate::diagnostics_counters::ORIGIN_TEARDOWN);
        let mut pending = self
            .pending_view_retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !pending.iter().any(|&(pending_view, _)| pending_view == view) {
            pending.push((view, family));
        }
        let candidates = core::mem::take(&mut *pending);
        drop(pending);
        let mut still_pending = Vec::new();
        for (candidate, family) in candidates {
            let space = self
                .view_spaces
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&candidate)
                .cloned();
            let Some(space) = space else {
                continue;
            };
            if self.family_blocks_release(family, domain) {
                crate::diagnostics_counters::record_view_space(
                    crate::diagnostics_counters::VIEW_SPACE_DESTROY_DEFERRED,
                );
                still_pending.push((candidate, family));
                continue;
            }
            // A stash entry blocks `begin_destroy` outright (`RetiredMirroredPagesPending`) and a
            // preserved generation is a claim `finish_destroy` would otherwise carry to the grave
            // unreaped -- both are releasable once no live descendant inherits from this family
            // (see `reap_fork_cow_retention`). `family_blocks_release` above already proved that
            // via this exact predicate (it no longer needs re-proving here), so only the
            // has-anything-to-reap check remains; a still-shared stash entry keeps the candidate
            // pending exactly as before.
            if space.has_fork_cow_retention_checked() {
                self.reap_fork_cow_retention(Some(candidate), &space);
            }
            match space.destroy() {
                Ok(()) | Err(HvfMemoryError::AddressSpaceDestroyed(_)) => {
                    self.view_spaces
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&candidate);
                    crate::diagnostics_counters::record_view_space(
                        crate::diagnostics_counters::VIEW_SPACE_DESTROYED,
                    );
                }
                Err(_) => {
                    crate::diagnostics_counters::record_view_space(
                        crate::diagnostics_counters::VIEW_SPACE_DESTROY_DEFERRED,
                    );
                    still_pending.push((candidate, family));
                }
            }
        }
        if !still_pending.is_empty() {
            self.pending_view_retirement
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(still_pending);
        }
        // `finish_destroy` handed every destroyed space's window/alias references back to the
        // registry; the origins that reached zero are released here, outside it.
        self.drain_origin_release_candidates();
    }

    /// FIX (hvf-exited-space-retention-family-blocks-release-non-exec-aware): whether
    /// `candidate`'s own [`HvfAddressSpace`] (named indirectly here by `family`, its
    /// domain-lineage family id captured before it was unregistered) must stay in
    /// [`Self::view_spaces`] a while longer because some live descendant might still resolve its
    /// fork-COW custody back to it: exactly
    /// [`GuestVaDomain::family_has_live_inheriting_descendant`] -- the same exec-aware predicate
    /// this same function's own caller, [`Self::release_view_space`], already applies one line
    /// below this call to gate `reap_fork_cow_retention`, and the one
    /// `PageManagementProvider::allocate_pages`/`deallocate_pages`/`try_allocate_cow_pages` already
    /// compute (as `keep_mirror_for_descendant`) to decide the very retention this call guards.
    ///
    /// Previously walked the non-exec-aware [`GuestVaDomain::live_descendant_views_of_family`] (a
    /// plain family-membership census with no [`FamilyRecord::exec_severed`] awareness) and
    /// blocked on ANY such descendant's [`HvfAddressSpace::has_unpromoted_cow_alias`] -- including
    /// one that has since `execve`d: an exec'd descendant's own pre-exec alias is never promoted
    /// (its new image never faults on the old GVA again) and its own space is itself queued in
    /// [`Self::pending_view_retirement`] exactly like any other exited space, so a dead,
    /// exec-severed descendant could pin its dead ancestor's release forever -- observed live as
    /// 7-9 EXITED spaces (2.4 GiB) never destroyed.
    /// [`GuestVaDomain::family_has_live_inheriting_descendant`] already walks straight through an
    /// exec-severed middle family to find a genuinely-still-inheriting one further down (see its
    /// own doc comment), so this loses no real blocking case while dropping the false one. Not a
    /// leak either way: a blocking descendant's own [`AddressSpaceState::aliases`] entry is cleared
    /// either by its own [`HvfAddressSpace::promote_cow_alias`] (the ordinary happy path) or by
    /// that descendant's own eventual [`Self::release_view_space`] (`finish_destroy` releases every
    /// `aliases` entry unconditionally) -- either way this stops blocking on the very next retry
    /// sweep, which every later `release_view_space` call performs for every still-pending
    /// candidate, not only its own.
    fn family_blocks_release(&self, family: Option<FamilyId>, domain: &GuestVaDomain) -> bool {
        family.is_some_and(|family| domain.family_has_live_inheriting_descendant(family))
    }

    /// Resolves the real host address a host-pointer dereference of `gva` under `view` should
    /// actually use, if `gva`'s page has ever been promoted to a per-view-diverged physical page
    /// in `view`'s own address space -- see [`HvfAddressSpace::resolve_host_redirect`], which
    /// this simply resolves the right space for. `None` means "no redirect: use `gva` itself",
    /// which is every page today, since nothing yet populates any space's own promoted-page
    /// table.
    ///
    /// Checks [`ANY_HOST_REDIRECT_EVER`] first, ahead of even resolving `view`'s own space via
    /// [`Self::space_for_view`] (which takes the `view_spaces` lock for a `Some(view)` lookup):
    /// while nothing has ever been promoted anywhere in the process -- the default, and the only
    /// state reachable today -- this never takes any lock at all.
    ///
    /// `Err(HvfBackendError::ViewSpaceCreationUnsupported)` from `space_for_view` (no space
    /// exists yet for `view`) maps to `None`: nothing could have been promoted into a space that
    /// was never created.
    pub fn resolve_host_redirect(&self, view: Option<VmViewId>, gva: usize) -> Option<usize> {
        if !ANY_HOST_REDIRECT_EVER.load(Ordering::Relaxed) {
            return None;
        }
        self.space_for_view(view).ok()?.resolve_host_redirect(gva)
    }

    /// [`Self::resolve_host_redirect`] for every page of `first_page..=last_page` (page-aligned),
    /// appended to `out` in address order: one `view_spaces` lookup and one
    /// [`HvfAddressSpace::resolve_host_redirects`] snapshot for the whole range instead of one of
    /// each per page (hvf-t1g-remainder-multisecond-service-guest-memory-access-convoy).
    pub fn resolve_host_redirects(
        &self,
        view: Option<VmViewId>,
        first_page: usize,
        last_page: usize,
        out: &mut Vec<Option<usize>>,
    ) {
        let space = if ANY_HOST_REDIRECT_EVER.load(Ordering::Relaxed) {
            self.space_for_view(view).ok()
        } else {
            None
        };
        match space {
            Some(space) => space.resolve_host_redirects(first_page, last_page, out),
            None => {
                let mut page = first_page;
                while page <= last_page {
                    out.push(None);
                    match page.checked_add(PAGE_SIZE) {
                        Some(next) => page = next,
                        None => break,
                    }
                }
            }
        }
    }

    /// Migrates `generation`'s vCPU participant onto `view`'s address space
    /// (as resolved by [`Self::space_for_view`]) if it is not already
    /// registered there, using the already-verified
    /// [`HvfAddressSpace::migrate_vcpu_participant`] primitive.
    ///
    /// Callable only from a genuine quiescence point for this exact lane --
    /// today that means the lane must not have an attachment in flight, which
    /// both call sites this is meant for (the top of `run_thread`'s
    /// per-iteration lease-acquire, before any `attach_vcpu`; and the
    /// lane-repair path, which only reaches a lane after it has been fully
    /// reaped) already guarantee by construction. Holds `generation`'s own
    /// `participant` lock for the whole migration so a concurrent caller can
    /// never observe (or attempt) a second migration of the same lane at the
    /// same time; never held across a call into `self.space_for_view`'s
    /// creation path (there is none today) or across any other lock.
    ///
    /// `HvfVcpuParticipant` holds no cheap placeholder value (its fields are
    /// live `Arc`s consumed by the memory manager, not a type with a safe
    /// `Default`), so the slot's participant is modeled as `Option` purely so
    /// this function can move it out by value with `Option::take` -- every
    /// other reader always observes `Some` because this is the only place
    /// that ever stores `None`, and only for the instant this lock is held.
    /// If the underlying `migrate_vcpu_participant` call fails, the old
    /// registration is not recoverable (it was consumed by value into that
    /// call either way -- see its own source for why), so the slot is left
    /// with `None`: callers must treat that as fatal to this lane generation,
    /// the same way an unrecoverable lane failure already is elsewhere in
    /// this module, rather than attempt to keep using it.
    fn ensure_lane_attached_to_view(
        &self,
        generation: &LaneGeneration,
        view: VmViewId,
    ) -> Result<(), HvfBackendError> {
        let mut slot = generation
            .participant
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.0 == Some(view) {
            return Ok(());
        }
        let recorded_view = slot.0;
        // hvf-exit-overhead-instrumentation: the migrate path (two exclusive VM operations, and
        // the next attach then requires a synchronization trip) is timed as `lane_migration`.
        let migration_start = Instant::now();
        let old = slot.1.take().ok_or(HvfBackendError::LanePoolCorrupt {
            index: usize::MAX,
        })?;
        let resolved = self
            .space_for_view(recorded_view)
            .and_then(|source| Ok((source, self.space_for_view(Some(view))?)))
            .and_then(|(source, target)| {
                generation
                    .handle
                    .participant_capability()
                    .map_err(HvfBackendError::from)
                    .map(|capability| (source, target, capability))
            });
        let (source, target, capability) = match resolved {
            Ok(resolved) => resolved,
            Err(error) => {
                // Nothing was attempted against either space yet: `old` is
                // still a valid, live registration in whatever space
                // `recorded_view` names, so it is safe -- and required -- to
                // put it right back rather than leave the slot poisoned.
                slot.1 = Some(old);
                return Err(error);
            }
        };
        match target.migrate_vcpu_participant(&source, old, capability) {
            Ok(migrated) => {
                // T1b: the tag follows the participant into the target space, under the same
                // `slot` guard that swaps the participant itself, and before this lane's next
                // attach to `target` -- so a mutator that sees this lane in flight in `target`
                // (published under `target`'s `cell.state`) necessarily sees this value.
                let target_tag = migrated.address_space().value();
                slot.1 = Some(migrated);
                slot.0 = Some(view);
                generation
                    .view_tag
                    .store(view_tag(Some(view)), Ordering::Relaxed);
                generation.space_tag.store(target_tag, Ordering::Release);
                crate::diagnostics_counters::record_lane_migration(
                    crate::diagnostics_counters::elapsed_ns(migration_start),
                );
                Ok(())
            }
            Err(error) => Err(HvfBackendError::from(error)),
        }
    }

    /// Reads [`Self::view_spaces`] for `view`'s already-created space without ever creating one
    /// -- unlike [`Self::space_for_view`]. Used only to resolve a fork-COW fault's *ancestor*
    /// view: an ancestor that is genuinely the source of real content must already have run (and
    /// so already have a real per-view space, created lazily the first time it ever executed a
    /// single instruction) by the time any descendant can fault against memory it inherited from
    /// that ancestor -- fabricating an empty space for it here would be a genuine bug, not a
    /// helpful fallback, so this deliberately returns `None` instead.
    fn existing_space_for_view(&self, view: VmViewId) -> Option<Arc<HvfAddressSpace>> {
        self.view_spaces
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&view)
            .cloned()
    }

    /// [`litebox::platform::PageManagementProvider::eagerly_diverge_fork_child_range`]'s real
    /// implementation: for every `PAGE_SIZE`-aligned page in `range`, synchronously installs a COW
    /// read alias from `ancestor_view`'s own live space into `child_view`'s own (created here if
    /// this is its first touch, via `space_for_view`, exactly as `child_view`'s own first real
    /// fault would) and immediately promotes it -- the same alias-then-promote pair
    /// `try_resolve_cow_fault` runs lazily, just run here eagerly, back to back, before either the
    /// ancestor or the child can race further. A page `ancestor_view` has nothing claimed at
    /// (`install_cow_read_alias` returning any error) is silently skipped: this is a best-effort
    /// narrowing of the fork-time divergence race for `range` (see the trait method's own doc
    /// comment for why the race exists at all), not a claim every named page is mapped.
    pub(crate) fn eagerly_diverge_fork_child_range(&self, child_view: VmViewId, ancestor_view: VmViewId, range: core::ops::Range<usize>) {
        let Some(ancestor) = self.existing_space_for_view(ancestor_view) else {
            return;
        };
        let _origin = crate::diagnostics_counters::enter_origin(
            crate::diagnostics_counters::ORIGIN_FORK_PROTECT,
        );
        let space = match self.space_for_view(Some(child_view)) {
            Ok(space) => space,
            Err(error) => {
                litebox_util_log::debug!(
                    child_view:?, ancestor_view:?, error:?;
                    "eagerly_diverge_fork_child_range: could not resolve the child's own space"
                );
                return;
            }
        };
        let start = range.start & !(PAGE_SIZE - 1);
        let end = range.end.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut page = start;
        while page < end {
            let aliased = self
                .settle_single_page_mutation(&space, MutationKind::Map, || {
                    space.install_cow_read_alias(&ancestor, page)
                })
                .is_ok();
            if aliased {
                let _ = self.settle_single_page_mutation(&space, MutationKind::Protect, || {
                    space.promote_cow_alias(&ancestor, page, None)
                });
            }
            page = page.saturating_add(PAGE_SIZE);
        }
    }

    /// Real HVF implementation of `PageManagementProvider::fork_time_ancestor_protect`: stamps
    /// the child's own fork-lineage origin once, then fork-write-protects every eligible page of
    /// `range` on the ancestor's own live space via [`HvfAddressSpace::fork_write_protect_range`]
    /// (the run-batched form of [`HvfAddressSpace::fork_write_protect_page`]), which is already
    /// fully self-contained (settles its own retirements, and already treats any mutation error
    /// -- `AliasBusy` from a concurrent same-view alias lease included -- as a silent skip, never
    /// a propagated failure) -- so no separate skip-and-continue wrapper is needed here, unlike
    /// `eagerly_diverge_fork_child_range`'s own `settle_single_page_mutation` use.
    pub(crate) fn fork_time_ancestor_protect(
        &self,
        child_view: VmViewId,
        ancestor_view: VmViewId,
        range: core::ops::Range<usize>,
    ) {
        let Some(ancestor) = self.existing_space_for_view(ancestor_view) else {
            return;
        };
        let _origin = crate::diagnostics_counters::enter_origin(
            crate::diagnostics_counters::ORIGIN_FORK_PROTECT,
        );
        let space = match self.space_for_view(Some(child_view)) {
            Ok(space) => space,
            Err(error) => {
                litebox_util_log::debug!(
                    child_view:?, ancestor_view:?, error:?;
                    "fork_time_ancestor_protect: could not resolve the child's own space"
                );
                return;
            }
        };
        space.set_fork_origin(&ancestor);
        ANY_FORK_VIEW_EVER.store(true, Ordering::Relaxed);
        FORK_GENERATION.fetch_add(1, Ordering::Relaxed);
        let start = range.start & !(PAGE_SIZE - 1);
        let end = range.end.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let _ = ancestor.fork_write_protect_range(start..end);
        // The child inherits the ancestor's file windows over this range as its own records
        // (each with its own origin reference); its first touch of a window page still resolves
        // the ancestor's pre-fork promotions through the lineage arms before the origin.
        space.clone_file_windows_from(&ancestor, &(start..end));
    }

    /// Whether the shared file-origin mechanism is live in this backend (an origin space
    /// exists); `false` under `LITEBOX_HVF_NO_FILE_COW=1`.
    pub(crate) fn file_cow_enabled(&self) -> bool {
        self.origin_space.is_some()
    }

    /// Acquires the `Ready` origin for the static slice `source` (creating and filling it when
    /// absent: one RW claim in the origin space, one `copy_nonoverlapping` through its host
    /// mirror, one `protect_range(READ|EXECUTE)` that publishes the bytes executable and retires
    /// the mirror's writer -- outside every lock, other mappers of the same key waiting on the
    /// registry condvar), returning one `windows` reference on it.
    #[track_caller]
    fn acquire_file_origin(&self, source: &'static [u8]) -> Result<OriginRef, CowAllocationError> {
        let Some(origin_space) = self.origin_space.as_ref() else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        let key = FileOriginKey {
            host_start: source.as_ptr() as usize,
            len: source.len(),
        };
        let pages = source.len() / PAGE_SIZE;
        let gva = {
            let mut table = FILE_ORIGINS
                .table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                match table.by_key.get_mut(&key) {
                    Some(origin) if origin.state == FileOriginState::Ready => {
                        origin.windows = origin.windows.saturating_add(1);
                        return Ok(OriginRef {
                            key,
                            gva: origin.gva,
                            armed: true,
                        });
                    }
                    Some(_) => {
                        // `Populating` by another mapper, or `Releasing` (recreated below once
                        // the entry is gone). `wait_on` is the ranked lock's own condvar wait: it
                        // masks FILE_ORIGINS out of the held set for the park (the condvar
                        // releases it) and counts the wait against everything ELSE held, so a
                        // real park-while-holding here is still a named violation.
                        table = FILE_ORIGINS
                            .table
                            .wait_on(&FILE_ORIGINS.changed, table)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    None => {
                        if table.pages.saturating_add(pages) > MAX_FILE_ORIGIN_PAGES {
                            file_cow_count(&FILE_COW_COUNTERS.fallback_origin_budget);
                            return Err(CowAllocationError::InternalFailure);
                        }
                        if table.by_key.try_reserve(1).is_err() {
                            return Err(CowAllocationError::InternalFailure);
                        }
                        let gva = next_file_origin_gva(source.len())
                            .map_err(|_| CowAllocationError::InternalFailure)?;
                        table.by_key.insert(
                            key,
                            FileOrigin {
                                gva,
                                pages,
                                windows: 1,
                                alias_refs: 0,
                                state: FileOriginState::Populating,
                            },
                        );
                        table.pages += pages;
                        break gva;
                    }
                }
            }
        };
        let range = gva..gva + source.len();
        let started = Instant::now();
        let filled = (|| -> Result<(), HvfMemoryError> {
            self.mutate_with_retry(origin_space, MutationKind::Map, || {
                origin_space.map_range(
                    range.clone(),
                    HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                    false,
                    false,
                )
            })?;
            // SAFETY: the origin space is mirrored, so the freshly claimed RW range is
            // host-writable at its own GVA and referenced by nothing else yet (its entry is
            // `Populating`, so no window or alias can name it); `source` is the runner-lifetime
            // static tar slice, `range.len() == source.len()`.
            unsafe {
                core::ptr::copy_nonoverlapping(source.as_ptr(), gva as *mut u8, source.len());
            }
            self.mutate_with_retry(origin_space, MutationKind::Protect, || {
                origin_space.protect_range(
                    range.clone(),
                    HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
                )
            })?;
            Ok(())
        })();
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        match filled {
            Ok(()) => {
                {
                    let mut table = FILE_ORIGINS.lock();
                    if let Some(origin) = table.by_key.get_mut(&key) {
                        origin.state = FileOriginState::Ready;
                    }
                }
                FILE_ORIGINS.changed.notify_all();
                FILE_COW_COUNTERS
                    .origin_fill_bytes
                    .fetch_add(source.len() as u64, Ordering::Relaxed);
                FILE_COW_COUNTERS
                    .origin_publish_ns_sum
                    .fetch_add(elapsed, Ordering::Relaxed);
                FILE_COW_COUNTERS
                    .origin_publish_count
                    .fetch_add(1, Ordering::Relaxed);
                FILE_COW_COUNTERS
                    .origin_publish_ns_max
                    .fetch_max(elapsed, Ordering::Relaxed);
                if FILE_COW_COUNTERS.origin_releases.load(Ordering::Relaxed) > 0 {
                    // Bookkeeping for the S6 refill/hit ratio: every origin created after the
                    // first release is a possible refill of a slice released too eagerly.
                    file_cow_count(&FILE_COW_COUNTERS.origin_refills);
                }
                litebox_util_log::debug!(
                    gva:? = gva, pages, elapsed_ns:? = elapsed;
                    "HVF file COW: origin published read+execute"
                );
                Ok(OriginRef {
                    key,
                    gva,
                    armed: true,
                })
            }
            Err(error) => {
                let _ = self.mutate_with_retry(origin_space, MutationKind::Unmap, || {
                    origin_space.unmap_range(range.clone(), false)
                });
                {
                    let mut table = FILE_ORIGINS.lock();
                    table.by_key.remove(&key);
                    table.pages = table.pages.saturating_sub(pages);
                }
                FILE_ORIGINS.changed.notify_all();
                litebox_util_log::warn!(
                    gva:? = gva, pages, error:% = error;
                    "HVF file COW: origin creation failed; this mapping takes the memcpy path"
                );
                file_cow_count(&FILE_COW_COUNTERS.fallback_origin_create_failed);
                Err(CowAllocationError::InternalFailure)
            }
        }
    }

    /// Unmaps every origin whose `windows` and `alias_refs` both reached zero, from the
    /// registry's candidate queue. Called only outside every space operation (after a
    /// `deallocate_pages`/`release_view_space`/exec sever/replace teardown returns), never
    /// inside `finish_destroy` or a `mutate_with_retry` closure: the origin unmap takes the
    /// manager's own locks. The registry lock is never held across that unmap (`Releasing`
    /// marks the entry meanwhile; a mapper that finds it waits and recreates).
    pub(crate) fn drain_origin_release_candidates(&self) {
        let Some(origin_space) = self.origin_space.as_ref() else {
            return;
        };
        let _origin =
            crate::diagnostics_counters::enter_origin(crate::diagnostics_counters::ORIGIN_FILE_MMAP);
        loop {
            let candidate = {
                let mut table = FILE_ORIGINS.lock();
                let Some(key) = table.release_candidates.pop() else {
                    return;
                };
                match table.by_key.get_mut(&key) {
                    Some(origin)
                        if origin.state == FileOriginState::Ready
                            && origin.windows == 0
                            && origin.alias_refs == 0 =>
                    {
                        origin.state = FileOriginState::Releasing;
                        Some((key, origin.gva, origin.pages))
                    }
                    // Still referenced (E11: a not-yet-destroyed space holds a stale alias) or
                    // mid-fill: left `Ready`/`Populating` for a later drain.
                    _ => None,
                }
            };
            let Some((key, gva, pages)) = candidate else {
                continue;
            };
            let range = gva..gva + pages * PAGE_SIZE;
            let result = self.mutate_with_retry(origin_space, MutationKind::Unmap, || {
                origin_space.unmap_range(range.clone(), false)
            });
            let released = {
                let mut table = FILE_ORIGINS.lock();
                match result {
                    Ok(_) => {
                        table.by_key.remove(&key);
                        table.pages = table.pages.saturating_sub(pages);
                        file_cow_count(&FILE_COW_COUNTERS.origin_releases);
                        litebox_util_log::debug!(
                            gva:? = gva, pages; "HVF file COW: unreferenced origin released"
                        );
                        true
                    }
                    Err(error) => {
                        litebox_util_log::warn!(
                            gva:? = gva, pages, error:% = error;
                            "HVF file COW: origin release failed; retried on a later drain"
                        );
                        if let Some(origin) = table.by_key.get_mut(&key) {
                            origin.state = FileOriginState::Ready;
                            if table.release_candidates.try_reserve(1).is_ok() {
                                table.release_candidates.push(key);
                            }
                        }
                        false
                    }
                }
            };
            FILE_ORIGINS.changed.notify_all();
            if !released {
                return;
            }
        }
    }

    /// `MacOsUserland::try_allocate_cow_pages`'s HVF branch: maps the static file slice
    /// `source` privately over `range` in `view`'s space as a window onto its shared origin,
    /// with no copy. `range` is already known to be page-aligned, inside the guest range and
    /// `MAP_FIXED`-replacing memory the view holds in its own custody (the caller checks the
    /// domain). Every refusal is counted and falls back to the memcpy path; a failure after the
    /// replace teardown leaves the range empty, which that path's own idempotent replace
    /// teardown absorbs.
    pub(crate) fn allocate_file_cow_pages(
        &self,
        range: Range<usize>,
        source: &'static [u8],
        permissions: MemoryRegionPermissions,
        view: VmViewId,
        keep_mirror_for_descendant: bool,
    ) -> Result<usize, CowAllocationError> {
        let Some(guest) = guest_permissions(permissions) else {
            // RWX at mmap: the memcpy path registers the W^X toggle through `allocate_pages`.
            file_cow_count(&FILE_COW_COUNTERS.fallback_rwx);
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        let _origin =
            crate::diagnostics_counters::enter_origin(crate::diagnostics_counters::ORIGIN_FILE_MMAP);
        if !range.start.is_multiple_of(PAGE_SIZE)
            || range.start >= range.end
            || !range.len().is_multiple_of(PAGE_SIZE)
            || range.start < GUEST_ADDR_MIN
            || range.end > GUEST_ADDR_MAX
        {
            file_cow_count(&FILE_COW_COUNTERS.fallback_unaligned);
            return Err(CowAllocationError::Unaligned);
        }
        if self.overlaps_reserved(&range) {
            file_cow_count(&FILE_COW_COUNTERS.fallback_reserved_overlap);
            return Err(CowAllocationError::UnsupportedSourceRegion);
        }
        let space = match self.resolve_view_space(Some(view)) {
            Ok(space) => space,
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "HVF file COW: could not resolve the view's space");
                file_cow_count(&FILE_COW_COUNTERS.fallback_no_view);
                return Err(CowAllocationError::UnsupportedSourceRegion);
            }
        };
        let origin_ref = self.acquire_file_origin(source)?;
        space
            .reserve_file_window()
            .map_err(|_| CowAllocationError::InternalFailure)?;
        // The `deallocate_pages` sequence over the replaced range, exec-aware like every other
        // unmap: retained promotions are reaped when no descendant inherits, the range's own
        // claims/lineage pages/file pages released (promoted window shadows retained for a live
        // inheriting descendant), the W^X bookkeeping dropped.
        if !keep_mirror_for_descendant && space.has_fork_cow_retention_checked() {
            self.reap_fork_cow_retention(Some(view), &space);
        }
        if let Err(error) = self.mutate_with_retry(&space, MutationKind::Unmap, || {
            space.unmap_range(range.clone(), keep_mirror_for_descendant)
        }) {
            litebox_util_log::warn!(
                start:? = range.start, end:? = range.end, error:% = error;
                "HVF file COW: replace teardown failed; this mapping takes the memcpy path"
            );
            file_cow_count(&FILE_COW_COUNTERS.fallback_replace_teardown);
            return Err(CowAllocationError::InternalFailure);
        }
        if !keep_mirror_for_descendant {
            self.wx_toggle.release(&range);
        }
        self.drain_origin_release_candidates();
        if let Err(error) = space.install_file_window(range.clone(), origin_ref.key, origin_ref.gva, guest) {
            litebox_util_log::warn!(
                start:? = range.start, end:? = range.end, error:% = error;
                "HVF file COW: window install refused; this mapping takes the memcpy path"
            );
            file_cow_count(&FILE_COW_COUNTERS.fallback_window_insert);
            drop(origin_ref);
            self.drain_origin_release_candidates();
            return Err(CowAllocationError::InternalFailure);
        }
        origin_ref.commit();
        file_cow_count(&FILE_COW_COUNTERS.mmap_hits);
        litebox_util_log::debug!(
            start:? = range.start, end:? = range.end, view:? = view, perms:? = guest;
            "HVF file COW: private file mapping installed as a window onto its shared origin"
        );
        Ok(range.start)
    }

    /// `PageManagementProvider::exec_sever_file_windows`: the exec'ing view's file windows,
    /// file aliases and promoted window pages are released regardless of custody (they resolve
    /// only to immutable origins), promoted shadows a live inheriting descendant may still need
    /// parked as preserved generations. Runs after `GuestVaDomain::mark_family_exec` and before
    /// the old image's own-custody release.
    pub(crate) fn exec_sever_file_windows(&self, view: VmViewId, keep_for_descendant: bool) {
        let Some(space) = self.existing_space_for_view(view) else {
            return;
        };
        match space.sever_file_windows(keep_for_descendant) {
            Ok(0) => {}
            Ok(count) => {
                file_cow_count(&FILE_COW_COUNTERS.windows_severed_at_exec);
                litebox_util_log::debug!(
                    view:? = view, windows:? = count, keep_for_descendant;
                    "HVF file COW: exec severed the view's file windows"
                );
            }
            Err(error) => {
                litebox_util_log::warn!(
                    view:? = view, error:% = error;
                    "HVF file COW: exec could not sever the view's file windows"
                );
            }
        }
        self.drain_origin_release_candidates();
    }

    /// `remap_pages`'s copy for the HVF backend: every page of `old_range` is read at the host
    /// address its content really lives at under `view` -- a promoted shadow or a file alias
    /// through the redirect, an untouched window page straight from the origin's host mirror
    /// (no alias or promotion is forced by the move), an own page at its GVA -- and written to
    /// the freshly claimed `new_start + offset` page.
    pub(crate) fn copy_range_for_remap(
        &self,
        view: Option<VmViewId>,
        old_range: Range<usize>,
        new_start: usize,
    ) -> Result<(), HvfMemoryError> {
        let space = self.resolve_view_space(view)?;
        let mut page = old_range.start;
        while page < old_range.end {
            let destination_page = new_start + (page - old_range.start);
            let source = match space.resolve_host_redirect(page) {
                Some(redirect) => redirect,
                None => match space.file_window_origin_host_address(page) {
                    Some(origin) => {
                        file_cow_count(&FILE_COW_COUNTERS.remap_window_pages);
                        origin
                    }
                    None => page,
                },
            };
            let destination = space
                .resolve_host_redirect(destination_page)
                .unwrap_or(destination_page);
            // SAFETY: `source` is a live, host-readable page (the caller holds the mapping lock
            // and every redirect target is this view's own claim, an origin mirror, or the
            // process-wide mirror at the GVA); `destination` is the just-allocated RW page.
            unsafe {
                core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, PAGE_SIZE);
            }
            page += PAGE_SIZE;
        }
        Ok(())
    }

    /// The file-COW counters and registry gauges as one JSON object (`hvf_file_cow` in the
    /// counters readout).
    pub(crate) fn file_cow_counters_json(&self) -> String {
        use std::fmt::Write as _;
        let c = &FILE_COW_COUNTERS;
        let (objects, pages, windows, alias_refs, pending) = {
            let table = FILE_ORIGINS.lock();
            (
                table.by_key.len(),
                table.pages,
                table.by_key.values().map(|origin| origin.windows).sum::<usize>(),
                table.by_key.values().map(|origin| origin.alias_refs).sum::<usize>(),
                table.release_candidates.len(),
            )
        };
        let load = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
        let mut out = String::new();
        let _ = write!(
            out,
            concat!(
                "{{\"enabled\":{},\"file_origin_objects\":{},\"file_origin_pages\":{},",
                "\"file_windows_live\":{},\"file_alias_pages_live\":{},",
                "\"file_origin_release_candidates_pending\":{},\"file_window_pages_live\":{},",
                "\"retired_promoted_live\":{},\"file_cow_mmap_hits\":{},",
                "\"file_origin_fill_bytes\":{},\"file_origin_publish_ns_sum\":{},",
                "\"file_origin_publish_count\":{},\"file_origin_publish_ns_max\":{},",
                "\"file_origin_releases\":{},\"file_origin_refills\":{},",
                "\"file_alias_installs\":{},\"file_promotions_guest\":{},",
                "\"file_promotions_host\":{},\"file_promotions_mprotect\":{},",
                "\"file_host_write_promotions\":{},\"file_remap_window_pages\":{},",
                "\"file_windows_severed_at_exec\":{},\"file_window_clone_failures\":{},",
                "\"host_access_multi_run\":{},\"host_access_efault_after_runs\":{},",
                "\"host_prepare\":{{\"calls\":{},\"resnapshots\":{},\"steps\":{},\"stale\":{},",
                "\"refused_write\":{},\"refused_read\":{}}},",
                "\"file_cow_fallbacks\":{{\"not_hvf\":{},\"disabled\":{},\"unaligned\":{},",
                "\"rwx\":{},\"no_view\":{},\"not_replace\":{},\"custody\":{},",
                "\"reserved_overlap\":{},\"origin_budget\":{},\"origin_create_failed\":{},",
                "\"replace_teardown\":{},\"window_insert\":{}}}}}"
            ),
            self.origin_space.is_some(),
            objects,
            pages,
            windows,
            alias_refs,
            pending,
            load(&c.window_pages_live),
            load(&c.retired_promoted_live),
            load(&c.mmap_hits),
            load(&c.origin_fill_bytes),
            load(&c.origin_publish_ns_sum),
            load(&c.origin_publish_count),
            load(&c.origin_publish_ns_max),
            load(&c.origin_releases),
            load(&c.origin_refills),
            load(&c.alias_installs),
            load(&c.promotions_guest),
            load(&c.promotions_host),
            load(&c.promotions_mprotect),
            load(&c.host_write_promotions),
            load(&c.remap_window_pages),
            load(&c.windows_severed_at_exec),
            load(&c.window_clone_failures),
            load(&c.host_access_multi_run),
            load(&c.host_access_efault_after_runs),
            load(&c.host_prepare_calls),
            load(&c.host_prepare_resnapshots),
            load(&c.host_prepare_steps),
            load(&c.host_prepare_stale),
            load(&c.host_prepare_refused_write),
            load(&c.host_prepare_refused_read),
            load(&c.fallback_not_hvf),
            load(&c.fallback_disabled),
            load(&c.fallback_unaligned),
            load(&c.fallback_rwx),
            load(&c.fallback_no_view),
            load(&c.fallback_not_replace),
            load(&c.fallback_custody),
            load(&c.fallback_reserved_overlap),
            load(&c.fallback_origin_budget),
            load(&c.fallback_origin_create_failed),
            load(&c.fallback_replace_teardown),
            load(&c.fallback_window_insert),
        );
        out
    }

    /// Per-origin state for `describe_spaces`: gva, pages, windows, alias_refs, state.
    fn describe_file_origins(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let table = FILE_ORIGINS.lock();
        let _ = write!(
            out,
            " file_origins(count={} pages={} pending_release={})=[",
            table.by_key.len(),
            table.pages,
            table.release_candidates.len()
        );
        let mut origins: Vec<&FileOrigin> = table.by_key.values().collect();
        origins.sort_by_key(|origin| core::cmp::Reverse(origin.pages));
        for origin in origins.iter().take(12) {
            let _ = write!(
                out,
                "{:#x}:{}p/w{}/a{}/{:?} ",
                origin.gva, origin.pages, origin.windows, origin.alias_refs, origin.state
            );
        }
        out.push(']');
        out
    }

    /// `PageManagementProvider::describe_guest_page`'s real implementation: one line of
    /// everything this backend knows about `page` under `view` for the opt-in guest-access
    /// fault trace -- the per-view space's own page record ([`HvfAddressSpace::describe_page`]),
    /// how a host access resolves there ([`HvfAddressSpace::host_alias_state`]), W^X-toggle
    /// registration, and [`Self::describe_spaces`] (a divergence or promotion refused for a
    /// `ResourceLimit` leaves the page exactly as the fault found it). Diagnostic only, never on
    /// a hot path.
    pub(crate) fn describe_page_state(&self, view: VmViewId, page: usize) -> String {
        use std::fmt::Write as _;
        let page = page & !(PAGE_SIZE - 1);
        let mut out = String::new();
        match self.existing_space_for_view(view) {
            Some(space) => {
                let _ = write!(
                    out,
                    "{} host_alias_state={:?} fork_write_protected={}",
                    space.describe_page(page),
                    space.host_alias_state(page),
                    space.is_fork_write_protected(page).into_value_unvalidated()
                );
            }
            None => {
                let _ = write!(out, "page={page:#x} view={view:?} space=none");
            }
        }
        let _ = write!(
            out,
            " wx_toggle_region={} {}",
            self.wx_toggle_region_contains(page),
            self.describe_spaces()
        );
        out
    }

    /// The memory manager's resource usage against its limits, plus where the claimed pages
    /// live: every per-view space's own totals, largest first (view id: own claims / aliases /
    /// promoted / retired stash / self-diverged generations), and how many released views are
    /// still waiting for their space to be destroyed -- so a resource-limit refusal can be
    /// attributed to the space, and the fork-COW retention, that holds the pages. Diagnostic
    /// only (the opt-in guest-access fault trace).
    pub(crate) fn describe_spaces(&self) -> String {
        use std::fmt::Write as _;
        let usage = self.memory.usage();
        let limits = self.memory.limits();
        let mut out = String::new();
        let _ = write!(
            out,
            "usage(claimed_pages={}/{} live_data_pages={}/{} host_slots={}/{} table_pages={}/{} address_spaces={}/{} retired_pages={} physical_backing_pages={} pinned_shared_backings={} pending_view_retirement={})",
            usage.claimed_pages,
            limits.max_claimed_pages,
            usage.live_data_pages,
            limits.max_live_data_pages,
            usage.host_slots,
            limits.max_host_slots,
            usage.table_pages,
            limits.max_table_pages,
            usage.address_spaces,
            limits.max_address_spaces,
            usage.retired_pages,
            usage.physical_backing_pages,
            usage.pinned_shared_backings,
            self.pending_view_retirement
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        );
        // A view in `pending_view_retirement` is one whose task already exited and whose space
        // `release_view_space` could not destroy yet -- per space, the three things that refuse
        // `begin_destroy` (a registered vCPU participant, a deferred retirement, a stash entry)
        // are listed so the blocker can be read off directly.
        let pending: std::collections::HashSet<VmViewId> = self
            .pending_view_retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(view, _)| *view)
            .collect();
        // CLASS C: clone the spaces out under a READ lock and sample them outside it -- those
        // methods take `cell.state` / `acknowledgements`, and holding a lock across them is the
        // shape that made this table's own lookup a convoy.
        let live: Vec<(VmViewId, Arc<HvfAddressSpace>)> = self
            .view_spaces
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(view, space)| (*view, Arc::clone(space)))
            .collect();
        let mut spaces: Vec<(VmViewId, bool, usize, usize, [usize; 7])> = live
            .iter()
            .map(|(view, space)| {
                (
                    *view,
                    pending.contains(view),
                    space.participant_count(),
                    space.pending_retirements(),
                    space.page_totals(),
                )
            })
            .collect();
        spaces.sort_by_key(|(_, _, _, _, totals)| core::cmp::Reverse(totals[5] + totals[3] + totals[4]));
        let mut sum = [0usize; 7];
        let mut exited_sum = [0usize; 7];
        let mut exited = 0;
        for (_, is_exited, _, _, totals) in &spaces {
            for (acc, value) in sum.iter_mut().zip(totals.iter()) {
                *acc += value;
            }
            if *is_exited {
                exited += 1;
                for (acc, value) in exited_sum.iter_mut().zip(totals.iter()) {
                    *acc += value;
                }
            }
        }
        let default_totals = self.default_space.page_totals();
        let _ = write!(
            out,
            " spaces={} exited_pending_destroy={} sum(own={} aliases={} promoted={} retired_stash={} generations={} own_mapped={} own_shared={}) exited_sum(own={} retired_stash={} generations={} own_mapped={}) default_space(own={} own_mapped={}) top(view[x=exited]:own/aliases/promoted/retired_stash/generations/own_mapped/own_shared|participants/pending_retirements)=[",
            spaces.len(),
            exited,
            sum[0],
            sum[1],
            sum[2],
            sum[3],
            sum[4],
            sum[5],
            sum[6],
            exited_sum[0],
            exited_sum[3],
            exited_sum[4],
            exited_sum[5],
            default_totals[0],
            default_totals[5]
        );
        for (view, is_exited, participants, pending_retirements, totals) in spaces.iter().take(20) {
            let _ = write!(
                out,
                "{}{}:{}/{}/{}/{}/{}/{}/{}|{}/{} ",
                view.get(),
                if *is_exited { "x" } else { "" },
                totals[0],
                totals[1],
                totals[2],
                totals[3],
                totals[4],
                totals[5],
                totals[6],
                participants,
                pending_retirements
            );
        }
        out.push(']');
        // File-COW state, appended after the pre-existing readout so its parsers stay valid:
        // per space (same order as above) windows/window_pages/file_aliases/retired_promoted,
        // then the origin registry (the origin space's own claims are the origins themselves).
        let file_totals: Vec<(VmViewId, [usize; 4])> = live
            .iter()
            .map(|(view, space)| (*view, space.file_page_totals()))
            .collect();
        let mut file_sum = [0usize; 4];
        for (_, totals) in &file_totals {
            for (acc, value) in file_sum.iter_mut().zip(totals.iter()) {
                *acc += value;
            }
        }
        let _ = write!(
            out,
            " file_cow_sum(windows={} window_pages={} file_aliases={} retired_promoted={}) file_cow_top(view:windows/window_pages/file_aliases/retired_promoted)=[",
            file_sum[0], file_sum[1], file_sum[2], file_sum[3]
        );
        for (view, _, _, _, _) in spaces.iter().take(20) {
            if let Some((_, totals)) = file_totals.iter().find(|(candidate, _)| candidate == view) {
                let _ = write!(
                    out,
                    "{}:{}/{}/{}/{} ",
                    view.get(),
                    totals[0],
                    totals[1],
                    totals[2],
                    totals[3]
                );
            }
        }
        out.push(']');
        if let Some(origin_space) = self.origin_space.as_ref() {
            let origin_totals = origin_space.page_totals();
            let _ = write!(
                out,
                " origin_space(own={} own_mapped={})",
                origin_totals[0], origin_totals[5]
            );
            out.push_str(&self.describe_file_origins());
        }
        out
    }

    /// FIX (hvf-fork-cow-retention-exhausts-live-data-pages): releases the fork-COW retention
    /// `space` keeps for descendants that can no longer resolve it -- preserved self-diverged
    /// generations and `retired_mirrored_pages` stash entries (see
    /// [`HvfAddressSpace::take_self_diverged_shadows`] and [`HvfAddressSpace::reap_retired_stash`]
    /// for the exact precondition: the caller has established that no live descendant still
    /// inherits `space`'s pages by lineage). Each is an ordinary shadow claim by then, unmapped
    /// like any other; bounded per call so a guest `munmap` never stalls on a backlog (the
    /// remainder goes on the next call). Observed live before this existed: 8 GiB of live data
    /// pages consumed in under four minutes of ordinary Chromium desktop use, every fork-COW
    /// divergence and every `execve` image load then failing with `ResourceLimit`, surfacing as
    /// forced `SIGSEGV`s and `EFAULT`s the guest could never recover from. Returns how many
    /// shadow claims were released.
    fn reap_fork_cow_retention(&self, view: Option<VmViewId>, space: &HvfAddressSpace) -> usize {
        // Each shadow unmap is a full narrowing mutation (candidate root, lane kick), so a backlog
        // is worked off across successive calls rather than in one stall.
        const REAP_LIMIT: usize = 256;
        if fork_cow_reap_disabled() {
            return 0;
        }
        let _origin =
            crate::diagnostics_counters::enter_origin(crate::diagnostics_counters::ORIGIN_REAP);
        let mut shadows = space.take_self_diverged_shadows(REAP_LIMIT);
        if shadows.len() < REAP_LIMIT {
            // Adoption publishes each stashed page as a generation, so drain those too.
            let adopted = space.reap_retired_stash(REAP_LIMIT - shadows.len());
            if !adopted.is_empty() {
                shadows.extend(space.take_self_diverged_shadows(REAP_LIMIT));
            }
        }
        shadows.sort_unstable();
        shadows.dedup();
        let mut released = 0;
        for shadow in shadows {
            match self.settle_single_page_mutation(space, MutationKind::Unmap, || {
                space.unmap_range(shadow..shadow + PAGE_SIZE, false)
            }) {
                Ok(_) => released += 1,
                Err(error) => {
                    litebox_util_log::debug!(
                        shadow:? = shadow, view:? = view, error:% = error;
                        "HVF fork-COW: reaping a retained shadow claim failed"
                    );
                }
            }
        }
        if released > 0 {
            let totals = space.page_totals();
            litebox_util_log::debug!(
                released:? = released, view:? = view, own:? = totals[0], retired_stash:? = totals[3],
                generations:? = totals[4], live_data_pages:? = self.memory.usage().live_data_pages;
                "HVF fork-COW: reaped fork-COW retention no live descendant can still resolve"
            );
            // Opt-in trace: a periodic (at most every 10 s) readout of where every live data
            // page is, so growth can be attributed without waiting for a refusal.
            if guest_access_fault_trace() {
                static LAST_READOUT: AtomicU64 = AtomicU64::new(0);
                let now = Instant::now();
                static EPOCH: OnceLock<Instant> = OnceLock::new();
                let elapsed = now.duration_since(*EPOCH.get_or_init(|| now)).as_secs();
                let last = LAST_READOUT.load(Ordering::Relaxed);
                if elapsed >= last + 10
                    && LAST_READOUT
                        .compare_exchange(last, elapsed, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    litebox_util_log::info!(
                        spaces:% = self.describe_spaces();
                        "guest-access fault trace: periodic spaces readout"
                    );
                }
            }
        }
        released
    }

    /// Diverges every page of `range` that `space` still fork-time write-protects
    /// ([`HvfAddressSpace::fork_write_protect_page`]) BEFORE a caller changes `space`'s own
    /// permission there: `update_permissions` (a guest `mprotect`) and `commit_wx_flip_host` (a
    /// W^X-toggle flip) both run ahead of `try_resolve_cow_fault`'s own fault-time resolution, so
    /// either would otherwise re-grant WRITE (or replace the recorded logical permission) on a
    /// page whose fork-instant content a live descendant may still need -- silently reopening
    /// the exact race Mechanism A closes. Self-divergence is always correct here regardless of
    /// whether a live descendant exists (it costs one page copy and preserves the generation
    /// either way), which is why this never needs the shim's own live-descendant query.
    ///
    /// Plan-then-act through [`revalidated_rounds`]: the listing is re-taken after every round
    /// that diverged something, so a page a concurrent fork (another thread) write-protected
    /// while this one's divergences blocked is diverged too, and a page whose divergence failed
    /// is not retried. `true` when the final listing is empty (nothing in `range` is still
    /// protected); a host-side write must not proceed otherwise.
    fn diverge_fork_write_protected_pages(&self, space: &HvfAddressSpace, range: &Range<usize>) -> bool {
        let _origin = crate::diagnostics_counters::enter_origin(
            crate::diagnostics_counters::ORIGIN_FORK_DIVERGE,
        );
        let mut failed: Vec<usize> = Vec::new();
        let remaining = revalidated_rounds(
            HOST_PREPARE_ROUNDS,
            || {
                // CLASS R: settled here, not reported upward by `pass` -- see
                // `prepare_guest_access`'s own snapshot closure for the measured reason (a round
                // spent re-planning is a round not spent diverging, and `is_empty()` below is a
                // judgment that must not be made from a plan the domain has moved on from: a page
                // a concurrent fork write-protected after the listing was taken is absent from it,
                // so the permission change it gates goes ahead undiverged).
                space
                    .settle_gate(GrSite::ForkWriteProtectedPagesIn, || {
                        space.fork_write_protected_pages_in(range)
                    })
                    .0
            },
            |pages| {
                let mut acted = false;
                for &page in pages {
                    if failed.binary_search(&page).is_ok() {
                        continue;
                    }
                    acted = true;
                    if !self.self_diverge_for_host_access(space, page) {
                        if let Err(index) = failed.binary_search(&page) {
                            failed.insert(index, page);
                        }
                    }
                }
                acted
            },
        );
        // `is_empty()` is the judgment: `true` means nothing in `range` is still protected, so the
        // caller's permission change or host write may go ahead. The listing it judges was settled
        // by the snapshot closure above, and it is the one a round had nothing left to diverge in.
        remaining.is_empty()
    }

    /// One self-divergence of `space`'s fork-time write-protected `page` (see
    /// [`Self::diverge_fork_write_protected_pages`]); `true` on success.
    fn self_diverge_for_host_access(&self, space: &HvfAddressSpace, page: usize) -> bool {
        let result = self.settle_single_page_mutation(space, MutationKind::Protect, || {
            space.self_diverge_fork_protected_page(page)
        });
        litebox_util_log::debug!(
            page:? = page, ok:? = result.is_ok();
            "HVF fork-COW: diverged a fork-time write-protected page ahead of a permission change"
        );
        if let Err(error) = &result
            && guest_access_fault_trace()
        {
            litebox_util_log::warn!(
                page:? = page, error:% = error, state:% = space.describe_page(page),
                spaces:% = self.describe_spaces();
                "guest-access fault trace: fork-time write-protected page could not be diverged ahead of a host-side write"
            );
        }
        result.is_ok()
    }

    /// `PageManagementProvider::prepare_guest_access`'s real implementation. A HOST-side access
    /// to `view`'s guest memory (a syscall buffer, exec's argv/envp strings, a signal frame) never
    /// takes the guest's own stage-one translation or permission fault, so the two fork-COW
    /// mechanisms that rely on those faults have to be applied here explicitly, before the
    /// exception-table-backed copy runs:
    ///
    /// * ANCESTOR side (`write` only): a fork-time write-protected page of `view`'s own space
    ///   would otherwise fail the copy outright -- observed live as a `DeliverFault`-forced
    ///   `SIGSEGV` on the forking parent when its child's exit `SIGCHLD` frame was pushed onto a
    ///   stack page Mechanism A had stripped. Resolved by `diverge_fork_write_protected_pages`.
    /// * DESCENDANT side: a lineage-inherited page `view` has not materialized yet resolves, at the
    ///   host, to the process-wide mirror at that GVA -- i.e. whatever slot the ANCESTOR holds
    ///   there NOW, not what `view`'s own guest sees through its alias. That is wrong content once
    ///   the ancestor self-diverged the page (its slot moved to a shadow with no mirror; observed
    ///   live as `execve` returning `EFAULT` inside the mirror teardown/reinstall window), and
    ///   for a write it would land in the ancestor's page instead of `view`'s own. So the page is
    ///   materialized exactly as a guest fault would: an alias is installed if none exists, and
    ///   promoted for a write or whenever the alias's source slot has been relocated. Pages
    ///   promoted here are returned so the caller can publish the divergence into the domain
    ///   (the fault path does that through `EnterShim::cow_custody_publish_divergence`).
    ///
    /// Both sides run as [`revalidated_rounds`] over `host_access_plan` snapshots, and the final,
    /// action-free snapshot is the post-condition: an access whose page still is not usable (see
    /// [`HostPagePreparer::usable`] -- for a write, any host target that is not `view`'s own
    /// page) is refused (`GuestAccessPreparation::refused`, EFAULT to the guest) instead of
    /// performed against an ancestor's or an origin's memory.
    ///
    /// Gated on [`ANY_FORK_VIEW_EVER`] ahead of even resolving the space, exactly like
    /// `resolve_host_redirect`'s own hint, so a never-forking process pays one relaxed load per
    /// host-side access; `ancestor_of` is only consulted for a fork child's own pages.
    pub(crate) fn prepare_guest_access(
        &self,
        view: VmViewId,
        range: Range<usize>,
        write: bool,
        ancestor_of: &dyn Fn(usize) -> Option<VmViewId>,
    ) -> GuestAccessPreparation {
        let mut prepared = GuestAccessPreparation::default();
        if !ANY_FORK_VIEW_EVER.load(Ordering::Relaxed) && !ANY_FILE_WINDOW_EVER.load(Ordering::Relaxed)
        {
            return prepared;
        }
        let Some(space) = self.existing_space_for_view(view) else {
            return prepared;
        };
        let fork_child = space.is_fork_child();
        let has_windows = space.has_file_windows();
        if !fork_child && !has_windows {
            // The ancestor side alone: a forking process's own write-protected pages.
            if write && !self.diverge_fork_write_protected_pages(&space, &range) {
                file_cow_count(&FILE_COW_COUNTERS.host_prepare_refused_write);
                prepared.refused = true;
            }
            return prepared;
        }
        file_cow_count(&FILE_COW_COUNTERS.host_prepare_calls);
        let start = range.start & !(PAGE_SIZE - 1);
        let end = range.end.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut preparer = HostPagePreparer {
            backend: self,
            space: &space,
            view,
            write,
            fork_child,
            ancestors: AncestorCache {
                view,
                ancestor_of,
                cached: None,
            },
            failed: vec![0; (end - start) / PAGE_SIZE],
            promoted: &mut prepared.promoted,
        };
        let mut snapshots = 0u64;
        // Both sides, every page, one snapshot per round (one `cell.state` acquisition and one
        // claims pass for the whole range -- hvf-t1g-remainder-multisecond-service-guest-memory-
        // access-convoy): the per-page `host_alias_state` + `page_kinds` pair used to take the
        // lock twice and scan every claim of the space for each page of every host-side access.
        // A snapshot is only ever acted on in the round that took it (`revalidated_rounds`):
        // T1h's first version walked ONE snapshot through every page's settles, so a sibling
        // thread's fault could alias a later page in between, its install then answered
        // `AddressOverlap`, the page was skipped, and a host write landed in the ancestor's page.
        // CLASS R: each round's plan is SETTLED before the round spends it, and the final snapshot
        // is the one a round had nothing left to do in -- so it is both settled and post-condition.
        //
        // The settle belongs INSIDE the snapshot rather than in `pass` reporting staleness upward:
        // `revalidated_rounds` spends one of its `HOST_PREPARE_ROUNDS` acting rounds on every
        // `true` `pass` returns, so a round spent re-planning is a round not spent preparing, and
        // the budget can run out with the preparation unfinished. Measured on `grs2 stress
        // secs=300 workers=3 pages=8`: with `pass` bailing out (`return true`) on a stale plan the
        // harness reported `iov_wrong_data` 5,042-6,187 (~11-18 % of its host-copy iterations) and
        // the host-copy thread's throughput fell a third; with the settle here, 0.
        //
        // This is a RE-PLAN, never a refusal: the previous pass of this step added a
        // `!judged_ok -> refused` branch, and a refusal is not a re-plan -- it changes what the
        // guest gets instead of asking the domain again.
        let mut last_agreed = true;
        let remaining = revalidated_rounds(
            HOST_PREPARE_ROUNDS,
            || {
                snapshots += 1;
                if gr_stale_skips_round() {
                    let plan = space.host_access_plan(&(start..end));
                    let abandon = space.check_plan(&plan).is_err();
                    last_agreed = !abandon;
                    return RoundPlan {
                        entries: plan.into_value_unvalidated(),
                        abandon,
                    };
                }
                let (entries, agreed) = space.settle_gate(GrSite::HostAccessPlan, || {
                    space.host_access_plan(&(start..end))
                });
                last_agreed = agreed;
                RoundPlan {
                    entries,
                    abandon: false,
                }
            },
            |round| preparer.pass(round),
        );
        if snapshots > 1 {
            FILE_COW_COUNTERS
                .host_prepare_resnapshots
                .fetch_add(snapshots - 1, Ordering::Relaxed);
        }
        if !last_agreed {
            GR_COUNTERS.judged_on_stale_plan.fetch_add(1, Ordering::Relaxed);
        }
        space.check_invariants_range(&(start..end), GrSite::HostAccessBoundary);
        let refused = remaining.entries.iter().find(|entry| !preparer.usable(entry));
        if let Some(entry) = refused {
            file_cow_count(if write {
                &FILE_COW_COUNTERS.host_prepare_refused_write
            } else {
                &FILE_COW_COUNTERS.host_prepare_refused_read
            });
            if guest_access_fault_trace() {
                litebox_util_log::warn!(
                    page:? = entry.page, view:? = view, write:? = write, entry:? = entry,
                    state:% = space.describe_page(entry.page);
                    "guest-access fault trace: host-side access refused: a page could not be prepared for it"
                );
            }
            prepared.refused = true;
        }
        prepared
    }

    /// The host-side counterpart of the guest's terminal window arm, for an untouched window
    /// page no lineage ancestor holds content for: a read installs the origin alias (the copy
    /// then reads the origin mirror through the redirect); a write goes straight to a private
    /// shadow copied out of the origin at the window's own permission (`Exact`), pushed into
    /// `promoted` for custody publication like every other host-side promotion.
    fn prepare_window_page_for_host_access(
        &self,
        space: &HvfAddressSpace,
        view: VmViewId,
        page: usize,
        write: bool,
        promoted: &mut Vec<usize>,
    ) -> HostStepOutcome {
        let Some(origin) = self.origin_space.as_ref() else {
            return HostStepOutcome::NotApplicable;
        };
        let Some(window) = space.settle_gate(GrSite::FileWindowAt, || space.file_window_at(page)).0 else {
            return HostStepOutcome::NotApplicable;
        };
        if window.perms == HvfGuestPermissions::NONE {
            return HostStepOutcome::NotApplicable;
        }
        if write {
            let result = self.settle_single_page_mutation(space, MutationKind::Protect, || {
                space.materialize_file_window_page(origin, page, window.perms)
            });
            return match result {
                Ok(changed) => {
                    if changed {
                        file_cow_count(&FILE_COW_COUNTERS.promotions_host);
                        file_cow_count(&FILE_COW_COUNTERS.host_write_promotions);
                        promoted.push(page);
                    }
                    HostStepOutcome::Acted { ok: true }
                }
                Err(error) => {
                    if guest_access_fault_trace() {
                        litebox_util_log::warn!(
                            page:? = page, view:? = view, error:% = error, state:% = space.describe_page(page);
                            "guest-access fault trace: file window page could not be materialized ahead of a host-side write"
                        );
                    }
                    HostStepOutcome::Acted { ok: false }
                }
            };
        }
        let execute = window.perms.contains(HvfGuestPermissions::EXECUTE)
            || self.wx_toggle_region_contains(page);
        let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
            space.install_file_alias(origin, page, execute)
        });
        match result {
            Ok(_) => HostStepOutcome::Acted { ok: true },
            Err(error) => {
                if matches!(error, HvfMemoryError::AddressOverlap(_)) {
                    file_cow_count(&FILE_COW_COUNTERS.host_prepare_stale);
                } else if guest_access_fault_trace() {
                    litebox_util_log::warn!(
                        page:? = page, view:? = view, error:% = error, state:% = space.describe_page(page);
                        "guest-access fault trace: file window page could not be aliased ahead of a host-side read"
                    );
                }
                HostStepOutcome::Acted { ok: false }
            }
        }
    }

    /// The `mprotect` arm for a run of `FileAlias` or `FileWindow` pages of `space`: a window
    /// page a lineage ancestor holds content for (the parent promoted it before the fork) is
    /// materialized at exactly `guest` from that ancestor, every other window page only has its
    /// window permission recorded (no page is created: Chromium's RELRO `mprotect` over untouched
    /// pages costs nothing); live file aliases are rewritten to `guest & !WRITE` in one root
    /// rewrite (NONE releases them), promoted lazily by the next store.
    fn materialize_file_run(
        &self,
        space: &HvfAddressSpace,
        run: Range<usize>,
        kind: PageKind,
        guest: HvfGuestPermissions,
        requested_execute: bool,
        ancestor_space: &dyn Fn(usize) -> Option<Arc<HvfAddressSpace>>,
    ) -> Result<(), HvfMemoryError> {
        let Some(origin) = self.origin_space.as_ref() else {
            return Err(HvfMemoryError::RangeUnmapped(run));
        };
        let _origin_scope =
            crate::diagnostics_counters::enter_origin(crate::diagnostics_counters::ORIGIN_FILE_COW);
        match kind {
            PageKind::FileWindow => {
                let mut page = run.start;
                while page < run.end {
                    if let Some(ancestor) = ancestor_space(page)
                        && ancestor.has_page_content(page)
                    {
                        self.settle_single_page_mutation(space, MutationKind::Protect, || {
                            space.materialize_page_with_permissions(Some(&ancestor), page, guest)
                        })?;
                        file_cow_count(&FILE_COW_COUNTERS.promotions_mprotect);
                    }
                    page += PAGE_SIZE;
                }
                space.set_file_window_perms(&run, guest)?;
                if requested_execute {
                    // The shim invalidates the host instruction cache over the whole range right
                    // after any `mprotect` that asked for EXEC succeeds (RWX included, whose
                    // logical `guest` is READ|WRITE under the W^X toggle), through the raw GVAs:
                    // every page must be host-readable there, which an untouched window page only
                    // is once its alias (with the origin's host view) exists. The alias carries
                    // EXECUTE only when the guest permission does; in a toggle region the lazy
                    // flip installs it. `AddressOverlap` is a page the loop above materialized,
                    // or a concurrent fault already aliased.
                    let execute = guest.contains(HvfGuestPermissions::EXECUTE);
                    let mut page = run.start;
                    while page < run.end {
                        let installed =
                            self.settle_single_page_mutation(space, MutationKind::Map, || {
                                space.install_file_alias(origin, page, execute)
                            });
                        if let Err(error) = installed
                            && !matches!(error, HvfMemoryError::AddressOverlap(_))
                        {
                            litebox_util_log::debug!(
                                page:? = page, error:% = error;
                                "HVF file COW: executable window page could not be aliased ahead of the icache invalidation"
                            );
                        }
                        page += PAGE_SIZE;
                    }
                }
                Ok(())
            }
            PageKind::FileAlias => {
                space.set_file_window_perms(&run, guest)?;
                if space.reprotect_file_aliases(origin, &run, guest)? {
                    self.kick_running_lanes_in(space);
                }
                Ok(())
            }
            _ => Err(HvfMemoryError::RangeUnmapped(run)),
        }
    }

    /// GSIGSEGV2: this thread's consecutive attempts to service ONE fault, identified by
    /// `(page, translation_generation)` -- never by the page alone.
    ///
    /// Both arms below ([`Self::try_resolve_cow_fault`]'s `page_writable_now` resume and
    /// [`Self::try_repair_own_page`]) are unconditionally correct while their own precondition
    /// holds: a write permission fault against a page that is writable in this space's CURRENT
    /// mapping was taken through a translation older than that mapping, so re-executing it is
    /// the only right answer. On a page every thread writes and every fork re-write-protects --
    /// a process's shared BSS counter page -- that situation is ROUTINE and self-healing
    /// (measured live on the standing `race-stress/grs2 stress`: 857564 of 2115955 raw exception
    /// exits were stale-view reruns, ~1000/s).
    ///
    /// Keying the bound on the page alone (what both arms did before) counted EVERY transient
    /// stale fault this thread ever took on that page, not one fault's retries. That total passes
    /// the bound within seconds and then stays past it for the rest of the process's life --
    /// nothing ever decrements it -- permanently disabling BOTH transparent recovery arms for
    /// that `(thread, page)`. Every later, entirely benign fault then fell through to the shim,
    /// whose own consecutive-fault bound finally turned it into a real, fatal SIGSEGV. That is
    /// the standing gate's death at ~700-1200 s with every integrity counter at zero; measured
    /// live at the fatal instant, `attempts=76` against a bound of 16, on a page whose live
    /// stage-one descriptor read `ap=RW`, whose stage-two authority was `Writer` and whose
    /// `writable_now` was `true` -- i.e. a healthy page the guest had merely faulted on stale.
    ///
    /// Keying on the translation generation the fault was taken against (`snapshot`'s
    /// `pending_tlbi_generation`) makes the count mean what its bound claims: retries of the one
    /// translation this fault was actually taken through. A fault taken after the space moved on
    /// is a different fault and starts a fresh, bounded allowance; a genuine livelock -- the same
    /// stale translation faulting over and over with nothing moving -- still reaches the bound and
    /// still surfaces loudly.
    fn fault_repeat_count(
        slot: &'static std::thread::LocalKey<core::cell::Cell<(usize, u64, u32)>>,
        page: usize,
        translation_generation: u64,
    ) -> u32 {
        slot.try_with(|cell| {
            let (last_page, last_generation, count) = cell.get();
            let count = if last_page == page && last_generation == translation_generation {
                count.saturating_add(1)
            } else {
                1
            };
            cell.set((page, translation_generation, count));
            count
        })
        .unwrap_or(u32::MAX)
    }

    /// Consulted after `classify_wx_fault` declines a direct-guest abort: services the fork-COW
    /// events a per-view space's own physical emptiness produces, which `classify_wx_fault` is
    /// not shaped for -- a translation fault against a page this view's family logically owns via
    /// lineage but `space` has no physical mapping for yet (installs a read-only alias onto the
    /// ancestor's own content), and a write OR execute permission fault against a page `space` has
    /// already aliased that way (promotes it to an independent copy, deriving the result
    /// permission from the W^X toggle's own lazy model when the page is one of its registered
    /// regions -- see `promote_cow_alias`'s own doc comment).
    ///
    /// Returns `true` if it served the fault (the guest should resume), `false` if this is not
    /// this mechanism's fault to resolve -- the caller falls through to ordinary signal delivery
    /// exactly as before this mechanism existed, matching `classify_wx_fault`'s own "not mine"
    /// idiom. Unlike the WX toggle this commits directly rather than splitting into a separate
    /// classify/shim-revalidate/commit trio: the only cross-shim step is the read-only lineage
    /// query (`EnterShim::cow_custody_ancestor`), and `install_cow_read_alias`/
    /// `promote_cow_alias` each already re-check their own space's live alias state immediately
    /// before committing.
    fn try_resolve_cow_fault(
        &self,
        space: &HvfAddressSpace,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        view: Option<VmViewId>,
        class: u64,
        far: u64,
        esr: u64,
        // GSIGSEGV2: this fault's own translation identity -- the `pending_tlbi_generation` of
        // the snapshot the faulting run was attached with. Only used to key the two
        // stale-translation retry bounds ([`Self::fault_repeat_count`]).
        translation_generation: u64,
    ) -> bool {
        if !matches!(class, EC_INSTRUCTION_ABORT_LOWER_EL | EC_DATA_ABORT_LOWER_EL) {
            return false;
        }
        let Some(view) = view else {
            return false;
        };
        let Ok(far) = usize::try_from(far) else {
            return false;
        };
        let _origin = crate::diagnostics_counters::enter_origin(
            crate::diagnostics_counters::ORIGIN_FORK_COW_FAULT,
        );
        let page = far & !(PAGE_SIZE - 1);
        space.check_invariants_range(&(page..page + PAGE_SIZE), GrSite::FaultBoundary);
        if page == SIGRETURN_TRAMPOLINE_GVA || self.vdso.contains(&page) {
            // The trampoline's and the vDSO pages' permanent aliases are installed once, at
            // space creation, never torn down or promoted -- a stray write there must keep
            // faulting for real, exactly as it did before this mechanism existed.
            // T1f-a: a fault this path declines by construction (`fault_arms.declined`).
            crate::diagnostics_counters::record_fault_arm(
                crate::diagnostics_counters::FAULT_ARM_DECLINED,
                false,
                space.id(),
                page,
            );
            return false;
        }
        let is_write_permission_fault = class == EC_DATA_ABORT_LOWER_EL
            && esr & ESR_WNR != 0
            && esr & ESR_FSC_PERMISSION_FAULT_MASK == ESR_FSC_PERMISSION_FAULT;
        // A first-ever EXECUTE of an inherited, not-yet-independently-claimed page is a
        // permission fault exactly like the write case above -- the alias `install_cow_read_alias`
        // installed has whatever permission `source` had at aliasing time, minus WRITE only, so a
        // page the ancestor never flipped to executable (or flipped back to writable) faults here
        // on first execute, with no promotion path before this arm existed.
        let is_execute_permission_fault = class == EC_INSTRUCTION_ABORT_LOWER_EL
            && esr & ESR_FSC_PERMISSION_FAULT_MASK == ESR_FSC_PERMISSION_FAULT;
        if is_write_permission_fault || is_execute_permission_fault {
            // GENERAL FIX (general-fork-time-ancestor-write-protection-for-the-per-view-hvf):
            // checked ahead of the existing `is_cow_aliased` branch below, which handles a
            // DESCENDANT diverging from an ancestor -- this is the symmetric case, an ANCESTOR
            // (`space` itself) taking a permission fault on its OWN page after `space` fork-time
            // write-protected it (`Platform::fork_time_ancestor_protect`, wired into
            // `do_process_clone`).
            let (protected, _) = space.settle_gate(GrSite::IsForkWriteProtected, || {
                space.is_fork_write_protected(page)
            });
            if protected {
                // FIX (chromium-zygote-stack-slot-reuse-stale-cow-alias-ping-corruption): always
                // self-diverge here, never `restore_fork_write_protected_page` -- this permission
                // fault is `space`'s own next write to a page ITS OWN prior fork protected, i.e.
                // exactly the write immediately preceding `space`'s own NEXT fork.
                // `fork_family_has_live_descendant` can only answer whether a PAST descendant is
                // still alive right now; it cannot know whether the descendant about to be
                // created FROM THIS VERY WRITE will need the content this write is about to
                // overwrite -- a genuine TOCTOU once every prior descendant has already exited (a
                // single long-lived descendant, such as a real GPU-type child that survives
                // several seconds, provides no cover at all once it is gone; a short-lived
                // descendant that crashes near-instantly on a stale read never provides cover
                // either, which sustains the false "no live descendant" reading for every
                // following fork once it first fires). `diverge_fork_write_protected_pages`
                // (this same file, `prepare_guest_access`'s own ancestor-side helper for the
                // host-side write case) already establishes that self-divergence is
                // unconditionally correct here regardless of live-descendant status -- it costs
                // one page copy and preserves the generation either way -- and deliberately never
                // consults this same query; this call site now matches it instead of trusting the
                // live-descendant reading for a decision it cannot safely answer.
                let result = self.settle_single_page_mutation(space, MutationKind::Protect, || {
                    space.self_diverge_fork_protected_page(page)
                });
                crate::diagnostics_counters::record_fault_arm(
                    crate::diagnostics_counters::FAULT_ARM_SELF_DIVERGE,
                    result.is_ok(),
                    space.id(),
                    page,
                );
                litebox_util_log::debug!(
                    page:? = page, view:? = view, ok:? = result.is_ok();
                    "HVF fork-COW fault: resolved a fork-time ancestor write-protection fault"
                );
                if let Err(error) = &result
                    && guest_access_fault_trace()
                {
                    litebox_util_log::warn!(
                        page:? = page, view:? = view, far:? = far, esr:? = esr, error:% = error,
                        state:% = space.describe_page(page), spaces:% = self.describe_spaces();
                        "guest-access fault trace: guest write to its own fork-time write-protected page could not be diverged"
                    );
                }
                if result.is_ok() {
                    // FIX (chromium-zygote-stack-slot-reuse-stale-cow-alias-ping-corruption): a
                    // page that reaches this branch at all was, by construction, WRITE-eligible in
                    // `space` at the moment `fork_write_protect_range` protected it -- but that
                    // does not mean `space`'s own family ever published custody for it: a page
                    // `space` claimed directly (never inherited via `promote_cow_alias` from a
                    // further ancestor -- e.g. a fresh post-exec stack slot `space` itself is the
                    // very first owner of) never runs through the ONE pre-existing publish call
                    // site below (the `is_cow_aliased` branch), so `space`'s own family map can
                    // stay permanently `Unclaimed` for it there -- every descendant's own
                    // `cow_custody_ancestor` lineage walk then skips straight past `space` to
                    // whatever `space`'s own (possibly pre-exec, semantically unrelated) ancestor
                    // happens to hold at the same numeric address, or finds nothing at all, and the
                    // fault falls through to the generic (non-COW) page-fault path's own zero-fill
                    // instead of a real alias onto `space`'s actual content. Publishing here, on
                    // every successful self-divergence of `space`'s own repeatedly-reused page,
                    // closes that gap exactly like the `is_cow_aliased` branch's own long-standing
                    // `cow_custody_publish_divergence` call already does for a descendant's own
                    // divergence -- reusing that SAME already-gated (on
                    // `family_has_live_descendant_of`) primitive, not a new one.
                    shim.cow_custody_publish_divergence(view, page..page + PAGE_SIZE);
                }
                return result.is_ok();
            }
            // The page is writable in this space's current mapping: this fault was taken through
            // a translation that predates a sibling thread's self-divergence of the page's
            // fork-time protection (each divergence re-checks and drops the protection inside its
            // own commit -- T1h fix-up -- so the siblings that faulted on it find it resolved
            // rather than diverging it again and losing each other's writes). Resuming
            // re-attaches onto the current root. Bounded per thread and per translation, so a
            // page that keeps faulting under one unchanged stale translation still surfaces as a
            // real fault -- see [`Self::fault_repeat_count`] for why the bound is keyed on the
            // fault's own translation, not on the page.
            let (writable_now, _) =
                space.settle_gate(GrSite::PageWritableNow, || space.page_writable_now(page));
            if is_write_permission_fault && writable_now {
                const WRITABLE_NOW_RESUME_LIMIT: u32 = 64;
                let resumes = Self::fault_repeat_count(
                    &WRITABLE_NOW_RESUMES,
                    page,
                    translation_generation,
                );
                if resumes <= WRITABLE_NOW_RESUME_LIMIT {
                    return true;
                }
            }
            // A file alias (a read-only stage-1 alias onto a shared file origin page), ahead of
            // the lineage gate below: a write promotes it to a private shadow copied out of the
            // origin (never into it); refused -- a real SIGSEGV -- when the window lacks WRITE
            // and no W^X toggle region covers the page. An execute permission fault cannot be
            // this alias's (its descriptor carries EXECUTE whenever the window does) unless the
            // page sits in a toggle region, whose lazy flip already declined above; then the
            // promotion lands in the execute direction like a lineage alias's would.
            let (file_aliased, _) =
                space.settle_gate(GrSite::IsFileAliased, || space.is_file_aliased(page));
            if file_aliased {
                let Some(origin) = self.origin_space.as_ref() else {
                    return false;
                };
                let target = if self.wx_toggle_region_contains(page) {
                    PromoteTarget::WxToggle(is_execute_permission_fault)
                } else if is_execute_permission_fault {
                    return false;
                } else {
                    PromoteTarget::Inherit
                };
                let result = self.settle_single_page_mutation(space, MutationKind::Protect, || {
                    space.promote_file_alias(origin, page, target)
                });
                crate::diagnostics_counters::record_fault_arm(
                    crate::diagnostics_counters::FAULT_ARM_FILE_PROMOTE,
                    result.is_ok(),
                    space.id(),
                    page,
                );
                litebox_util_log::debug!(
                    page:? = page, view:? = view, ok:? = result.is_ok(), target:? = target;
                    "HVF file COW fault: promoted a file alias after a permission fault"
                );
                match &result {
                    Ok(_) => {
                        file_cow_count(&FILE_COW_COUNTERS.promotions_guest);
                        shim.cow_custody_publish_divergence(view, page..page + PAGE_SIZE);
                    }
                    Err(error) => {
                        if guest_access_fault_trace()
                            && !matches!(error, HvfMemoryError::Witness(_))
                        {
                            litebox_util_log::warn!(
                                page:? = page, view:? = view, far:? = far, esr:? = esr, error:% = error,
                                state:% = space.describe_page(page);
                                "guest-access fault trace: guest permission fault on a file alias could not be promoted"
                            );
                        }
                    }
                }
                return result.is_ok();
            }
            let (cow_aliased, _) =
                space.settle_gate(GrSite::IsCowAliased, || space.is_cow_aliased(page));
            if !cow_aliased {
                return self.try_repair_own_page(space, view, page, translation_generation);
            }
            let Some(ancestor_view) = shim.cow_custody_ancestor(view, page) else {
                return self.try_repair_own_page(space, view, page, translation_generation);
            };
            let Some(ancestor) = self.existing_space_for_view(ancestor_view) else {
                return self.try_repair_own_page(space, view, page, translation_generation);
            };
            // `None` (the ordinary, non-W^X-toggle path) unless `page` is inside one of the W^X
            // toggle's own registered regions, in which case the promotion must derive its
            // resulting permission from which direction actually faulted here rather than from
            // `source`'s current, ephemeral R+W-vs-R+X hardware permission -- see
            // `promote_cow_alias`'s own doc comment.
            let wx_toggle_want_execute = self
                .wx_toggle_region_contains(page)
                .then_some(is_execute_permission_fault);
            let result = self.settle_single_page_mutation(space, MutationKind::Protect, || {
                space.promote_cow_alias(&ancestor, page, wx_toggle_want_execute)
            });
            crate::diagnostics_counters::record_fault_arm(
                crate::diagnostics_counters::FAULT_ARM_COW_PROMOTE,
                result.is_ok(),
                space.id(),
                page,
            );
            litebox_util_log::debug!(
                page:? = page, ancestor_view:? = ancestor_view, ok:? = result.is_ok(),
                execute:? = is_execute_permission_fault, wx_toggle:? = wx_toggle_want_execute.is_some();
                "HVF fork-COW fault: promoted an aliased page after a permission fault"
            );
            if let Err(error) = &result
                && guest_access_fault_trace()
            {
                litebox_util_log::warn!(
                    page:? = page, view:? = view, ancestor_view:? = ancestor_view, far:? = far,
                    esr:? = esr, error:% = error, state:% = space.describe_page(page);
                    "guest-access fault trace: guest permission fault on an aliased page could not be promoted"
                );
            }
            if result.is_ok() {
                // `space`'s own first divergence of `page` (this promotion): publish it into
                // `space`'s own family's custody map so a later fork's own grandchild-lineage walk
                // resolves to `space`, not the stale ancestor it aliased from -- see
                // `EnterShim::cow_custody_publish_divergence`'s own doc comment for the gating this
                // is deliberately left to the shim to apply.
                shim.cow_custody_publish_divergence(view, page..page + PAGE_SIZE);
            }
            return result.is_ok();
        }
        if esr & ESR_FSC_TRANSLATION_FAULT_MASK != ESR_FSC_TRANSLATION_FAULT {
            // T1f-a: neither a permission fault this path handles nor a translation fault: not
            // ours to resolve (`fault_arms.declined`).
            crate::diagnostics_counters::record_fault_arm(
                crate::diagnostics_counters::FAULT_ARM_DECLINED,
                false,
                space.id(),
                page,
            );
            return false;
        }
        let (any_aliased, _) =
            space.settle_gate(GrSite::IsAnyAliased, || space.is_any_aliased(page));
        if any_aliased {
            // Already aliased, lineage or file (a concurrent fault on the same page already
            // installed it): resume and re-execute against the alias that is already there.
            crate::diagnostics_counters::record_fault_arm(
                crate::diagnostics_counters::FAULT_ARM_ALREADY_ALIASED,
                true,
                space.id(),
                page,
            );
            return true;
        }
        // FIX (chromium-zygote-stack-slot-reuse-stale-cow-alias-ping-corruption): try this fork
        // child's own REAL, immediate ancestor first, straight from the HVF layer's own
        // `fork_origin` (see `HvfAddressSpace::direct_fork_parent`'s own doc comment) -- accurate
        // unconditionally, with no dependency on whatever the shim's own domain-mediated
        // `cow_custody_ancestor` lineage walk below currently has published for an intermediate
        // family. Only a fault this cannot resolve (the direct parent itself never claimed this
        // page -- a genuinely deeper lineage, or a non-fork-related mapping) falls through to that
        // pre-existing path, completely unchanged.
        if let Some(direct_parent) = space.direct_fork_parent() {
            let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
                space.install_cow_read_alias(&direct_parent, page)
            });
            crate::diagnostics_counters::record_fault_arm(
                crate::diagnostics_counters::FAULT_ARM_COW_ALIAS_DIRECT,
                result.is_ok(),
                space.id(),
                page,
            );
            litebox_util_log::debug!(
                page:? = page, view:? = view, ok:? = result.is_ok();
                "HVF fork-COW fault: installed a read alias directly from this view's own fork parent"
            );
            if result.is_ok() {
                return true;
            }
            // GSIGSEGV: the source itself may be the reason this could not be aliased -- see
            // [`Self::repair_source_then_alias`].
            if self.repair_source_then_alias(&direct_parent, space, page) {
                return true;
            }
        }
        let custody_ancestor = shim
            .cow_custody_ancestor(view, page)
            .and_then(|ancestor_view| {
                self.existing_space_for_view(ancestor_view)
                    .map(|ancestor| (ancestor_view, ancestor))
            });
        if let Some((ancestor_view, ancestor)) = custody_ancestor.as_ref() {
            let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
                space.install_cow_read_alias(ancestor, page)
            });
            crate::diagnostics_counters::record_fault_arm(
                crate::diagnostics_counters::FAULT_ARM_COW_ALIAS_CUSTODY,
                result.is_ok(),
                space.id(),
                page,
            );
            litebox_util_log::debug!(
                page:? = page, ancestor_view:? = ancestor_view, ok:? = result.is_ok(),
                error:? = result.as_ref().err().map(|error| error.to_string());
                "HVF fork-COW fault: installed a read alias for a lineage-inherited page"
            );
            if result.is_ok() {
                return true;
            }
            // GSIGSEGV: same as the direct-parent arm above -- `ancestor`'s own copy of `page`
            // may be the thing that is missing, not anything about `space`.
            if self.repair_source_then_alias(ancestor, space, page) {
                return true;
            }
        }
        // Terminal arm, after every lineage arm (a grandparent's pre-fork promotion of a window
        // page must win over the origin): a page inside one of this space's file windows aliases
        // the shared origin page read-only.
        let aliased = self.install_window_alias_for_fault(
            space,
            view,
            page,
            custody_ancestor.as_ref().map(|(_, ancestor)| ancestor.as_ref()),
        );
        // T1f-a: the file-window arm, the last of the fault arms (F1's fault-around target).
        crate::diagnostics_counters::record_fault_arm(
            crate::diagnostics_counters::FAULT_ARM_FILE_ALIAS,
            aliased,
            space.id(),
            page,
        );
        if aliased {
            return true;
        }
        // GSIGSEGV: the terminal repair arm, after every lineage/file arm has declined. See
        // [`Self::try_repair_own_page`].
        self.try_repair_own_page(space, view, page, translation_generation)
    }

    /// GSIGSEGV: the same repair as [`Self::try_repair_own_page`], applied to the *source* of a
    /// COW read alias instead of to the faulting space.
    ///
    /// [`HvfAddressSpace::install_cow_read_alias`] fails closed with
    /// `Witness("COW alias source page has no stage-two mapping")` whenever the ancestor's own
    /// copy of `page` has lost its stage-2 translation -- the exact state
    /// [`HvfAddressSpace::own_page_repair_target`] detects. Left alone that is unrecoverable for
    /// the descendant as well as for the owner: the ancestor's content is the only source the
    /// descendant can ever read, and every later fault takes the identical path. Measured live
    /// (`fault_arms.cow_alias_custody err`) during the standing `race-stress/grs stress` gate.
    /// Reinstall the ancestor's own page from its own claim, then retry the alias once.
    fn repair_source_then_alias(
        &self,
        source: &HvfAddressSpace,
        space: &HvfAddressSpace,
        page: usize,
    ) -> bool {
        let Some(target) = source.own_page_repair_target(page) else {
            return false;
        };
        let repaired = self.settle_single_page_mutation(source, MutationKind::Map, || {
            source.protect_range(page..page + PAGE_SIZE, target)
        });
        crate::diagnostics_counters::record_fault_arm(
            crate::diagnostics_counters::FAULT_ARM_REPAIR_OWN,
            repaired.is_ok(),
            source.id(),
            page,
        );
        if repaired.is_err() {
            if let Err(error) = &repaired
                && guest_access_fault_trace()
            {
                litebox_util_log::warn!(
                    page:? = page, source:? = source.id(), target:? = target, error:% = error,
                    state:% = source.describe_page(page);
                    "guest-access fault trace: a COW alias source page could not be reinstalled"
                );
            }
            return false;
        }
        let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
            space.install_cow_read_alias(source, page)
        });
        litebox_util_log::debug!(
            page:? = page, source:? = source.id(), target:? = target, ok:? = result.is_ok();
            "HVF fork-COW fault: reinstalled a COW alias source page and retried the alias"
        );
        result.is_ok()
    }

    /// GSIGSEGV: the terminal repair arm for a guest fault no other arm could resolve.
    ///
    /// A page can end up logically owned -- the guest's `Vmem` covers it, so the shim classifies
    /// a fault there as `SEGV_ACCERR` and the domain still shows this view's own custody -- while
    /// physically unusable: no stage-2 translation at all, or one installed at an authority that
    /// is not the permission this space's own claim records. Nothing in the fault chain could
    /// ever fix that: every arm above needs a lineage ancestor, a file window or an alias, and a
    /// plain anonymous private page has none of those, and
    /// [`HvfAddressSpace::atomically_diverge_claimed_page`] refuses a page with no mapping
    /// outright. The only outcome was `MacOsUserland::handle_page_fault` resuming the guest into
    /// the identical fault `PAGE_FAULT_FALLBACK_RETRY_LIMIT` times and then delivering a real,
    /// fatal `SIGSEGV` -- which is exactly what ended the standing `race-stress/grs stress` gate
    /// at ~700-1200 s in every arm, with every integrity counter at zero.
    ///
    /// Reinstalling the claim's own recorded permission (read-only while a fork-time
    /// write-protection is still in force, so a live descendant's COW content is untouched) is
    /// what the page was always supposed to carry. It is deliberately a no-op -- `None` from
    /// [`HvfAddressSpace::own_page_repair_target`] -- whenever the hardware already agrees, so
    /// this can never replace the bounded, loud failure with an unbounded resume loop.
    ///
    /// GSIGSEGV2: that no-op case is not a malfunction, it is the common one. A fault that no arm
    /// could explain while the claim already records the very permission the hardware carries is
    /// a fault taken through a translation older than this space's current mapping -- and this
    /// arm is then just the resume that re-attaches onto the current root. So its bound has to
    /// count attempts against ONE translation, exactly like [`Self::fault_repeat_count`] says;
    /// counted per page alone it disarmed this arm for the rest of the process after the first
    /// sixteen faults of any kind on the process's hottest page.
    fn try_repair_own_page(
        &self,
        space: &HvfAddressSpace,
        view: VmViewId,
        page: usize,
        translation_generation: u64,
    ) -> bool {
        // A W^X toggle region legitimately carries R+X while its claim records R+W, and the
        // toggle's own lazy flip is the only thing allowed to decide that direction.
        if space.settle_gate(GrSite::IsAnyAliased, || space.is_any_aliased(page)).0
            || space.settle_gate(GrSite::IsFileAliased, || space.is_file_aliased(page)).0
            || self.wx_toggle_region_contains(page)
        {
            return false;
        }
        // A repair that succeeds but changes nothing the guest can observe would otherwise be
        // an unbounded resume loop -- the one thing the bounded-refuse fallback exists to
        // prevent. Bound it per thread and per translation like `try_resolve_cow_fault`'s own
        // `WRITABLE_NOW_RESUME_LIMIT`: a handful of genuine repairs on one fault, then the
        // ordinary loud `SIGSEGV` backstop.
        const REPAIR_RESUME_LIMIT: u32 = 16;
        let attempts =
            Self::fault_repeat_count(&REPAIR_RESUMES, page, translation_generation);
        if attempts > REPAIR_RESUME_LIMIT {
            if guest_access_fault_trace() {
                litebox_util_log::warn!(
                    page:? = page, view:? = view, attempts:% = attempts,
                    state:% = space.describe_page(page);
                    "guest-access fault trace: own-page repair gave up after its bounded attempts"
                );
            }
            return false;
        }
        let Some(target) = space.own_page_repair_target(page) else {
            if guest_access_fault_trace() {
                litebox_util_log::warn!(
                    page:? = page, view:? = view, attempts:% = attempts,
                    state:% = space.describe_page(page);
                    "guest-access fault trace: own-page repair has no target for this page"
                );
            }
            return false;
        };
        if guest_access_fault_trace() {
            litebox_util_log::warn!(
                page:? = page, view:? = view, attempts:% = attempts, target:? = target,
                before:% = space.describe_page(page);
                "guest-access fault trace: own-page repair attempt"
            );
        }
        let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
            space.protect_range(page..page + PAGE_SIZE, target)
        });
        let ok = result.is_ok();
        crate::diagnostics_counters::record_fault_arm(
            crate::diagnostics_counters::FAULT_ARM_REPAIR_OWN,
            ok,
            space.id(),
            page,
        );
        litebox_util_log::debug!(
            page:? = page, view:? = view, target:? = target, ok:? = ok,
            error:? = result.as_ref().err().map(|error| error.to_string());
            "HVF fault: reinstalled a page this space owns but could not execute against"
        );
        if guest_access_fault_trace() {
            litebox_util_log::warn!(
                page:? = page, view:? = view, attempts:% = attempts, target:? = target, ok:? = ok,
                after:% = space.describe_page(page);
                "guest-access fault trace: own-page repair attempt result"
            );
        }
        if let Err(error) = &result
            && guest_access_fault_trace()
        {
            litebox_util_log::warn!(
                page:? = page, view:? = view, target:? = target, error:% = error,
                state:% = space.describe_page(page);
                "guest-access fault trace: a page this space owns could not be reinstalled"
            );
        }
        ok
    }

    /// The translation-fault window arm: installs `page`'s read-only alias onto its window's
    /// origin page (EXECUTE included whenever the window is executable or a W^X toggle region
    /// covers the page). A missing window record (the fork-time clone silently skipped it, see
    /// `fork_time_ancestor_protect`) falls back one hop to the custody ancestor's own record,
    /// counted and warned. `AddressOverlap` means a concurrent same-page fault won: resume.
    fn install_window_alias_for_fault(
        &self,
        space: &HvfAddressSpace,
        view: VmViewId,
        page: usize,
        custody_ancestor: Option<&HvfAddressSpace>,
    ) -> bool {
        let Some(origin) = self.origin_space.as_ref() else {
            return false;
        };
        let (window, _) = space.settle_gate(GrSite::FileWindowAt, || space.file_window_at(page));
        let window = match window {
            Some(window) => window,
            None => {
                // The one-hop fallback reads the ANCESTOR's window record; it is settled against
                // the ANCESTOR's own domain, but whether that domain moved is not checked here
                // (remainder: it needs a cross-space plan).
                let Some(window) = custody_ancestor.and_then(|ancestor| {
                    ancestor
                        .settle_gate(GrSite::FileWindowAt, || ancestor.file_window_at(page))
                        .0
                }) else {
                    return false;
                };
                file_cow_count(&FILE_COW_COUNTERS.window_clone_failures);
                litebox_util_log::warn!(
                    page:? = page, view:? = view;
                    "HVF file COW: window record missing in the fork child; resolved one hop through the custody ancestor's window"
                );
                // A one-page record of its own so the alias, its later promotion and its unmap
                // all account against the same origin.
                let installed = space.install_file_window(
                    page..page + PAGE_SIZE,
                    window.key,
                    window.origin_page(page),
                    window.perms,
                );
                if installed.is_err() {
                    return false;
                }
                file_origin_adjust(window.key, 1, 0);
                FileWindow {
                    start: page,
                    end: page + PAGE_SIZE,
                    key: window.key,
                    origin_gva: window.origin_page(page),
                    perms: window.perms,
                }
            }
        };
        if window.perms == HvfGuestPermissions::NONE {
            return false;
        }
        let execute = window.perms.contains(HvfGuestPermissions::EXECUTE)
            || self.wx_toggle_region_contains(page);
        let around = fault_around_pages();
        let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
            // T1f-b F1: alias the faulting page together with up to `around - 1` following pages
            // of the same window, in one stage-1 rewrite. The execute bit is asked per page, so a
            // W^X toggle region that covers only part of the window cannot leak EXECUTE onto a
            // page a fault there would not have given it.
            space.install_file_alias_around(origin, page, |candidate| {
                window.perms.contains(HvfGuestPermissions::EXECUTE)
                    || self.wx_toggle_region_contains(candidate)
            }, around)
        });
        litebox_util_log::debug!(
            page:? = page, view:? = view, execute, ok:? = result.is_ok(),
            error:? = result.as_ref().err().map(|error| error.to_string());
            "HVF file COW fault: installed a read alias onto the shared file origin"
        );
        match result {
            Ok(_) => true,
            Err(HvfMemoryError::AddressOverlap(_)) => true,
            Err(error) => {
                if guest_access_fault_trace() {
                    litebox_util_log::warn!(
                        page:? = page, view:? = view, error:% = error, state:% = space.describe_page(page);
                        "guest-access fault trace: file window page could not be aliased"
                    );
                }
                false
            }
        }
    }

    fn start_lane_maintenance(&'static self) -> Result<(), HvfBackendError> {
        let mut owner = self
            .lane_maintenance
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owner.is_some() {
            return Err(HvfBackendError::LanePoolCorrupt { index: usize::MAX });
        }
        match std::thread::Builder::new()
            .name("litebox-hvf-lane-maintenance".to_owned())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.lane_maintenance_loop();
                }));
                if outcome.is_err() {
                    self.fail_lane_pool(LaneReplacementFailure {
                        index: usize::MAX,
                        generation: 0,
                        stage: "running lane maintenance",
                    });
                }
            }) {
            Ok(thread) => {
                *owner = Some(thread);
                Ok(())
            }
            Err(error) => {
                drop(owner);
                self.fail_lane_pool(LaneReplacementFailure {
                    index: usize::MAX,
                    generation: 0,
                    stage: "starting lane maintenance",
                });
                Err(HvfBackendError::LaneMaintenanceThread(error))
            }
        }
    }

    fn request_lane_maintenance(&self) {
        let mut requested = self
            .lane_maintenance
            .requested
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *requested = true;
        drop(requested);
        self.lane_maintenance.wake.notify_one();
    }

    fn retiring_lane_count(&self) -> usize {
        self.free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retiring
    }

    #[track_caller]
    fn lane_maintenance_loop(&'static self) {
        loop {
            // CLASS A: `Condvar::wait` consumes a plain `MutexGuard`, so this lock is taken
            // through the ranked wrapper's own condvar wait -- `wait_on` releases the rank for
            // the park (which is what `Condvar::wait` does to the mutex) and re-takes it on
            // return, so "parked on the maintenance condvar while holding something else" is
            // still a named violation and the park itself is not a false positive.
            let mut requested = self
                .lane_maintenance
                .requested
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*requested {
                requested = self
                    .lane_maintenance
                    .requested
                    .wait_on(&self.lane_maintenance.wake, requested)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            *requested = false;
            drop(requested);
            while self.retiring_lane_count() != 0 {
                let mut progressed = false;
                for index in 0..self.lanes.len() {
                    match self.repair_retired_lane(index) {
                        Ok(repaired) => progressed |= repaired,
                        Err(error) => {
                            litebox_util_log::error!(
                                index:? = error.failure.index,
                                generation:? = error.failure.generation,
                                stage:? = error.failure.stage,
                                error:% = error.source;
                                "HVF lane replacement failed"
                            );
                            self.fail_lane_pool(error.failure);
                            return;
                        }
                    }
                }
                if !progressed && self.retiring_lane_count() != 0 {
                    // CLASS A: the same primitive as the park above, with a timeout. The first
                    // pass took this lock through the bare mutex with no hold at all, so the
                    // acquisition was unchecked and the park invisible; `wait_timeout_on` does
                    // both.
                    let requested = self
                        .lane_maintenance
                        .requested
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (mut requested, _) = self
                        .lane_maintenance
                        .requested
                        .wait_timeout_on(
                            &self.lane_maintenance.wake,
                            requested,
                            LANE_REPLACEMENT_POLL,
                        )
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *requested = false;
                }
            }
        }
    }

    fn repair_retired_lane(&self, index: usize) -> Result<bool, LaneMaintenanceFailure> {
        let generation = {
            let slot = self.lanes[index]
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*slot {
                LaneSlotState::Retiring(generation) => Arc::clone(generation),
                _ => return Ok(false),
            }
        };
        let old_generation = generation.handle.generation();
        if Arc::strong_count(&generation) != 2 {
            return Ok(false);
        }
        let reaped = {
            let mut lane = generation
                .lane
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lane = lane.as_mut().ok_or_else(|| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "finding retired lane ownership",
                },
                source: HvfBackendError::LanePoolCorrupt { index },
            })?;
            lane.try_reaped().map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "waiting for owner reaping",
                },
                source: error.into(),
            })?
        };
        if !reaped {
            return Ok(false);
        }
        let old = {
            let pool = self
                .free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut slot = self.lanes[index]
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pool.failure.is_some() || pool.retiring == 0 {
                return Err(LaneMaintenanceFailure {
                    failure: LaneReplacementFailure {
                        index,
                        generation: old_generation,
                        stage: "claiming retired lane ownership",
                    },
                    source: HvfBackendError::LanePoolCorrupt { index },
                });
            }
            let old =
                match core::mem::replace(&mut *slot, LaneSlotState::Replacing { old_generation }) {
                    LaneSlotState::Retiring(current) if Arc::ptr_eq(&current, &generation) => {
                        current
                    }
                    other => {
                        *slot = other;
                        return Err(LaneMaintenanceFailure {
                            failure: LaneReplacementFailure {
                                index,
                                generation: old_generation,
                                stage: "claiming retired lane ownership",
                            },
                            source: HvfBackendError::LanePoolCorrupt { index },
                        });
                    }
                };
            drop(slot);
            drop(pool);
            old
        };
        drop(generation);
        let LaneGeneration {
            lane,
            handle,
            participant,
            view_tag: _,
            space_tag: _,
        } = Arc::try_unwrap(old).map_err(|_| LaneMaintenanceFailure {
            failure: LaneReplacementFailure {
                index,
                generation: old_generation,
                stage: "isolating retired lane ownership",
            },
            source: HvfBackendError::LanePoolCorrupt { index },
        })?;
        drop(
            lane.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        drop(handle);
        let (recorded_view, participant) = participant
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut participant =
            Some(participant.ok_or_else(|| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "finding retired participant ownership",
                },
                source: HvfBackendError::LanePoolCorrupt { index },
            })?);
        let participant_id = participant
            .as_ref()
            .expect("just constructed as Some")
            .id();
        let space = self
            .space_for_view(recorded_view)
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "resolving retired participant's address space",
                },
                source: error,
            })?;
        let deregistration =
            space.deregister_vcpu_participant(participant.as_mut().ok_or_else(|| {
                LaneMaintenanceFailure {
                    failure: LaneReplacementFailure {
                        index,
                        generation: old_generation,
                        stage: "finding retired participant ownership",
                    },
                    source: HvfBackendError::LanePoolCorrupt { index },
                }
            })?);
        match deregistration {
            Ok(()) => {}
            Err(HvfMemoryError::ParticipantBusy(_)) => {
                let _recovery = self
                    .participant_recovery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(participant.take());
                let receipts = space
                    .recover_stopped_vcpu_participants()
                    .map_err(|error| LaneMaintenanceFailure {
                        failure: LaneReplacementFailure {
                            index,
                            generation: old_generation,
                            stage: "recovering retired participant",
                        },
                        source: error.into(),
                    })?;
                if !receipts
                    .iter()
                    .any(|receipt| receipt.participant == participant_id && receipt.removed)
                {
                    return Err(LaneMaintenanceFailure {
                        failure: LaneReplacementFailure {
                            index,
                            generation: old_generation,
                            stage: "verifying retired participant recovery",
                        },
                        source: HvfBackendError::LanePoolCorrupt { index },
                    });
                }
            }
            Err(error) => {
                return Err(LaneMaintenanceFailure {
                    failure: LaneReplacementFailure {
                        index,
                        generation: old_generation,
                        stage: "deregistering retired participant",
                    },
                    source: error.into(),
                });
            }
        }
        drop(participant);
        space
            .pump_retirements()
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "settling retired participant",
                },
                source: error.into(),
            })?;
        if process_hvf_vm()
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "checking replacement VM state",
                },
                source: error.into(),
            })?
            .is_poisoned()
        {
            return Err(LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "checking replacement VM state",
                },
                source: HvfError::Poisoned.into(),
            });
        }
        let replacement =
            Self::create_lane_generation(&self.registry, &space, recorded_view, self.el1)
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "creating replacement generation",
                },
                source: error,
            })?;
        let replacement_generation = replacement.handle.generation();
        let replacement_view_tag = replacement.view_tag.load(Ordering::Relaxed);
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut slot = self.lanes[index]
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = pool.failure.is_none()
            && pool.retiring != 0
            && replacement_generation > old_generation
            && !pool.free.iter().any(|free| free.index == index)
            && matches!(
                &*slot,
                LaneSlotState::Replacing {
                    old_generation: current
                } if *current == old_generation
            );
        if !valid {
            drop(slot);
            drop(pool);
            return Err(LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "publishing replacement generation",
                },
                source: HvfBackendError::LanePoolCorrupt { index },
            });
        }
        *slot = LaneSlotState::Ready(replacement);
        pool.retiring -= 1;
        pool.free.push_back(FreeLane {
            index,
            generation: replacement_generation,
            view_tag: replacement_view_tag,
        });
        drop(slot);
        drop(pool);
        self.available.notify_all();
        Ok(true)
    }

    fn fail_lane_pool(&self, failure: LaneReplacementFailure) {
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.index < self.lanes.len() {
            let mut slot = self.lanes[failure.index]
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(
                &*slot,
                LaneSlotState::Retiring(current)
                    if current.handle.generation() == failure.generation
            ) || matches!(
                &*slot,
                LaneSlotState::Replacing { old_generation }
                    if *old_generation == failure.generation
            ) {
                pool.retiring = pool.retiring.saturating_sub(1);
            }
            *slot = LaneSlotState::Failed(failure);
        }
        pool.failure.get_or_insert(failure);
        drop(pool);
        self.available.notify_all();
        self.kick_running_lanes();
        // Step GF (b): a lane generation that failed must not stay in a thread's retained lease --
        // that thread reads `pool.failure` only when it acquires, and a retained lease never
        // acquires. Ask every holder back so the failure is seen.
        bump_lane_yield_epoch();
    }

    fn current_lane_handle(&self, index: usize) -> Result<HvfVcpuLaneHandle, HvfBackendError> {
        let slot = self
            .lanes
            .get(index)
            .ok_or(HvfBackendError::LanePoolCorrupt { index })?
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*slot {
            LaneSlotState::Ready(generation) | LaneSlotState::Retiring(generation) => {
                Ok(generation.handle.clone())
            }
            LaneSlotState::Replacing { .. } => Err(HvfBackendError::LanePoolCorrupt { index }),
            LaneSlotState::Failed(failure) => Err(lane_replacement_error(*failure)),
        }
    }

    fn install_trampoline(&self) -> Result<(), HvfBackendError> {
        let range = self.trampoline.clone();
        let mapped = self.default_space.map_range(
            range.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
            false,
            false,
        )?;
        let mapping = OwnedGuestRange::new(self, range.clone());
        self.default_space.defer_retirement(mapped.retirement)?;
        // The host view is mirrored, so the page is writable at its own GVA.
        let mut bytes = [0u8; SIGRETURN_TRAMPOLINE.len() * 4];
        for (index, instruction) in SIGRETURN_TRAMPOLINE.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&instruction.to_le_bytes());
        }
        // SAFETY: `range` was just mapped read/write in the mirrored host
        // view and nothing else references it yet.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), range.start as *mut u8, bytes.len());
        }
        let executable = self.default_space.protect_range(
            range.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        )?;
        self.default_space.defer_retirement(executable.retirement)?;
        self.default_space.pump_retirements()?;
        // SAFETY: the page is readable in the mirrored host view.
        let readback = unsafe { core::ptr::read_unaligned(range.start as *const [u8; 8]) };
        if readback != bytes {
            return Err(HvfBackendError::Trampoline(
                "trampoline bytes did not read back through the mirrored view",
            ));
        }
        mapping.disarm();
        Ok(())
    }

    /// Installs the guest vDSO (see [`crate::vdso`]) the same way [`Self::install_trampoline`]
    /// installs the trampoline: both pages start read/write in the mirrored host view, get
    /// their content written through it, and are then restricted to what the guest may do
    /// (execute the image, read the clock page). Afterwards the host keeps the clock page
    /// current through the page's own storage alias, the one host mapping of it that stays
    /// writable once the guest may only read it.
    fn install_vdso(&self) -> Result<(), HvfBackendError> {
        let image = self.vdso.start..self.vdso.start + PAGE_SIZE;
        let clock = image.end..self.vdso.end;
        let mapped = self.default_space.map_range(
            self.vdso.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
            false,
            false,
        )?;
        let mapping = OwnedGuestRange::new(self, self.vdso.clone());
        self.default_space.defer_retirement(mapped.retirement)?;
        // SAFETY: both pages were just mapped read/write (zeroed) in the mirrored host view
        // and nothing else references them yet.
        let page = unsafe { core::slice::from_raw_parts_mut(image.start as *mut u8, PAGE_SIZE) };
        let image_len = crate::vdso::build_image(page, PAGE_SIZE).map_err(HvfBackendError::Vdso)?;
        let values = self
            .vdso_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values;
        // SAFETY: as above -- the clock page is still host-writable through the mirror here,
        // 16 KiB aligned, and no other writer exists yet.
        unsafe { crate::vdso::publish_clock(clock.start as *mut u64, values) };
        let executable = self.default_space.protect_range(
            image.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        )?;
        self.default_space.defer_retirement(executable.retirement)?;
        let readonly = self
            .default_space
            .protect_range(clock.clone(), HvfGuestPermissions::READ)?;
        self.default_space.defer_retirement(readonly.retirement)?;
        self.default_space.pump_retirements()?;
        // SAFETY: the page is readable in the mirrored host view.
        let readback = unsafe { core::ptr::read_unaligned(image.start as *const [u8; 4]) };
        if readback != *b"\x7fELF" {
            return Err(HvfBackendError::Vdso(
                "vDSO image did not read back through the mirrored view",
            ));
        }
        let storage = self.default_space.host_storage_address(clock.start)?;
        self.vdso_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .storage = storage;
        litebox_util_log::info!(
            image:? = image.start, clock:? = clock.start, image_len;
            "guest vDSO installed: clock_gettime/gettimeofday/clock_getres run without exits"
        );
        mapping.disarm();
        Ok(())
    }

    /// The guest address of the vDSO ELF image, for `AT_SYSINFO_EHDR`.
    pub(crate) fn vdso_address(&self) -> usize {
        self.vdso.start
    }

    /// Records the instant the shim counts `CLOCK_MONOTONIC` from, so the vDSO's monotonic
    /// clocks share the shim's epoch exactly (see [`crate::vdso`]).
    pub(crate) fn publish_vdso_monotonic_epoch(&self, epoch_ns: u64) {
        self.publish_vdso_clock(Some(epoch_ns));
    }

    /// Republishes the clock data page: the current host `CLOCK_REALTIME - CLOCK_MONOTONIC_RAW`
    /// offset, and the monotonic epoch when the shim hands one over.
    fn publish_vdso_clock(&self, mono_epoch_ns: Option<u64>) {
        let mut clock = self
            .vdso_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(epoch) = mono_epoch_ns {
            clock.values.mono_epoch_ns = epoch;
        }
        clock.values.real_offset_ns = crate::vdso::host_real_offset_ns();
        if clock.storage != 0 {
            // SAFETY: `storage` is the clock page's host-writable storage address recorded by
            // `install_vdso`, valid for the life of `default_space`, and this mutex is the only
            // writer.
            unsafe { crate::vdso::publish_clock(clock.storage as *mut u64, clock.values) };
        }
    }

    /// Keeps the vDSO's `CLOCK_REALTIME` offset tracking the host's wall clock; see
    /// [`crate::vdso::CLOCK_REFRESH_INTERVAL`] for the staleness bound this gives.
    fn start_vdso_clock_refresher(&'static self) -> std::io::Result<()> {
        std::thread::Builder::new()
            .name("litebox-hvf-vdso-clock".to_owned())
            .spawn(move || loop {
                std::thread::sleep(crate::vdso::CLOCK_REFRESH_INTERVAL);
                self.publish_vdso_clock(None);
            })
            .map(|_thread| ())
    }

    pub(crate) fn trampoline_address(&self) -> usize {
        self.trampoline.start
    }

    pub(crate) fn reserved_ranges(&self) -> Vec<Range<usize>> {
        vec![self.trampoline.clone(), self.vdso.clone()]
    }

    /// Whether `range` touches a page this backend itself owns at a fixed GVA (the sigreturn
    /// trampoline or the vDSO pages), which no guest mapping may ever cover.
    fn overlaps_reserved(&self, range: &Range<usize>) -> bool {
        overlaps(range, &self.trampoline) || overlaps(range, &self.vdso)
    }

    // -- lane pool ---------------------------------------------------------

    /// Acquires any idle lane in strict arrival order: a waiter is served
    /// only once every waiter that started waiting before it has already been
    /// served, so a thread that repeatedly releases and reacquires a lane can
    /// never barge ahead of one that has been waiting longer. This is what
    /// makes `LANE_ACQUIRE_TIMEOUT` a bound on genuine sustained
    /// oversubscription rather than on adversarial scheduling luck.
    fn acquire_lane(&self) -> Result<LaneLease<'_>, HvfBackendError> {
        self.acquire_lane_inner(None, view_tag(None), None)?
            .ok_or(HvfBackendError::LaneAcquisitionTimeout)
    }

    /// `view` is the calling guest thread's current view, so the pool can prefer a lane already
    /// registered in it, and `preferred` the lane it last ran on (see [`preferred_free_lane`]).
    fn acquire_lane_for_thread(
        &self,
        slot: &HvfThreadSlot,
        view: Option<VmViewId>,
        preferred: Option<(usize, u64)>,
    ) -> Result<Option<LaneLease<'_>>, HvfBackendError> {
        self.acquire_lane_inner(Some(slot), view_tag(view), preferred)
    }

    fn acquire_lane_inner(
        &self,
        interrupt: Option<&HvfThreadSlot>,
        view_tag: u64,
        preferred: Option<(usize, u64)>,
    ) -> Result<Option<LaneLease<'_>>, HvfBackendError> {
        // CLASS A: the pool lock is the one a guest thread parks on (`available`), so it is taken
        // and parked through the ranked wrapper itself -- `wait_on` / `wait_timeout_on` release
        // the pool's rank for the park (which is what `Condvar::wait` does to the mutex) and
        // re-take it on return. The explicit `rank_hold_scoped` the first pass used here kept the
        // pool in the held set ACROSS the park, so every legitimate park was an asserted
        // `wait_while_holding`.
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(failure) = pool.failure {
            return Err(lane_replacement_error(failure));
        }
        let deadline = Instant::now()
            .checked_add(LANE_ACQUIRE_TIMEOUT)
            .ok_or(HvfBackendError::LaneAcquisitionTimeout)?;
        let ticket = pool.next_ticket;
        let successor = ticket
            .checked_add(1)
            .ok_or(HvfBackendError::LaneTicketExhausted)?;
        pool.next_ticket = successor;
        loop {
            if let Some(failure) = pool.failure {
                pool.next_serving = pool.next_serving.max(successor);
                advance_canceled_tickets(&mut pool)?;
                drop(pool);
                self.available.notify_all();
                return Err(lane_replacement_error(failure));
            }
            if interrupt.is_some_and(HvfThreadSlot::has_pending) {
                if !pool.canceled_tickets.insert(ticket) {
                    return Err(HvfBackendError::LanePoolCorrupt { index: usize::MAX });
                }
                advance_canceled_tickets(&mut pool)?;
                drop(pool);
                self.available.notify_all();
                return Ok(None);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                pool.next_serving = pool.next_serving.max(successor);
                advance_canceled_tickets(&mut pool)?;
                drop(pool);
                self.available.notify_all();
                return Err(HvfBackendError::LaneAcquisitionTimeout);
            }
            if ticket == pool.next_serving
                && let Some(position) = preferred_free_lane(&pool.free, view_tag, preferred)
            {
                let free = pool.free[position];
                if let Some(preferred) = preferred {
                    crate::diagnostics_counters::record_resident(
                        if (free.index, free.generation) == preferred {
                            crate::diagnostics_counters::RESIDENT_AFFINITY_HITS
                        } else {
                            crate::diagnostics_counters::RESIDENT_AFFINITY_MISSES
                        },
                        1,
                    );
                }
                let Some(pooled) = self.lanes.get(free.index) else {
                    return Err(HvfBackendError::LanePoolCorrupt { index: free.index });
                };
                let slot = pooled
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let generation = match &*slot {
                    LaneSlotState::Ready(generation)
                        if generation.handle.generation() == free.generation =>
                    {
                        Arc::clone(generation)
                    }
                    _ => {
                        return Err(HvfBackendError::LanePoolCorrupt { index: free.index });
                    }
                };
                let checked_out = pool
                    .checked_out
                    .checked_add(1)
                    .ok_or(HvfBackendError::LanePoolCorrupt { index: free.index })?;
                if pool.free.remove(position) != Some(free) {
                    return Err(HvfBackendError::LanePoolCorrupt { index: free.index });
                }
                pool.checked_out = checked_out;
                pool.next_serving = successor;
                advance_canceled_tickets(&mut pool)?;
                drop(slot);
                drop(pool);
                self.available.notify_all();
                return Ok(Some(LaneLease {
                    backend: self,
                    index: free.index,
                    generation,
                    return_to_pool: true,
                }));
            }
            let wait = interrupt.map_or(remaining, |_| remaining.min(Duration::from_millis(10)));
            // Step GF (b): tell every thread holding a retained lane that someone is queued. It
            // is incremented only around an actual park, so a thread that is served on its first
            // look is never counted as a waiter.
            self.lane_waiters.fetch_add(1, Ordering::SeqCst);
            let (next, _) = self
                .free
                .wait_timeout_on(&self.available, pool, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.lane_waiters.fetch_sub(1, Ordering::SeqCst);
            pool = next;
        }
    }

    /// FXR: asks lane `index` (only while it is still generation `generation`) to hand the
    /// resident SIMD/FP file `(cell, seq)` back to its thread; whether the request reached the
    /// lane's queue. Best effort: a lane that was replaced, is closing or whose queue is full is
    /// not asked -- every path by which a lane gives a resident file up (an eviction, a
    /// synchronization trip, its own close) deposits it anyway, and the waiter asks again.
    fn request_fp_materialization(
        &self,
        index: usize,
        generation: u64,
        cell: &Arc<HvfGuestRegisterCell>,
        seq: u64,
    ) -> bool {
        let Some(pooled) = self.lanes.get(index) else {
            return false;
        };
        let handle = {
            let slot = pooled
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*slot {
                LaneSlotState::Ready(current) | LaneSlotState::Retiring(current)
                    if current.handle.generation() == generation =>
                {
                    Some(current.handle.clone())
                }
                _ => None,
            }
        };
        handle.is_some_and(|handle| handle.request_fp_materialization(cell, seq).is_ok())
    }

    fn release_lane(&self, index: usize, generation: &Arc<LaneGeneration>) {
        let generation_id = generation.handle.generation();
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pooled) = self.lanes.get(index) else {
            drop(pool);
            fatal(
                "returning a vCPU lane to the pool",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        };
        let slot = pooled
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = pool.checked_out != 0
            && !pool.free.iter().any(|free| free.index == index)
            && matches!(
                &*slot,
                LaneSlotState::Ready(current)
                    if current.handle.generation() == generation_id
                        && Arc::ptr_eq(current, generation)
            );
        if valid {
            pool.checked_out -= 1;
            if pool.failure.is_none() {
                pool.free.push_back(FreeLane {
                    index,
                    generation: generation_id,
                    view_tag: generation.view_tag.load(Ordering::Relaxed),
                });
            }
        }
        drop(slot);
        drop(pool);
        if !valid {
            fatal(
                "returning a vCPU lane to the pool",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        }
        self.available.notify_all();
    }

    /// Takes a specific lane out of the pool only if it is idle right now.
    /// Deliberately bypasses ticket ordering: the shootdown loop targets one
    /// exact lane it already knows is retired-root-affected, not "the next
    /// fair turn," so admitting it out of order here does not defeat
    /// `acquire_lane`'s fairness guarantee for ordinary guest threads.
    fn try_acquire_lane(&self, index: usize) -> Option<LaneLease<'_>> {
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pool.failure.is_some() {
            return None;
        }
        let Some(position) = pool.free.iter().position(|free| free.index == index) else {
            return None;
        };
        let free = pool.free[position];
        let Some(pooled) = self.lanes.get(index) else {
            drop(pool);
            fatal(
                "checking out a targeted vCPU lane",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        };
        let slot = pooled
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = match &*slot {
            LaneSlotState::Ready(generation)
                if generation.handle.generation() == free.generation =>
            {
                Arc::clone(generation)
            }
            _ => {
                drop(slot);
                drop(pool);
                fatal(
                    "checking out a targeted vCPU lane",
                    &HvfBackendError::LanePoolCorrupt { index },
                );
            }
        };
        let Some(checked_out) = pool.checked_out.checked_add(1) else {
            drop(slot);
            drop(pool);
            fatal(
                "checking out a targeted vCPU lane",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        };
        if pool.free.remove(position) != Some(free) {
            drop(slot);
            drop(pool);
            fatal(
                "checking out a targeted vCPU lane",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        }
        pool.checked_out = checked_out;
        drop(slot);
        Some(LaneLease {
            backend: self,
            index,
            generation,
            return_to_pool: true,
        })
    }

    /// Drains process-global quarantined memory resources (aliases, data
    /// pages, table pages, host slots, backings, SDK mapping fragments) if
    /// any are outstanding, folding the result into
    /// [`HvfExceptionCounters`]. Cheap no-op when nothing is quarantined
    /// ([`HvfMemory::usage`] is an O(1) running counter). Called from every
    /// ordinary settled mutation (not only reactively from [`Self::shootdown`]
    /// under resource pressure), so a transient quarantine entry created
    /// outside a `ResourceLimit` episode is still drained on the very next
    /// mutation instead of sitting forever.
    fn pump_quarantine(&self) {
        if self.memory.usage().quarantined_resources == 0 {
            return;
        }
        match self.memory.retry_quarantined_resources() {
            Ok(report) => {
                self.exception_counters
                    .quarantine_pump_runs
                    .fetch_add(1, Ordering::Relaxed);
                let reclaimed = (report.aliases_restored
                    + report.data_pages_released
                    + report.table_pages_released
                    + report.host_slots_released
                    + report.backings_released
                    + report.sdk_mapping_fragments_released) as u64;
                if reclaimed != 0 {
                    self.exception_counters
                        .quarantine_pump_reclaimed
                        .fetch_add(reclaimed, Ordering::Relaxed);
                }
                if report.permanent_entries_observed != 0 {
                    self.exception_counters
                        .quarantine_permanent_failures
                        .fetch_add(report.permanent_entries_observed as u64, Ordering::Relaxed);
                }
            }
            Err(error) => {
                litebox_util_log::warn!(error:% = error;
                    "HVF quarantine pump could not drain quarantined resources this pass");
            }
        }
    }

    /// The Linux TLB-shootdown equivalent after a mapping mutation: every
    /// lane still running the retired root is kicked out of the guest, idle
    /// lanes that owe an acknowledgement are synchronized here directly, and
    /// deferred retirements are pumped until none remain (or the bound
    /// expires, in which case they stay deferred and are pumped later).
    fn shootdown(&self, space: &HvfAddressSpace) {
        // Step GF (fix-up): release this thread's own retained lane before the loop below tries to
        // take every lane out of the pool. A shootdown is reached from the mutating thread's own
        // dispatch (`settle_mutation`'s `ResourceLimit` arm), and that thread retained its lane
        // *before* the dispatch -- so the lane it is about to wait for is the one it is holding,
        // and it has no loop top of its own until this returns. Bumping the yield epoch cannot
        // break that tie (the bump is only observed at the holder's next loop top), so without
        // this the mutator spins here for the whole `SHOOTDOWN_TIMEOUT` and then reports
        // `ResourceLimit` -- strictly worse than before stickiness existed, when the caller's lane
        // was back in the pool and drainable.
        release_retained_lane(crate::diagnostics_counters::LANE_STICKY_RELEASED_YIELD);
        let deadline = Instant::now()
            .checked_add(SHOOTDOWN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        self.kick_running_lanes_in(space);
        loop {
            let _ = space.pump_retirements();
            self.pump_quarantine();
            if space.pending_retirements() == 0 {
                return;
            }
            for index in 0..self.lanes.len() {
                // Enforced per lane, not only once per outer loop iteration:
                // a single stalled lane's own command timeout must not be
                // able to consume the whole shootdown budget on its own.
                if Instant::now() >= deadline {
                    litebox_util_log::warn!(
                        pending:? = space.pending_retirements();
                        "HVF shootdown did not drain every retirement within its bound"
                    );
                    return;
                }
                let Some(lease) = self.try_acquire_lane(index) else {
                    // Step GF (fix-up): ask for the lane back only when it is one a thread is
                    // actually keeping between runs. A bump here revokes every retained lease
                    // process-wide, so doing it for a lane that is merely mid-run -- which this
                    // loop just has to wait out, and which is the common case -- used to switch
                    // stickiness off for every thread on every shootdown.
                    if self.lane_is_retained(index) {
                        bump_lane_yield_epoch();
                    }
                    continue;
                };
                let mut retire = false;
                {
                    let lane = lease.lane();
                    // A lane not currently registered as a participant in `space` (it belongs to
                    // a different view, or to `default_space`) simply fails to attach here --
                    // already handled as a harmless no-op by the `Err(_) => {}` arm below, since
                    // this shootdown has nothing to say about a mutation on a space this lane
                    // isn't even attached to.
                    let attached = {
                        let participant = lane
                            .participant
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))
                    };
                    match attached {
                        Ok(attachment) if attachment.requires_synchronization() => {
                            if let Err(error) = lane.handle.synchronize_before(attachment, deadline)
                                && !lane.handle.is_reusable()
                            {
                                litebox_util_log::warn!(index:? = index, error:% = error;
                                    "retiring an HVF lane that exceeded the shootdown bound");
                                retire = true;
                            }
                        }
                        Ok(attachment) => drop(attachment),
                        Err(_) => {}
                    }
                }
                if retire {
                    lease.retire();
                } else {
                    drop(lease);
                }
            }
            // BCORE-4 (fix-up): the bound counterpart of the lane loop above. `kick_running_lanes`
            // can only `request_kick` a bound entry, which answers `VcpuNotRunning` for an
            // `Idle`/`Completing` one -- so a bound vCPU that is in flight but not running during
            // this window used to have no drain path at all besides its own next exit, whenever
            // that happened to be. Ask for one: the entry's owner thread re-evaluates at its loop
            // top (interrupting it first, so a thread parked in a shim wait comes back with
            // EINTR), and the attach there synchronizes and acknowledges what this vCPU owes.
            // Only the owner may `hv_vcpu_run`, so asking is all a foreign thread can do -- and
            // the wait below is bounded by this shootdown's own deadline either way.
            if bound_enabled() {
                let space_tag = space.id().value();
                let entries: Vec<Arc<BoundEntry>> = {
                    let entries = self
                        .bound_entries
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    entries.clone()
                };
                for entry in entries {
                    if entry.space_tag.load(Ordering::Acquire) != space_tag {
                        continue;
                    }
                    entry.sync_requested.store(true, Ordering::Release);
                    entry.thread.interrupt();
                }
                let _ = space.pump_retirements();
                if space.pending_retirements() == 0 {
                    return;
                }
            }
            let _ = space.pump_retirements();
            if space.pending_retirements() == 0 {
                return;
            }
            if Instant::now() >= deadline {
                litebox_util_log::warn!(
                    pending:? = space.pending_retirements();
                    "HVF shootdown did not drain every retirement within its bound"
                );
                return;
            }
            std::thread::sleep(SHOOTDOWN_POLL);
        }
    }

    /// Kicks every lane that is currently running guest code so it exits,
    /// re-attaches (synchronizing onto the newest root) and acknowledges
    /// pending retirements.  Best effort: a lane that is not running simply
    /// reports so.
    ///
    /// VM-wide: used where there is no single mutated space to scope to (the lane-pool failure
    /// path, where every lane of the VM may be about to be retired).
    #[track_caller]
    fn kick_running_lanes(&self) {
        self.kick_lanes(None, core::panic::Location::caller());
    }

    /// T1b (hvf-kick-only-lanes-in-mutated-space): [`Self::kick_running_lanes`] scoped to one
    /// address space. A mutation of `space` only ever needs the participants of `space` to
    /// acknowledge, so lanes (and bound vCPUs) registered elsewhere are skipped instead of being
    /// asked to cancel a run that owes this mutation nothing -- today that is 11 requests per
    /// round (one per lane in the VM) no matter how few spaces are involved.
    #[track_caller]
    fn kick_running_lanes_in(&self, space: &HvfAddressSpace) {
        self.kick_lanes(Some(space.id().value()), core::panic::Location::caller());
    }

    /// `scope` is `Some(address space id)` to kick only that space's participants, `None` for
    /// every lane in the VM. `caller` is the caller of the public wrapper, so the T1f-a kick-site
    /// table keeps attributing each round to the mutation path that issued it.
    fn kick_lanes(&self, scope: Option<u64>, caller: &'static core::panic::Location<'static>) {
        // hvf-exit-overhead-instrumentation: one `lane_kicks.rounds` per call, one
        // `lane_kicks.requests` per lane asked, split by what the lane answered.
        crate::diagnostics_counters::record_kick_round();
        // T1f-a: and one row per `kick_running_lanes` call site, so a kick round can be traced
        // back to the mutation path that issued it.
        crate::diagnostics_counters::record_kick_round_at(caller);
        crate::diagnostics_counters::record_kick_round_scope(scope.is_some());
        // BCORE-4: bound vCPUs are participants of the mutated space too, so they owe the same
        // acknowledgement and must be kicked the same way -- and, like the lane loop below, only
        // when they are participants of the space being mutated.
        if bound_enabled() {
            let entries: Vec<Arc<BoundEntry>> = {
                let entries = self
                    .bound_entries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                entries.clone()
            };
            for entry in entries {
                // T1b: a bound vCPU registered in another space owes this mutation nothing.
                if let Some(tag) = scope
                    && entry.space_tag.load(Ordering::Acquire) != tag
                {
                    crate::diagnostics_counters::record_kick_skip_other_space();
                    continue;
                }
                crate::diagnostics_counters::record_kick_considered();
                let outcome = match entry
                    .control
                    .request_kick(entry.generation, &entry.cancellation, None)
                {
                    Ok(()) => crate::diagnostics_counters::KickOutcome::Requested,
                    Err(HvfVcpuLaneError::VcpuNotRunning) => {
                        crate::diagnostics_counters::KickOutcome::Idle
                    }
                    Err(_) => crate::diagnostics_counters::KickOutcome::Error,
                };
                crate::diagnostics_counters::record_kick_request(outcome);
            }
        }
        for lane in &self.lanes {
            let handle = {
                let slot = lane
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match &*slot {
                    LaneSlotState::Ready(generation) | LaneSlotState::Retiring(generation) => {
                        // T1b: read the lane's space tag in the same critical section that hands
                        // out its handle, so the pair (handle, tag) describes one lane generation
                        // at one instant.
                        Some((generation.handle.clone(), generation.space_tag.load(Ordering::Acquire)))
                    }
                    LaneSlotState::Replacing { .. } | LaneSlotState::Failed(_) => None,
                }
            };
            if let Some((handle, tag)) = handle {
                // T1b: skip lanes that are participants of a different space. The identity
                // `requests + skipped_other_space == considered` holds exactly per round.
                if let Some(scope) = scope
                    && tag != scope
                {
                    crate::diagnostics_counters::record_kick_skip_other_space();
                    continue;
                }
                crate::diagnostics_counters::record_kick_considered();
                let outcome = match handle.cancellation().request() {
                    Ok(()) => crate::diagnostics_counters::KickOutcome::Requested,
                    Err(HvfVcpuLaneError::VcpuNotRunning) => {
                        crate::diagnostics_counters::KickOutcome::Idle
                    }
                    Err(_) => crate::diagnostics_counters::KickOutcome::Error,
                };
                crate::diagnostics_counters::record_kick_request(outcome);
            }
        }
    }

    /// Settles one mutation the way Linux settles a page-table change:
    ///
    /// * A new mapping needs no shootdown at all -- no vCPU can hold a
    ///   translation for a range that was unmapped, so nothing is stale.
    /// * Narrowing (protect, unmap) kicks every running lane once, without
    ///   waiting: each kicked lane re-attaches and synchronizes before it
    ///   runs again, and any access it makes through a stale entry in the
    ///   meantime either still hits its own (retired, not yet reused) memory
    ///   or faults -- and a fault on a stale view is rerun after
    ///   synchronization rather than delivered (see `dispatch_monitor_exit`).
    ///   Retired resources are released as acknowledgements arrive; they are
    ///   never reused before every in-flight participant has acknowledged.
    /// * Only resource pressure (a `ResourceLimit`) triggers the bounded,
    ///   synchronous drain, after which the caller retries once.
    fn settle_mutation(
        &self,
        space: &HvfAddressSpace,
        kind: MutationKind,
        mutation: Result<HvfRangeMutation, HvfMemoryError>,
        site: u16,
        closure_ticks: u64,
    ) -> Result<bool, HvfMemoryError> {
        // T1f-a: `site` is the (call site, origin, kind) row `mutate_with_retry` /
        // `settle_single_page_mutation` resolved for this call and `closure_ticks` is what the
        // mutation's own closure (the stage-1/stage-2 work, before any settling) cost.
        let kind_code = match kind {
            MutationKind::Map => 0,
            MutationKind::Protect => 1,
            MutationKind::Unmap => 2,
        };
        match mutation {
            Ok(mutation) => {
                let changed = mutation.changed;
                crate::diagnostics_counters::record_mutation(kind_code, changed);
                crate::diagnostics_counters::record_mutation_site(
                    site,
                    changed,
                    kind != MutationKind::Map,
                    closure_ticks,
                    false,
                );
                crate::diagnostics_counters::record_space_mutation(space.id());
                space
                    .defer_retirement(mutation.retirement)
                    .map_err(|error| {
                        HvfMemoryError::after_publication("retirement deferral", error)
                    })?;
                if kind != MutationKind::Map {
                    self.kick_running_lanes_in(space);
                }
                let _ = space.pump_retirements();
                self.pump_quarantine();
                let count = self
                    .mutations
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_add(1);
                if count % 256 == 0 {
                    let usage = self.memory.usage();
                    let snapshot = self.exception_counters_snapshot();
                    litebox_util_log::debug!(
                        mutations:? = count,
                        pending_retirements:? = space.pending_retirements(),
                        retired_generations:? = usage.retired_generations,
                        claimed_pages:? = usage.claimed_pages,
                        table_pages:? = usage.table_pages,
                        host_slots:? = usage.host_slots,
                        ipa_owned_pages:? = usage.ipa_owned_pages,
                        raw_exception_exits:? = snapshot.raw_exception_exits,
                        stale_view_reruns:? = snapshot.stale_view_reruns,
                        wx_service_requests:? = snapshot.wx_service_requests,
                        wx_service_settled:? = snapshot.wx_service_settled,
                        wx_service_refaulted:? = snapshot.wx_service_refaulted,
                        wx_alias_conflict_refusals:? = snapshot.wx_alias_conflict_refusals,
                        guest_faults_serviced:? = snapshot.guest_faults_serviced,
                        guest_faults_delivered:? = snapshot.guest_faults_delivered,
                        exceptions_in_flight:? = snapshot.in_flight,
                        fatal_faults:? = snapshot.fatal_faults,
                        delivered_task_ring:? = snapshot.delivered_task_ring,
                        quarantine_pump_runs:? = snapshot.quarantine_pump_runs,
                        quarantine_pump_reclaimed:? = snapshot.quarantine_pump_reclaimed,
                        quarantine_permanent_failures:? = snapshot.quarantine_permanent_failures,
                        pinned_shared_backings:? = usage.pinned_shared_backings;
                        "HVF mutation counters"
                    );
                }
                Ok(changed)
            }
            Err(HvfMemoryError::ResourceLimit {
                resource,
                requested,
                limit,
            }) => {
                // T1f-a: a resource limit is the one arm that kicks unconditionally (it drains
                // every lane through `shootdown`), so it is recorded as kicked.
                crate::diagnostics_counters::record_mutation_site(site, false, true, closure_ticks, true);
                self.shootdown(space);
                Err(HvfMemoryError::ResourceLimit {
                    resource,
                    requested,
                    limit,
                })
            }
            Err(error) => {
                crate::diagnostics_counters::record_mutation_site(site, false, false, closure_ticks, false);
                Err(error)
            }
        }
    }

    /// Loads every counter in [`HvfExceptionCountersSnapshot`]'s taxonomy in one pass (all
    /// `Acquire`, so no field observed here can be torn relative to a concurrent
    /// [`checked_increment`]), tagged with the current mutation count as `generation`. See
    /// [`HvfExceptionCountersSnapshot`] for the invariant equations this is meant to let a
    /// caller check by hand against real before/after deltas.
    pub(crate) fn exception_counters_snapshot(&self) -> HvfExceptionCountersSnapshot {
        let counters = &self.exception_counters;
        let delivered_task_ring = core::array::from_fn(|i| {
            core::num::NonZeroU64::new(DELIVERED_TASK_RING[i].load(Ordering::Acquire))
        });
        HvfExceptionCountersSnapshot {
            raw_exception_exits: counters.raw_exception_exits.load(Ordering::Acquire),
            stale_view_reruns: counters.stale_view_reruns.load(Ordering::Acquire),
            wx_service_requests: counters.wx_service_requests.load(Ordering::Acquire),
            wx_service_settled: counters.wx_service_settled.load(Ordering::Acquire),
            wx_service_refaulted: counters.wx_service_refaulted.load(Ordering::Acquire),
            wx_alias_conflict_refusals: counters.wx_alias_conflict_refusals.load(Ordering::Acquire),
            guest_faults_serviced: GUEST_FAULTS_SERVICED.load(Ordering::Acquire),
            guest_faults_delivered: GUEST_FAULTS_DELIVERED.load(Ordering::Acquire),
            fatal_faults: FATAL_FAULTS.load(Ordering::Acquire),
            in_flight: counters.in_flight.load(Ordering::Acquire),
            generation: self.mutations.load(Ordering::Acquire),
            delivered_task_ring,
            quarantine_pump_runs: counters.quarantine_pump_runs.load(Ordering::Acquire),
            quarantine_pump_reclaimed: counters.quarantine_pump_reclaimed.load(Ordering::Acquire),
            quarantine_permanent_failures: counters
                .quarantine_permanent_failures
                .load(Ordering::Acquire),
            wx_service_latency_count: counters.wx_service_latency_count.load(Ordering::Acquire),
            wx_service_latency_sum_ns: counters.wx_service_latency_sum_ns.load(Ordering::Acquire),
            wx_service_latency_max_ns: counters.wx_service_latency_max_ns.load(Ordering::Acquire),
            wx_service_latency_buckets: core::array::from_fn(|i| {
                counters.wx_service_latency_buckets[i].load(Ordering::Acquire)
            }),
        }
    }

    /// wx-service-latency-measurement: records one W^X service latency sample (see
    /// [`HvfExceptionCounters::wx_service_latency_count`] for exactly which call sites feed
    /// this). Relaxed atomics only -- a best-effort diagnostic histogram, not a correctness
    /// dependency, exactly like [`crate::diagnostics_counters`]'s own tables.
    fn record_wx_service_latency(&self, elapsed: Duration) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let counters = &self.exception_counters;
        counters.wx_service_latency_count.fetch_add(1, Ordering::Relaxed);
        counters.wx_service_latency_sum_ns.fetch_add(ns, Ordering::Relaxed);
        counters.wx_service_latency_max_ns.fetch_max(ns, Ordering::Relaxed);
        counters.wx_service_latency_buckets[crate::diagnostics_counters::latency_bucket_index(ns)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `wx-latency-readout`: every `interval`, logs one `info`-level line summarizing the
    /// wx-service-latency counters this backend already instruments (see
    /// [`HvfExceptionCounters::wx_service_latency_count`]'s own doc comment for exactly which
    /// call sites feed those samples). Started from [`install`] only when an operator opts in
    /// via `LITEBOX_HVF_DIAG_INTERVAL=<secs>` -- unset by default, so this thread is never
    /// spawned and the feature costs nothing beyond the one env-var read at startup, the same
    /// low-risk, default-off pattern `LITEBOX_HVF_LANES` already uses in [`HvfBackend::create`].
    ///
    /// Deliberately a log line, not another file/JSON surface:
    /// [`crate::diagnostics_counters::full_snapshot_json`] (via
    /// `litebox_runner_linux_on_macos_userland::counters_publisher`) already republishes these
    /// exact fields to an mmap'd file unconditionally every 250ms, but reading that back needs a
    /// separate `--unstable --counters <run-dir>` invocation from a second process -- nothing
    /// puts these numbers where an operator already watching a live session's ordinary log
    /// stream would see them. This is a coarse, opt-in, human-readable complement to that
    /// surface, not a replacement for it -- prerequisite instrumentation so a future session can
    /// confirm or rule out wx-toggle latency as a real contributor to perceived slowness with
    /// actual numbers, instead of leaving it an open architectural possibility.
    fn start_diagnostics_readout(&'static self, interval: Duration) -> std::io::Result<()> {
        std::thread::Builder::new()
            .name("litebox-hvf-diag-readout".to_owned())
            .spawn(move || loop {
                std::thread::sleep(interval);
                self.log_wx_service_latency_snapshot();
            })
            .map(|_thread| ())
    }

    /// The one line [`start_diagnostics_readout`] logs every tick: sample count, mean, and max
    /// nanoseconds (of every wx-service-latency sample recorded since process start), plus a
    /// sparse (zero buckets omitted) `bucket:count` rendering of the same log2(ns) histogram
    /// [`crate::diagnostics_counters::full_snapshot_json`] publishes densely -- see
    /// [`crate::diagnostics_counters::latency_bucket_index`]'s own doc comment for the
    /// bucket-index convention (bucket `i` covers `[2^(i-1), 2^i)` nanoseconds; bucket `0` is
    /// exactly `ns == 0`). A free-standing method rather than inlined into the loop above, so a
    /// future one-shot caller (e.g. an acceptance witness wanting one on-demand line) can reuse
    /// it without spinning up a thread first.
    fn log_wx_service_latency_snapshot(&self) {
        let e = self.exception_counters_snapshot();
        let mean_ns = if e.wx_service_latency_count == 0 {
            0
        } else {
            e.wx_service_latency_sum_ns / e.wx_service_latency_count
        };
        let mut histogram = String::new();
        for (bucket, count) in e.wx_service_latency_buckets.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            if !histogram.is_empty() {
                histogram.push(',');
            }
            let _ = std::fmt::Write::write_fmt(&mut histogram, format_args!("{bucket}:{count}"));
        }
        litebox_util_log::info!(
            count = e.wx_service_latency_count,
            mean_ns,
            max_ns = e.wx_service_latency_max_ns,
            histogram_log2_ns:% = histogram.as_str();
            "LITEBOX_HVF_DIAG_INTERVAL: wx-service-latency snapshot"
        );
    }

    /// Snapshots every counter [`HvfLifecycleResidualSnapshot`] documents. `self.registry` and
    /// `self.memory` each take their own lock independently (like every other multi-field report
    /// in this module, e.g. [`Self::exception_counters_snapshot`]), so this is a consistent
    /// point-in-time read of each individual counter, not one atomic transaction across all of
    /// them -- sufficient for the umbrella lifecycle witness, which only ever reads this with no
    /// concurrent guest activity in flight (strictly before a workload starts or strictly after
    /// every task it spawned has exited and been reaped).
    pub(crate) fn lifecycle_residual_snapshot(&self) -> HvfLifecycleResidualSnapshot {
        let usage = self.memory.usage();
        let (file_origin_objects, file_windows_live, file_alias_pages_live) = {
            let table = FILE_ORIGINS.lock();
            (
                table.by_key.len(),
                table.by_key.values().map(|origin| origin.windows).sum(),
                table.by_key.values().map(|origin| origin.alias_refs).sum(),
            )
        };
        HvfLifecycleResidualSnapshot {
            file_origin_objects,
            file_windows_live,
            file_alias_pages_live,
            active_lanes: self.registry.active(),
            custodial_lanes: self.registry.custodial(),
            retired_generations: usage.retired_generations,
            address_spaces: usage.address_spaces,
            host_slots: usage.host_slots,
            backing_objects: usage.backing_objects,
            alias_quarantine_reservations: usage.alias_quarantine_reservations,
            data_quarantine_reservations: usage.data_quarantine_reservations,
            quarantined_resources: usage.quarantined_resources,
            page_settlement_rows_pending: self.memory.total_rows_pending(),
            pinned_shared_backings: usage.pinned_shared_backings,
            claimed_pages: usage.claimed_pages,
            live_data_pages: usage.live_data_pages,
            bound_vcpus: self.registry.bound(),
            lost_vcpus: self.registry.lost(),
        }
    }

    #[track_caller]
    fn mutate_with_retry(
        &self,
        space: &HvfAddressSpace,
        kind: MutationKind,
        mut operation: impl FnMut() -> Result<HvfRangeMutation, HvfMemoryError>,
    ) -> Result<bool, HvfMemoryError> {
        let started = crate::diagnostics_counters::ticks();
        // T1f-a: attribute this mutation to the (call site, origin, kind) row it belongs to; the
        // origin is the guest activity that asked for it (a syscall number, a fault arm, a
        // teardown, ...), recorded whichever of its two attempts settles.
        let site = crate::diagnostics_counters::mutation_site_index(
            core::panic::Location::caller(),
            match kind {
                MutationKind::Map => 0,
                MutationKind::Protect => 1,
                MutationKind::Unmap => 2,
            },
            crate::diagnostics_counters::current_origin(),
        );
        let attempt = |operation: &mut dyn FnMut() -> Result<HvfRangeMutation, HvfMemoryError>| {
            let closure_started = crate::diagnostics_counters::ticks();
            let outcome = operation();
            let closure_ticks = crate::diagnostics_counters::ticks().wrapping_sub(closure_started);
            self.settle_mutation(space, kind, outcome, site, closure_ticks)
        };
        let mut result = attempt(&mut operation);
        if matches!(result, Err(HvfMemoryError::ResourceLimit { .. })) {
            result = attempt(&mut operation);
        }
        crate::diagnostics_counters::record_mutation_duration(started);
        match result {
            Err(error) if error.published_before_failure() => {
                let error = HvfBackendError::Memory(error);
                fatal(
                    match kind {
                        MutationKind::Map => "completing a published guest map",
                        MutationKind::Protect => "completing a published guest protection change",
                        MutationKind::Unmap => "completing a published guest unmap",
                    },
                    &error,
                )
            }
            result => result,
        }
    }

    /// Like [`Self::mutate_with_retry`], minus its final `published_before_failure` ->
    /// `fatal` escalation. A single guest page spans at most one claim, so a mid-operation
    /// split here (e.g. `protect_range`'s own materialize-then-publish-executable steps for
    /// a not-yet-backed page) can only ever leave that one page further along than before --
    /// never the multi-page/multi-claim inconsistency the escalation in `mutate_with_retry`
    /// exists to catch. Every caller of this (the fork-COW fault path, the W^X commit path)
    /// already treats any `Err` as an ordinary retryable miss and lets the guest re-fault, so
    /// escalating to `fatal` here would crash the whole host over a same-view concurrent
    /// thread race instead.
    #[track_caller]
    fn settle_single_page_mutation(
        &self,
        space: &HvfAddressSpace,
        kind: MutationKind,
        mut operation: impl FnMut() -> Result<HvfRangeMutation, HvfMemoryError>,
    ) -> Result<bool, HvfMemoryError> {
        let started = crate::diagnostics_counters::ticks();
        let site = crate::diagnostics_counters::mutation_site_index(
            core::panic::Location::caller(),
            match kind {
                MutationKind::Map => 0,
                MutationKind::Protect => 1,
                MutationKind::Unmap => 2,
            },
            crate::diagnostics_counters::current_origin(),
        );
        let attempt = |operation: &mut dyn FnMut() -> Result<HvfRangeMutation, HvfMemoryError>| {
            let closure_started = crate::diagnostics_counters::ticks();
            let outcome = operation();
            let closure_ticks = crate::diagnostics_counters::ticks().wrapping_sub(closure_started);
            self.settle_mutation(space, kind, outcome, site, closure_ticks)
        };
        let mut result = attempt(&mut operation);
        if matches!(result, Err(HvfMemoryError::ResourceLimit { .. })) {
            result = attempt(&mut operation);
        }
        crate::diagnostics_counters::record_mutation_duration(started);
        result
    }

    /// Whether the address space has moved past the generations a run was
    /// attached with, i.e. whether that run may have executed on a stale
    /// translation.  Only consulted on memory-abort exits.
    ///
    /// CLASS C: reads the three generations under the space's own `cell.state` lock
    /// ([`HvfAddressSpace::generation_snapshot`]) instead of taking the exclusive VM operation
    /// gate for a read, as [`HvfAddressSpace::vcpu_snapshot`] does. The generations are written
    /// only under that same lock, so the answer is the one the exclusive read returned, and the
    /// test's meaning is unchanged either way (a stale answer costs one rerun or one
    /// fault-service attempt, exactly as today).
    fn view_was_stale(&self, space: &HvfAddressSpace, snapshot: &HvfVcpuMemorySnapshot) -> bool {
        // Step GC A/B knob: `LITEBOX_HVF_CLASSC=0` puts this read back under the exclusive VM
        // operation (`vcpu_snapshot`), which is exactly what it did before this step.
        if !crate::diagnostics_counters::class_c_enabled() {
            return space.vcpu_snapshot().is_ok_and(|current| {
                current.root_generation > snapshot.root_generation
                    || current.executable_generation > snapshot.executable_generation
                    || current.pending_tlbi_generation > snapshot.pending_tlbi_generation
            });
        }
        space.generation_snapshot().is_ok_and(|(root, executable, tlbi)| {
            root > snapshot.root_generation
                || executable > snapshot.executable_generation
                || tlbi > snapshot.pending_tlbi_generation
        })
    }

    // -- page management ---------------------------------------------------

    /// Resolves `view`'s address space (via [`Self::space_for_view`]) folding
    /// [`HvfBackendError`] down to [`HvfMemoryError`] so every one of this section's page-
    /// management functions can compose it directly with the same `allocation_error`/etc.
    /// conversions they already apply to an ordinary `HvfAddressSpace` method's own error.
    /// `space_for_view`'s only realistic failure today is a wrapped [`HvfMemoryError`] (a
    /// resource limit or table-allocation failure while creating or aliasing a fresh per-view
    /// space); anything else folds to a fixed [`HvfMemoryError::Witness`] rather than inventing a
    /// new shared error shape for a case that should not occur in practice.
    fn resolve_view_space(&self, view: Option<VmViewId>) -> Result<ResolvedSpace<'_>, HvfMemoryError> {
        self.space_for_view(view).map_err(|error| match error {
            HvfBackendError::Memory(error) => error,
            _ => HvfMemoryError::Witness(
                "resolving a per-view HVF address space failed for a non-memory reason",
            ),
        })
    }

    pub(crate) fn allocate_pages(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
        view: Option<VmViewId>,
        keep_mirror_for_descendant: bool,
    ) -> Result<usize, AllocationError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(AllocationError::Unaligned);
        }
        if range.start < GUEST_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > GUEST_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if self.overlaps_reserved(&range) {
            return Err(AllocationError::AddressInUseByPlatform);
        }
        let space = self.resolve_view_space(view).map_err(allocation_error)?;
        let replace = fixed_address_behavior == FixedAddressBehavior::Replace;
        // MAP_FIXED over live pages is an unmap as far as stale views go.
        let kind = if replace {
            MutationKind::Unmap
        } else {
            MutationKind::Map
        };
        let Some(guest) = guest_permissions(permissions) else {
            // Combined write+execute, same as `update_permissions`: never
            // hand `HvfAddressSpace` a combined request (its own refusal
            // stays exactly as strict), register the range for
            // `try_resolve_wx_fault` instead, and materialize it read+write.
            // This path is reached not only for a guest `mmap(..., RWX,
            // ...)` directly, but also whenever `Vmem::reset_pages`
            // (`MADV_DONTNEED`/`MADV_FREE` on part of an already-registered
            // WX-toggle region) re-creates a mapping from its stored,
            // guest-visible `VmArea` flags -- which are legitimately RWX
            // once `update_permissions` above started accepting that. Both
            // cases need the same accommodation, or the second one panics
            // (`reset_pages`'s `.expect` treats re-establishing a
            // previously-successful mapping as infallible).
            self.wx_toggle.register(range.clone());
            self.mutate_with_retry(&space, kind, || {
                space.map_range(
                    range.clone(),
                    HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                    replace,
                    keep_mirror_for_descendant,
                )
            })
            .map_err(allocation_error)?;
            return Ok(range.start);
        };
        self.mutate_with_retry(&space, kind, || {
            space.map_range(range.clone(), guest, replace, keep_mirror_for_descendant)
        })
        .map_err(allocation_error)?;
        Ok(range.start)
    }

    pub(crate) fn allocate_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
        view: Option<VmViewId>,
    ) -> Result<usize, AllocationError> {
        if !range.start.is_multiple_of(PAGE_SIZE)
            || !range.len().is_multiple_of(PAGE_SIZE)
            || !backing_offset.is_multiple_of(PAGE_SIZE)
        {
            return Err(AllocationError::Unaligned);
        }
        if range.start < GUEST_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > GUEST_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if self.overlaps_reserved(&range) {
            return Err(AllocationError::AddressInUseByPlatform);
        }
        let space = self.resolve_view_space(view).map_err(allocation_error)?;
        let guest = guest_permissions(permissions).ok_or(AllocationError::OutOfMemory)?;
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        space
            .preflight_map_range(&range, guest)
            .map_err(allocation_error)?;
        let replaced = if fixed_address_behavior == FixedAddressBehavior::Replace {
            self.mutate_with_retry(&space, MutationKind::Unmap, || {
                space.unmap_range(range.clone(), false)
            })
            .map_err(allocation_error)?
        } else {
            false
        };
        match self.mutate_with_retry(&space, MutationKind::Map, || {
            space.map_shared_range(range.clone(), guest, key)
        }) {
            Ok(_) => Ok(range.start),
            // Same pre-publish guarantee `map_range`/`map_shared_range` already exempt on
            // (`claim_with`'s `ensure_claim_gap`/`admit_resource` admission checks always run
            // before any lock/mutation of *this* range, and every later `claim_with` failure is
            // unwound by its own cleanup helpers before it returns, so none of these three errors
            // can ever be `map_shared_range`'s own claim half-applied): an already-published
            // unmap from `replaced` above does not make a subsequent AddressOverlap/
            // MonitorOverlap/ResourceLimit on the re-claim a torn host state -- it is an ordinary
            // "another actor claimed this range first" race, or transient VM-wide claimed-page/
            // live-page budget pressure, and `allocation_error` already has the recoverable
            // `AddressInUse`/`OutOfMemory` arms for exactly these variants. Forcing them through
            // `fatal()` here turned that ordinary race/retry into a host abort.
            Err(
                error @ (HvfMemoryError::AddressOverlap(_)
                | HvfMemoryError::MonitorOverlap(_)
                | HvfMemoryError::ResourceLimit { .. }),
            ) => Err(allocation_error(error)),
            Err(error) if replaced => {
                let error = HvfBackendError::Memory(HvfMemoryError::after_publication(
                    "shared MAP_FIXED replacement",
                    error,
                ));
                fatal("completing a published shared guest map", &error)
            }
            Err(error) => Err(allocation_error(error)),
        }
    }

    pub(crate) fn deallocate_pages(
        &self,
        range: Range<usize>,
        view: Option<VmViewId>,
        keep_mirror_for_descendant: bool,
    ) -> Result<(), DeallocationError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(DeallocationError::Unaligned);
        }
        if self.overlaps_reserved(&range) {
            return Err(DeallocationError::AlreadyUnallocated);
        }
        let space = self.resolve_view_space(view).map_err(|error| {
            litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF unmap failed to resolve its per-view space");
            DeallocationError::AlreadyUnallocated
        })?;
        // `keep_mirror_for_descendant` false is the caller's own (exec-aware) finding that no live
        // descendant still inherits this space's pages -- exactly when everything retained for
        // earlier descendants can go (see `reap_fork_cow_retention`).
        if !keep_mirror_for_descendant && space.has_fork_cow_retention_checked() {
            self.reap_fork_cow_retention(view, &space);
        }
        let unmapped = self
            .mutate_with_retry(&space, MutationKind::Unmap, || {
                space.unmap_range(range.clone(), keep_mirror_for_descendant)
            })
            .map(|_| ())
            .map_err(|error| {
                litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF unmap failed");
                DeallocationError::AlreadyUnallocated
            });
        // A deferred page's real, physical stage-two mapping deliberately outlives this unmap
        // (see `keep_mirror_for_descendant`'s own doc trail in hvf_memory.rs); releasing this
        // range's W^X-toggle bookkeeping regardless would make `classify_wx_fault` forget the
        // range is under W^X emulation at all -- a fresh COW alias installed later at the exact
        // same GVA would then see a real, permission-level instruction/data abort neither
        // `try_resolve_cow_fault` nor `classify_wx_fault` recognizes as their own, falling through
        // to a genuine (and wrong) SIGSEGV instead of the ordinary lazy RW/RX flip. `register`
        // still fully resets this range's tracking the moment the ancestor claims fresh RWX here,
        // so its own subsequent placement traffic is unaffected either way.
        if unmapped.is_ok() && !keep_mirror_for_descendant {
            self.wx_toggle.release(&range);
        }
        // Outside the space operation above: an origin whose last window/alias this unmap
        // released is unmapped from the registry's own queue, never inside `unmap_range`.
        self.drain_origin_release_candidates();
        unmapped
    }

    pub(crate) fn update_permissions(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        view: Option<VmViewId>,
    ) -> Result<(), PermissionUpdateError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(PermissionUpdateError::Unaligned);
        }
        if self.overlaps_reserved(&range) {
            return Err(PermissionUpdateError::Unallocated);
        }
        let space = self.resolve_view_space(view).map_err(|error| {
            litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF protect failed to resolve its per-view space");
            PermissionUpdateError::Unallocated
        })?;
        self.diverge_fork_write_protected_pages(&space, &range);
        let Some(guest) = guest_permissions(permissions) else {
            // Combined write+execute: `guest_permissions` only ever refuses
            // this exact combination (see its own body), so reaching here
            // unambiguously means the guest wants RWX. Never ask
            // `HvfAddressSpace` for that -- `refuse_write_execute` inside it
            // (and every one of its own callers) refuses it too, and that
            // invariant is not weakened by any of this. Instead grant the
            // guest's logical view as RWX (real Linux's own promise) while
            // registering the range for `try_resolve_wx_fault` to enforce a
            // real, single-direction stage-2 permission on each page,
            // flipping it lazily on demand. See `WxToggle`'s doc comment.
            self.wx_toggle.register(range.clone());
            return self
                .protect_view_range(
                    &space,
                    range.clone(),
                    HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                    true,
                )
                .map_err(|error| {
                    litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF WX-toggle registration protect failed");
                    PermissionUpdateError::Unallocated
                });
        };
        // An ordinary, non-combined permission change means the guest is
        // deliberately leaving whatever regime it had (including a prior
        // WX-toggle registration) -- release it so a later fault here is
        // never misattributed to this mechanism.
        self.wx_toggle.release(&range);
        self.protect_view_range(
            &space,
            range.clone(),
            guest,
            permissions.contains(MemoryRegionPermissions::EXEC),
        )
            .map_err(|error| {
                litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF protect failed");
                PermissionUpdateError::Unallocated
            })
    }

    /// `protect_range` over `range` in `space`, minus the assumption that every page there is
    /// one of `space`'s own claims: a per-view space also holds promoted pages (an independent
    /// copy reached through a redirect, see `AddressSpaceState::promoted`), which are
    /// reprotected one at a time; own claims are protected in address-ordered runs. A page held
    /// only as a COW read alias, or not at all, is refused exactly as before.
    fn protect_view_range(
        &self,
        space: &HvfAddressSpace,
        range: Range<usize>,
        guest: HvfGuestPermissions,
        requested_execute: bool,
    ) -> Result<(), HvfMemoryError> {
        space.check_invariants_range(&range, GrSite::MutationBoundary);
        let (has_cow, _) =
            space.settle_gate(GrSite::HasCowPagesIn, || space.has_cow_pages_in(&range));
        if !has_cow {
            return self
                .mutate_with_retry(space, MutationKind::Protect, || {
                    space.protect_range(range.clone(), guest)
                })
                .map(|_| ());
        }
        let (kinds, _) = space.settle_gate(GrSite::PageKinds, || space.page_kinds(&range));
        let mut index = 0;
        while index < kinds.len() {
            let (page, kind) = kinds[index];
            match kind {
                PageKind::Own => {
                    let mut end = index + 1;
                    while end < kinds.len() && kinds[end].1 == PageKind::Own {
                        end += 1;
                    }
                    let run = page..kinds[end - 1].0 + PAGE_SIZE;
                    self.mutate_with_retry(space, MutationKind::Protect, || {
                        space.protect_range(run.clone(), guest)
                    })?;
                    index = end;
                }
                PageKind::Promoted => {
                    self.settle_single_page_mutation(space, MutationKind::Protect, || {
                        space.materialize_page_with_permissions(None, page, guest)
                    })?;
                    index += 1;
                }
                PageKind::FileAlias | PageKind::FileWindow => {
                    let mut end = index + 1;
                    while end < kinds.len() && kinds[end].1 == kind {
                        end += 1;
                    }
                    let run = page..kinds[end - 1].0 + PAGE_SIZE;
                    self.materialize_file_run(space, run, kind, guest, requested_execute, &|_| None)?;
                    index = end;
                }
                PageKind::Alias | PageKind::Missing => {
                    return Err(HvfMemoryError::RangeUnmapped(page..page + PAGE_SIZE));
                }
            }
        }
        Ok(())
    }

    /// `PageManagementProvider::materialize_inherited_range`'s real implementation: a fork
    /// child's `mprotect` of memory it holds only by lineage. Every page of `range` ends up as
    /// `view`'s own independent page at exactly `permissions` (see
    /// `HvfAddressSpace::materialize_page_with_permissions`); own claims and pages nobody in the
    /// lineage has content for are handled in address-ordered runs, aliases and promoted pages
    /// one at a time. `ancestor_of` names the view whose content a page inherits.
    pub(crate) fn materialize_inherited_range(
        &self,
        view: VmViewId,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        ancestor_of: &dyn Fn(usize) -> Option<VmViewId>,
    ) -> Result<(), PermissionUpdateError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(PermissionUpdateError::Unaligned);
        }
        if self.overlaps_reserved(&range) || range.len() / PAGE_SIZE > MATERIALIZE_PAGE_BOUND {
            return Err(PermissionUpdateError::Unallocated);
        }
        let space = self.resolve_view_space(Some(view)).map_err(|error| {
            litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF materialize failed to resolve its per-view space");
            PermissionUpdateError::Unallocated
        })?;
        self.diverge_fork_write_protected_pages(&space, &range);
        let guest = match guest_permissions(permissions) {
            Some(guest) => {
                self.wx_toggle.release(&range);
                guest
            }
            None => {
                self.wx_toggle.register(range.clone());
                HvfGuestPermissions::READ | HvfGuestPermissions::WRITE
            }
        };
        let ancestor_space = |page: usize| {
            ancestor_of(page)
                .filter(|ancestor| *ancestor != view)
                .and_then(|ancestor| self.existing_space_for_view(ancestor))
        };
        let inherits_content = |page: usize| {
            ancestor_space(page).is_some_and(|ancestor| ancestor.has_page_content(page))
        };
        space.check_invariants_range(&range, GrSite::MutationBoundary);
        let (kinds, _) = space.settle_gate(GrSite::PageKinds, || space.page_kinds(&range));
        let mut index = 0;
        while index < kinds.len() {
            let (page, kind) = kinds[index];
            // File pages first, in runs of one kind: an untouched window page must never enter
            // the fresh-zero run below (`has_page_content` is false for it by design), and a
            // file alias is rewritten, not promoted, unless the parent's pre-fork promotion
            // supplies real content.
            if kind == PageKind::FileAlias || kind == PageKind::FileWindow {
                let mut end = index + 1;
                while end < kinds.len() && kinds[end].1 == kind {
                    end += 1;
                }
                let run = page..kinds[end - 1].0 + PAGE_SIZE;
                self.materialize_file_run(
                    &space,
                    run.clone(),
                    kind,
                    guest,
                    permissions.contains(MemoryRegionPermissions::EXEC),
                    &ancestor_space,
                )
                    .map_err(|error| {
                        litebox_util_log::warn!(view:? = view, start:? = run.start, end:? = run.end, kind:? = kind, error:% = error; "HVF materialize failed");
                        PermissionUpdateError::Unallocated
                    })?;
                index = end;
                continue;
            }
            let run_of_own = kind == PageKind::Own;
            let run_of_fresh = kind == PageKind::Missing && !inherits_content(page);
            if run_of_own || run_of_fresh {
                let mut end = index + 1;
                while end < kinds.len() {
                    let (next_page, next_kind) = kinds[end];
                    let same = if run_of_own {
                        next_kind == PageKind::Own
                    } else {
                        next_kind == PageKind::Missing && !inherits_content(next_page)
                    };
                    if !same {
                        break;
                    }
                    end += 1;
                }
                let run = page..kinds[end - 1].0 + PAGE_SIZE;
                let result = if run_of_own {
                    self.mutate_with_retry(&space, MutationKind::Protect, || {
                        space.protect_range(run.clone(), guest)
                    })
                } else {
                    self.mutate_with_retry(&space, MutationKind::Map, || {
                        space.map_range(run.clone(), guest, false, false)
                    })
                };
                result.map_err(|error| {
                    litebox_util_log::warn!(view:? = view, start:? = run.start, end:? = run.end, own:? = run_of_own, error:% = error; "HVF materialize failed");
                    PermissionUpdateError::Unallocated
                })?;
                index = end;
                continue;
            }
            let ancestor = ancestor_space(page);
            self.settle_single_page_mutation(&space, MutationKind::Protect, || {
                space.materialize_page_with_permissions(ancestor.as_deref(), page, guest)
            })
            .map_err(|error| {
                litebox_util_log::warn!(view:? = view, page:? = page, kind:? = kind, error:% = error; "HVF materialize failed");
                PermissionUpdateError::Unallocated
            })?;
            index += 1;
        }
        Ok(())
    }

    pub(crate) fn remap_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
        view: Option<VmViewId>,
    ) -> Result<usize, RemapError> {
        if !old_range.start.is_multiple_of(PAGE_SIZE)
            || !old_range.len().is_multiple_of(PAGE_SIZE)
            || !new_range.start.is_multiple_of(PAGE_SIZE)
            || !new_range.len().is_multiple_of(PAGE_SIZE)
            || !backing_offset.is_multiple_of(PAGE_SIZE)
        {
            return Err(RemapError::Unaligned);
        }
        if overlaps(&old_range, &new_range) {
            return Err(RemapError::Overlapping);
        }
        if new_range.len() < old_range.len() {
            return Err(RemapError::OutOfMemory);
        }
        let Some(guest) = guest_permissions(permissions) else {
            return Err(RemapError::OutOfMemory);
        };
        let space = match self.resolve_view_space(view) {
            Ok(space) => space,
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "HVF shared remap failed to resolve its per-view space");
                return Err(RemapError::OutOfMemory);
            }
        };
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        let transaction = process_hvf_vm()
            .map_err(HvfMemoryError::from)
            .and_then(|vm| {
                vm.with_operation(|_| {
                    space.preflight_mapped_range(&old_range)?;
                    space.preflight_map_range(&new_range, guest)?;
                    self.mutate_with_retry(&space, MutationKind::Map, || {
                        space.map_shared_range(new_range.clone(), guest, key)
                    })?;
                    // `changed == false` from this unmap never means "old range still mapped":
                    // `preflight_mapped_range` proved it fully claimed before anything was
                    // published, and a mirrored space (every real guest space) settles the
                    // retired pieces itself and returns a no-op ticket; see `unmap_range`.
                    match self.mutate_with_retry(&space, MutationKind::Unmap, || {
                        space.unmap_range(old_range.clone(), false)
                    }) {
                        Ok(_) => Ok(new_range.start),
                        Err(error) => Err(error),
                    }
                })
            });
        match transaction {
            Ok(start) => Ok(start),
            Err(error) if error.published_before_failure() => {
                let error = HvfBackendError::Memory(error);
                fatal("completing a published shared guest remap", &error)
            }
            Err(HvfMemoryError::RangeUnmapped(_)) => Err(RemapError::AlreadyUnallocated),
            Err(HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_)) => {
                Err(RemapError::AlreadyAllocated)
            }
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "HVF shared remap failed before publication");
                Err(RemapError::OutOfMemory)
            }
        }
    }

    #[track_caller]
    pub(crate) fn initialize_shared_pages<E>(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        length: usize,
        mut initialize: impl FnMut(Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(end) = backing_offset.checked_add(length) else {
            return Ok(());
        };
        let requested = backing_offset..end;
        loop {
            let mut registry = self
                .shared_initialization
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let initialized = registry
                .initialized
                .get(&backing_identity)
                .cloned()
                .unwrap_or_default();
            let missing = subtract_ranges(&requested, &initialized);
            if missing.is_empty() {
                return Ok(());
            }
            let in_progress = registry
                .in_progress
                .get(&backing_identity)
                .cloned()
                .unwrap_or_default();
            let claimable = missing
                .iter()
                .flat_map(|range| subtract_ranges(range, &in_progress))
                .next();
            let Some(claim) = claimable else {
                // CLASS A: the ranked lock's own condvar wait -- the registry's rank is released
                // for the park, so this is a violation only when something ELSE is held.
                registry = self
                    .shared_initialization
                    .wait_on(&self.shared_initialization_changed, registry)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(registry);
                continue;
            };
            registry
                .in_progress
                .entry(backing_identity)
                .or_default()
                .push(claim.clone());
            drop(registry);

            let relative = (claim.start - backing_offset)..(claim.end - backing_offset);
            let result = initialize(relative);

            // CLASS A: the registry is a ranked lock, so taking it through `lock()` is the check;
            // nothing is parked on it here.
            let mut registry = self
                .shared_initialization
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(list) = registry.in_progress.get_mut(&backing_identity) {
                list.retain(|range| *range != claim);
            }
            if result.is_ok() {
                let list = registry.initialized.entry(backing_identity).or_default();
                list.push(claim);
                normalize_ranges(list);
            }
            self.shared_initialization_changed.notify_all();
            drop(registry);
            result?;
        }
    }

    #[track_caller]
    fn wait_shared_initialization(&self, backing_identity: usize, requested: &Range<usize>) {
        // CLASS A: same shape as the wait above -- the registry is taken and parked through the
        // ranked wrapper, so its own rank is released for the park.
        let mut registry = self
            .shared_initialization
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let busy = registry
                .in_progress
                .get(&backing_identity)
                .is_some_and(|list| list.iter().any(|range| overlaps(range, requested)));
            if !busy {
                return;
            }
            registry = self
                .shared_initialization
                .wait_on(&self.shared_initialization_changed, registry)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    pub(crate) fn read_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &mut [u8],
    ) -> Result<(), SharedPageIoError> {
        let end = backing_offset
            .checked_add(data.len())
            .ok_or(SharedPageIoError::OutOfRange)?;
        self.wait_shared_initialization(backing_identity, &(backing_offset..end));
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        self.memory
            .with_shared_backing(key, data.len(), |bytes| data.copy_from_slice(bytes))
            .map_err(|_| SharedPageIoError::Io)
    }

    pub(crate) fn write_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &[u8],
    ) -> Result<(), SharedPageIoError> {
        let end = backing_offset
            .checked_add(data.len())
            .ok_or(SharedPageIoError::OutOfRange)?;
        self.wait_shared_initialization(backing_identity, &(backing_offset..end));
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        self.memory
            .with_shared_backing(key, data.len(), |bytes| bytes.copy_from_slice(data))
            .map_err(|_| SharedPageIoError::Io)?;
        self.mark_initialized(backing_identity, backing_offset..end);
        Ok(())
    }

    pub(crate) fn zero_shared_pages(
        &self,
        backing_identity: usize,
        backing_range: Range<usize>,
    ) -> Result<(), SharedPageIoError> {
        if backing_range.is_empty() {
            return Ok(());
        }
        self.wait_shared_initialization(backing_identity, &backing_range);
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_range.start,
        };
        self.memory
            .with_shared_backing(key, backing_range.len(), |bytes| bytes.fill(0))
            .map_err(|_| SharedPageIoError::Io)?;
        self.mark_initialized(backing_identity, backing_range);
        Ok(())
    }

    /// Releases this caller's pin on the process-global shared backing object
    /// `backing_identity` -- see [`HvfMemory::release_shared_backing`]. A thin passthrough: the
    /// pin (like the shared object itself) is process-global, not per-view, so unlike
    /// `allocate_shared_pages`/`deallocate_pages` this needs no address-space resolution.
    pub(crate) fn forget_shared_backing(&self, backing_identity: usize) -> Result<(), SharedPageIoError> {
        self.memory
            .release_shared_backing(backing_identity)
            .map(|_fully_released| ())
            .map_err(|_| SharedPageIoError::Io)
    }

    fn mark_initialized(&self, backing_identity: usize, range: Range<usize>) {
        // CLASS A: the registry is a ranked lock; nothing is parked on it here, so `lock()` is
        // the whole check.
        let mut registry = self
            .shared_initialization
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = registry.initialized.entry(backing_identity).or_default();
        list.push(range);
        normalize_ranges(list);
        self.shared_initialization_changed.notify_all();
    }

}

// ---------------------------------------------------------------------------
// BCORE: a vCPU a guest thread owns instead of borrowing from the lane pool.
// ---------------------------------------------------------------------------
//
// A pooled run pays ~11-11.7 us of lane hand-off per guest syscall: the task thread stamps a
// command, wakes the lane's owner thread, waits, and is woken back -- two kernel wakeups plus a
// channel and whole-state copies -- because Hypervisor.framework only lets the thread that
// created a vCPU run it. A bound vCPU removes the boundary: the guest thread creates its own
// vCPU and calls `hv_vcpu_run` itself, so the hand-off disappears and only the hypervisor's
// own entry/exit cost and the shim's service remain.
//
// Everything else stays exactly as it is on the pooled path: the bound vCPU registers an
// ordinary memory-manager participant, attaches through `attach_submitted_vcpu`, takes the
// synchronization monitor trip when the space's generations moved, is cancelled through the
// same `RunControl` (`hv_vcpus_exit` is the one SDK call that is *not* owner-affine), and is
// destroyed on its owner thread before the thread leaves the run loop.
//
// Behind `LITEBOX_HVF_BOUND=0` (the default) `bound_enabled()` is a cached `false`, every hook
// is one predicted branch, and the pooled path is byte-for-byte the one it always was.

/// BCORE: the knob. `LITEBOX_HVF_BOUND=1` turns the bound path on; anything else (including
/// unset) leaves it off. Read once, cached -- the same default-off pattern `LITEBOX_HVF_LANES`
/// uses in [`HvfBackend::create`].
///
/// Forced off under `LITEBOX_HVF_LANES`: the lane-count override exists to exercise the pooled
/// path at a fixed pool size, and the two are mutually exclusive by construction.
fn bound_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if !std::env::var_os("LITEBOX_HVF_BOUND").is_some_and(|value| value == "1") {
            return false;
        }
        if std::env::var_os("LITEBOX_HVF_LANES").is_some() {
            litebox_util_log::warn!(
                "LITEBOX_HVF_BOUND=1 ignored: LITEBOX_HVF_LANES is set (the lane-count override and the bound path are mutually exclusive)"
            );
            return false;
        }
        true
    })
}

/// BCORE-4: how many pooled iterations inside [`BOUND_TRIGGER_WINDOW`] make a thread "hot"
/// enough to take a vCPU of its own. 32 exits in 4 ms is a thread doing nothing but
/// syscalling, which is exactly the shape the lane hand-off dominates.
const BOUND_TRIGGER_EXITS: u32 = 32;
const BOUND_TRIGGER_WINDOW: Duration = Duration::from_millis(4);
/// BCORE-4: a bound thread that has not run for this long gives its vCPU back, so a thread
/// that blocked in a slow syscall does not hold a vCPU while it waits.
const BOUND_IDLE_UNBIND: Duration = Duration::from_millis(200);

/// BCORE-4: the address space a bound thread's participant is registered in, owned. A lane
/// reaches the same thing through `ResolvedSpace`, which borrows the backend; a bound thread
/// outlives any single call, so it needs its own handle.
enum BoundSpace {
    Default,
    View(Arc<HvfAddressSpace>),
}

impl BoundSpace {
    fn get<'a>(&'a self, backend: &'a HvfBackend) -> &'a HvfAddressSpace {
        match self {
            Self::Default => &backend.default_space,
            Self::View(space) => space,
        }
    }
}

/// BCORE-4: one live bound vCPU as the rest of the backend sees it. A mapping mutation kicks
/// these exactly the way it kicks running lanes: they are participants of the mutated space
/// too, so they owe the same acknowledgement.
pub(crate) struct BoundEntry {
    generation: u64,
    /// The address space this vCPU's participant is registered in, so a mutation aimed at one
    /// space's participants needs no look-up under a lock.
    space_tag: AtomicU64,
    control: Arc<RunControl>,
    cancellation: HvfVcpuCancellation,
    /// Host ticks of this vCPU's last exit: the pick for pressure eviction.
    last_exit_ns: AtomicU64,
    /// BCORE-4: another thread could not get a slot and picked this entry to give one up. The
    /// victim unbinds at its own loop top -- never synchronously, so an unbind never runs
    /// inside someone else's mutation.
    evict_requested: AtomicBool,
    /// BCORE-4 (fix-up): a mapping mutation's shootdown asked this vCPU to re-evaluate at its
    /// own loop top. Only the owner thread may `hv_vcpu_run` (Hypervisor.framework is
    /// owner-affine), so a shootdown cannot synchronize a bound vCPU the way it does an idle
    /// lane; it can only ask, and the ask is answered here.
    sync_requested: AtomicBool,
    /// BCORE-5 (fix-up): a thread-exit unbind that had to wait because the thread was inside
    /// its own dispatch when the shim asked for it.
    unbind_requested: AtomicBool,
    thread: crate::ThreadHandle,
}

/// BCORE-4: a guest thread's own vCPU, plus what the run loop needs to drive it.
///
/// `participant` is `None` only for the instant inside a view migration, where it has been
/// moved out to be passed by value into `migrate_vcpu_participant`; every failure path there
/// unbinds instead of leaving it empty.
struct BoundThread {
    vcpu: HvfBoundVcpu,
    participant: Option<HvfVcpuParticipant>,
    /// The view this vCPU's participant is registered against; a change migrates it.
    view: Option<VmViewId>,
    space: BoundSpace,
    entry: Arc<BoundEntry>,
    /// When this vCPU last exited: the idle-eviction clock.
    last_exit: Instant,
}

impl Drop for BoundThread {
    /// BCORE2-FX: the unwind arm of the teardown, made to discharge the participant too.
    ///
    /// `vcpu` is declared before `participant`, so Rust drops (and destroys) the vCPU first;
    /// only afterwards would `HvfVcpuParticipant::drop` run, and that destructor does no more
    /// than mark the capability `PARTICIPANT_ABANDONED` -- it does not remove the record from
    /// `AddressSpaceState::participants`. `HvfAddressSpace::begin_destroy` refuses with
    /// `AddressSpaceBusy` while that map is non-empty, so before this destructor existed one
    /// unwound bound owner stranded its address space for the life of the process.
    ///
    /// This destructor runs before any field falls, so the participant is discharged BEFORE
    /// the vCPU is destroyed -- the order `unbind_current_thread` uses, through the same
    /// [`HvfBackend::discharge_bound_participant`] it calls.
    fn drop(&mut self) {
        // `active()` is `None` only once the backend itself is gone, in which case there is no
        // space left to deregister against.
        if let Some(backend) = crate::hvf_backend::active() {
            backend.discharge_bound_participant(self);
        }
    }
}

/// What [`HvfBackend::bound_iteration`] decided for one loop pass.
enum BoundOutcome {
    /// The bound path ran one iteration; the caller continues its loop with this disposition.
    Ran(ContinueOperation),
    /// This thread is not bound (any more): fall through to the pooled path.
    Unbound,
}

impl HvfBackend {
    /// BCORE-4: gives the calling thread a vCPU of its own, registered as a participant of
    /// `view`'s address space. `false`, with no side effects, when the registry refused, the
    /// space could not be resolved, or the participant could not be registered -- the caller
    /// then simply stays on the pool.
    fn bind_current_thread(&self, view: Option<VmViewId>) -> bool {
        if HVF_THREAD.with(|context| context.borrow().bound.is_some()) {
            return true;
        }
        let space = match self.space_for_view(view) {
            Ok(space) => space,
            Err(error) => {
                litebox_util_log::debug!(error:% = error; "HVF bound vCPU: address space unresolved");
                return false;
            }
        };
        let owned = match &space {
            ResolvedSpace::Default(_) => BoundSpace::Default,
            ResolvedSpace::View(space) => BoundSpace::View(Arc::clone(space)),
        };
        let space_tag = space.id().value();
        let mut vcpu = match HvfBoundVcpu::bind(&self.registry, &self.el1) {
            Ok(vcpu) => vcpu,
            Err(error) => {
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_BIND_REFUSED,
                    1,
                );
                // BCORE-4: the budget is spent. Ask the bound entry that has gone longest
                // without an exit to give its vCPU up; it does so at its own loop top, so an
                // unbind never runs inside someone else's mutation. This thread stays on the
                // pool either way -- a refusal never waits.
                self.request_bound_eviction();
                litebox_util_log::debug!(error:% = error; "HVF bound vCPU: bind refused");
                return false;
            }
        };
        // A bound run installs the FULL register file, so the thread's authoritative SIMD/FP
        // file must be on the host before the first one: a file still resident in a lane would
        // otherwise be installed as zeros.
        HVF_THREAD.with(|context| {
            let _ = context.borrow_mut().materialized_fp();
        });
        let participant =
            match owned
                .get(self)
                .register_vcpu_participant(vcpu.participant_capability())
            {
                Ok(participant) => participant,
                Err(error) => {
                    litebox_util_log::debug!(error:% = error; "HVF bound vCPU: participant registration failed");
                    vcpu.stop_owner();
                    let _ = vcpu.unbind(false);
                    crate::diagnostics_counters::add_stat(
                        crate::diagnostics_counters::BOUND_BIND_REFUSED,
                        1,
                    );
                    return false;
                }
            };
        let entry = Arc::new(BoundEntry {
            generation: vcpu.generation(),
            space_tag: AtomicU64::new(space_tag),
            control: vcpu.control(),
            cancellation: vcpu.sdk_cancellation(),
            last_exit_ns: AtomicU64::new(crate::diagnostics_counters::ticks()),
            evict_requested: AtomicBool::new(false),
            sync_requested: AtomicBool::new(false),
            unbind_requested: AtomicBool::new(false),
            thread: crate::ThreadHandle::current(),
        });
        self.bound_entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::clone(&entry));
        crate::diagnostics_counters::add_stat(crate::diagnostics_counters::BOUND_LIVE, 1);
        HVF_THREAD.with(|context| {
            context.borrow_mut().bound = Some(BoundThread {
                vcpu,
                participant: Some(participant),
                view,
                space: owned,
                entry,
                last_exit: Instant::now(),
            });
        });
        true
    }

    /// BCORE-5: gives this thread's bound vCPU back and deregisters its participant.
    ///
    /// Order matters: `owner_stopped` must be set BEFORE the deregistration, because that is
    /// what lets `deregister_vcpu_participant` acknowledge retirements this participant still
    /// owes instead of refusing with `ParticipantRetirementPending` (which would strand a
    /// retirement row and, with it, an address space). That order lives in
    /// [`Self::discharge_bound_participant`], which `Drop for BoundThread` calls too -- so an
    /// owner thread that unwinds past `unbind_current_thread` discharges its participant by
    /// exactly the same steps instead of stranding the record.
    pub(crate) fn unbind_current_thread(&self, reason: usize) {
        let Some(mut bound) = HVF_THREAD.with(|context| context.borrow_mut().bound.take()) else {
            return;
        };
        self.discharge_bound_participant(&mut bound);
        self.remove_bound_entry(bound.vcpu.generation());
        // BCORE-2 (fix-up): `unbind` terminalizes this vCPU's control before destroying it, so
        // a kick still outstanding at teardown is reported (`kicks_abandoned` /
        // `kicks_expired_terminal`) instead of silently dropped, and any thread still waiting
        // on a cancellation attempt is completed with `Terminalized`. `BOUND_UNBINDS_FAILED` is
        // the one reason that can follow a run error, so it is the one that terminalizes as
        // untrusted; every orderly teardown is not.
        let untrusted = reason == crate::diagnostics_counters::BOUND_UNBINDS_FAILED;
        if bound.vcpu.unbind(untrusted).is_err() {
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_UNBINDS_FAILED,
                1,
            );
        }
        crate::diagnostics_counters::add_stat(reason, 1);
        // `BOUND_LIVE` is a gauge: `u64::MAX` is a wrapping -1.
        crate::diagnostics_counters::add_stat(crate::diagnostics_counters::BOUND_LIVE, u64::MAX);
    }

    /// BCORE2-FX: discharges a bound vCPU's participant -- the one step a destroyed vCPU cannot
    /// do for itself, and the one that keeps its address space destroyable.
    ///
    /// `stop_owner` first: it is what lets `deregister_vcpu_participant` acknowledge the
    /// retirements this participant owes instead of refusing with `ParticipantRetirementPending`
    /// (which would strand a retirement row and, with it, an address space). Then the
    /// deregistration; then, if that refused, participant recovery.
    ///
    /// Both teardown arms call it -- [`Self::unbind_current_thread`] (the orderly one) and
    /// `Drop for BoundThread` (an owner thread that unwound) -- so the two cannot drift. It is
    /// panic-safe on purpose: it runs inside a destructor on the unwind arm, where a second
    /// panic would abort the process.
    fn discharge_bound_participant(&self, bound: &mut BoundThread) {
        bound.vcpu.stop_owner();
        let Some(mut participant) = bound.participant.take() else {
            return;
        };
        let generation = bound.vcpu.generation();
        let space = bound.space.get(self);
        let deregistered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            space.deregister_vcpu_participant(&mut participant)
        }));
        if matches!(deregistered, Ok(Ok(()))) {
            return;
        }
        if let Ok(Err(error)) = &deregistered {
            litebox_util_log::warn!(
                error:% = error, generation:? = generation;
                "HVF bound vCPU: participant deregistration failed; running participant recovery"
            );
        }
        crate::diagnostics_counters::add_stat(
            crate::diagnostics_counters::BOUND_DEREGISTER_FAILED,
            1,
        );
        // The handle's own `Drop` marks the capability `PARTICIPANT_ABANDONED`, which is
        // exactly the shape `recover_stopped_vcpu_participants` repairs: it removes the record
        // from the space and acknowledges this participant's owed retirements on its behalf.
        // Without it the record lives as long as the process does, and `begin_destroy` answers
        // `AddressSpaceBusy` for that whole time.
        drop(participant);
        let recovered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            space.recover_stopped_vcpu_participants()
        }));
        match recovered {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                litebox_util_log::warn!(
                    error:% = error, generation:? = generation;
                    "HVF bound vCPU: participant recovery failed"
                );
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_DEREGISTER_RECOVERY_FAILED,
                    1,
                );
            }
            Err(_) => {
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_DEREGISTER_RECOVERY_FAILED,
                    1,
                );
            }
        }
    }

    /// BCORE-5: drops the [`BoundEntry`] for `generation`, if one is still listed.
    ///
    /// Both paths that destroy a bound vCPU call it -- [`Self::unbind_current_thread`] (the
    /// orderly one) and `HvfBoundVcpu::drop` (an owner thread that unwound) -- so a vCPU that
    /// is gone is never left in [`Self::bound_entries`] for the mutation kick rounds and the
    /// pressure-eviction pick to walk.
    pub(crate) fn remove_bound_entry(&self, generation: u64) {
        self.bound_entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|entry| entry.generation != generation);
    }

    /// BCORE-4: moves a bound vCPU's participant to `view`'s address space. `false` on any
    /// failure, after which the caller unbinds (a vCPU registered in the wrong space may not
    /// run at all).
    fn migrate_bound_thread(&self, view: Option<VmViewId>) -> bool {
        let target = match self.space_for_view(view) {
            Ok(space) => space,
            Err(_) => return false,
        };
        let owned = match &target {
            ResolvedSpace::Default(_) => BoundSpace::Default,
            ResolvedSpace::View(space) => BoundSpace::View(Arc::clone(space)),
        };
        let target_tag = target.id().value();
        let (capability, old) = match HVF_THREAD.with(|context| {
            let mut context = context.borrow_mut();
            let bound = context.bound.as_mut()?;
            Some((bound.vcpu.participant_capability(), bound.participant.take()?))
        }) {
            Some(pair) => pair,
            None => return false,
        };
        let source_view = HVF_THREAD.with(|context| context.borrow().bound.as_ref()?.view);
        let source = match self.space_for_view(source_view) {
            Ok(space) => space,
            Err(_) => return false,
        };
        match owned
            .get(self)
            .migrate_vcpu_participant(&source, old, capability)
        {
            Ok(participant) => {
                HVF_THREAD.with(|context| {
                    let mut context = context.borrow_mut();
                    if let Some(bound) = context.bound.as_mut() {
                        bound.participant = Some(participant);
                        bound.space = owned;
                        bound.view = view;
                        bound.entry.space_tag.store(target_tag, Ordering::Release);
                    }
                });
                true
            }
            Err(error) => {
                litebox_util_log::debug!(error:% = error; "HVF bound vCPU: view migration failed");
                false
            }
        }
    }

    /// BCORE-4/BCORE-3: one bound run, or [`BoundOutcome::Unbound`] when this thread has no
    /// bound vCPU (and did not just take one).
    fn bound_iteration(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
        slot: &HvfThreadSlot,
        view: Option<VmViewId>,
        streak: &mut (Instant, u32),
    ) -> BoundOutcome {
        use crate::diagnostics_counters::{
            BOUND_ELIGIBLE_HANDOFFS, BOUND_GATE_LOCKS, BOUND_RUNS, BOUND_UNBINDS_FAILED,
            BOUND_UNBINDS_IDLE, BOUND_UNBINDS_INELIGIBLE, BOUND_UNBINDS_PRESSURE,
        };
        // BCORE-5 (fix-up): everything below runs with this thread's bound vCPU live, so a
        // `Task::drop` on this thread (a failed `spawn_thread`, an aborted `ProcessLaunch`) must
        // not be able to unbind it from inside the dispatch -- it defers instead, and the loop
        // top honours the request here.
        BOUND_DISPATCH_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        let _dispatch_scope = BoundDispatchScope;
        let now = Instant::now();
        // BCORE-5 (fix-up): a deferred unbind from this thread's own dispatch. Safe here:
        // between exits, with the vCPU idle, and before any address space can be torn down.
        if HVF_THREAD.with(|context| {
            context
                .borrow()
                .bound
                .as_ref()
                .is_some_and(|bound| bound.entry.unbind_requested.swap(false, Ordering::AcqRel))
        }) {
            self.unbind_current_thread(crate::diagnostics_counters::BOUND_UNBINDS_EXIT);
            return BoundOutcome::Unbound;
        }
        let bound_present = HVF_THREAD.with(|context| context.borrow().bound.is_some());
        if !bound_present {
            // A task whose process still shares its parent's address space (the vfork window)
            // may not take a vCPU of its own: handing a shared space to a waiter requires
            // quiescing every participant, and a bound participant is only quiesced at its own
            // loop top.
            if !crate::current_vcpu_bind_eligible() {
                return BoundOutcome::Unbound;
            }
            if now.duration_since(streak.0) > BOUND_TRIGGER_WINDOW {
                *streak = (now, 1);
            } else {
                streak.1 = streak.1.saturating_add(1);
            }
            crate::diagnostics_counters::add_stat(BOUND_ELIGIBLE_HANDOFFS, 1);
            if streak.1 < BOUND_TRIGGER_EXITS {
                return BoundOutcome::Unbound;
            }
            if !self.bind_current_thread(view) {
                // Refused: stop trying for another window instead of retrying every exit.
                *streak = (now, 0);
                return BoundOutcome::Unbound;
            }
        }
        // From here the thread is bound. Every path that gives the vCPU up unbinds and returns
        // `Unbound`, so the caller falls through to the pool for exactly one pass.
        //
        // Step GF (fix-up): a bound thread runs on a vCPU of its own and never asks the pool for a
        // lane, so a lease it retained on an earlier *unbound* pass would otherwise sit in
        // [`RETAINED_LANE`] unchecked -- the caller's `BoundOutcome::Ran(_) => continue` returns
        // before `take_retained_lane`, so neither the waiter check nor the retention bounds ever
        // ran for it. Give it up at the point the thread becomes bound.
        release_retained_lane(crate::diagnostics_counters::LANE_STICKY_RELEASED_YIELD);
        if !crate::current_vcpu_bind_eligible() {
            self.unbind_current_thread(BOUND_UNBINDS_INELIGIBLE);
            return BoundOutcome::Unbound;
        }
        if HVF_THREAD.with(|context| {
            context
                .borrow()
                .bound
                .as_ref()
                .is_some_and(|bound| now.duration_since(bound.last_exit) > BOUND_IDLE_UNBIND)
        }) {
            self.unbind_current_thread(BOUND_UNBINDS_IDLE);
            return BoundOutcome::Unbound;
        }
        if HVF_THREAD.with(|context| {
            context
                .borrow()
                .bound
                .as_ref()
                .is_some_and(|bound| bound.entry.evict_requested.load(Ordering::Acquire))
        }) {
            self.unbind_current_thread(BOUND_UNBINDS_PRESSURE);
            return BoundOutcome::Unbound;
        }
        // BCORE-4 (fix-up): a mapping mutation's shootdown asked this vCPU to re-evaluate. It
        // cannot synchronize a bound vCPU the way it synchronizes an idle lane -- only the
        // thread that created the vCPU may `hv_vcpu_run` it -- so it asks, and the ask is
        // answered here: the attach below sees the space's moved generation and synchronizes
        // (acknowledging whatever retirement this vCPU owes) on this very iteration.
        if HVF_THREAD.with(|context| {
            context
                .borrow()
                .bound
                .as_ref()
                .is_some_and(|bound| bound.entry.sync_requested.swap(false, Ordering::AcqRel))
        }) {
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_SHOOTDOWN_SYNC_REQUESTS,
                1,
            );
        }
        if HVF_THREAD.with(|context| {
            context
                .borrow()
                .bound
                .as_ref()
                .is_some_and(|bound| bound.view != view)
        }) && !self.migrate_bound_thread(view)
        {
            self.unbind_current_thread(BOUND_UNBINDS_FAILED);
            return BoundOutcome::Unbound;
        }

        let iteration_start = crate::diagnostics_counters::ticks();
        let control = HVF_THREAD.with(|context| context.borrow().bound.as_ref().map(|b| b.vcpu.control()));
        let Some(control) = control else {
            return BoundOutcome::Unbound;
        };
        let epoch = match HVF_THREAD.with(|context| {
            let context = context.borrow();
            match context.bound.as_ref() {
                Some(bound) => bound.vcpu.reserve_run(),
                None => Err(HvfVcpuLaneError::LaneClosed),
            }
        }) {
            Ok(epoch) => epoch,
            Err(error) => {
                litebox_util_log::debug!(error:% = error; "HVF bound vCPU: run reservation failed");
                self.unbind_current_thread(BOUND_UNBINDS_FAILED);
                return BoundOutcome::Unbound;
            }
        };
        // Publish this run's cancellation exactly the way the pooled path does, so an
        // interrupt aimed at this thread from another thread reaches this vCPU (and so a kick
        // that lands before guest entry latches instead of being lost).
        let mine = {
            let mut current = slot
                .current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.take_pending() {
                drop(current);
                let _ = control.settle_reservation(epoch, true, false);
                return BoundOutcome::Ran(shim.interrupt(ctx));
            }
            let mine = HVF_THREAD.with(|context| {
                context
                    .borrow()
                    .bound
                    .as_ref()
                    .map(|bound| bound.vcpu.cancellation_for(epoch))
            });
            match mine {
                Some(mine) => {
                    *current = Some(mine.clone());
                    mine
                }
                None => {
                    drop(current);
                    let _ = control.settle_reservation(epoch, true, false);
                    self.unbind_current_thread(BOUND_UNBINDS_FAILED);
                    return BoundOutcome::Unbound;
                }
            }
        };
        // BCORE-4: counted across the whole bound iteration's VM-operation work -- the merged
        // attach/submit shared operation (4) plus the run scope (3) = 7 per trip-free run,
        // against 20 on today's pooled path.
        let gate_locks_before = crate::diagnostics_counters::gate_locks_this_thread();
        let attached = HVF_THREAD.with(|context| {
            let context = context.borrow();
            let bound = context.bound.as_ref()?;
            let participant = bound.participant.as_ref()?;
            Some(bound.space.get(self).attach_submitted_vcpu(participant))
        });
        let attachment = match attached {
            Some(Ok(attachment)) => attachment,
            Some(Err(error)) => {
                // Same expectation as the pooled path: a mutation landing in the window between
                // attach and submit is ordinary contention, not a failure -- so this is not
                // fatal here. Give the vCPU back and let the pooled path's own (bounded,
                // counted) attachment-race retry resolve it with a fresh attachment; a genuine
                // failure fails there, fatally, the same way it always did.
                let _ = control.settle_reservation(epoch, true, true);
                self.clear_slot_current(slot, &mine);
                self.unbind_current_thread(BOUND_UNBINDS_FAILED);
                litebox_util_log::debug!(error:% = error; "HVF bound vCPU: attachment race");
                return BoundOutcome::Unbound;
            }
            None => {
                let _ = control.settle_reservation(epoch, true, false);
                self.clear_slot_current(slot, &mine);
                self.unbind_current_thread(BOUND_UNBINDS_FAILED);
                return BoundOutcome::Unbound;
            }
        };
        let snapshot = attachment.snapshot().clone();
        let deadline = time_slice_deadline();
        let run = HVF_THREAD.with(|context| {
            let mut context = context.borrow_mut();
            let Some(generation) = context.bound.as_ref().map(|b| b.vcpu.generation()) else {
                return Err(HvfVcpuLaneError::LaneClosed);
            };
            // `run_input` first: it may materialize a SIMD/FP file still resident in a lane,
            // and a bound run installs the FULL register file, so the host copy has to be
            // authoritative before the install.
            let (state, _claim, _cell) = context.run_input(ctx, (usize::MAX, generation));
            let Some(bound) = context.bound.as_mut() else {
                return Err(HvfVcpuLaneError::LaneClosed);
            };
            bound
                .vcpu
                .execute(epoch, attachment, &state, Some(deadline))
        });
        self.clear_slot_current(slot, &mine);
        let run = match run {
            Ok(run) => run,
            Err(error) => {
                self.unbind_current_thread(BOUND_UNBINDS_FAILED);
                fatal("running the guest on a bound vCPU", &error.into());
            }
        };
        if matches!(run.exit, HvfVcpuExit::Canceled) {
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_CANCELED_EXITS,
                1,
            );
            if slot.has_pending() {
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_CANCELED_INTERRUPTS,
                    1,
                );
            }
        }
        let gate_locks = crate::diagnostics_counters::gate_locks_this_thread()
            .wrapping_sub(gate_locks_before);
        crate::diagnostics_counters::add_stat(BOUND_RUNS, 1);
        crate::diagnostics_counters::add_stat(BOUND_GATE_LOCKS, gate_locks);
        crate::diagnostics_counters::record_bound_run_wall(run.run_wall_ns);
        let exit_ticks = crate::diagnostics_counters::ticks();
        HVF_THREAD.with(|context| {
            let mut context = context.borrow_mut();
            let state = match &run.state {
                HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => {
                    state
                }
            };
            // `run.fp` is `Materialized` on the bound path (the exit read is the full 74
            // registers), so this keeps `FpLocation::Host`.
            context.absorb_exit(state, run.fp, (usize::MAX, run.run_epoch));
            if let Some(bound) = context.bound.as_mut() {
                bound.last_exit = Instant::now();
                bound.entry.last_exit_ns.store(exit_ticks, Ordering::Relaxed);
            }
        });
        // Opportunistic acknowledgement work, exactly as the pooled path does it: the check
        // never waits for the ledger, and a contended check skips this exit's pass.
        // Take the space handle OUT of the thread-local first: `pump_retirements` (and, below,
        // `dispatch`) may run shim callbacks that borrow `HVF_THREAD` themselves, and a
        // `RefCell` borrow held across one is a panic.
        let owned = self.bound_space_handle();
        let space = self.bound_space(&owned);
        if let Some(space) = space {
            if matches!(space.pending_retirements_if_uncontended(), Some(pending) if pending != 0) {
                let _ = space.pump_retirements();
            }
        }
        // BCORE-3: a vtimer exit is the end of a time slice. On the pooled path it just
        // re-queues the thread; here there is no queue, so the slice either delivers a host
        // signal that is already pending (bounding interrupt latency by one slice) or yields
        // once so another guest thread can have the core.
        let disposition = if matches!(
            (run.exit, &run.state),
            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(_))
        ) {
            let state = match &run.state {
                HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => {
                    state
                }
            };
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_VTIMER_EXITS,
                1,
            );
            write_direct_exit(ctx, state);
            if crate::host_signals_pending() {
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_HOST_SIGNAL_FASTPATH,
                    1,
                );
                shim.interrupt(ctx)
            } else {
                std::thread::yield_now();
                ContinueOperation::Resume
            }
        } else {
            self.dispatch_bound(shim, ctx, slot, &run, &snapshot)
        };
        crate::diagnostics_counters::record_bound_exit_overhead(
            crate::diagnostics_counters::ticks_to_ns(
                crate::diagnostics_counters::ticks().wrapping_sub(iteration_start),
            ),
        );
        BoundOutcome::Ran(disposition)
    }

    /// BCORE-4: picks the bound entry that has gone longest without an exit and asks it to
    /// give its vCPU up (`BoundEntry::evict_requested` plus a thread interrupt, so a victim
    /// parked in a wait re-evaluates at its next loop top).
    fn request_bound_eviction(&self) {
        let victim = {
            let entries = self
                .bound_entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut oldest: Option<(u64, Arc<BoundEntry>)> = None;
            for entry in entries.iter() {
                let last = entry.last_exit_ns.load(Ordering::Relaxed);
                // Wrapping comparison: `u64::MAX / 2` ahead means strictly older.
                let older = oldest
                    .as_ref()
                    .is_none_or(|(best, _)| last.wrapping_sub(*best) > u64::MAX / 2);
                if older {
                    oldest = Some((last, Arc::clone(entry)));
                }
            }
            oldest.map(|(_, entry)| entry)
        };
        if let Some(victim) = victim {
            victim.evict_requested.store(true, Ordering::Release);
            victim.thread.interrupt();
        }
    }

    /// Clears this thread's published cancellation if it is still this run's.
    fn clear_slot_current(&self, slot: &HvfThreadSlot, mine: &HvfVcpuLaneCancellation) {
        let mut current = slot
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let still_mine = current
            .as_ref()
            .is_some_and(|current| current.is_same_run(mine));
        if still_mine {
            *current = None;
        }
    }

    /// BCORE-4: this thread's bound address space, cloned out of the thread-local so the
    /// `RefCell` borrow is over. `None` for the default space.
    fn bound_space_handle(&self) -> Option<Arc<HvfAddressSpace>> {
        HVF_THREAD.with(|context| match context.borrow().bound.as_ref()?.space {
            BoundSpace::Default => None,
            BoundSpace::View(ref space) => Some(Arc::clone(space)),
        })
    }

    /// BCORE-4: `&HvfAddressSpace` for [`Self::bound_space_handle`]'s result (the default space
    /// when it is `None`), with a lifetime tied to `self` rather than to `HVF_THREAD`.
    fn bound_space<'a>(&'a self, handle: &'a Option<Arc<HvfAddressSpace>>) -> Option<&'a HvfAddressSpace> {
        match handle {
            Some(space) => Some(space),
            None => HVF_THREAD
                .with(|context| context.borrow().bound.is_some())
                .then_some(&self.default_space),
        }
    }

    /// BCORE-4: the exit dispatch for a bound run -- the ordinary `dispatch`, with the space and
    /// view this vCPU is registered against.
    ///
    /// The `HVF_THREAD` borrow is deliberately over before `dispatch` runs: it calls back into
    /// the shim (`EnterShim::syscall` / `exception` / `interrupt`), which borrows the same
    /// thread-local (FP state, TPIDR, guest-access context).
    fn dispatch_bound(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
        slot: &HvfThreadSlot,
        run: &HvfVcpuRunResult,
        snapshot: &HvfVcpuMemorySnapshot,
    ) -> ContinueOperation {
        let view = HVF_THREAD.with(|context| context.borrow().bound.as_ref().and_then(|b| b.view));
        let owned = self.bound_space_handle();
        let Some(space) = self.bound_space(&owned) else {
            // BCORE-4 (fix-up): the thread has no bound vCPU any more (a deferred unbind from
            // its own loop top being the only way that can happen mid-iteration). Dispatching
            // against the default space is still right -- the exit is a real guest exit and the
            // shim must see it -- where dropping it would silently skip this iteration's exit
            // and resume the guest without ever having looked at why it came out.
            let mut stale_view_reruns = 0u32;
            let mut alias_conflict_reruns = 0u32;
            return self.dispatch(
                shim,
                ctx,
                slot,
                run,
                snapshot,
                &mut stale_view_reruns,
                &mut alias_conflict_reruns,
                &self.default_space,
                None,
            );
        };
        let mut stale_view_reruns = 0u32;
        let mut alias_conflict_reruns = 0u32;
        self.dispatch(
            shim,
            ctx,
            slot,
            run,
            snapshot,
            &mut stale_view_reruns,
            &mut alias_conflict_reruns,
            space,
            view,
        )
    }
}

/// BCORE-5: gives the calling thread's bound vCPU back, if it has one.
///
/// Called from the shim's thread-exit path and from `run_thread`'s return, so a bound vCPU
/// never outlives the guest thread that owns it -- an address space can only be destroyed once
/// every participant is deregistered, and `prepare_for_exit` runs before
/// `release_view_space`.
///
/// BCORE-5 (fix-up): `Task::prepare_for_exit` runs from EVERY `Task::drop`, not only from the
/// owning thread's own: a failed `spawn_thread` drops the new `Task` on the *spawning* thread,
/// and an aborted `ProcessLaunch` on the launcher. Both therefore used to arrive here from a
/// thread that is in the middle of dispatching its own guest exit, and taking its bound vCPU
/// away there meant that iteration's exit was never dispatched at all. So when this thread is
/// inside its own bound dispatch, the unbind is deferred to its loop top (a few microseconds
/// away, and still before the thread can leave the loop) rather than performed here.
pub(crate) fn unbind_current_thread_vcpu() {
    if !bound_enabled() {
        return;
    }
    let Some(backend) = active() else {
        return;
    };
    let deferred = bound_dispatch_depth() != 0
        && HVF_THREAD.with(|context| {
            let context = context.borrow();
            let Some(bound) = context.bound.as_ref() else {
                return false;
            };
            bound
                .entry
                .unbind_requested
                .store(true, Ordering::Release);
            true
        });
    if deferred {
        crate::diagnostics_counters::add_stat(
            crate::diagnostics_counters::BOUND_UNBINDS_DEFERRED,
            1,
        );
        return;
    }
    backend.unbind_current_thread(crate::diagnostics_counters::BOUND_UNBINDS_EXIT);
}

/// BCORE-5 (fix-up): how deep the calling thread currently is inside its own bound
/// dispatch ([`HvfBackend::bound_iteration`]). Zero between exits, i.e. exactly when an unbind
/// requested from the shim can be performed on the spot.
fn bound_dispatch_depth() -> u32 {
    BOUND_DISPATCH_DEPTH.with(|depth| depth.get())
}

thread_local! {
    /// BCORE-5 (fix-up): see [`bound_dispatch_depth`]. A depth, not a flag, so a nested entry
    /// (a shim callback that re-enters the run loop) can never clear it early.
    static BOUND_DISPATCH_DEPTH: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// BCORE-5 (fix-up): unwinds [`BOUND_DISPATCH_DEPTH`] on every exit from
/// [`HvfBackend::bound_iteration`], including the error paths that `return` early.
struct BoundDispatchScope;

impl Drop for BoundDispatchScope {
    fn drop(&mut self) {
        BOUND_DISPATCH_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

impl HvfBackend {
    // -- execution ---------------------------------------------------------

    /// Runs one guest thread to completion: the HVF counterpart of
    /// `guest::run_thread`.  `ctx` is the thread's authoritative integer
    /// context; the vector file and thread pointer live in [`HVF_THREAD`].
    pub(crate) fn run_thread(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
    ) {
        if shim.init(ctx) == ContinueOperation::Terminate {
            return;
        }
        self.run_thread_loop(shim, ctx);
        // Step GF (b): a thread that is leaving must not keep its lane -- this is the one exit
        // path `run_thread_loop` itself cannot cover, because it returns from anywhere inside it.
        release_retained_lane(crate::diagnostics_counters::LANE_STICKY_RELEASED_EXIT);
        // BCORE-5: a bound vCPU is destroyed by its owner thread and nowhere else, so it is
        // given back here -- before this thread's `ThreadHandle` goes away and before any
        // address space it is registered in can be destroyed.
        if bound_enabled() {
            self.unbind_current_thread(crate::diagnostics_counters::BOUND_UNBINDS_EXIT);
        }
    }

    fn run_thread_loop(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
    ) {
        let thread = crate::ThreadHandle::current();
        let slot = thread.hvf_slot();
        let mut consecutive_attachment_races = 0u32;
        let mut stale_view_reruns = 0u32;
        let mut alias_conflict_reruns = 0u32;
        // BCORE-4: `(window start, pooled iterations in this window)` for the bind trigger.
        // Only read or written when the knob is on; the pooled path never touches it.
        let mut bind_streak: (Instant, u32) = (Instant::now(), 0);
        use crate::diagnostics_counters::{
            GUEST_ATTACH, GUEST_DISPATCH, GUEST_EXECUTE, GUEST_LANE_WAIT, GUEST_LOOP_TOP,
            GUEST_PRE_EXECUTE, GUEST_PUMP, GUEST_RECORD, GUEST_RELEASE, GUEST_RESERVE,
            GUEST_SPACE_LOOKUP, GUEST_STATE_BUILD, GUEST_VIEW_ATTACH, ticks_to_ns,
        };
        // hvf-exit-overhead-instrumentation: when the previous `run_with_deadline_reserved` on
        // this thread returned (host ticks), so the next submit can bank the whole-iteration
        // overhead (`exit_overhead`, minus the shim syscall time the dispatch in between recorded).
        let mut last_execute_end: Option<u64> = None;
        // Step GF (b): the installed backend as a `&'static`, so a lease this thread keeps can
        // outlive this call's `&self` borrow. `None` (only possible if some future caller runs a
        // backend other than the installed one) simply disables retention for this thread.
        let sticky_backend: Option<&'static HvfBackend> =
            active().filter(|installed| std::ptr::eq(*installed, self));
        // Step G: a thread is runnable from the moment it starts running here -- it has never
        // waited yet -- so the first interval is measured against this stamp.
        crate::diagnostics_counters::rbnr_became_ready(crate::diagnostics_counters::ticks(), 0);
        loop {
            let mut spans = crate::diagnostics_counters::GuestSpans::start();
            if slot.take_pending() && shim.interrupt(ctx) == ContinueOperation::Terminate {
                return;
            }
            // k2p-exit-handoff-lane-wait-counters: time the lane wait here and, below, the whole
            // lane-held span plus the `execute()` round trip inside it, so the per-exit overhead
            // the syscall histogram cannot see (`dispatch_monitor_exit` times only the shim
            // dispatch) is published next to it. Host-tick reads and relaxed atomics only.
            // hvf-lane-view-affinity: this thread's view is resolved before the acquire so the
            // pool can hand out a lane already registered in it; the same value is what
            // `ensure_lane_attached_to_view` below attaches to (nothing between here and there
            // can change the thread-local it comes from).
            let view = crate::current_guest_view();
            // BCORE-4: a thread with a vCPU of its own runs here and never reaches the pool.
            // With `LITEBOX_HVF_BOUND=0` this is one load of a cached `false`.
            if bound_enabled() {
                match self.bound_iteration(shim, ctx, slot, view, &mut bind_streak) {
                    BoundOutcome::Ran(ContinueOperation::Terminate) => return,
                    BoundOutcome::Ran(_) => continue,
                    BoundOutcome::Unbound => {}
                }
            }
            // Step GF (b): reuse the lane this thread kept from its previous run when it has one
            // and nothing has asked for it back. `preferred` (FXR's resident-state hint) is only
            // read on the pool path -- a retained lease IS the lane holding this thread's
            // resident state, so asking the pool to prefer it would be tautological.
            spans.mark(GUEST_LOOP_TOP);
            let retained = self.take_retained_lane();
            let retained_hit = retained.is_some();
            // Step GF (fix-up): the run count the retained lease has already served. It is carried
            // into this iteration's `retain_lane`, which is what makes `LANE_STICKY_MAX_RUNS` a
            // real bound; it was dropped on the floor before, so every retain restarted at 0 and
            // the cap was unreachable. Reset to 0 whenever this iteration does not reuse a lease.
            let mut carried_runs = 0u32;
            let acquired = match retained {
                Some(retained) => {
                    carried_runs = retained.runs;
                    Ok(Some(retained.lease))
                }
                // FXR: the lane holding this thread's resident state (its vector file, or at
                // least the integer file its cache last saw) is the one to ask the pool for.
                None => {
                    let preferred = HVF_THREAD.with(|context| context.borrow().preferred_lane());
                    self.acquire_lane_for_thread(slot, view, preferred)
                }
            };
            crate::diagnostics_counters::record_lane_wait(ticks_to_ns(spans.mark(GUEST_LANE_WAIT)));
            let lane_held_start = spans.last();
            crate::diagnostics_counters::record_lane_sticky(if retained_hit {
                crate::diagnostics_counters::LANE_STICKY_REUSED
            } else {
                crate::diagnostics_counters::LANE_STICKY_ACQUIRED
            });
            let lease = match acquired {
                Ok(Some(lease)) => lease,
                Ok(None) => {
                    if slot.take_pending() && shim.interrupt(ctx) == ContinueOperation::Terminate {
                        return;
                    }
                    continue;
                }
                Err(error) => fatal("acquiring a vCPU lane", &error),
            };
            let mut active = ActiveThreadLaneLease::new(lease, slot);
            {
                let mut current = slot
                    .current
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if slot.take_pending() {
                    drop(current);
                    drop(active);
                    if shim.interrupt(ctx) == ContinueOperation::Terminate {
                        return;
                    }
                    continue;
                }
                if current.is_some() {
                    drop(current);
                    drop(active);
                    fatal(
                        "reserving a vCPU lane with stale thread authority",
                        &HvfBackendError::LanePoolCorrupt { index: usize::MAX },
                    );
                }
                let reservation = match active.lane().handle.reserve_run() {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        drop(current);
                        drop(active);
                        fatal("reserving a vCPU run epoch", &error.into());
                    }
                };
                let cancellation = reservation.cancellation();
                active.install(reservation, cancellation.clone());
                *current = Some(cancellation);
            }
            spans.mark(GUEST_RESERVE);
            let space = {
                let _origin = crate::diagnostics_counters::enter_origin(
                    crate::diagnostics_counters::ORIGIN_LANE_MAINTENANCE,
                );
                if let Some(view) = view
                    && let Err(error) = self.ensure_lane_attached_to_view(active.lane(), view)
                {
                    fatal("attaching an HVF vCPU lane to its guest view", &error);
                }
                spans.mark(GUEST_VIEW_ATTACH);
                match self.space_for_view(view) {
                    Ok(space) => space,
                    Err(error) => fatal(
                        "resolving a guest thread's per-view HVF address space",
                        &error,
                    ),
                }
            };
            spans.mark(GUEST_SPACE_LOOKUP);
            let lane_key = (active.index(), active.lane().handle.generation());
            let (state, fp_claim, register_cell) =
                HVF_THREAD.with(|context| context.borrow_mut().run_input(ctx, lane_key));
            let deadline = time_slice_deadline();
            spans.mark(GUEST_STATE_BUILD);
            let gate_locks_before = crate::diagnostics_counters::gate_locks_this_thread();
            let attached = {
                let participant = active
                    .lane()
                    .participant
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // T2d: attach and submit in one shared operation (seven gate mutex acquisitions
                // per syscall -> four).
                space.attach_submitted_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))
            };
            spans.mark(GUEST_ATTACH);
            let outcome = match attached {
                Err(error) => Err(HvfBackendError::from(error)),
                Ok(attachment) => {
                    let snapshot = attachment.snapshot().clone();
                    let reservation = active.take_reservation();
                    spans.mark(GUEST_PRE_EXECUTE);
                    let execute_start = spans.last();
                    // Step G: `running_at`. Everything from this thread's `ready_at` to here is
                    // time it was runnable but not running; `rbnr_record` names the spans.
                    crate::diagnostics_counters::rbnr_record(space.id(), &spans);
                    if let Some(previous_end) = last_execute_end.take() {
                        crate::diagnostics_counters::record_iteration(
                            ticks_to_ns(execute_start.wrapping_sub(previous_end)),
                            crate::diagnostics_counters::take_last_syscall_ns(),
                        );
                    }
                    let run = active.lane().handle.run_guest_reserved(
                        reservation,
                        attachment,
                        &state,
                        register_cell,
                        fp_claim,
                        deadline,
                    );
                    spans.mark(GUEST_EXECUTE);
                    let execute_end = spans.last();
                    run.map(|run| {
                        (
                            run,
                            snapshot,
                            ticks_to_ns(execute_end.wrapping_sub(execute_start)),
                            execute_end,
                        )
                    })
                    .map_err(HvfBackendError::from)
                }
            };
            let guest_gate_locks = crate::diagnostics_counters::gate_locks_this_thread()
                .wrapping_sub(gate_locks_before);
            // Step GF (b): decide here whether this thread keeps the lane for its next run. The
            // run has returned, so the attachment is consumed and the lane is quiescent -- the
            // only moment at which keeping it is legal. Everything that can invalidate the
            // decision afterwards (a waiter appearing, a shootdown, this thread parking) is
            // handled at the next loop top by [`Self::take_retained_lane`], or before the park
            // itself by [`release_retained_lane`].
            if outcome.is_ok()
                && crate::diagnostics_counters::lane_sticky_enabled()
                // The vfork window: a parent parked hand-off-hand must not hold a lane.
                && crate::current_vcpu_bind_eligible()
                && let Some(lease) = active.settle_keeping_lane()
                && let Some(backend) = sticky_backend
            {
                crate::diagnostics_counters::record_lane_sticky(
                    crate::diagnostics_counters::LANE_STICKY_KEPT,
                );
                let epoch = self.lane_yield_epoch.load(Ordering::Acquire);
                let deadline = Instant::now()
                    .checked_add(lane_sticky_max_hold())
                    .unwrap_or_else(Instant::now);
                retain_lane(lease.with_backend(backend), carried_runs, epoch, deadline);
            }
            drop(active);
            spans.mark(GUEST_RELEASE);
            let lane_held_ns = ticks_to_ns(spans.last().wrapping_sub(lane_held_start));
            let (run, snapshot, execute_ns, execute_end) = match outcome {
                Ok(run) => run,
                // `attach_vcpu` snapshots the address space's generations at
                // the moment it is called, but this thread's `submit`/
                // `begin_running` only reach the lane's own serialized
                // command queue afterwards; a concurrent mutation landing in
                // that window is expected and recoverable, not a genuine
                // failure -- retry with a fresh attachment against whatever
                // generation is now current instead of aborting the process.
                Err(error) if is_recoverable_attachment_race(&error) => {
                    consecutive_attachment_races += 1;
                    if consecutive_attachment_races >= ATTACHMENT_RACE_RETRY_LIMIT {
                        fatal("retrying past a stale HVF vCPU attachment", &error);
                    }
                    continue;
                }
                Err(error) => fatal("running the guest on a vCPU lane", &error),
            };
            // FXR: take the exit state in before anything on this thread can look at it --
            // `tpidr_el0` from the exit read, and where the vector file now is.
            HVF_THREAD.with(|context| {
                let state = match &run.state {
                    HvfVcpuExitState::DirectGuest(state)
                    | HvfVcpuExitState::LowerElMonitor(state) => state,
                };
                context.borrow_mut().absorb_exit(state, run.fp, lane_key);
            });
            consecutive_attachment_races = 0;
            last_execute_end = Some(execute_end);
            crate::diagnostics_counters::record_handoff(
                lane_held_ns,
                execute_ns,
                run.owner_ns,
                run.run_wall_ns,
            );
            crate::diagnostics_counters::record_run_gate_locks(
                guest_gate_locks,
                run.owner_gate_locks,
            );
            spans.mark(GUEST_RECORD);
            // Opportunistic acknowledgement work: keeps retired resources
            // flowing back without any mutator having to wait for it. The
            // check never waits for the ledger (see
            // `pending_retirements_if_uncontended`): a contended check skips
            // this exit's pass, and the next exit looks again.
            if space
                .pending_retirements_if_uncontended()
                .is_some_and(|pending| pending != 0)
            {
                let _ = space.pump_retirements();
            }
            spans.mark(GUEST_PUMP);
            let disposition = self.dispatch(
                shim,
                ctx,
                slot,
                &run,
                &snapshot,
                &mut stale_view_reruns,
                &mut alias_conflict_reruns,
                &space,
                view,
            );
            spans.mark(GUEST_DISPATCH);
            crate::diagnostics_counters::record_guest_iteration(&spans);
            // Step G: the iteration is over. If the dispatch in between left this thread blocked
            // in a wait, `rbnr_became_ready` has already been stamped by the wake (or the
            // timeout) exactly at the moment it became runnable; otherwise it is runnable now.
            crate::diagnostics_counters::rbnr_iteration_end(
                spans.last(),
                ticks_to_ns(spans.span(GUEST_PUMP)),
            );
            if disposition == ContinueOperation::Terminate {
                return;
            }
        }
    }

    fn dispatch(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
        slot: &HvfThreadSlot,
        run: &HvfVcpuRunResult,
        snapshot: &HvfVcpuMemorySnapshot,
        stale_view_reruns: &mut u32,
        alias_conflict_reruns: &mut u32,
        space: &HvfAddressSpace,
        view: Option<VmViewId>,
    ) -> ContinueOperation {
        match (run.exit, &run.state) {
            (HvfVcpuExit::Exception(exception), HvfVcpuExitState::LowerElMonitor(state))
                if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_HVC64
                    && exception.syndrome & HVC_IMMEDIATE_MASK == MONITOR_HVC_IMMEDIATE =>
            {
                self.dispatch_monitor_exit(
                    shim,
                    ctx,
                    state,
                    snapshot,
                    stale_view_reruns,
                    alias_conflict_reruns,
                    space,
                    view,
                )
            }
            (HvfVcpuExit::Exception(exception), HvfVcpuExitState::DirectGuest(state))
                if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_BRK64 =>
            {
                // Hypervisor.framework intercepts an EL0 BRK before the guest's
                // EL1 vector even though ordinary synchronous exceptions are
                // delivered through the monitor. The direct EL0 state and SDK
                // syndrome are authoritative, so surface the same exception to
                // the shim instead of requiring a monitor HVC that cannot occur.
                checked_increment(&self.exception_counters.raw_exception_exits);
                let _in_flight = InFlightExceptionGuard::new(&self.exception_counters.in_flight);
                write_direct_exit(ctx, state);
                *stale_view_reruns = 0;
                *alias_conflict_reruns = 0;
                ctx.syscallno = -1;
                let info = ExceptionInfo {
                    exception: Exception(u8::try_from(EC_BRK64).expect("BRK EC fits in u8")),
                    fault_address: usize::try_from(exception.virtual_address).unwrap_or(usize::MAX),
                    esr: exception.syndrome,
                    kernel_mode: false,
                    // `ctx` was just populated by `write_direct_exit` above,
                    // so `ctx.regs[29]` (x29/FP) already reflects the
                    // faulting frame's own real guest register value.
                    backtrace: if exception_backtrace_wanted() {
                        capture_frame_backtrace(ctx.regs[29])
                    } else {
                        litebox::shim::FrameBacktrace::EMPTY
                    },
                };
                // Never routes through `kernel_mode`-gated `PageManager::handle_page_fault` (see
                // `kernel_mode: false` above), so this is always a genuine delivered signal, not
                // a candidate for `guest_faults_serviced` -- credited to the shared
                // process-global static directly, same as the non-abort catch-all below.
                checked_increment(&GUEST_FAULTS_DELIVERED);
                let exception_started = Instant::now();
                let op = shim.exception(ctx, &info);
                crate::diagnostics_counters::record_exception_service(
                    crate::diagnostics_counters::elapsed_ns(exception_started),
                );
                op
            }
            (HvfVcpuExit::Exception(exception), HvfVcpuExitState::DirectGuest(state))
                if matches!(
                    (exception.syndrome >> EC_SHIFT) & EC_MASK,
                    EC_INSTRUCTION_ABORT_LOWER_EL | EC_DATA_ABORT_LOWER_EL
                ) =>
            {
                // Hypervisor.framework intercepts a stage-1 permission fault taken
                // from EL0 the same way it intercepts `BRK` above: directly, before
                // the guest's own EL1 vector, so no monitor `HVC` ever runs and
                // `dispatch_monitor_exit` (which reads the guest's own saved
                // `ESR_EL1`/`FAR_EL1`, populated only when the guest's EL1 vector
                // actually ran) cannot be reused here. The SDK's own `exception`
                // syndrome/address are authoritative instead, exactly as for `BRK`.
                // A JIT that toggles a page between writable and executable (V8's
                // baseline/optimizing tiers included) reaches this arm on the
                // execute side: without it, the very first such instruction-fetch
                // permission fault is an unclassified exit and the whole process
                // is torn down, which live testing confirmed is reliably reachable
                // under real Node workloads well before any meaningful exception
                // count accrues.
                let _origin = crate::diagnostics_counters::enter_origin(
                    crate::diagnostics_counters::ORIGIN_GUEST_FAULT,
                );
                let _in_flight = InFlightExceptionGuard::new(&self.exception_counters.in_flight);
                write_direct_exit(ctx, state);
                ctx.syscallno = -1;
                let class = (exception.syndrome >> EC_SHIFT) & EC_MASK;
                checked_increment(&self.exception_counters.raw_exception_exits);
                if *stale_view_reruns < STALE_VIEW_RERUN_LIMIT && self.view_was_stale(space, snapshot) {
                    *stale_view_reruns += 1;
                    checked_increment(&self.exception_counters.stale_view_reruns);
                    litebox_util_log::debug!(
                        class:? = class, far:? = exception.virtual_address, pc:? = ctx.pc,
                        reruns:? = *stale_view_reruns;
                        "HVF direct-guest abort on a stale view: rerunning after synchronization"
                    );
                    return ContinueOperation::Resume;
                }
                if let Some(request) =
                    self.classify_wx_fault(class, exception.virtual_address, exception.syndrome)
                {
                    match shim.memory_service(request) {
                        WxFlipOutcome::Committed(_) => {
                            checked_increment(&self.exception_counters.wx_service_requests);
                            checked_increment(&self.exception_counters.wx_service_settled);
                            *stale_view_reruns = 0;
                            *alias_conflict_reruns = 0;
                            return ContinueOperation::Resume;
                        }
                        WxFlipOutcome::StaleGeneration => {
                            checked_increment(&self.exception_counters.wx_service_requests);
                            checked_increment(&self.exception_counters.wx_service_refaulted);
                            *stale_view_reruns = 0;
                            *alias_conflict_reruns = 0;
                            return ContinueOperation::Resume;
                        }
                        WxFlipOutcome::AliasConflictRefused => {
                            checked_increment(&self.exception_counters.wx_service_requests);
                            checked_increment(&self.exception_counters.wx_alias_conflict_refusals);
                            *stale_view_reruns = 0;
                            // See `ALIAS_CONFLICT_RERUN_LIMIT`'s own doc comment: most refusals are
                            // a genuine transient race (a concurrent mmap/mprotect/munmap) that
                            // clears within a handful of reruns, but a page refused because it is
                            // still only lineage-inherited (never independently claimed by this
                            // view) never clears by rerunning alone. Falling through below --
                            // instead of unconditionally resuming here -- gives
                            // `try_resolve_cow_fault` the same chance to materialize it that a
                            // `HostFailure` already gets.
                            if *alias_conflict_reruns < ALIAS_CONFLICT_RERUN_LIMIT {
                                *alias_conflict_reruns += 1;
                                return ContinueOperation::Resume;
                            }
                        }
                        WxFlipOutcome::HostFailure => {}
                    }
                }
                if self.try_resolve_cow_fault(
                    space,
                    shim,
                    view,
                    class,
                    exception.virtual_address,
                    exception.syndrome,
                    snapshot.pending_tlbi_generation.value(),
                ) {
                    // FIX (hvf-cow-fault-resolution-uncredited-exception-bucket): this exit was
                    // already counted into `raw_exception_exits` above (before any of the arms in
                    // this function ran); a successful `try_resolve_cow_fault` resolves it with no
                    // guest-visible signal -- a COW-split/promotion/alias-install, exactly
                    // `guest_faults_serviced`'s own documented scope (see its doc comment) -- so
                    // credit it here. Without this, every fork-COW fault this fast path resolves
                    // left `raw_exception_exits` ahead of the sum of the equation's five named
                    // buckets, which live reproduction confirmed is the overwhelming majority of
                    // all real hardware exceptions on any fork-heavy workload.
                    checked_increment(&GUEST_FAULTS_SERVICED);
                    *stale_view_reruns = 0;
                    *alias_conflict_reruns = 0;
                    return ContinueOperation::Resume;
                }
                *stale_view_reruns = 0;
                *alias_conflict_reruns = 0;
                let info = ExceptionInfo {
                    exception: Exception(u8::try_from(class).unwrap_or(0)),
                    fault_address: usize::try_from(exception.virtual_address).unwrap_or(usize::MAX),
                    esr: exception.syndrome,
                    // Same reasoning as `dispatch_monitor_exit`'s own abort arm: routing
                    // through `kernel_mode: true` is what makes `PageManager::handle_page_fault`
                    // (stack growth, real fault classification) reachable for a direct-guest
                    // abort too, instead of only for one that happened to route via the monitor.
                    kernel_mode: true,
                    // `ctx` was populated by `write_direct_exit` earlier in this
                    // same arm; see the `EC_BRK64` arm's identical comment.
                    backtrace: if exception_backtrace_wanted() {
                        capture_frame_backtrace(ctx.regs[29])
                    } else {
                        litebox::shim::FrameBacktrace::EMPTY
                    },
                };
                litebox_util_log::debug!(
                    class:? = class, esr:? = exception.syndrome, far:? = exception.virtual_address,
                    pc:? = ctx.pc;
                    "HVF direct-guest abort dispatched to shim.exception"
                );
                // `guest_faults_delivered` is credited downstream (by whether
                // `handle_page_fault` services or delivers it), same as the monitor path's
                // abort arm -- crediting it here too would double-count one raw exit.
                let exception_started = Instant::now();
                let op = shim.exception(ctx, &info);
                crate::diagnostics_counters::record_exception_service(
                    crate::diagnostics_counters::elapsed_ns(exception_started),
                );
                op
            }
            (HvfVcpuExit::Canceled, HvfVcpuExitState::LowerElMonitor(state))
                if state.pc == MONITOR_LOWER_EL_SYNC_OFFSET =>
            {
                // The authenticated kick won immediately after EL0 exception
                // entry but before the monitor's HVC ran. The original exception
                // is already complete in ELR_EL1/SPSR_EL1/ESR_EL1; dispatch it
                // exactly once instead of dropping a syscall or treating valid
                // EL1h state as a corrupt guest exit. A real thread interrupt
                // remains latched in `slot` and is delivered on the next loop.
                crate::diagnostics_counters::record_canceled(
                    crate::diagnostics_counters::CanceledKind::MonitorExit,
                );
                self.dispatch_monitor_exit(
                    shim,
                    ctx,
                    state,
                    snapshot,
                    stale_view_reruns,
                    alias_conflict_reruns,
                    space,
                    view,
                )
            }
            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(state)) => {
                let interrupted = slot.take_pending();
                write_direct_exit(ctx, state);
                if interrupted {
                    crate::diagnostics_counters::record_canceled(
                        crate::diagnostics_counters::CanceledKind::Interrupt,
                    );
                    shim.interrupt(ctx)
                } else {
                    // Mapping shootdowns use the same authenticated lane
                    // cancellation but do not create a thread-interrupt
                    // obligation. Reattach on the current root without
                    // spuriously entering the shim's signal path.
                    // hvf-exit-overhead-instrumentation: `lane_kicks.canceled_exits` -- a whole
                    // loop iteration spent for a mutation kick, resumed at the same PC.
                    crate::diagnostics_counters::record_canceled(
                        crate::diagnostics_counters::CanceledKind::Exit,
                    );
                    ContinueOperation::Resume
                }
            }
            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(state)) => {
                // End of a time slice: the thread simply re-queues for a lane,
                // which is what gives other guest threads a turn.
                write_direct_exit(ctx, state);
                ContinueOperation::Resume
            }
            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::LowerElMonitor(state))
                if state.pc == MONITOR_LOWER_EL_SYNC_OFFSET =>
            {
                // Same race as the `(Canceled, LowerElMonitor)` arm above, just with a
                // vtimer deadline instead of an authenticated kick winning it -- and safe
                // for the identical reason, not merely by analogy. `MONITOR_LOWER_EL_SYNC_OFFSET`
                // is the ARM-mandated lower-EL/AArch64 synchronous vector slot, and the
                // monitor's only instruction there is `hvc #0x4c42` (hvf_monitor.S),
                // immediately followed by the unrelated `_litebox_hvf_monitor_resume: eret`
                // at the next instruction. `HVC` unconditionally traps and its own
                // architectural return address is the *next* instruction, so a reported PC
                // of exactly this offset is only possible if that `HVC` has not yet run.
                // A vtimer exit, like a cancellation, is a host-driven preemption that HVF
                // always reports at a clean instruction boundary, never mid-instruction --
                // so this is not a guess: the original EL0 exception this monitor entry
                // exists to relay is already fully latched in
                // `ELR_EL1`/`SPSR_EL1`/`ESR_EL1`/`FAR_EL1` by hardware (done atomically as
                // part of taking that exception, before the vector's first instruction
                // runs), and nothing else has touched it. Dispatching it now is therefore
                // equivalent to letting the `HVC` execute and trap normally --
                // `dispatch_monitor_exit` itself never reads `run.exit`, only
                // `state.esr_el1`, so it does not care which of the two host-preemption
                // reasons got it here.
                //
                // This is deliberately NOT the `(VtimerActivated, DirectGuest)` arm's
                // "just re-queue at the current PC" handling just above: `write_direct_exit`
                // trusts `state.pc`/`state.cpsr` as the guest's own resume point, but a
                // `LowerElMonitor` state's `pc` is the monitor's *own* EL1 PC (this offset),
                // not the guest's EL0 one -- that is `state.elr_el1`, which only
                // `write_monitor_exit` (reached via `dispatch_monitor_exit` below) uses.
                // Copying the `DirectGuest` arm here would silently resume the guest at
                // `ctx.pc == MONITOR_LOWER_EL_SYNC_OFFSET` instead of its real PC.
                self.dispatch_monitor_exit(
                    shim,
                    ctx,
                    state,
                    snapshot,
                    stale_view_reruns,
                    alias_conflict_reruns,
                    space,
                    view,
                )
            }
            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::LowerElMonitor(state)) => {
                // Every OTHER `LowerElMonitor` PC paired with `VtimerActivated` (i.e. every
                // `state.pc` other than the sync entry handled just above) is, as far as
                // this codebase's own current call graph goes, unreachable rather than
                // merely untested -- not a reason to fold it into the generic catch-all
                // below, since that is exactly the "guess it's fine in vCPU-dispatch code"
                // this arm exists to avoid. The monitor's (hvf_monitor.S) only other two
                // labels are `_litebox_hvf_monitor_resume` (a lone `eret` immediately after
                // the sync entry) and `_litebox_hvf_monitor_synchronize`. No Rust call site
                // anywhere in this crate ever sets a vCPU's `state.pc` to `resume_offset` --
                // it is validated at monitor-load time (`hvf_sdk.rs`) but otherwise dead in
                // the live dispatch surface today. `synchronize_offset` is reached only
                // through `hvf_vcpu.rs`'s `synchronize_once`, which calls
                // `suppress_internal_interrupts` (masking the vtimer) before its own raw,
                // undeadlined `vcpu.run()` -- so `VtimerActivated` cannot occur there at
                // all -- and even an unexpected exit from that call is consumed entirely
                // inside `finish_synchronizing`/`synchronize_once`, surfacing (if at all) as
                // `HvfVcpuLaneError::InvalidSynchronizationExit`, never as an
                // `HvfVcpuRunResult` reaching this `dispatch()` match. None of that is an
                // architectural guarantee, only the current, read code, so this stays
                // explicitly fatal -- with its own reason -- rather than assumed safe:
                // nothing has established what partial state the monitor's own sequence
                // would be mid-mutating at an arbitrary PC.
                fatal(
                    "classifying a vCPU exit: vtimer activated in the EL1 monitor away from its sync entry",
                    &HvfBackendError::UnexpectedExit {
                        exit: run.exit,
                        source_pc: Some(state.pc),
                    },
                )
            }
            _ => {
                let state = match &run.state {
                    HvfVcpuExitState::DirectGuest(state)
                    | HvfVcpuExitState::LowerElMonitor(state) => state,
                };
                fatal(
                    "classifying a vCPU exit",
                    &HvfBackendError::UnexpectedExit {
                        exit: run.exit,
                        source_pc: Some(state.pc),
                    },
                )
            }
        }
    }

    fn dispatch_monitor_exit(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
        state: &HvfArchitecturalState,
        snapshot: &HvfVcpuMemorySnapshot,
        stale_view_reruns: &mut u32,
        alias_conflict_reruns: &mut u32,
        space: &HvfAddressSpace,
        view: Option<VmViewId>,
    ) -> ContinueOperation {
        // `raw_exception_exits` is deliberately NOT incremented here (before knowing which
        // class this monitor exit is): an ordinary guest syscall (`EC_SVC64`) or `WFI`/`WFE`
        // (`EC_WFX`) is an expected, business-as-usual guest action, not a hardware exception in
        // the sense this counter's own invariant equation is about -- neither has a bucket in
        // that equation, and counting them here would make
        // `raw_exception_exits == stale_view_reruns + wx_service_requests + guest_faults_serviced
        // + guest_faults_delivered + fatal_faults` false on any workload that makes a real
        // syscall. It is incremented only in the `_` arm below (and separately, in `dispatch`,
        // for the direct-guest `BRK` exit path) -- exactly the set of exits this equation
        // accounts for. `in_flight`, by contrast, IS a live gauge over every dispatched monitor
        // exit including syscalls and WFx (see its own doc comment), so its guard stays
        // unconditional here.
        let _in_flight = InFlightExceptionGuard::new(&self.exception_counters.in_flight);
        write_monitor_exit(ctx, state);
        let class = (state.esr_el1 >> EC_SHIFT) & EC_MASK;
        match class {
            EC_SVC64 => {
                *stale_view_reruns = 0;
                *alias_conflict_reruns = 0;
                ctx.syscallno =
                    u32::try_from(state.x[8] & 0xffff_ffff).map_or(-1, |number| number as i32);
                ctx.orig_x0 = ctx.regs[0];
                // hvf-per-space-syscall-cost-and-handoff-counters (sub-pieces 1+2): per-space
                // SVC exit counts, a syscall-cost histogram, and the structured per-syscall
                // ring, timed around the real dispatch with a monotonic clock. `space.id()` is
                // cheap (a field read, no lock); the ring/table writes below are lock-free too,
                // so this adds only a handful of relaxed atomic RMWs to every guest syscall.
                // hvf-exit-overhead-instrumentation: clear any interruptible-wait time banked on
                // this thread outside a syscall dispatch (signal delivery, fault service) so the
                // blocked/service split below is exactly this one syscall's.
                let _ = crate::diagnostics_counters::take_blocked_ns();
                let origin = crate::diagnostics_counters::enter_syscall_origin(ctx.syscallno);
                // hvf-glive-unattributed-slow-syscall-mass: host-thread CPU time across this
                // syscall, so a slow record can say whether its wall time was spent running or
                // not running. 0 (and no mach call at all) unless LITEBOX_HVF_SYSCALL_CPU=1.
                let cpu_start = crate::diagnostics_counters::thread_cpu_ns();
                let syscall_start = Instant::now();
                let outcome = shim.syscall(ctx);
                let elapsed_ns = u64::try_from(syscall_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                let cpu_ns = crate::diagnostics_counters::thread_cpu_ns_since(cpu_start);
                drop(origin);
                let blocked_ns = crate::diagnostics_counters::take_blocked_ns();
                // Bit-preserving reinterpretation of the raw x0 return value as signed -- the
                // AArch64 Linux syscall ABI's own representation of a negative errno.
                let result = ctx.regs[0] as i64;
                crate::diagnostics_counters::record_syscall_exit(
                    space.id(),
                    ctx.syscallno,
                    result,
                    elapsed_ns,
                    blocked_ns,
                    cpu_ns,
                );
                outcome
            }
            EC_WFX => {
                // `WFI`/`WFE` at EL0: skip the instruction and give up the
                // lane for a moment instead of halting a real core.
                *stale_view_reruns = 0;
                *alias_conflict_reruns = 0;
                ctx.pc = ctx.pc.wrapping_add(4);
                ctx.syscallno = -1;
                std::thread::yield_now();
                ContinueOperation::Resume
            }
            _ => {
                let _origin = crate::diagnostics_counters::enter_origin(
                    crate::diagnostics_counters::ORIGIN_GUEST_FAULT,
                );
                checked_increment(&self.exception_counters.raw_exception_exits);
                let raw_exception_exits_now =
                    self.exception_counters.raw_exception_exits.load(Ordering::Relaxed);
                if raw_exception_exits_now % 64 == 0 {
                    let snapshot = self.exception_counters_snapshot();
                    litebox_util_log::debug!(
                        raw_exception_exits:? = snapshot.raw_exception_exits,
                        stale_view_reruns:? = snapshot.stale_view_reruns,
                        wx_service_requests:? = snapshot.wx_service_requests,
                        wx_service_settled:? = snapshot.wx_service_settled,
                        wx_service_refaulted:? = snapshot.wx_service_refaulted,
                        wx_alias_conflict_refusals:? = snapshot.wx_alias_conflict_refusals,
                        guest_faults_serviced:? = snapshot.guest_faults_serviced,
                        guest_faults_delivered:? = snapshot.guest_faults_delivered,
                        exceptions_in_flight:? = snapshot.in_flight,
                        fatal_faults:? = snapshot.fatal_faults,
                        generation:? = snapshot.generation,
                        delivered_task_ring:? = snapshot.delivered_task_ring;
                        "HVF hardware exception counters (short cadence)"
                    );
                }
                ctx.syscallno = -1;
                // A memory abort taken through a translation this vCPU may
                // have cached before a concurrent mapping change is not yet a
                // guest fault: the faulting PC is unchanged, so resuming
                // re-attaches (which synchronizes onto the current root) and
                // re-executes exactly that instruction.  Only a fault that
                // recurs on a current view is delivered.  Bounded so a real
                // fault under continuous unrelated mutation still surfaces.
                let is_abort = matches!(class, 0x20 | 0x21 | 0x24 | 0x25);
                if is_abort
                    && *stale_view_reruns < STALE_VIEW_RERUN_LIMIT
                    && self.view_was_stale(space, snapshot)
                {
                    *stale_view_reruns += 1;
                    checked_increment(&self.exception_counters.stale_view_reruns);
                    litebox_util_log::debug!(
                        class:? = class, far:? = state.far_el1, pc:? = ctx.pc,
                        reruns:? = *stale_view_reruns;
                        "HVF memory abort on a stale view: rerunning after synchronization"
                    );
                    return ContinueOperation::Resume;
                }
                if is_abort
                    && let Some(request) =
                        self.classify_wx_fault(class, state.far_el1, state.esr_el1)
                {
                    // wx-service-latency-measurement: fault-exit-to-resume timing for the
                    // resumed-in-place outcomes below (see `wx_service_latency_count`'s own doc
                    // comment for exactly which outcomes count).
                    let wx_service_start = Instant::now();
                    // `classify_wx_fault` is pure (no mutation, lock released
                    // before returning); `shim.memory_service` revalidates the
                    // request's page against the shim's own `GuestVaDomain`
                    // custody before ever committing, then re-locks `wx_toggle`
                    // only for a cheap generation compare/claim and performs
                    // the real permission mutation with no lock held across
                    // it. A successful flip, a stale-generation refusal
                    // (another racing fault on the same page already claimed
                    // it), and (up to `ALIAS_CONFLICT_RERUN_LIMIT` times) a
                    // domain alias-conflict refusal (the page's owning view
                    // changed since classification, or is still only
                    // lineage-inherited) all just resume the guest at the same
                    // instruction -- none of these is a delivered guest fault.
                    // A genuine host mutation failure, or an alias-conflict
                    // refusal that has exhausted its own bound, falls through
                    // to `try_resolve_cow_fault` and then to ordinary
                    // guest-signal delivery below instead.
                    match shim.memory_service(request) {
                        WxFlipOutcome::Committed(_) => {
                            checked_increment(&self.exception_counters.wx_service_requests);
                            checked_increment(&self.exception_counters.wx_service_settled);
                            *stale_view_reruns = 0;
                            *alias_conflict_reruns = 0;
                            self.record_wx_service_latency(wx_service_start.elapsed());
                            return ContinueOperation::Resume;
                        }
                        WxFlipOutcome::StaleGeneration => {
                            checked_increment(&self.exception_counters.wx_service_requests);
                            checked_increment(&self.exception_counters.wx_service_refaulted);
                            *stale_view_reruns = 0;
                            *alias_conflict_reruns = 0;
                            self.record_wx_service_latency(wx_service_start.elapsed());
                            return ContinueOperation::Resume;
                        }
                        WxFlipOutcome::AliasConflictRefused => {
                            checked_increment(&self.exception_counters.wx_service_requests);
                            checked_increment(&self.exception_counters.wx_alias_conflict_refusals);
                            *stale_view_reruns = 0;
                            if *alias_conflict_reruns < ALIAS_CONFLICT_RERUN_LIMIT {
                                *alias_conflict_reruns += 1;
                                self.record_wx_service_latency(wx_service_start.elapsed());
                                return ContinueOperation::Resume;
                            }
                        }
                        // A genuine host mutation failure means this fault is not this
                        // mechanism's to account for after all -- it falls through to ordinary
                        // guest-signal delivery below, uncounted here, so it contributes to
                        // exactly one bucket of the `raw_exception_exits` equation
                        // (`guest_faults_delivered`), never both.
                        WxFlipOutcome::HostFailure => {}
                    }
                }
                if is_abort
                    && self.try_resolve_cow_fault(
                        space,
                        shim,
                        view,
                        class,
                        state.far_el1,
                        state.esr_el1,
                        snapshot.pending_tlbi_generation.value(),
                    )
                {
                    // FIX (hvf-cow-fault-resolution-uncredited-exception-bucket): see the
                    // identical credit in `dispatch`'s own direct-guest abort arm -- this exit is
                    // already counted in `raw_exception_exits` above, and a successful
                    // `try_resolve_cow_fault` is a `guest_faults_serviced`-scoped resolution (a
                    // COW-split/promotion/alias-install with no guest-visible signal), not an
                    // uncounted freebie.
                    checked_increment(&GUEST_FAULTS_SERVICED);
                    *stale_view_reruns = 0;
                    *alias_conflict_reruns = 0;
                    return ContinueOperation::Resume;
                }
                *stale_view_reruns = 0;
                *alias_conflict_reruns = 0;
                let info = ExceptionInfo {
                    exception: Exception(u8::try_from(class).unwrap_or(0)),
                    // RUNWALL FC2 review fix-up: FAR_EL1 is architecturally updated only on an
                    // abort (EC 0x20/0x21/0x24/0x25), so on every other class the register still
                    // holds the previous abort's address -- and an EL0 entry no longer reinstalls
                    // it, because measuring that reinstall cost ~260 ns of raw `hv_vcpu_run` p50
                    // per run under load. Zero it here instead: this is the only reader of
                    // `far_el1` that is not already `is_abort`-gated (`classify_wx_fault` and
                    // `try_resolve_cow_fault` above, and the two debug logs), and
                    // `litebox_shim_linux` has always derived 0 for non-abort classes anyway, so
                    // this makes the platform's own contract explicit rather than inherited.
                    fault_address: if is_abort {
                        usize::try_from(state.far_el1).unwrap_or(usize::MAX)
                    } else {
                        0
                    },
                    esr: state.esr_el1,
                    // A real EL0 data/instruction abort (`is_abort`) is exactly
                    // the case `litebox_shim_linux`'s `exception()` gates
                    // `PageManager::handle_page_fault` on -- routing it there
                    // instead of the generic guest-signal path is what makes
                    // `VM_GROWSDOWN` stack growth and `MacOsUserland`'s own
                    // `VmemPageFaultHandler` impl (`access_error`/
                    // `handle_page_fault`) reachable on this backend. Every
                    // other exception class (`BRK`, undefined instruction,
                    // ...) keeps `kernel_mode: false`, unaffected.
                    kernel_mode: is_abort,
                    // `ctx` was populated by `write_monitor_exit` at the top
                    // of `dispatch_monitor_exit`; see the direct-guest
                    // `EC_BRK64` arm's identical comment.
                    backtrace: if exception_backtrace_wanted() {
                        capture_frame_backtrace(ctx.regs[29])
                    } else {
                        litebox::shim::FrameBacktrace::EMPTY
                    },
                };
                // Permanent diagnostic aid: every non-SVC/non-WFx monitor
                // exception is rare enough in practice (aborts, undefined
                // instructions, BRK) that a debug-level trace here costs
                // nothing when logging is off and saves a debugger session
                // when a genuine guest fault needs to be diagnosed later.
                litebox_util_log::debug!(
                    class:? = class, esr:? = state.esr_el1, far:? = state.far_el1,
                    pc:? = ctx.pc;
                    "HVF monitor exception dispatched to shim.exception"
                );
                if !is_abort {
                    // `kernel_mode: false` above means `litebox_shim_linux`'s `exception()`
                    // never routes this into `PageManager::handle_page_fault` -- this call site
                    // is the only place a delivery decision is made for it, so credit it here.
                    // A real EL0 abort (`is_abort`), by contrast, is decided downstream by
                    // whether `handle_page_fault` returns `Ok` (serviced) or `Err` (delivered via
                    // `Task::deliver_page_fault_segv`'s own provider-hook call) -- crediting it
                    // here too would double-count one raw exit across two buckets.
                    checked_increment(&GUEST_FAULTS_DELIVERED);
                }
                let exception_started = Instant::now();
                let op = shim.exception(ctx, &info);
                crate::diagnostics_counters::record_exception_service(
                    crate::diagnostics_counters::elapsed_ns(exception_started),
                );
                op
            }
        }
    }

    /// Pure classifier for a guest stage-2 permission fault against a
    /// WX-toggle-eligible region (see [`WxToggle`]). Takes the `wx_toggle`
    /// lock only long enough to read the faulting page's current direction
    /// and generation and compute the request to attempt; performs zero
    /// mutation and zero calls into `mutate_with_retry`/`protect_range`, and
    /// the lock is released (end of scope) before this returns. `None` means
    /// this fault is not this mechanism's to resolve -- including a
    /// permission fault whose direction already matches the page's current
    /// real state, which means something other than this toggle caused it --
    /// so the caller falls through to ordinary guest-signal delivery exactly
    /// as before this mechanism existed.
    fn classify_wx_fault(&self, class: u64, far_el1: u64, esr_el1: u64) -> Option<WxFlipRequest> {
        // `wx_service_requests` is incremented by the caller, exactly once per `Some(..)`
        // returned here, keyed off `commit_wx_flip`'s own outcome -- not here, before the
        // outcome (or even whether this mechanism claims the fault at all) is known.
        if esr_el1 & ESR_FSC_PERMISSION_FAULT_MASK != ESR_FSC_PERMISSION_FAULT {
            return None;
        }
        let want_execute = match class {
            EC_INSTRUCTION_ABORT_LOWER_EL => true,
            EC_DATA_ABORT_LOWER_EL if esr_el1 & ESR_WNR != 0 => false,
            _ => return None,
        };
        let page = usize::try_from(far_el1).ok()? & !(PAGE_SIZE - 1);
        let state = self
            .wx_toggle
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.regions.range(..=page).next_back().is_some_and(|(_, &end)| page < end) {
            return None;
        }
        let current = state.executable_pages.get(&page);
        let currently_executable = current.is_some_and(|entry| entry.executable);
        let expected_generation = current.map_or(0, |entry| entry.generation);
        if currently_executable == want_execute {
            // Its real permission already matches what the guest wants --
            // this fault is not this mechanism's doing.
            return None;
        }
        Some(WxFlipRequest {
            page,
            want_execute,
            expected_generation,
        })
    }

    /// Whether `page` falls inside one of the W^X toggle's own registered combined-RWX regions
    /// (see `WxToggleState::regions`) -- the same region test [`Self::classify_wx_fault`] uses,
    /// factored out for [`Self::try_resolve_cow_fault`]'s own use: a COW-inherited page in such a
    /// region is logically RWX regardless of its CURRENT, ephemeral R+W-vs-R+X hardware direction,
    /// so a promotion of it must derive its resulting permission from the fault's own direction
    /// instead of from that ephemeral direction (see `HvfAddressSpace::promote_cow_alias`'s own
    /// doc comment).
    fn wx_toggle_region_contains(&self, page: usize) -> bool {
        let state = self
            .wx_toggle
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.regions.range(..=page).next_back().is_some_and(|(_, &end)| page < end)
    }

    /// Commits a request `classify_wx_fault` produced (after the shim side, via
    /// `EnterShim::memory_service`, has already revalidated it against `GuestVaDomain` custody --
    /// this method never decides `AliasConflictRefused` itself, only `Committed`/`StaleGeneration`/
    /// `HostFailure`). Re-locks `wx_toggle` only to compare `req.expected_generation` against the
    /// page's live generation; a mismatch (another racing fault on the same page already claimed
    /// it) is refused as [`WxFlipOutcome::StaleGeneration`] with the lock released immediately, no
    /// wait. On a match, the generation is bumped immediately (claiming exclusive commit rights
    /// for this page) and the lock is dropped *before* the real mutation -- this lock is NEVER
    /// held across `mutate_with_retry`, which can itself block on shootdown/quarantine
    /// convergence. The claim is what prevents two concurrent flips on the same page from both
    /// reaching `protect_range`: a second racer sees the already-bumped generation and is refused
    /// before it can mutate anything, so no two backing aliases ever hold simultaneous
    /// writer+executor authority over one page.
    pub(crate) fn commit_wx_flip_host(
        &self,
        page: usize,
        want_execute: bool,
        expected_generation: u64,
        view: Option<VmViewId>,
    ) -> WxFlipOutcome {
        let _origin =
            crate::diagnostics_counters::enter_origin(crate::diagnostics_counters::ORIGIN_WX_TOGGLE);
        let space = match self.resolve_view_space(view) {
            Ok(space) => space,
            Err(error) => {
                litebox_util_log::warn!(page:? = page, error:% = error; "HVF WX-toggle flip failed to resolve its per-view space");
                return WxFlipOutcome::HostFailure;
            }
        };
        let req = WxFlipRequest { page, want_execute, expected_generation };
        let claimed_generation = {
            let mut state = self
                .wx_toggle
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = state.executable_pages.entry(req.page).or_insert(WxPageState {
                executable: false,
                generation: 0,
            });
            if entry.generation != req.expected_generation {
                return WxFlipOutcome::StaleGeneration;
            }
            entry.generation = entry.generation.wrapping_add(1);
            entry.generation
        };
        let want = if req.want_execute {
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE
        } else {
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE
        };
        let mutate_started = Instant::now();
        let flip_range = req.page..req.page + PAGE_SIZE;
        self.diverge_fork_write_protected_pages(&space, &flip_range);
        // Dispatched on how the space holds the page, exactly like `protect_view_range`: an
        // own claim flips in place; a promoted page (a COW shadow, lineage or file) flips
        // through its shadow's own `protect_range`, which publishes EXECUTE for the shadow's
        // bytes; a file alias only ever carries READ or READ|EXECUTE (the write direction
        // leaves it READ and the next store promotes); an untouched window page has nothing to
        // flip yet -- its first touch installs the alias in the toggle's direction.
        let (kinds, _) = space.settle_gate(GrSite::PageKinds, || space.page_kinds(&flip_range));
        let kind = kinds.first().map_or(PageKind::Missing, |(_, kind)| *kind);
        let flip = match kind {
            PageKind::Promoted => self.settle_single_page_mutation(&space, MutationKind::Protect, || {
                space.materialize_page_with_permissions(None, req.page, want)
            }),
            PageKind::FileAlias => match self.origin_space.as_ref() {
                Some(origin) => space
                    .reprotect_file_aliases(origin, &flip_range, want)
                    .map(|changed| {
                        if changed {
                            self.kick_running_lanes_in(&space);
                        }
                        changed
                    }),
                None => Err(HvfMemoryError::RangeUnmapped(flip_range.clone())),
            },
            PageKind::FileWindow => Ok(false),
            _ => self.settle_single_page_mutation(&space, MutationKind::Protect, || {
                space.protect_range(flip_range.clone(), want)
            }),
        };
        let mutate_elapsed_nanos = u64::try_from(mutate_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut state = self
            .wx_toggle
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = state.executable_pages.get_mut(&req.page) else {
            // Released (munmap/mprotect-away) while unlocked; nothing to
            // record either way.
            return match flip {
                Ok(_) => WxFlipOutcome::Committed(mutate_elapsed_nanos),
                Err(_) => WxFlipOutcome::HostFailure,
            };
        };
        if entry.generation != claimed_generation {
            // Someone else's register/release touched this page while we
            // were unlocked; our own claim is moot either way.
            return match flip {
                Ok(_) => WxFlipOutcome::Committed(mutate_elapsed_nanos),
                Err(_) => WxFlipOutcome::HostFailure,
            };
        }
        match flip {
            Ok(_) => {
                // `wx_service_settled`/`wx_service_refaulted` are the caller's responsibility
                // (`dispatch_monitor_exit`, keyed off this method's returned outcome) -- not
                // incremented here, so a `Committed` outcome is credited exactly once regardless
                // of which of this function's three `Committed` return points produced it.
                entry.executable = req.want_execute;
                WxFlipOutcome::Committed(mutate_elapsed_nanos)
            }
            Err(error) => {
                // Roll the claim back so a later fault on this page can
                // retry instead of being permanently wedged at a generation
                // no future `expected_generation` will ever match.
                entry.generation = req.expected_generation;
                litebox_util_log::warn!(page:? = req.page, error:% = error; "HVF WX-toggle flip failed");
                WxFlipOutcome::HostFailure
            }
        }
    }

}

/// Guest-transparent write-xor-execute emulation for a guest `mprotect`
/// requesting simultaneous WRITE and EXECUTE (e.g. V8/JIT CodeRange setup).
/// `guest_permissions` below refuses that combination outright, and every
/// path through `HvfAddressSpace` still refuses it too (`refuse_write_execute`
/// in `hvf_memory.rs`) -- no guest page is ever granted real, simultaneous
/// write+execute stage-2 permission by this mechanism or any other. Instead,
/// a registered region is granted the guest's *logical* view as RWX (so
/// `mprotect`/`/proc/self/maps` see exactly what real Linux would show, via
/// the ordinary `VmArea`/`VmFlags` bookkeeping in `litebox/src/mm/linux.rs`,
/// which is populated from whatever `MemoryRegionPermissions` this platform's
/// `update_permissions` returns `Ok` for) while the *real* stage-2 permission
/// on each page is either read+write or read+execute, flipping a single page
/// on demand -- see [`HvfBackend::try_resolve_wx_fault`] -- the instant a
/// stage-2 permission fault proves the guest actually needs the other one. A
/// page absent from `executable_pages` is the default, read+write, matching
/// the state every registration (re-)establishes.
#[derive(Default)]
struct WxToggle {
    state: Mutex<WxToggleState>,
}

#[derive(Default)]
struct WxToggleState {
    /// Disjoint address ranges currently granted combined RWX, start -> end.
    regions: BTreeMap<usize, usize>,
    /// Per-page real-permission direction and a generation counter used by
    /// [`HvfBackend::commit_wx_flip_host`] to admit only one in-flight flip per
    /// page at a time. A page absent from this map behaves exactly as
    /// `executable: false, generation: 0` -- read+write, the default a
    /// region starts at.
    executable_pages: HashMap<usize, WxPageState>,
}

/// Per-page state tracked by [`WxToggleState`]. See that type's own doc
/// comment.
#[derive(Clone, Copy, Debug)]
struct WxPageState {
    /// Whether this page's real stage-2 permission is currently read+execute
    /// (`true`) or read+write (`false`).
    executable: bool,
    /// Bumped on every successful or claimed flip attempt; used by
    /// [`HvfBackend::commit_wx_flip_host`] as a cheap compare-and-claim so two
    /// concurrent faults on the same page cannot both reach
    /// `protect_range`.
    generation: u64,
}

impl WxToggle {
    /// Grants `range` combined RWX from the guest's point of view. The real
    /// permission for every page in `range` starts (or resets to) read+write
    /// -- matching real Linux's own `mprotect(RWX)`, which does not preserve
    /// whatever a page happened to contain permission-wise beforehand.
    /// Overlapping/adjacent existing registrations are merged so `contains`
    /// sees one continuous region rather than fragments.
    fn register(&self, range: Range<usize>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.executable_pages.retain(|page, _| !range.contains(page));
        let mut start = range.start;
        let mut end = range.end;
        let overlapping: Vec<(usize, usize)> = state
            .regions
            .iter()
            .filter(|&(&s, &e)| s <= end && start <= e)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            state.regions.remove(&s);
            start = start.min(s);
            end = end.max(e);
        }
        state.regions.insert(start, end);
    }

    /// Releases `range` from toggle tracking: a guest `mprotect` to a
    /// non-combined permission, or an `munmap`, means this address range is
    /// no longer under this emulation, and any later fault there must be
    /// treated as a genuine guest fault rather than a toggle-eligible one.
    fn release(&self, range: &Range<usize>) {
        if range.start >= range.end {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.executable_pages.retain(|page, _| !range.contains(page));
        let overlapping: Vec<(usize, usize)> = state
            .regions
            .iter()
            .filter(|&(&s, &e)| s < range.end && range.start < e)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            state.regions.remove(&s);
            if s < range.start {
                state.regions.insert(s, range.start);
            }
            if range.end < e {
                state.regions.insert(range.end, e);
            }
        }
    }
}

/// Whether `error` is the expected, recoverable "the address space moved
/// between attachment and submission" race.
fn is_recoverable_attachment_race(error: &HvfBackendError) -> bool {
    fn memory_is_race(error: &HvfMemoryError) -> bool {
        matches!(error, HvfMemoryError::AttachmentGenerationChanged)
    }
    fn lane_is_race(error: &HvfVcpuLaneError) -> bool {
        match error {
            HvfVcpuLaneError::Memory(inner) => memory_is_race(inner),
            HvfVcpuLaneError::Cleanup { primary, cleanup } => {
                lane_is_race(primary) && lane_is_race(cleanup)
            }
            _ => false,
        }
    }
    match error {
        HvfBackendError::Memory(inner) => memory_is_race(inner),
        HvfBackendError::Lane(inner) => lane_is_race(inner),
        _ => false,
    }
}

/// Process-global count of terminal [`fatal`] calls. Separate from
/// [`HvfExceptionCounters`] because `fatal` has no backend handle at some of
/// its call sites (e.g. before the backend is published); the process aborts
/// immediately after incrementing it, so the count is witnessed only in the
/// log lines below, never read back in-process.
static FATAL_FAULTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Increments a monotonic, checked (never-wrapping) hardware-exception counter that
/// participates in one of [`HvfExceptionCounters`]'s two invariant equations. A wrap here would
/// be a host-lifetime accounting bug, not a guest-controlled condition (the guest cannot force
/// `u64::MAX` real exception exits), so failing open by silently wrapping would defeat the exact
/// thing these counters exist to prove -- abort instead, exactly the fail-stop idiom
/// `litebox::utils::ids`'s checked identity minters already use for the same reason.
fn checked_increment(counter: &std::sync::atomic::AtomicU64) {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("hardware-exception counter overflowed a u64 -- host invariant violated");
}

/// Process-global count of guest page faults resolved with no guest-visible signal -- stack
/// growth, lazy materialization, COW-split, overlay-wait, or page-table repopulation. See
/// [`PageManagementProvider::record_guest_fault_serviced`](litebox::platform::page_mgmt::PageManagementProvider::record_guest_fault_serviced).
/// Process-global rather than a field on [`HvfExceptionCounters`] because
/// `litebox::mm::PageManager::handle_page_fault` (a different crate) calls the provider hook
/// that increments this with no `&HvfBackend` handle in scope, and only one `HvfBackend` is ever
/// installed per process.
///
/// FIX (hvf-cow-fault-resolution-uncredited-exception-bucket): `dispatch`'s direct-guest abort
/// arm and `dispatch_monitor_exit`'s catch-all arm also increment this directly (not via the
/// provider hook above) whenever [`HvfBackend::try_resolve_cow_fault`] resolves a fork-COW
/// fault. That path is a `guest_faults_serviced` case by the exact same "resolved with no
/// guest-visible signal" definition (a COW-split/promotion/alias-install), but never reaches
/// `PageManager::handle_page_fault` at all -- it resumes the guest straight out of `dispatch`/
/// `dispatch_monitor_exit`, before `shim.exception` is ever called -- so crediting it only
/// through the provider hook would silently miss it, which is exactly the gap this row was
/// filed against: `raw_exception_exits` counted the exit but no bucket in
/// [`HvfExceptionCountersSnapshot`]'s own documented invariant equation credited it back.
static GUEST_FAULTS_SERVICED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One-way, process-wide flip: set the first time any per-view fork child is stamped with a fork
/// origin (`HvfBackend::fork_time_ancestor_protect`), never cleared. `prepare_guest_access`
/// checks this ahead of resolving any space, so a process that never forks pays one relaxed
/// load per host-side guest access.
static ANY_FORK_VIEW_EVER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Process-wide count of `fork_time_ancestor_protect` calls (one per owned range per fork) --
/// `PageManagementProvider::fork_generation`: read before a host-side guest access and again
/// when that access faults after `prepare_guest_access` approved it, so the fault can be
/// attributed to a fork that stripped the page in between (or ruled out as one).
static FORK_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn fork_generation() -> u64 {
    FORK_GENERATION.load(Ordering::Relaxed)
}

/// `PageManagementProvider::guest_access_fault_trace`: `LITEBOX_GUEST_ACCESS_FAULT_TRACE=1` in
/// the environment turns on the opt-in trace of host-side guest accesses that fault after
/// `prepare_guest_access` approved them (and of the fork-COW divergence/promotion failures that
/// leave a page in that state). Read once, cached for the life of the process, so the untraced
/// path costs one `OnceLock` load.
pub(crate) fn guest_access_fault_trace() -> bool {
    static TRACE: OnceLock<bool> = OnceLock::new();
    *TRACE.get_or_init(|| {
        std::env::var_os("LITEBOX_GUEST_ACCESS_FAULT_TRACE").is_some_and(|value| value == "1")
    })
}

/// T1f-b F1: how many pages of one file window a single fault may alias at once
/// (`LITEBOX_HVF_FAULT_AROUND`; `1` is the default, i.e. one page per fault -- what every
/// measurement before this step used, and what this step's own measurement selected).
///
/// Measured on the idle desktop (five 60 s windows, same signed binary, arm `t1f-desk-c1` at 4
/// against arm `t1f-desk-c0` at 1 -- that pair is the baseline quoted below, and it is the one
/// `.gm/syscall-bench/steps/t1f/notes.md` tabulates): fault-around cut the file-window installs
/// by 63 %, the guest faults by 46 %, the mutation attempts by 45 % and the settled mutations by
/// 32 % per 1000 guest syscalls. Against the earlier instrumentation-only arm `t1f-desk-a1`
/// (a different, quieter session) the same four figures read 61 % / 42 % / 42 % / 29 % -- both
/// are correct for their own baseline, so quote the arm with them.
///
/// It left the runner's idle CPU per 1000 syscalls unchanged (1.53 -> 1.56, inside the arm's own
/// 1.01-1.75 window spread) while raising `file_alias_pages_live` by 77 %, `host_slots` by 17 %
/// and `live_data_pages` by 15 % (every speculative page carries a host slot and an origin alias
/// reference), and it made xterm typing 200x worse (11.8 -> 2436 ms median). Not worth shipping
/// by default on a host whose live-data budget is the known failure mode, so the mechanism stays
/// wired for the next measurement behind this knob. Its multi-page path has **no** race witness:
/// `--hvf-alias-race` exercises anonymous `map_range`/`unmap_range` and never reaches this
/// function, so running it with the knob set proves nothing about it (PRD row
/// `hvf-t1f-fault-around-multipage-path-has-no-race-witness`). Read once, so the shipped path
/// costs one `OnceLock` load.
pub(crate) fn fault_around_pages() -> usize {
    static AROUND: OnceLock<usize> = OnceLock::new();
    *AROUND.get_or_init(|| {
        std::env::var("LITEBOX_HVF_FAULT_AROUND")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .map_or(1, |value| value.min(16))
    })
}

/// How many acting rounds a host-side access's page preparation may run (see
/// [`revalidated_rounds`]) before its next snapshot is judged as it stands. A page needs at most
/// three steps in sequence (ancestor-side divergence, alias install, promotion), each run in its
/// own round, so four rounds cover every ordinary path plus one lost race.
const HOST_PREPARE_ROUNDS: usize = 4;

/// Plan-then-act with structural revalidation -- the one shape every host-side page preparation
/// takes (T1h fix-up; class rule: nothing is decided from state read before a possibly-blocking
/// or mutating call). `snapshot` reads the state of every page of interest under one lock;
/// `pass` walks THAT snapshot, runs at most one action per page and reports whether it ran any.
/// An action (a `settle_single_page_mutation`) can block -- VM operation gate, TLBI, retirement
/// pumps -- and lets sibling threads change the space meanwhile, so a snapshot is only ever acted
/// on in the round that took it: a round that ran an action is followed by a fresh snapshot, and
/// an action that finds its page already changed (a lost race: `AddressOverlap`, a no-op
/// promotion) is re-decided from that fresh snapshot rather than skipped. Every action re-checks
/// its own precondition under its own locks, so the one kind of stale entry a pass can still act
/// on (a page a sibling changed after this round's snapshot) costs a failed or no-op action,
/// never a wrong one. Returns the first snapshot a round had nothing to do in -- necessarily taken
/// after the last action, so it is the post-condition the caller judges -- or, after `rounds`
/// acting rounds, the next snapshot unacted.
fn revalidated_rounds<S>(
    rounds: usize,
    mut snapshot: impl FnMut() -> S,
    mut pass: impl FnMut(&S) -> bool,
) -> S {
    let mut acted = 0;
    loop {
        let state = snapshot();
        if acted == rounds || !pass(&state) {
            return state;
        }
        acted += 1;
    }
}

/// One host-access preparation step for one page (see [`HostPagePreparer::step_for`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostPageStep {
    /// Ancestor side: self-diverge this space's own fork-time write-protected page (a write).
    SelfDiverge,
    /// Promote a file alias to a private copy (a write: the origin is never host-writable).
    PromoteFileAlias,
    /// Install a COW read alias onto the lineage ancestor's page (a fork child's page).
    InstallAlias,
    /// Promote a COW read alias to a private copy (a write, or its source slot relocated).
    PromoteAlias,
    /// An untouched file window page: alias the origin (a read) or materialize it (a write).
    WindowPage,
}

impl HostPageStep {
    const fn bit(self) -> u8 {
        match self {
            Self::SelfDiverge => 1,
            Self::PromoteFileAlias => 2,
            Self::InstallAlias => 4,
            Self::PromoteAlias => 8,
            Self::WindowPage => 16,
        }
    }
}

/// What running one [`HostPageStep`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostStepOutcome {
    /// Nothing to run it against (no ancestor, no origin, no window): no action, no change.
    NotApplicable,
    /// A settled mutation ran; `ok` is its result.
    Acted { ok: bool },
}

/// The lineage-ancestor spaces one host-access preparation resolves, one lookup per distinct
/// ancestor view.
struct AncestorCache<'a> {
    view: VmViewId,
    ancestor_of: &'a dyn Fn(usize) -> Option<VmViewId>,
    cached: Option<(VmViewId, Arc<HvfAddressSpace>)>,
}

impl AncestorCache<'_> {
    /// The view holding `page` by lineage, when that is another view.
    fn holder(&self, page: usize) -> Option<VmViewId> {
        (self.ancestor_of)(page).filter(|holder| *holder != self.view)
    }

    fn resolve(
        &mut self,
        backend: &HvfBackend,
        page: usize,
    ) -> Option<(VmViewId, Arc<HvfAddressSpace>)> {
        let holder = self.holder(page)?;
        if let Some((cached_view, cached)) = &self.cached
            && *cached_view == holder
        {
            return Some((holder, cached.clone()));
        }
        let resolved = backend.existing_space_for_view(holder)?;
        self.cached = Some((holder, resolved.clone()));
        Some((holder, resolved))
    }
}

/// One round's plan, plus how this build spends one the domain has moved on from (see
/// [`HostPagePreparer::pass`]).
struct RoundPlan {
    entries: Vec<HostAccessEntry>,
    /// Abandon the round instead of walking `entries`: only ever set by the
    /// `LITEBOX_HVF_GR_STALE_SKIPS_ROUND` control arm.
    abandon: bool,
}

/// One host-side access's page preparation (`HvfBackend::prepare_guest_access`), driven through
/// [`revalidated_rounds`] over `HvfAddressSpace::host_access_plan` snapshots.
struct HostPagePreparer<'a> {
    backend: &'a HvfBackend,
    space: &'a HvfAddressSpace,
    view: VmViewId,
    write: bool,
    fork_child: bool,
    ancestors: AncestorCache<'a>,
    /// Per page of the range: the [`HostPageStep::bit`]s whose run failed (or had nothing to run
    /// against), never tried again by this access -- a page whose state still calls for one of
    /// them is judged by [`Self::usable`] instead.
    failed: Vec<u8>,
    promoted: &'a mut Vec<usize>,
}

impl HostPagePreparer<'_> {
    /// The next step `entry`'s page needs, skipping steps that already failed on it.
    fn step_for(&self, entry: &HostAccessEntry, failed: u8) -> Option<HostPageStep> {
        let open = |step: HostPageStep| failed & step.bit() == 0;
        if self.write && entry.fork_protected && open(HostPageStep::SelfDiverge) {
            return Some(HostPageStep::SelfDiverge);
        }
        match entry.alias_state {
            HostAliasState::Promoted => None,
            // A read is served from the origin's own host mirror through the redirect.
            HostAliasState::FileAlias => (self.write && open(HostPageStep::PromoteFileAlias))
                .then_some(HostPageStep::PromoteFileAlias),
            HostAliasState::Alias { relocated } => ((self.write || relocated)
                && open(HostPageStep::PromoteAlias))
            .then_some(HostPageStep::PromoteAlias),
            // `Own`: a page `view` claims itself (a `MAP_SHARED` mapping inherited by claim,
            // anything mapped after the fork) -- its own claim is the host mirror there, and the
            // lineage lookup, which may well still name the ancestor, must not alias over it
            // (observed live as a spurious `install_cow_read_alias` per host-side write). An
            // untouched window page tries the lineage ancestor first (a grandparent's pre-fork
            // promotion wins over the origin), then the origin.
            HostAliasState::Other => match entry.kind {
                PageKind::Own => None,
                PageKind::FileWindow => {
                    if self.fork_child && open(HostPageStep::InstallAlias) {
                        Some(HostPageStep::InstallAlias)
                    } else {
                        open(HostPageStep::WindowPage).then_some(HostPageStep::WindowPage)
                    }
                }
                _ => (self.fork_child && open(HostPageStep::InstallAlias))
                    .then_some(HostPageStep::InstallAlias),
            },
        }
    }

    /// One round over one snapshot: at most one ACTING step per page (a step with nothing to run
    /// against is recorded as failed and the page's next step is tried at once: no state
    /// changed). Returns whether any step acted.
    fn pass(&mut self, round: &RoundPlan) -> bool {
        // CLASS R: `abandon` is the control arm's shape only (`LITEBOX_HVF_GR_STALE_SKIPS_ROUND`);
        // the shipped shape never reaches this branch because its plan is settled by the snapshot.
        if round.abandon {
            return true;
        }
        let mut acted = false;
        for (index, entry) in round.entries.iter().enumerate() {
            let Some(mut failed) = self.failed.get(index).copied() else {
                continue;
            };
            while let Some(step) = self.step_for(entry, failed) {
                let outcome = self.run(entry.page, step);
                if outcome != (HostStepOutcome::Acted { ok: true }) {
                    failed |= step.bit();
                }
                if outcome != HostStepOutcome::NotApplicable {
                    file_cow_count(&FILE_COW_COUNTERS.host_prepare_steps);
                    acted = true;
                    break;
                }
            }
            if let Some(slot) = self.failed.get_mut(index) {
                *slot = failed;
            }
        }
        acted
    }

    /// Whether the access may use `entry`'s page as it stands (judged on the final snapshot). A
    /// write needs a host target that is this view's own page -- a promoted copy, its own claim,
    /// or an unmaterialized page no lineage ancestor holds -- never an alias of an ancestor's
    /// page, a shared file origin, an untouched window page, a lineage-held page, or one still
    /// fork-time write-protected. A read needs the host target to show this view's content, which
    /// only an alias whose source slot relocated fails (the mirror at its GVA shows the
    /// ancestor's newer bytes). Everything else keeps its pre-existing behavior (a host fault
    /// there is retried and then refused by the access itself).
    fn usable(&self, entry: &HostAccessEntry) -> bool {
        if !self.write {
            return entry.alias_state != (HostAliasState::Alias { relocated: true });
        }
        if entry.fork_protected {
            return false;
        }
        match entry.alias_state {
            HostAliasState::Promoted => true,
            HostAliasState::FileAlias | HostAliasState::Alias { .. } => false,
            HostAliasState::Other => match entry.kind {
                PageKind::Own => true,
                PageKind::FileWindow => false,
                _ => !self.fork_child || self.ancestors.holder(entry.page).is_none(),
            },
        }
    }

    /// Runs one step against `page`'s current state; each underlying mutation re-checks its own
    /// precondition under its own locks, so a stale decision costs a failed or no-op action.
    fn run(&mut self, page: usize, step: HostPageStep) -> HostStepOutcome {
        let backend = self.backend;
        let space = self.space;
        let view = self.view;
        let write = self.write;
        match step {
            HostPageStep::SelfDiverge => HostStepOutcome::Acted {
                ok: backend.self_diverge_for_host_access(space, page),
            },
            HostPageStep::PromoteFileAlias => {
                let Some(origin) = backend.origin_space.as_ref() else {
                    return HostStepOutcome::NotApplicable;
                };
                let target = space
                    .settle_gate(GrSite::FileWindowAt, || space.file_window_at(page))
                    .0
                    .map_or(PromoteTarget::Inherit, |window| PromoteTarget::Exact(window.perms));
                let result = backend.settle_single_page_mutation(space, MutationKind::Protect, || {
                    space.promote_file_alias(origin, page, target)
                });
                match result {
                    Ok(_) => {
                        file_cow_count(&FILE_COW_COUNTERS.promotions_host);
                        file_cow_count(&FILE_COW_COUNTERS.host_write_promotions);
                        self.promoted.push(page);
                        HostStepOutcome::Acted { ok: true }
                    }
                    Err(error) => {
                        if guest_access_fault_trace() {
                            litebox_util_log::warn!(
                                page:? = page, view:? = view, error:% = error, state:% = space.describe_page(page);
                                "guest-access fault trace: file alias could not be promoted ahead of a host-side write"
                            );
                        }
                        HostStepOutcome::Acted { ok: false }
                    }
                }
            }
            HostPageStep::InstallAlias => {
                let Some((ancestor_view, ancestor)) = self.ancestors.resolve(backend, page) else {
                    return HostStepOutcome::NotApplicable;
                };
                let result = backend.settle_single_page_mutation(space, MutationKind::Map, || {
                    space.install_cow_read_alias(&ancestor, page)
                });
                match result {
                    Ok(_) => HostStepOutcome::Acted { ok: true },
                    Err(error) => {
                        // `AddressOverlap`: the page gained a state of its own after the snapshot
                        // (a sibling thread's fault aliased or promoted it): the next snapshot
                        // shows which, and the page is re-decided from it.
                        if matches!(error, HvfMemoryError::AddressOverlap(_)) {
                            file_cow_count(&FILE_COW_COUNTERS.host_prepare_stale);
                        } else if guest_access_fault_trace() {
                            litebox_util_log::warn!(
                                page:? = page, view:? = view, ancestor_view:? = ancestor_view, write:? = write,
                                error:% = error, state:% = space.describe_page(page);
                                "guest-access fault trace: lineage-inherited page could not be aliased ahead of a host-side access"
                            );
                        }
                        HostStepOutcome::Acted { ok: false }
                    }
                }
            }
            HostPageStep::PromoteAlias => {
                let Some((ancestor_view, ancestor)) = self.ancestors.resolve(backend, page) else {
                    return HostStepOutcome::NotApplicable;
                };
                let wx_toggle_want_execute = backend.wx_toggle_region_contains(page).then_some(false);
                let result = backend.settle_single_page_mutation(space, MutationKind::Protect, || {
                    space.promote_cow_alias(&ancestor, page, wx_toggle_want_execute)
                });
                litebox_util_log::debug!(
                    page:? = page, view:? = view, ancestor_view:? = ancestor_view, write:? = write,
                    ok:? = result.is_ok();
                    "HVF fork-COW: promoted a lineage-inherited page ahead of a host-side access"
                );
                match result {
                    Ok(_) => {
                        self.promoted.push(page);
                        HostStepOutcome::Acted { ok: true }
                    }
                    Err(error) => {
                        if guest_access_fault_trace() {
                            litebox_util_log::warn!(
                                page:? = page, view:? = view, ancestor_view:? = ancestor_view,
                                write:? = write, error:% = error, state:% = space.describe_page(page);
                                "guest-access fault trace: lineage-inherited page could not be promoted ahead of a host-side access"
                            );
                        }
                        HostStepOutcome::Acted { ok: false }
                    }
                }
            }
            HostPageStep::WindowPage => {
                backend.prepare_window_page_for_host_access(space, view, page, write, self.promoted)
            }
        }
    }
}

/// `LITEBOX_HVF_NO_FORK_COW_REAP=1` turns `HvfBackend::reap_fork_cow_retention` off -- the
/// operator escape hatch for bisecting a fork-COW regression against the retention leak it
/// closes, same default-off pattern as `LITEBOX_HVF_LANES`. Read once, cached.
fn fork_cow_reap_disabled() -> bool {
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var_os("LITEBOX_HVF_NO_FORK_COW_REAP").is_some_and(|value| value == "1")
    })
}

/// `LITEBOX_HVF_NO_FILE_COW=1` turns the shared read-only file origins off: no origin space is
/// created and `try_allocate_cow_pages` refuses every request, so every private file mapping
/// takes the shim's memcpy path exactly as before origins existed -- the A/B switch for the same
/// binary. Read once, cached.
pub(crate) fn file_cow_disabled() -> bool {
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var_os("LITEBOX_HVF_NO_FILE_COW").is_some_and(|value| value == "1")
    })
}

/// One `windows` reference on a `Ready` file origin, taken by
/// [`HvfBackend::acquire_file_origin`]; handed to the window record on a successful install
/// (`commit`), otherwise given back on drop with the key queued for the next drain -- so no
/// failure between the acquire and the install ever leaks a reference (design I6).
struct OriginRef {
    key: FileOriginKey,
    gva: usize,
    armed: bool,
}

impl OriginRef {
    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for OriginRef {
    fn drop(&mut self) {
        if self.armed {
            file_origin_adjust(self.key, -1, 0);
        }
    }
}

/// Process-global count of guest page faults that resulted in a real delivered `SIGSEGV`. See
/// [`PageManagementProvider::record_guest_fault_delivered`](litebox::platform::page_mgmt::PageManagementProvider::record_guest_fault_delivered).
static GUEST_FAULTS_DELIVERED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const DELIVERED_TASK_RING_LEN: usize = 16;

/// Ring of the most recently delivered-to task identities, for
/// [`HvfBackend::exception_counters_snapshot`]. `0` marks an empty slot (never a valid
/// `TaskInstanceId`, which is a nonzero `u64`); a full ring simply overwrites its oldest entry.
static DELIVERED_TASK_RING: [std::sync::atomic::AtomicU64; DELIVERED_TASK_RING_LEN] = {
    const ZERO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    [ZERO; DELIVERED_TASK_RING_LEN]
};
static DELIVERED_TASK_RING_CURSOR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The `Platform::any_host_redirect_active` front door -- see [`ANY_HOST_REDIRECT_EVER`]. Unlike
/// [`active`], this needs no live [`HvfBackend`]: the flag can only ever be set by code that runs
/// through one, so with no backend installed it is trivially still clear.
pub(crate) fn any_host_redirect_active_hint() -> bool {
    ANY_HOST_REDIRECT_EVER.load(Ordering::Relaxed)
}

pub(crate) fn record_guest_fault_serviced() {
    checked_increment(&GUEST_FAULTS_SERVICED);
}

pub(crate) fn record_guest_fault_delivered(task: litebox::utils::ids::TaskInstanceId) {
    checked_increment(&GUEST_FAULTS_DELIVERED);
    let slot =
        DELIVERED_TASK_RING_CURSOR.fetch_add(1, Ordering::Relaxed) % DELIVERED_TASK_RING_LEN;
    DELIVERED_TASK_RING[slot].store(task.get().get(), Ordering::Relaxed);
}

fn fatal(what: &str, error: &HvfBackendError) -> ! {
    checked_increment(&FATAL_FAULTS);
    let count = FATAL_FAULTS.load(Ordering::Relaxed);
    litebox_util_log::error!(error:% = error, fatal_faults:? = count; "fatal HVF backend failure while {what}");
    eprintln!(
        "litebox_platform_macos_userland: fatal HVF backend failure while {what} (fatal_faults={count}): {error}"
    );
    std::process::abort()
}

fn time_slice_deadline() -> u64 {
    let now: u64;
    // SAFETY: EL0 reads of `CNTVCT_EL0` are permitted on Apple Silicon (it is
    // what `mach_absolute_time` itself reads); the guest sees the same counter
    // because the backend never programs a virtual-timer offset.
    unsafe {
        core::arch::asm!("isb", "mrs {counter}, cntvct_el0", counter = out(reg) now, options(nomem, nostack));
    }
    let ticks = TIME_SLICE
        .as_nanos()
        .saturating_mul(u128::from(TIMER_TICKS_PER_SECOND))
        / 1_000_000_000;
    now.saturating_add(u64::try_from(ticks).unwrap_or(u64::MAX))
}

/// The architectural state a run installs: `ctx`'s integer file, the thread pointer, and the
/// vector file only while the host copy is authoritative (FXR: otherwise the run keeps the
/// resident one and these Q/FPCR/FPSR stay zero -- a stale host copy never leaves the thread).
fn architectural_state(ctx: &PtRegs, thread: &HvfThreadContext) -> HvfArchitecturalState {
    let mut state = HvfArchitecturalState::default();
    for (destination, source) in state.x.iter_mut().zip(ctx.regs.iter()) {
        *destination = *source as u64;
    }
    state.sp_el0 = ctx.sp as u64;
    state.sp_el1 = 0;
    state.pc = ctx.pc as u64;
    state.cpsr = ctx.pstate;
    if thread.fp_host_valid() {
        for (destination, source) in state.q.iter_mut().zip(thread.fp.v.iter()) {
            *destination = HvfSimd128 {
                bytes: source.to_le_bytes(),
            };
        }
        state.fpcr = u64::from(thread.fp.fpcr);
        state.fpsr = u64::from(thread.fp.fpsr);
    }
    state.tpidr_el0 = thread.tpidr_el0;
    state
}

fn write_registers(ctx: &mut PtRegs, state: &HvfArchitecturalState, pc: u64, pstate: u64) {
    for (destination, source) in ctx.regs.iter_mut().zip(state.x.iter()) {
        *destination = usize::try_from(*source).unwrap_or(usize::MAX);
    }
    ctx.sp = usize::try_from(state.sp_el0).unwrap_or(usize::MAX);
    ctx.pc = usize::try_from(pc).unwrap_or(usize::MAX);
    ctx.pstate = pstate;
    ctx.orig_x0 = ctx.regs[0];
    ctx.syscallno = -1;
}

/// The guest was interrupted at EL0: its own PC and PSTATE are authoritative.
fn write_direct_exit(ctx: &mut PtRegs, state: &HvfArchitecturalState) {
    write_registers(ctx, state, state.pc, state.cpsr);
}

/// The guest took an EL0 exception into the monitor: the interrupted PC and
/// PSTATE are what the exception entry saved.
fn write_monitor_exit(ctx: &mut PtRegs, state: &HvfArchitecturalState) {
    write_registers(ctx, state, state.elr_el1, state.spsr_el1);
}

fn guest_permissions(permissions: MemoryRegionPermissions) -> Option<HvfGuestPermissions> {
    let mut guest = HvfGuestPermissions::NONE;
    if permissions.contains(MemoryRegionPermissions::READ) {
        guest = guest | HvfGuestPermissions::READ;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE) {
        // Linux grants read with write; the compact manager requires it.
        guest = guest | HvfGuestPermissions::READ | HvfGuestPermissions::WRITE;
    }
    if permissions.contains(MemoryRegionPermissions::EXEC) {
        guest = guest | HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE)
        && permissions.contains(MemoryRegionPermissions::EXEC)
    {
        return None;
    }
    Some(guest)
}

fn allocation_error(error: HvfMemoryError) -> AllocationError {
    match error {
        HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_) => {
            AllocationError::AddressInUse
        }
        HvfMemoryError::ResourceLimit { .. } | HvfMemoryError::IpaExhausted(_) => {
            AllocationError::OutOfMemory
        }
        other => {
            litebox_util_log::warn!(error:% = other; "HVF mapping failed");
            AllocationError::OutOfMemory
        }
    }
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// `range` minus every range in `subtrahends`, as sorted disjoint pieces.
fn subtract_ranges(range: &Range<usize>, subtrahends: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut pieces = vec![range.clone()];
    for subtrahend in subtrahends {
        let mut next = Vec::new();
        for piece in pieces {
            if !overlaps(&piece, subtrahend) {
                next.push(piece);
                continue;
            }
            if piece.start < subtrahend.start {
                next.push(piece.start..subtrahend.start);
            }
            if subtrahend.end < piece.end {
                next.push(subtrahend.end..piece.end);
            }
        }
        pieces = next;
    }
    pieces
}

/// Sorts and merges adjacent/overlapping ranges in place.
fn normalize_ranges(ranges: &mut Vec<Range<usize>>) {
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    *ranges = merged;
}
