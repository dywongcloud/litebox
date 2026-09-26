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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
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
    HvfArchitecturalState, HvfEl1State, HvfError, HvfSimd128, HvfVcpuExit, process_hvf_vm,
};
use crate::hvf_memory::{
    ANY_FILE_WINDOW_EVER, ANY_HOST_REDIRECT_EVER, FILE_COW_COUNTERS, FILE_ORIGINS, FileOrigin,
    FileOriginKey, FileOriginState, FileWindow, HostAccessEntry, HostAliasState, HvfAddressSpace,
    HvfGuestPermissions, HvfMemory, MAX_FILE_ORIGIN_PAGES, PageKind, PromoteTarget,
    HvfMemoryError, HvfRangeMutation, HvfSharedBackingKey, HvfVcpuMemorySnapshot,
    HvfVcpuParticipant, HvfVcpuRunAttachment, fallible_read_u64, file_cow_count,
    file_origin_adjust, next_file_origin_gva, process_hvf_memory,
};
use litebox::platform::page_mgmt::CowAllocationError;
use crate::hvf_vcpu::{
    HvfExitFp, HvfFpDeposit, HvfGuestFpClaim, HvfGuestRegisterCell, HvfVcpuExitState,
    HvfVcpuLane, HvfVcpuLaneCancellation, HvfVcpuLaneError, HvfVcpuLaneHandle, HvfVcpuRegistry,
    HvfVcpuRunReservation, HvfVcpuRunResult,
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
    current: Mutex<Option<HvfVcpuLaneCancellation>>,
}

impl HvfThreadSlot {
    pub(crate) const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            current: Mutex::new(None),
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
    lane: Mutex<Option<HvfVcpuLane>>,
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
    /// `HvfAddressSpace::migrate_vcpu_participant` -- that method holds this
    /// same lock for its entire duration, so no other reader can ever
    /// observe `None` here. Every other reader treats `None` as a logic
    /// error (a lane whose only participant registration was lost to a
    /// migration failure, which the caller must treat as fatal to this lane
    /// generation, not silently skipped).
    participant: Mutex<(Option<VmViewId>, Option<HvfVcpuParticipant>)>,
    /// hvf-lane-view-affinity: lock-free mirror of `participant.0` as a [`view_tag`] key, for
    /// the lane pool's handout choice ([`preferred_free_lane`]). Written only where
    /// `participant.0` is written (construction, and the migrate arm of
    /// [`HvfBackend::ensure_lane_attached_to_view`], under that same lock) and read under the
    /// pool lock WITHOUT taking `participant`, so the pool never acquires a lock that
    /// `ensure_lane_attached_to_view` holds across an exclusive VM operation. A stale value can
    /// only cost one migration: `ensure_lane_attached_to_view` still decides from
    /// `participant.0` itself.
    view_tag: AtomicU64,
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
    state: Mutex<LaneSlotState>,
}

struct LaneMaintenance {
    requested: Mutex<bool>,
    wake: Condvar,
    owner: Mutex<Option<std::thread::JoinHandle<()>>>,
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
/// whose participant is already registered in that view if there is one, else the least recently
/// released lane (the deque's front, the pre-existing LRU choice); `None` only when no lane is
/// free. Ticket fairness is untouched -- this only chooses WHICH idle lane the served ticket
/// gets. The point: with several views interleaving, the LRU lane was most likely last run by
/// another view, and handing it out made `ensure_lane_attached_to_view` migrate its participant
/// (two exclusive VM operations, serialized behind every other process's mapping mutation) and
/// the fresh participant then forced a synchronization monitor trip (a second `hv_vcpu_run`)
/// before the real run -- on most syscalls of a multi-process desktop (52-55% of runs measured).
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
    free.iter()
        .position(|lane| lane.view_tag == view_tag)
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
    view_spaces: Mutex<HashMap<VmViewId, Arc<HvfAddressSpace>>>,
    /// Views already permanently retired at the domain level (see
    /// [`Self::release_view_space`]) whose own [`Self::view_spaces`] entry has not yet been
    /// destroyed -- [`HvfAddressSpace::destroy`] refused at least once, or a live descendant still
    /// held an unpromoted COW alias possibly sourced from this view (see
    /// [`Self::family_blocks_release`]), so the entry stays reachable here for a later retry
    /// instead of being dropped unreachable-but-still-alive. Each entry's own [`FamilyId`] is
    /// captured once, by the caller, before the view is unregistered from the domain -- see
    /// [`GuestVaDomain::family_of_view`]'s own doc comment for why a fresh per-retry lookup by
    /// [`VmViewId`] alone cannot work here.
    pending_view_retirement: Mutex<Vec<(VmViewId, Option<FamilyId>)>>,
    registry: HvfVcpuRegistry,
    el1: HvfEl1State,
    lanes: Vec<PooledLane>,
    free: Mutex<LanePool>,
    available: Condvar,
    lane_maintenance: LaneMaintenance,
    participant_recovery: Mutex<()>,
    trampoline: Range<usize>,
    /// The vDSO image page followed by its clock data page; see [`crate::vdso`].
    vdso: Range<usize>,
    /// The clock data page's host-writable storage address and the values last published
    /// there; one mutex serializes the shim's epoch hand-over against the periodic realtime
    /// refresher (see [`Self::publish_vdso_clock`]).
    vdso_clock: Mutex<VdsoClock>,
    shared_initialization: Mutex<SharedInitialization>,
    shared_initialization_changed: Condvar,
    /// Running count of settled mutations, for the periodic debug counters.
    mutations: std::sync::atomic::AtomicU64,
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

        // Dropping an unsubmitted reservation settles its exact epoch. This is
        // deliberately after clearing `slot.current`, so no new interrupt can
        // acquire stale authority while the reservation is being canceled.
        drop(self.reservation.take());

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
static HVF_BACKEND_INSTALL: Mutex<()> = Mutex::new(());

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
            execution_time: 0,
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
    let _installation = HVF_BACKEND_INSTALL
        .lock()
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
                state: Mutex::new(LaneSlotState::Ready(generation)),
            });
        }
        let backend = Self {
            memory,
            default_space,
            origin_space,
            view_spaces: Mutex::new(HashMap::new()),
            pending_view_retirement: Mutex::new(Vec::new()),
            registry,
            el1,
            lanes,
            free: Mutex::new(LanePool {
                free: VecDeque::from(free),
                checked_out: 0,
                retiring: 0,
                failure: None,
                canceled_tickets: BTreeSet::new(),
                next_ticket: 0,
                next_serving: 0,
            }),
            available: Condvar::new(),
            lane_maintenance: LaneMaintenance {
                requested: Mutex::new(false),
                wake: Condvar::new(),
                owner: Mutex::new(None),
            },
            participant_recovery: Mutex::new(()),
            trampoline: SIGRETURN_TRAMPOLINE_GVA..SIGRETURN_TRAMPOLINE_GVA + PAGE_SIZE,
            vdso: VDSO_GVA..VDSO_GVA + 2 * PAGE_SIZE,
            vdso_clock: Mutex::new(VdsoClock {
                storage: 0,
                values: crate::vdso::ClockValues {
                    numer,
                    denom,
                    mono_epoch_ns: 0,
                    real_offset_ns: crate::vdso::host_real_offset_ns(),
                },
            }),
            shared_initialization: Mutex::new(SharedInitialization {
                initialized: HashMap::new(),
                in_progress: HashMap::new(),
            }),
            shared_initialization_changed: Condvar::new(),
            mutations: std::sync::atomic::AtomicU64::new(0),
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
        Ok(Arc::new(LaneGeneration {
            lane: Mutex::new(Some(lane)),
            handle,
            participant: Mutex::new((view, Some(participant))),
            view_tag: AtomicU64::new(view_tag(view)),
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
            .lock()
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
                .lock()
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
            .lock()
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
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&candidate)
                .cloned();
            let Some(space) = space else {
                continue;
            };
            if self.family_blocks_release(family, domain) {
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
            if space.has_fork_cow_retention() {
                self.reap_fork_cow_retention(Some(candidate), &space);
            }
            match space.destroy() {
                Ok(()) | Err(HvfMemoryError::AddressSpaceDestroyed(_)) => {
                    self.view_spaces
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&candidate);
                }
                Err(_) => still_pending.push((candidate, family)),
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
                slot.1 = Some(migrated);
                slot.0 = Some(view);
                generation
                    .view_tag
                    .store(view_tag(Some(view)), Ordering::Relaxed);
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
            .lock()
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
            let mut table = FILE_ORIGINS.lock();
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
                        // the entry is gone).
                        table = FILE_ORIGINS
                            .changed
                            .wait(table)
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
        if !keep_mirror_for_descendant && space.has_fork_cow_retention() {
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
                    space.is_fork_write_protected(page)
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
        let mut spaces: Vec<(VmViewId, bool, usize, usize, [usize; 7])> = self
            .view_spaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let file_totals: Vec<(VmViewId, [usize; 4])> = self
            .view_spaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            || space.fork_write_protected_pages_in(range),
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
        let last = revalidated_rounds(
            HOST_PREPARE_ROUNDS,
            || {
                snapshots += 1;
                space.host_access_plan(&(start..end))
            },
            |plan| preparer.pass(plan),
        );
        if snapshots > 1 {
            FILE_COW_COUNTERS
                .host_prepare_resnapshots
                .fetch_add(snapshots - 1, Ordering::Relaxed);
        }
        let refused = last.iter().find(|entry| !preparer.usable(entry));
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
        let Some(window) = space.file_window_at(page) else {
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
                    self.kick_running_lanes();
                }
                Ok(())
            }
            _ => Err(HvfMemoryError::RangeUnmapped(run)),
        }
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
        if page == SIGRETURN_TRAMPOLINE_GVA || self.vdso.contains(&page) {
            // The trampoline's and the vDSO pages' permanent aliases are installed once, at
            // space creation, never torn down or promoted -- a stray write there must keep
            // faulting for real, exactly as it did before this mechanism existed.
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
            if space.is_fork_write_protected(page) {
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
            // re-attaches onto the current root. Bounded per thread and page, so a page that keeps
            // faulting on a current writable mapping still surfaces as a real fault.
            if is_write_permission_fault && space.page_writable_now(page) {
                const WRITABLE_NOW_RESUME_LIMIT: u32 = 64;
                thread_local! {
                    static WRITABLE_NOW_RESUMES: core::cell::Cell<(usize, u32)> =
                        const { core::cell::Cell::new((0, 0)) };
                }
                let resumes = WRITABLE_NOW_RESUMES
                    .try_with(|cell| {
                        let (last, count) = cell.get();
                        let count = if last == page { count.saturating_add(1) } else { 1 };
                        cell.set((page, count));
                        count
                    })
                    .unwrap_or(u32::MAX);
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
            if space.is_file_aliased(page) {
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
            if !space.is_cow_aliased(page) {
                return false;
            }
            let Some(ancestor_view) = shim.cow_custody_ancestor(view, page) else {
                return false;
            };
            let Some(ancestor) = self.existing_space_for_view(ancestor_view) else {
                return false;
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
            return false;
        }
        if space.is_any_aliased(page) {
            // Already aliased, lineage or file (a concurrent fault on the same page already
            // installed it): resume and re-execute against the alias that is already there.
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
            litebox_util_log::debug!(
                page:? = page, view:? = view, ok:? = result.is_ok();
                "HVF fork-COW fault: installed a read alias directly from this view's own fork parent"
            );
            if result.is_ok() {
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
            litebox_util_log::debug!(
                page:? = page, ancestor_view:? = ancestor_view, ok:? = result.is_ok(),
                error:? = result.as_ref().err().map(|error| error.to_string());
                "HVF fork-COW fault: installed a read alias for a lineage-inherited page"
            );
            if result.is_ok() {
                return true;
            }
        }
        // Terminal arm, after every lineage arm (a grandparent's pre-fork promotion of a window
        // page must win over the origin): a page inside one of this space's file windows aliases
        // the shared origin page read-only.
        self.install_window_alias_for_fault(
            space,
            view,
            page,
            custody_ancestor.as_ref().map(|(_, ancestor)| ancestor.as_ref()),
        )
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
        let window = match space.file_window_at(page) {
            Some(window) => window,
            None => {
                let Some(window) = custody_ancestor.and_then(|ancestor| ancestor.file_window_at(page))
                else {
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
        let result = self.settle_single_page_mutation(space, MutationKind::Map, || {
            space.install_file_alias(origin, page, execute)
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

    fn lane_maintenance_loop(&'static self) {
        loop {
            let mut requested = self
                .lane_maintenance
                .requested
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*requested {
                requested = self
                    .lane_maintenance
                    .wake
                    .wait(requested)
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
                    let requested = self
                        .lane_maintenance
                        .requested
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (mut requested, _) = self
                        .lane_maintenance
                        .wake
                        .wait_timeout(requested, LANE_REPLACEMENT_POLL)
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
            let (next, _) = self
                .available
                .wait_timeout(pool, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let deadline = Instant::now()
            .checked_add(SHOOTDOWN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        self.kick_running_lanes();
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
    fn kick_running_lanes(&self) {
        // hvf-exit-overhead-instrumentation: one `lane_kicks.rounds` per call, one
        // `lane_kicks.requests` per lane asked, split by what the lane answered.
        crate::diagnostics_counters::record_kick_round();
        for lane in &self.lanes {
            let handle = {
                let slot = lane
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match &*slot {
                    LaneSlotState::Ready(generation) | LaneSlotState::Retiring(generation) => {
                        Some(generation.handle.clone())
                    }
                    LaneSlotState::Replacing { .. } | LaneSlotState::Failed(_) => None,
                }
            };
            if let Some(handle) = handle {
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
    ) -> Result<bool, HvfMemoryError> {
        match mutation {
            Ok(mutation) => {
                let changed = mutation.changed;
                crate::diagnostics_counters::record_mutation(
                    match kind {
                        MutationKind::Map => 0,
                        MutationKind::Protect => 1,
                        MutationKind::Unmap => 2,
                    },
                    changed,
                );
                space
                    .defer_retirement(mutation.retirement)
                    .map_err(|error| {
                        HvfMemoryError::after_publication("retirement deferral", error)
                    })?;
                if kind != MutationKind::Map {
                    self.kick_running_lanes();
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
                self.shootdown(space);
                Err(HvfMemoryError::ResourceLimit {
                    resource,
                    requested,
                    limit,
                })
            }
            Err(error) => Err(error),
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
        }
    }

    fn mutate_with_retry(
        &self,
        space: &HvfAddressSpace,
        kind: MutationKind,
        mut operation: impl FnMut() -> Result<HvfRangeMutation, HvfMemoryError>,
    ) -> Result<bool, HvfMemoryError> {
        let started = crate::diagnostics_counters::ticks();
        let result = match self.settle_mutation(space, kind, operation()) {
            Err(HvfMemoryError::ResourceLimit { .. }) => {
                self.settle_mutation(space, kind, operation())
            }
            result => result,
        };
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
    fn settle_single_page_mutation(
        &self,
        space: &HvfAddressSpace,
        kind: MutationKind,
        mut operation: impl FnMut() -> Result<HvfRangeMutation, HvfMemoryError>,
    ) -> Result<bool, HvfMemoryError> {
        let started = crate::diagnostics_counters::ticks();
        let result = match self.settle_mutation(space, kind, operation()) {
            Err(HvfMemoryError::ResourceLimit { .. }) => self.settle_mutation(space, kind, operation()),
            result => result,
        };
        crate::diagnostics_counters::record_mutation_duration(started);
        result
    }

    /// Whether the address space has moved past the generations a run was
    /// attached with, i.e. whether that run may have executed on a stale
    /// translation.  Only consulted on memory-abort exits, which are rare.
    fn view_was_stale(&self, space: &HvfAddressSpace, snapshot: &HvfVcpuMemorySnapshot) -> bool {
        space.vcpu_snapshot().is_ok_and(|current| {
            current.root_generation > snapshot.root_generation
                || current.executable_generation > snapshot.executable_generation
                || current.pending_tlbi_generation > snapshot.pending_tlbi_generation
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
        if !keep_mirror_for_descendant && space.has_fork_cow_retention() {
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
        if !space.has_cow_pages_in(&range) {
            return self
                .mutate_with_retry(space, MutationKind::Protect, || {
                    space.protect_range(range.clone(), guest)
                })
                .map(|_| ());
        }
        let kinds = space.page_kinds(&range);
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
        let kinds = space.page_kinds(&range);
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
                registry = self
                    .shared_initialization_changed
                    .wait(registry)
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

    fn wait_shared_initialization(&self, backing_identity: usize, requested: &Range<usize>) {
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
                .shared_initialization_changed
                .wait(registry)
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
        let mut registry = self
            .shared_initialization
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = registry.initialized.entry(backing_identity).or_default();
        list.push(range);
        normalize_ranges(list);
        self.shared_initialization_changed.notify_all();
    }

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
        let thread = crate::ThreadHandle::current();
        let slot = thread.hvf_slot();
        let mut consecutive_attachment_races = 0u32;
        let mut stale_view_reruns = 0u32;
        let mut alias_conflict_reruns = 0u32;
        use crate::diagnostics_counters::{
            GUEST_ATTACH, GUEST_DISPATCH, GUEST_EXECUTE, GUEST_LANE_WAIT, GUEST_LOOP_TOP,
            GUEST_PRE_EXECUTE, GUEST_PUMP, GUEST_RECORD, GUEST_RELEASE, GUEST_RESERVE,
            GUEST_SPACE_LOOKUP, GUEST_STATE_BUILD, GUEST_VIEW_ATTACH, ticks_to_ns,
        };
        // hvf-exit-overhead-instrumentation: when the previous `run_with_deadline_reserved` on
        // this thread returned (host ticks), so the next submit can bank the whole-iteration
        // overhead (`exit_overhead`, minus the shim syscall time the dispatch in between recorded).
        let mut last_execute_end: Option<u64> = None;
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
            // FXR: the lane holding this thread's resident state (its vector file, or at least
            // the integer file its cache last saw) is the one to ask the pool for.
            let preferred = HVF_THREAD.with(|context| context.borrow().preferred_lane());
            spans.mark(GUEST_LOOP_TOP);
            let acquired = self.acquire_lane_for_thread(slot, view, preferred);
            crate::diagnostics_counters::record_lane_wait(ticks_to_ns(spans.mark(GUEST_LANE_WAIT)));
            let lane_held_start = spans.last();
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
                space.attach_vcpu(participant.1.as_ref().expect("lane participant present outside migration"))
            };
            spans.mark(GUEST_ATTACH);
            let outcome = match attached {
                Err(error) => Err(HvfBackendError::from(error)),
                Ok(attachment) => {
                    let snapshot = attachment.snapshot().clone();
                    let reservation = active.take_reservation();
                    spans.mark(GUEST_PRE_EXECUTE);
                    let execute_start = spans.last();
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
                    backtrace: capture_frame_backtrace(ctx.regs[29]),
                };
                // Never routes through `kernel_mode`-gated `PageManager::handle_page_fault` (see
                // `kernel_mode: false` above), so this is always a genuine delivered signal, not
                // a candidate for `guest_faults_serviced` -- credited to the shared
                // process-global static directly, same as the non-abort catch-all below.
                checked_increment(&GUEST_FAULTS_DELIVERED);
                shim.exception(ctx, &info)
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
                    backtrace: capture_frame_backtrace(ctx.regs[29]),
                };
                litebox_util_log::debug!(
                    class:? = class, esr:? = exception.syndrome, far:? = exception.virtual_address,
                    pc:? = ctx.pc;
                    "HVF direct-guest abort dispatched to shim.exception"
                );
                // `guest_faults_delivered` is credited downstream (by whether
                // `handle_page_fault` services or delivers it), same as the monitor path's
                // abort arm -- crediting it here too would double-count one raw exit.
                shim.exception(ctx, &info)
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
                let syscall_start = Instant::now();
                let outcome = shim.syscall(ctx);
                let elapsed_ns = u64::try_from(syscall_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
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
                    && self.try_resolve_cow_fault(space, shim, view, class, state.far_el1, state.esr_el1)
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
                    fault_address: usize::try_from(state.far_el1).unwrap_or(usize::MAX),
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
                    backtrace: capture_frame_backtrace(ctx.regs[29]),
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
                shim.exception(ctx, &info)
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
        let kind = space
            .page_kinds(&flip_range)
            .first()
            .map_or(PageKind::Missing, |(_, kind)| *kind);
        let flip = match kind {
            PageKind::Promoted => self.settle_single_page_mutation(&space, MutationKind::Protect, || {
                space.materialize_page_with_permissions(None, req.page, want)
            }),
            PageKind::FileAlias => match self.origin_space.as_ref() {
                Some(origin) => space
                    .reprotect_file_aliases(origin, &flip_range, want)
                    .map(|changed| {
                        if changed {
                            self.kick_running_lanes();
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
    fn pass(&mut self, plan: &[HostAccessEntry]) -> bool {
        let mut acted = false;
        for (index, entry) in plan.iter().enumerate() {
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
                    .file_window_at(page)
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
