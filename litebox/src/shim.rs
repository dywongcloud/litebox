// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Types and traits implemented by shims, for calling from platforms.

/// An object to initialize a newly spawned platform thread for use with the
/// shim that spawned it.
///
/// This is implemented by the shim for passing to
/// [`ThreadProvider::spawn_thread`](crate::platform::ThreadProvider::spawn_thread).
pub trait InitThread: Send {
    /// The execution context type passed to the shim.
    ///
    /// FUTURE: use a single per-architecture type for all shims and platforms.
    type ExecutionContext;

    /// Initializes the thread, returning the shim interface for the new thread.
    #[must_use]
    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn crate::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>;
}

/// An interface for entering the shim from the platform.
pub trait EnterShim {
    /// The execution context type passed to the shim.
    ///
    /// FUTURE: use a single per-architecture type for all shims and platforms.
    type ExecutionContext;

    /// Initialize a new thread. Must be called by the platform exactly once
    /// before running the thread in the guest for the first time.
    ///
    /// Shims might use this to capture the thread handle via
    /// [`ThreadProvider::current_thread`] and to validate that the thread is
    /// still needed now that it has had a chance to run.
    ///
    /// This is called both for the initial thread and for any threads created
    /// via [`ThreadProvider::spawn_thread`]. In the latter case, the platform
    /// must first call [`InitThread::init`] on the object provided by the shim
    /// to set up thread local storage. (FUTURE: [`InitThread::init`] should
    /// return `Box<dyn EnterShim>` rather than rely on TLS.)
    ///
    /// [`ThreadProvider::spawn_thread`]:
    ///     crate::platform::ThreadProvider::spawn_thread
    /// [`ThreadProvider::current_thread`]:
    ///     crate::platform::ThreadProvider::current_thread
    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation;

    /// Handle a syscall.
    ///
    /// The platform should call this in response to `syscall` on x86_64 and
    /// `int 0x80` on x86.
    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation;

    /// Handle a hardware exception.
    ///
    /// The type of exception information passed depends on the architecture.
    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation;

    /// Handle an interrupt signaled by
    /// [`ThreadProvider::interrupt_thread`](crate::platform::ThreadProvider::interrupt_thread).
    ///
    /// Note that if another event occurs (e.g., a syscall or exception) while
    /// the thread is interrupted, the platform may just call the corresponding
    /// handler instead of this one.
    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation;

    /// Re-enter a thread of a guest program or library that is already loaded
    /// in memory.
    ///
    /// Unlike [`init`](Self::init), which must be called exactly once before
    /// running the thread in the guest for the first time, `reenter` allows
    /// the platform to enter the loaded program or library repeatedly until
    /// it is torn down.
    ///
    /// This is useful for scenarios such as OP-TEE trusted applications where
    /// the same TA may be invoked multiple times during its lifetime or dynamically
    /// loaded libraries like cryptographic libraries.
    ///
    /// By default, this implementation just exits the thread because `reenter` is
    /// not supported by all shims.
    fn reenter(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        ContinueOperation::Terminate
    }

    /// Services a platform-classified W^X custody flip request, revalidating it against the
    /// shim's own memory-domain bookkeeping before committing.
    ///
    /// A platform (e.g. HVF's `commit_wx_flip`) classifies which page needs its real
    /// read/write-vs-execute permission flipped and at what generation, but only the shim side
    /// knows the [`GuestVaDomain`](crate::mm::domain::GuestVaDomain) custody that page's owning
    /// view currently holds. This entry point lets a platform hand the classified request back
    /// across the shim boundary for that revalidation plus the real commit, instead of the
    /// platform committing blind.
    ///
    /// The default returns [`WxFlipOutcome::HostFailure`] (never attempts a mutation) for shims
    /// that do not participate in this flow -- the same "not this mechanism's to resolve, fall
    /// through" behavior a caller already gets from a genuine host mutation failure.
    fn memory_service(&self, req: WxFlipRequest) -> WxFlipOutcome {
        let _ = req;
        WxFlipOutcome::HostFailure
    }

    /// Looks up which ancestor view, by fork lineage, currently holds the real backing content
    /// for `page` in `view`'s own memory domain -- see
    /// [`GuestVaDomain::custody_at_via_lineage`](crate::mm::domain::GuestVaDomain::custody_at_via_lineage).
    ///
    /// Consulted by a platform's HVF-shaped fault classifier (see `hvf_backend.rs`'s
    /// `try_resolve_cow_fault`) when a per-view address space takes a fault against a page it has
    /// no independent physical mapping for, to find the ancestor space to alias/copy from instead
    /// of delivering a spurious guest signal for perfectly legitimate, lineage-inherited memory
    /// this view's own physical space simply has not materialized yet.
    ///
    /// The default returns `None` (no lineage-based custody available) for shims and platforms
    /// that do not participate in this flow -- the caller then falls through to ordinary fault
    /// delivery exactly as it would without this mechanism.
    fn cow_custody_ancestor(
        &self,
        view: crate::utils::ids::VmViewId,
        page: usize,
    ) -> Option<crate::utils::ids::VmViewId> {
        let _ = (view, page);
        None
    }

    /// Publishes `view`'s own successful private divergence of `range` (an ordinary COW
    /// write/execute fault resolved via a platform's `promote_cow_alias`-shaped primitive, never
    /// an explicit mmap/mprotect/munmap syscall) into `view`'s own family's custody map, so a
    /// later fork of `view` has a grandchild's own lineage walk
    /// ([`GuestVaDomain::custody_at_via_lineage`](crate::mm::domain::GuestVaDomain::custody_at_via_lineage))
    /// correctly resolve to `view` itself instead of skipping past it to a stale, earlier
    /// ancestor -- see
    /// [`GuestVaDomain::confirm_present_or_reconcile`](crate::mm::domain::GuestVaDomain::confirm_present_or_reconcile).
    ///
    /// Consulted by a platform's HVF-shaped fault classifier (see `hvf_backend.rs`'s
    /// `try_resolve_cow_fault`) immediately after a successful divergence, gated by the caller on
    /// [`GuestVaDomain::family_has_live_descendant_of`](crate::mm::domain::GuestVaDomain::family_has_live_descendant_of)
    /// returning `false` for `view` at that moment: publishing while a live descendant of `view`
    /// already exists (forked *before* this divergence) would let that descendant's own later
    /// first touch of `range` see content newer than its own fork instant -- a cross-lineage
    /// content leak strictly worse than the stale-content gap this method exists to close.
    ///
    /// The default is a no-op for shims and platforms that do not participate in this flow,
    /// matching [`Self::cow_custody_ancestor`]'s own precedent.
    fn cow_custody_publish_divergence(
        &self,
        view: crate::utils::ids::VmViewId,
        range: core::ops::Range<usize>,
    ) {
        let _ = (view, range);
    }

    /// Thin wrapper around
    /// [`GuestVaDomain::family_has_live_descendant_of`](crate::mm::domain::GuestVaDomain::family_has_live_descendant_of)
    /// for `view` (the forking ancestor whose own page just took a fork-time write-protection
    /// fault, not a descendant) -- mirrors [`Self::cow_custody_ancestor`]/
    /// [`Self::cow_custody_publish_divergence`]'s own precedent of exposing a narrow, read-only
    /// lineage query to a platform's HVF-shaped fault classifier.
    ///
    /// Consulted by `hvf_backend.rs`'s `try_resolve_cow_fault` to choose between preserving
    /// `page`'s pre-fault content for a still-live descendant (`true`) or simply lifting the
    /// write-protection in place with no copy at all, since nothing needs the old content anymore
    /// (`false`).
    ///
    /// The default is `true` -- the fail-safe choice for a shim or platform that does not
    /// participate in this flow: assume a live descendant might still exist rather than silently
    /// skip preserving content that turns out to be needed, matching this whole mechanism's own
    /// "when genuinely uncertain, preserve rather than lose content" discipline. Contrast
    /// [`Self::cow_custody_ancestor`]'s own `None` default, safe there for the opposite reason (no
    /// lineage information at all means nothing to alias from, so falling through to ordinary
    /// fault delivery is itself the safe choice).
    fn fork_family_has_live_descendant(&self, view: crate::utils::ids::VmViewId) -> bool {
        let _ = view;
        true
    }
}

/// A classified, not-yet-committed W^X custody flip request, handed from a platform's fault
/// classifier to [`EnterShim::memory_service`].
#[derive(Clone, Copy, Debug)]
pub struct WxFlipRequest {
    /// The `ALIGN`-aligned page address to flip.
    pub page: usize,
    /// Whether the page should become executable (`true`) or writable (`false`) -- the two
    /// mutually exclusive real permission states this toggle switches between.
    pub want_execute: bool,
    /// The page's custody generation at classification time, for the commit side's
    /// compare-and-claim against a racing classification of the same page.
    pub expected_generation: u64,
}

/// Result of [`EnterShim::memory_service`] servicing one [`WxFlipRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WxFlipOutcome {
    /// The real permission was flipped (or another commit for the same page raced ahead and
    /// already produced the same real effect). Carries the wall-clock duration, in nanoseconds,
    /// the real host mutation call took -- `0` on the two racer-observed-already-done paths that
    /// never themselves invoked the host mutation this round.
    Committed(u64),
    /// Another fault on the same page claimed it first; the guest should just resume and
    /// re-fault if still necessary. Never a delivered guest signal.
    StaleGeneration,
    /// The domain revalidation found this page's owning view no longer matches the view that
    /// was in effect at classification time (a concurrent mmap/mprotect/munmap raced ahead) --
    /// refused rather than flipped, since a page's eligibility cannot be judged by guest virtual
    /// address alone once its owning view may have changed. Never a delivered guest signal; the
    /// caller just resumes and re-faults against the now-current state.
    AliasConflictRefused,
    /// The real mutation failed at the host level; falls through to ordinary guest-signal
    /// delivery.
    HostFailure,
}

/// The operation to perform after returning from a shim handler
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ContinueOperation {
    /// Resume the interrupted execution.
    Resume,
    /// Terminate the interrupted execution.
    Terminate,
}

/// Information about a hardware exception.
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Debug)]
pub struct ExceptionInfo {
    /// The x86 exception type.
    pub exception: Exception,
    /// The hardware error code associated with the exception.
    pub error_code: u32,
    /// The value of the CR2 register at the time of the exception, if
    /// applicable (e.g., for page faults).
    pub cr2: usize,
    /// Whether the exception occurred in kernel mode (e.g., a demand page
    /// fault during a kernel-mode access to a user-space address).
    pub kernel_mode: bool,
}

/// Information about a hardware exception on aarch64.
#[cfg(target_arch = "aarch64")]
#[derive(Copy, Clone, Debug)]
pub struct ExceptionInfo {
    /// The aarch64 exception class from ESR_EL1\[31:26\].
    pub exception: Exception,
    /// The fault address (FAR_EL1).
    pub fault_address: usize,
    /// The exception syndrome register value (ESR_EL1).
    pub esr: u64,
    /// Whether the exception occurred in kernel mode.
    pub kernel_mode: bool,
    /// Best-effort, bounded AAPCS64 frame-pointer backtrace captured at the
    /// fault, if the reporting platform backend can practically populate
    /// one (currently: the macOS HVF backend's direct-guest and
    /// monitor-relayed exception paths only). See [`FrameBacktrace`]'s own
    /// doc comment for what it contains and why it can see past a single
    /// faulting-frame LR/`x30` register read.
    ///
    /// Always valid, including empty (`FrameBacktrace::EMPTY`/`Default`) --
    /// purely diagnostic, never required for correctness, and never
    /// changes guest-visible behavior. Every platform/backend that does
    /// not populate it must use the empty/default value.
    pub backtrace: FrameBacktrace,
}

/// A bounded, best-effort AAPCS64 return-address chain, captured (where a
/// platform backend supports it) by walking the saved frame-pointer
/// (`x29`) chain in guest memory starting from the faulting frame's own
/// `x29`.
///
/// Entry `i` is the return address recorded in the `i`-th ancestor frame's
/// own saved-LR slot (`[x29+8]`): `as_slice()[0]` names the call site in
/// the function that called the one that faulted, `as_slice()[1]` names
/// its own caller's call site, and so on. This can see meaningfully
/// further than the single faulting-frame `x30`/LR register alone, which
/// can be degenerate -- equal to the fault PC itself -- when the fault is
/// inside a callee the crashing frame just `bl`ed into (a real, live
/// example of exactly this degeneracy is documented on this project's own
/// `chromium-fd-ownership-lr-degenerate-disassembly-proof` row).
///
/// A fixed-size array, not a heap-allocated `Vec`: this type is meant to be
/// populated on a hardware exception path, where allocation may be
/// undesirable or (inside a strict async-signal-safe handler) outright
/// unsound. `Default`/`EMPTY` (`len() == 0`) is always a valid value.
#[derive(Copy, Clone, Debug, Default)]
pub struct FrameBacktrace {
    addrs: [u64; Self::MAX_FRAMES],
    len: u8,
}

impl FrameBacktrace {
    /// Hard cap on captured frames. Small enough that a corrupted or even
    /// adversarial frame-pointer chain that somehow keeps passing a
    /// walker's own defensive per-step checks still terminates quickly
    /// regardless of those checks.
    pub const MAX_FRAMES: usize = 8;

    /// The empty backtrace (no frames captured). `const` so it can be used
    /// where `Default::default()` cannot, e.g. in a `const fn` initializer.
    pub const EMPTY: Self = Self {
        addrs: [0; Self::MAX_FRAMES],
        len: 0,
    };

    /// Builds a backtrace from up to `MAX_FRAMES` return addresses,
    /// outermost-known-caller first. Any entries beyond `MAX_FRAMES` are
    /// silently dropped rather than panicking: every current caller
    /// already stops at `MAX_FRAMES` on its own, but this keeps the
    /// constructor itself infallible regardless of what a future caller
    /// passes.
    #[must_use]
    pub fn from_frames(frames: &[u64]) -> Self {
        let mut addrs = [0u64; Self::MAX_FRAMES];
        let len = frames.len().min(Self::MAX_FRAMES);
        addrs[..len].copy_from_slice(&frames[..len]);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len is clamped to MAX_FRAMES (8) just above"
        )]
        Self {
            addrs,
            len: len as u8,
        }
    }

    /// The captured return addresses, outermost-known-caller first. Empty
    /// when nothing was captured.
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.addrs[..self.len as usize]
    }
}

/// An x86 exception type.
#[cfg(target_arch = "x86_64")]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Exception(pub u8);

#[cfg(target_arch = "x86_64")]
impl Exception {
    /// #DE
    pub const DIVIDE_ERROR: Self = Self(0);
    /// #BP
    pub const BREAKPOINT: Self = Self(3);
    /// #UD
    pub const INVALID_OPCODE: Self = Self(6);
    /// #GP
    pub const GENERAL_PROTECTION_FAULT: Self = Self(13);
    /// #PF
    pub const PAGE_FAULT: Self = Self(14);
}

/// An aarch64 exception class from ESR_EL1\[31:26\].
#[cfg(target_arch = "aarch64")]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Exception(pub u8);

#[cfg(target_arch = "aarch64")]
impl Exception {
    /// Unknown reason. This is the class an undefined instruction raises, among
    /// other unattributable traps.
    pub const UNKNOWN: Self = Self(0x00);
    /// Trapped `MSR`/`MRS`/system-instruction access from AArch64 state.
    pub const SYSTEM_REGISTER_TRAP: Self = Self(0x18);
    /// Trapped floating-point exception taken from AArch64 state.
    pub const FP_EXCEPTION_A64: Self = Self(0x2c);
    /// Breakpoint exception from a lower exception level.
    pub const BREAKPOINT_LOWER_EL: Self = Self(0x30);
    /// Breakpoint exception taken without a change in exception level.
    pub const BREAKPOINT_CURRENT_EL: Self = Self(0x31);
    /// BRK instruction trap from AArch64 state.
    pub const BRK64: Self = Self(0x3c);
    /// Instruction abort taken without a change in exception level.
    pub const INSTRUCTION_ABORT_CURRENT_EL: Self = Self(0x21);
    /// Instruction abort taken from a lower exception level.
    pub const INSTRUCTION_ABORT_LOWER_EL: Self = Self(0x20);
    /// Data abort taken without a change in exception level.
    pub const DATA_ABORT_CURRENT_EL: Self = Self(0x25);
    /// Data abort taken from a lower exception level.
    pub const DATA_ABORT_LOWER_EL: Self = Self(0x24);
}
