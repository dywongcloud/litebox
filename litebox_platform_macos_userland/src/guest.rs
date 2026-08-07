// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest entry for Darwin on aarch64.
//!
//! This is the one seam of the macOS platform that is not yet implemented, and
//! it is deliberately isolated here rather than scattered through the platform.
//! Everything else -- memory, locking, time, signals, threads, TLS, randomness,
//! stdio, networking -- is complete; what is missing is the transfer of control
//! *into* guest code and back out of it.
//!
//! # What entering the guest requires on this host
//!
//! The aarch64 rewriter (`litebox_syscall_rewriter::arm64`) already defines the
//! contract, and it names three things the runtime owes it:
//!
//! 1. **A host thread-pointer anchor.** Every gate reads `TPIDR_EL0` and
//!    expects the guest's own thread pointer to live at
//!    `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]`. Darwin keeps the thread self-pointer
//!    in `TPIDRRO_EL0` and does not document `TPIDR_EL0` as available to
//!    userland, so whether that register survives a context switch on Darwin has
//!    to be established before it can be used as the anchor. If it does not, the
//!    anchor has to move to a Darwin-owned per-thread slot and the rewriter
//!    needs a `Host::MacOs` variant that emits gates against it.
//! 2. **A trampoline the callback can be reached through.** The rewriter writes
//!    the syscall-callback address at offset 0 of the trampoline it appends to
//!    the image; the loader has to fill that slot with
//!    [`syscall_callback`] before any guest `SVC` runs.
//! 3. **A context switch.** Entry saves the host register state, loads the
//!    guest's from `PtRegs`, and branches to `pc`; the callback reverses it.
//!    This is the counterpart of the other platforms' `run_thread_arch`.
//!
//! On top of that, Darwin's W^X rules mean the guest's executable pages have to
//! be `MAP_JIT` mappings and every patch the rewriter applies has to be
//! bracketed by [`crate::jit_write_protect`], with the host binary signed for
//! the `com.apple.security.cs.allow-jit` entitlement.
//!
//! Until that is built, a thread that reaches guest code reports the gap and
//! unwinds cleanly rather than executing a half-formed context switch.

use litebox_common_linux::PtRegs;

/// Runs a guest thread with the given shim and initial context.
///
/// See the module documentation for what remains before this can transfer
/// control to the guest.
pub(crate) fn run_thread(
    _shim: &dyn litebox::shim::EnterShim<ExecutionContext = PtRegs>,
    _ctx: &mut PtRegs,
) {
    litebox_util_log::error!(
        "guest entry is not yet implemented for macOS on aarch64; the thread will exit without \
         running guest code. See the litebox_platform_macos_userland::guest module docs."
    );
}

/// The entry point a rewritten guest's `SVC` gate branches to.
///
/// [`litebox::platform::SystemInfoProvider::get_syscall_entry_point`] hands this
/// address to the loader, which writes it into the trampoline the rewriter
/// appended to the guest image.
///
/// # Safety
///
/// Called from guest context with a guest stack; see the module documentation
/// for the register state the gates establish before branching here.
pub(crate) unsafe extern "C" fn syscall_callback() {
    litebox_util_log::error!(
        "a guest reached the syscall callback, but guest entry is not implemented for macOS on \
         aarch64"
    );
}
