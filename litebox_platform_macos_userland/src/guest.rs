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
//! The aarch64 rewriter (`litebox_syscall_rewriter::arm64`) defines the
//! contract. Two of the three pieces it names are now in place; the third is
//! the remaining hole:
//!
//! 1. **A host thread-pointer anchor. (Resolved.)** The `Host::MacOs` rewriter
//!    variant emits its gates against `TPIDRRO_EL0` — established on real
//!    hardware to be the only per-thread register Darwin keeps stable across a
//!    context switch (`TPIDR_EL0` does not survive one) — and addresses the
//!    guest thread pointer at a reserved pthread TSD slot
//!    (`litebox_syscall_rewriter::MACOS_GUEST_TPIDR_TSD_SLOT`) rather than a
//!    raw offset into Apple's own pthread structure. The runtime's obligation
//!    here is to reserve that exact slot with `pthread_key_create` at init
//!    (confirming it was handed that slot) and store each guest thread's
//!    pointer into it before the thread runs guest code.
//! 2. **A trampoline the callback can be reached through.** The rewriter writes
//!    the syscall-callback address at offset 0 of the trampoline it appends to
//!    the image; the loader has to fill that slot with
//!    [`syscall_callback`] before any guest `SVC` runs.
//! 3. **A context switch. (Not implemented — the remaining hole.)** Entry
//!    saves the host register state, loads the guest's from `PtRegs`, and
//!    branches to `pc`; the callback reverses it. This is the counterpart of
//!    the other platforms' `run_thread_arch`, and no AArch64 version exists
//!    anywhere in the tree to adapt (the Linux platform's is entirely
//!    `#[cfg(target_arch = "x86_64")]`). It also needs a per-thread place to
//!    keep the host's own bookkeeping (host `sp`/`fp`/`lr`, an in-guest flag)
//!    that the callback can find after the guest's registers are loaded; on
//!    Darwin that can be an ordinary Rust `thread_local!` updated around the
//!    naked-asm call sites, not the hand-rolled TSD arithmetic the gates need.
//!    See `docs/roadmap.md` for the full design.
//!
//! On top of that, Darwin's W^X rules mean the guest's executable pages have to
//! be `MAP_JIT` mappings and every patch the rewriter applies has to be
//! bracketed by [`litebox::platform::PageManagementProvider::jit_write_protect`]
//! (which the shim's code-writing paths already do), with the host binary
//! signed for the `com.apple.security.cs.allow-jit` entitlement.
//!
//! Until the context switch is built, a thread that reaches guest code reports
//! the gap and unwinds cleanly rather than executing a half-formed switch.

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
