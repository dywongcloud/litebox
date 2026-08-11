// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{ShimFS, ShimPlatform, Task};

pub(crate) struct WaitState<Platform: ShimPlatform>(litebox::event::wait::WaitState<Platform>);

impl<Platform: ShimPlatform> WaitState<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }

    /// Returns the thread handle used to interrupt waits.
    pub(crate) fn thread_handle(&self) -> litebox::event::wait::ThreadHandle<Platform> {
        self.0.thread_handle()
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(self)
    }

    /// Marks that the task has just returned from running guest code.
    pub(crate) fn enter_from_guest(&self) {
        self.wait_state.0.finish_running_guest();
    }

    /// Prepares to return to run guest code. Returns `false` if the task should
    /// exit instead.
    #[must_use]
    pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
        self.wait_state.0.prepare_to_run_guest(|| {
            self.global.platform.take_pending_signals(|signal| {
                self.queue_signals(signal);
            });
            #[cfg(feature = "alarm_fallback")]
            self.check_alarm_deadline();
            self.process_signals(ctx);
            // After delivery, so that an `rt_sigsuspend` handler frame captured the temporary
            // mask rather than the one being put back here.
            self.restore_saved_signal_mask();
            !self.is_exiting()
        })
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::event::wait::CheckForInterrupt
    for Task<Platform, FS>
{
    fn check_for_interrupt(&self) -> bool {
        self.global.platform.take_pending_signals(|sig| {
            self.queue_signals(sig);
        });
        #[cfg(feature = "alarm_fallback")]
        self.check_alarm_deadline();
        self.is_exiting() || self.has_pending_signals()
    }

    /// Hands a shared guest address space to whichever other guest process wants it, for as long
    /// as this task is asleep.
    ///
    /// This is the hook that lets a `fork`ed child and its parent make progress in turn instead
    /// of the parent being suspended for the child's whole lifetime; see
    /// `syscalls::process::SharedAddressSpace`. It is a no-op -- a single predictable branch --
    /// for the overwhelmingly common case of a task that has never `fork`ed.
    fn yield_while_blocking(&self) {
        self.release_address_space();
    }

    fn resume_after_blocking(&self) {
        self.acquire_address_space();
    }
}
