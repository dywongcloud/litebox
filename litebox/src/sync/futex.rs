// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A Linux-y `futex`-like abstraction. Fast user-space mutexes.

// Implementation note: other submodules of `crate::sync` should NOT depend on
// this module directly, because this module itself depends on some of the other
// modules (specifically, this module depends on `LoanList`, which depends on
// `Mutex`). A refactoring could clean this up and prevent this dependency, but
// at the moment, it has been decided that this ordering of dependency is more
// fruitful.

use core::hash::BuildHasher as _;
use core::num::NonZeroU32;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::RawSyncPrimitivesProvider;
use crate::event::wait::{WaitContext, WaitError, Waker};
use crate::platform::RawPointerProvider;
use crate::platform::{RawConstPointer as _, TimeProvider};
use crate::utilities::loan_list::{LoanList, LoanListEntry};
use crate::utils::TruncateExt as _;
use thiserror::Error;

/// A manager of all available futexes.
///
/// Note: currently, this only supports "private" futexes, since it assumes only a single process.
/// In the future, this may be expanded to support multi-process futexes.
pub struct FutexManager<Platform: RawSyncPrimitivesProvider> {
    /// Chaining hash table to map from futex address to waiter lists.
    table: alloc::boxed::Box<[LoanList<Platform, FutexEntry<Platform>>; HASH_TABLE_ENTRIES]>,
    hash_builder: hashbrown::DefaultHashBuilder,
    /// Number of live waiter entries whose current futex word hashes to a
    /// bucket other than the one they physically reside in (a result of
    /// [`FutexManager::requeue`]). When non-zero, wake-ups must scan every
    /// bucket to find such entries.
    displaced: AtomicUsize,
}

/// The number of buckets in the hash table.
///
/// FUTURE: consider making this scale with some property of the platform, such
/// as number of CPUs.
const HASH_TABLE_ENTRIES: usize = 256;

struct FutexEntry<Platform: RawSyncPrimitivesProvider> {
    /// The futex word address this entry is waiting on. Only mutated (under
    /// the resident bucket's lock) when the waiter is requeued to another
    /// word; the entry stays in the bucket it was originally inserted into.
    addr: AtomicUsize,
    waker: Waker<Platform>,
    bitset: u32,
    done: AtomicBool,
    /// Whether this entry is currently counted in [`FutexManager::displaced`].
    displaced: AtomicBool,
}

const ALL_BITS: NonZeroU32 = NonZeroU32::new(u32::MAX).unwrap();

impl<Platform: RawSyncPrimitivesProvider + RawPointerProvider + TimeProvider>
    FutexManager<Platform>
{
    /// A new futex manager.
    // TODO(jayb): Integrate this into the `litebox` object itself, to prevent the possibility of
    // double-creation.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            table: alloc::boxed::Box::new(core::array::from_fn(|_| LoanList::new())),
            hash_builder: hashbrown::DefaultHashBuilder::default(),
            displaced: AtomicUsize::new(0),
        }
    }

    /// Returns the hash table bucket index for the given futex address.
    fn bucket_index(&self, addr: usize) -> usize {
        let hash: usize = self.hash_builder.hash_one(addr).trunc();
        hash % HASH_TABLE_ENTRIES
    }

    /// Returns the hash table bucket for the given futex address.
    fn bucket(&self, addr: usize) -> &LoanList<Platform, FutexEntry<Platform>> {
        &self.table[self.bucket_index(addr)]
    }

    /// Performs a futex wait.
    ///
    /// This function tests once if the futex word matches the expected value,
    /// returning immediately with
    /// [`FutexError::ImmediatelyWokenBecauseValueMismatch`] if it does not.
    /// Otherwise, it waits until woken by a corresponding until
    /// [`FutexManager::wake`] is called targeting the same futex word or until
    /// the wait times out or is interrupted.
    ///
    /// If `bitset` is `Some`, then the waiter is only woken if the wake call's
    /// `bitset` has a non-zero intersection with the waiter's mask. Specifying
    /// `None` is equivalent to setting all bits in the mask.
    pub fn wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        futex_addr: Platform::RawMutPointer<u32>,
        expected_value: u32,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), FutexError> {
        let bitset = bitset.unwrap_or(ALL_BITS).get();
        let addr = futex_addr.as_usize();
        if !addr.is_multiple_of(align_of::<u32>()) {
            return Err(FutexError::NotAligned);
        }

        // Optimistically check the futex word before touching the bucket: if the
        // value already mismatches, report that without paying for the bucket's
        // lock. This check alone is insufficient (the value could change right
        // after it), so the authoritative check below is done after inserting
        // into the bucket, ensuring no wakeup is missed.
        let value = futex_addr.read_at_offset(0).ok_or(FutexError::Fault)?;
        if value != expected_value {
            return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
        }

        let bucket = self.bucket(addr);
        let mut entry = pin!(LoanListEntry::new(FutexEntry {
            addr: AtomicUsize::new(addr),
            waker: cx.waker().clone(),
            bitset,
            done: AtomicBool::new(false),
            displaced: AtomicBool::new(false),
        },));

        // Insert into the bucket's list. It will be removed when woken or the
        // entry goes out of scope.
        entry.as_mut().insert(bucket);

        // Check the value again. Do this after inserting into the list so
        // that we don't miss a wakeup.
        let result = match futex_addr.read_at_offset(0) {
            None => Err(FutexError::Fault),
            Some(value) if value != expected_value => {
                Err(FutexError::ImmediatelyWokenBecauseValueMismatch)
            }
            // Only return when woken--don't reevaluate the futex word. This
            // ensures that the rate control mechanisms provided by the futex
            // interface are effective.
            Some(_) => cx
                .wait_until(|| entry.get().done.load(Ordering::Acquire))
                .map_err(FutexError::WaitError),
        };

        // Remove the entry before reading its `displaced` flag: once removed,
        // no concurrent requeue can touch the entry, making the flag stable.
        entry.as_mut().remove();
        if entry.get().displaced.load(Ordering::Relaxed) {
            self.displaced.fetch_sub(1, Ordering::SeqCst);
        }
        result
    }

    /// Wakes waiters on the given futex word.
    ///
    /// This operation wakes at most `num_to_wake` of the waiters that are
    /// waiting on the futex word. Most commonly, `num_to_wake` is specified as
    /// either 1 (wake up a single waiter) or max value (to wake up all
    /// waiters). No guarantee is provided about which waiters are awoken.
    ///
    /// If `bitset` is `Some`, then it contains a mask that specifies which
    /// waiters to wake up. Specifically, any waiters that have a non-zero
    /// intersection between their masks and the provided `bitset` can be woken,
    /// (subject to the `num_to_wake` limit). If `bitset` is `None`, then all
    /// waiters are eligible to be woken.
    ///
    /// Returns the number of waiters that were woken up.
    pub fn wake(
        &self,
        futex_addr: Platform::RawMutPointer<u32>,
        num_to_wake_up: NonZeroU32,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32, FutexError> {
        let addr = futex_addr.as_usize();
        if !addr.is_multiple_of(align_of::<u32>()) {
            return Err(FutexError::NotAligned);
        }
        let bitset = bitset.unwrap_or(ALL_BITS).get();
        let mut woken = 0;
        // Entries requeued across buckets stay in their original bucket, so
        // when any such entry exists the wake target may reside in any bucket
        // and they must all be scanned (rare).
        let buckets = if self.displaced.load(Ordering::SeqCst) == 0 {
            core::slice::from_ref(self.bucket(addr))
        } else {
            &self.table[..]
        };
        for bucket in buckets {
            // Extract matching entries from the bucket until we've woken enough.
            let entries = bucket.extract_if(|entry| {
                if entry.addr.load(Ordering::Relaxed) != addr || entry.bitset & bitset == 0 {
                    return core::ops::ControlFlow::Continue(false);
                }
                woken += 1;
                if woken >= num_to_wake_up.get() {
                    core::ops::ControlFlow::Break(true)
                } else {
                    core::ops::ControlFlow::Continue(true)
                }
            });
            // Wake the waiters outside the `extract_if` closure to minimize the list's lock hold
            // time.
            for entry in entries {
                // Clone the waker and publish `done` so the entry loan can be
                // returned *before* waking: `wake` may issue an expensive host wake
                // call, and holding the loan across it would block a concurrent
                // owner-side removal of the entry for that entire duration.
                let waker = entry.waker.clone();
                entry.done.store(true, Ordering::Release);
                drop(entry);
                waker.wake();
            }
            if woken >= num_to_wake_up.get() {
                break;
            }
        }
        Ok(woken)
    }

    /// Wakes and requeues waiters on the given futex word, implementing the
    /// semantics of `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE`.
    ///
    /// If `expected_value` is `Some`, the current value of the futex word at
    /// `futex_addr` is first compared against it, failing with
    /// [`FutexError::ImmediatelyWokenBecauseValueMismatch`] on a mismatch
    /// (Linux reports this as `EAGAIN`).
    ///
    /// Up to `num_to_wake_up` waiters on `futex_addr` are woken. Up to
    /// `num_to_requeue` of the remaining waiters are moved to wait on
    /// `target_addr` instead, without waking them; they become eligible for
    /// subsequent [`FutexManager::wake`] calls on `target_addr`.
    ///
    /// Returns `(woken, requeued)`.
    pub fn requeue(
        &self,
        futex_addr: Platform::RawMutPointer<u32>,
        target_addr: Platform::RawMutPointer<u32>,
        num_to_wake_up: u32,
        num_to_requeue: u32,
        expected_value: Option<u32>,
    ) -> Result<(u32, u32), FutexError> {
        let addr = futex_addr.as_usize();
        let target = target_addr.as_usize();
        if !addr.is_multiple_of(align_of::<u32>()) || !target.is_multiple_of(align_of::<u32>()) {
            return Err(FutexError::NotAligned);
        }
        if let Some(expected) = expected_value {
            let value = futex_addr.read_at_offset(0).ok_or(FutexError::Fault)?;
            if value != expected {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
        }
        let target_bucket_index = self.bucket_index(target);
        let source_bucket_index = self.bucket_index(addr);
        // As in `wake`, scan all buckets if any entry is displaced.
        let bucket_indices = if self.displaced.load(Ordering::SeqCst) == 0 {
            source_bucket_index..source_bucket_index + 1
        } else {
            0..HASH_TABLE_ENTRIES
        };
        let mut woken = 0;
        let mut requeued = 0;
        for resident in bucket_indices {
            let bucket = &self.table[resident];
            let entries = bucket.extract_if(|entry| {
                use core::ops::ControlFlow::{Break, Continue};
                if entry.addr.load(Ordering::Relaxed) != addr {
                    return Continue(false);
                }
                if woken < num_to_wake_up {
                    woken += 1;
                    return if woken >= num_to_wake_up && num_to_requeue == 0 {
                        Break(true)
                    } else {
                        Continue(true)
                    };
                }
                if requeued < num_to_requeue {
                    requeued += 1;
                    // Retarget the entry in place; it stays in its resident
                    // bucket, so track (while holding this bucket's lock)
                    // whether it is now displaced.
                    entry.addr.store(target, Ordering::Relaxed);
                    if target_bucket_index != resident {
                        if !entry.displaced.swap(true, Ordering::Relaxed) {
                            self.displaced.fetch_add(1, Ordering::SeqCst);
                        }
                    } else if entry.displaced.swap(false, Ordering::Relaxed) {
                        self.displaced.fetch_sub(1, Ordering::SeqCst);
                    }
                    return if requeued >= num_to_requeue {
                        Break(false)
                    } else {
                        Continue(false)
                    };
                }
                Break(false)
            });
            // Wake the waiters outside the `extract_if` closure to minimize
            // the list's lock hold time.
            for entry in entries {
                // As in `wake`: publish `done` and return the entry loan
                // before issuing the (potentially expensive) host wake.
                let waker = entry.waker.clone();
                entry.done.store(true, Ordering::Release);
                drop(entry);
                waker.wake();
            }
            if woken >= num_to_wake_up && requeued >= num_to_requeue {
                break;
            }
        }
        Ok((woken, requeued))
    }
}

/// Potential errors that can be returned by [`FutexManager`]'s operations.
#[derive(Debug, Error)]
pub enum FutexError {
    #[error("address not correctly aligned to 4-bytes")]
    NotAligned,
    #[error("immediately woken: value did not match expected")]
    ImmediatelyWokenBecauseValueMismatch,
    #[error("wait error")]
    WaitError(WaitError),
    #[error("fault reading futex word")]
    Fault,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::LiteBox;
    use crate::event::wait::WaitState;
    use crate::platform::mock::MockPlatform;
    use alloc::sync::Arc;
    use core::num::NonZeroU32;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_futex_wait_wake_single_thread() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let futex_word = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let futex_manager_clone = Arc::clone(&futex_manager);
        let futex_word_clone = Arc::clone(&futex_word);
        let barrier_clone = Arc::clone(&barrier);

        // Spawn waiter thread
        let waiter = thread::spawn(move || {
            let futex_addr =
                <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                    futex_word_clone.as_ptr() as usize,
                );

            barrier_clone.wait(); // Sync with main thread

            // Wait for value 0
            futex_manager_clone.wait(&WaitState::new(platform).context(), futex_addr, 0, None)
        });

        barrier.wait(); // Wait for waiter to be ready
        thread::sleep(Duration::from_millis(10)); // Give waiter time to block

        // Change the value and wake
        futex_word.store(1, Ordering::SeqCst);
        let futex_addr =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex_word.as_ptr() as usize,
            );
        let woken = futex_manager
            .wake(futex_addr, NonZeroU32::new(1).unwrap(), None)
            .unwrap();

        // Wait for waiter thread to complete
        let result = waiter.join().unwrap();
        assert!(result.is_ok());
        assert_eq!(woken, 1);
    }

    #[test]
    fn test_futex_wait_wake_single_thread_with_timeout() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let futex_word = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let futex_manager_clone = Arc::clone(&futex_manager);
        let futex_word_clone = Arc::clone(&futex_word);
        let barrier_clone = Arc::clone(&barrier);

        // Spawn waiter thread with timeout
        let waiter_thread = thread::spawn(move || {
            let futex_addr =
                <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                    futex_word_clone.as_ptr() as usize,
                );

            barrier_clone.wait(); // Sync with main thread

            // Wait for value 0 with some timeout
            futex_manager_clone.wait(
                &WaitState::new(platform)
                    .context()
                    .with_timeout(Duration::from_millis(300)),
                futex_addr,
                0,
                None,
            )
        });

        barrier.wait(); // Wait for waiter to be ready
        thread::sleep(Duration::from_millis(30)); // Give waiter time to block

        // Change the value and wake
        futex_word.store(1, Ordering::SeqCst);
        let futex_addr =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex_word.as_ptr() as usize,
            );
        let woken = futex_manager
            .wake(futex_addr, NonZeroU32::new(1).unwrap(), None)
            .unwrap();

        // Wait for waiter thread to complete
        let result = waiter_thread.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(woken, 1);
    }

    #[test]
    fn test_futex_multiple_waiters_with_timeout() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let futex_word = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(4)); // 3 waiters + 1 waker

        let mut waiters = std::vec::Vec::new();

        // Spawn 3 waiter threads with timeout
        for _ in 0..3 {
            let futex_manager_clone = Arc::clone(&futex_manager);
            let futex_word_clone = Arc::clone(&futex_word);
            let barrier_clone = Arc::clone(&barrier);

            let waiter = thread::spawn(move || {
                let futex_addr = <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                    futex_word_clone.as_ptr() as usize
                );

                barrier_clone.wait(); // Sync with other threads

                // Wait for value 0 with some timeout
                futex_manager_clone.wait(
                    &WaitState::new(platform)
                        .context()
                        .with_timeout(Duration::from_millis(300)),
                    futex_addr,
                    0,
                    None,
                )
            });
            waiters.push(waiter);
        }

        barrier.wait(); // Wait for all waiters to be ready
        thread::sleep(Duration::from_millis(10)); // Give waiters time to block

        // Change the value and wake all
        futex_word.store(1, Ordering::SeqCst);
        let futex_addr =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex_word.as_ptr() as usize,
            );
        let woken = futex_manager
            .wake(futex_addr, NonZeroU32::new(u32::MAX).unwrap(), None)
            .unwrap();

        // Wait for all waiter threads to complete
        for waiter in waiters {
            let result = waiter.join().unwrap();
            match result {
                Ok(())
                | Err(
                    FutexError::WaitError(_) | FutexError::ImmediatelyWokenBecauseValueMismatch,
                ) => {}
                Err(FutexError::NotAligned | FutexError::Fault) => {
                    unreachable!()
                }
            }
        }

        assert!((1..=3).contains(&woken));
    }

    #[test]
    fn test_futex_requeue() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let word_a = Arc::new(AtomicU32::new(0));
        let word_b = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(4)); // 3 waiters + 1 requeuer

        let addr_of = |word: &Arc<AtomicU32>| {
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                word.as_ptr() as usize,
            )
        };

        let mut waiters = std::vec::Vec::new();
        for _ in 0..3 {
            let futex_manager_clone = Arc::clone(&futex_manager);
            let word_a_clone = Arc::clone(&word_a);
            let barrier_clone = Arc::clone(&barrier);
            waiters.push(thread::spawn(move || {
                let futex_addr =
                    <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                        word_a_clone.as_ptr() as usize,
                    );
                barrier_clone.wait(); // Sync with the requeuer
                futex_manager_clone.wait(&WaitState::new(platform).context(), futex_addr, 0, None)
            }));
        }

        barrier.wait(); // Wait for the waiters to be ready
        thread::sleep(Duration::from_millis(100)); // Give the waiters time to block

        // A mismatched expected value must fail with EAGAIN semantics without
        // waking or requeueing anyone.
        assert!(matches!(
            futex_manager.requeue(addr_of(&word_a), addr_of(&word_b), 1, u32::MAX, Some(1)),
            Err(FutexError::ImmediatelyWokenBecauseValueMismatch)
        ));

        // Wake one waiter and requeue the rest onto word B.
        let (woken, requeued) = futex_manager
            .requeue(addr_of(&word_a), addr_of(&word_b), 1, u32::MAX, Some(0))
            .unwrap();
        assert_eq!(woken, 1);
        assert_eq!(requeued, 2);

        // No one is left waiting on word A...
        let woken_a = futex_manager
            .wake(addr_of(&word_a), NonZeroU32::new(u32::MAX).unwrap(), None)
            .unwrap();
        assert_eq!(woken_a, 0);

        // ...and the requeued waiters must be reachable via word B, even
        // though they physically reside in word A's bucket.
        let woken_b = futex_manager
            .wake(addr_of(&word_b), NonZeroU32::new(u32::MAX).unwrap(), None)
            .unwrap();
        assert_eq!(woken_b, 2);

        for waiter in waiters {
            assert!(waiter.join().unwrap().is_ok());
        }

        // Every displaced entry must have been un-counted on wake-up.
        assert_eq!(
            futex_manager.displaced.load(Ordering::SeqCst),
            0,
            "displaced counter must return to zero"
        );
    }
}
