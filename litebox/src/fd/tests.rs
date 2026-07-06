// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::string::ToString as _;
use alloc::vec;
use alloc::vec::Vec;

use crate::LiteBox;
use crate::fd::FdEnabledSubsystemEntry;
use crate::fd::{ErrRawIntFd, FdEnabledSubsystem, TypedFd};
use crate::platform::mock::MockPlatform;

struct MockSubsystem;
impl FdEnabledSubsystem for MockSubsystem {
    type Entry = MockEntry;
}
struct MockEntry {
    data: String,
}
impl FdEnabledSubsystemEntry for MockEntry {}

struct MockSubsystem2;
impl FdEnabledSubsystem for MockSubsystem2 {
    type Entry = MockEntry2;
}
struct MockEntry2 {
    stuff: String,
}
impl FdEnabledSubsystemEntry for MockEntry2 {}

fn litebox() -> LiteBox<MockPlatform> {
    LiteBox::new(MockPlatform::new())
}

#[test]
fn test_insert_and_remove_entry() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);

    assert_eq!(descriptors.entries.len(), 1);

    let removed_entry = descriptors.remove(&typed_fd);
    assert!(removed_entry.is_some());
    assert_eq!(removed_entry.unwrap().data, "test");
}

#[test]
fn test_iter_entries() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry1 = MockEntry {
        data: "entry1".to_string(),
    };
    let entry2 = MockEntry {
        data: "entry2".to_string(),
    };
    let entry3 = MockEntry2 {
        stuff: "x".to_string(),
    };

    let fd1: TypedFd<MockSubsystem> = descriptors.insert(entry1);
    let _fd2: TypedFd<MockSubsystem> = descriptors.insert(entry2);
    let _fd3: TypedFd<MockSubsystem2> = descriptors.insert(entry3);

    let mut entries: Vec<String> = descriptors
        .iter::<MockSubsystem>()
        .map(|(_, e)| e.data.clone())
        .collect();
    entries.sort();

    assert_eq!(entries, vec!["entry1", "entry2"]); // Notice that "x" does not show up

    // Remove one entry and check again
    descriptors.remove(&fd1);
    let entries_after_removal: Vec<String> = descriptors
        .iter::<MockSubsystem>()
        .map(|(_, e)| e.data.clone())
        .collect();
    assert_eq!(entries_after_removal, vec!["entry2"]);

    // Check that the entry from MockSubsystem2 shows up in the iteration if looking within that
    // subsystem
    let entries_subsystem2: Vec<String> = descriptors
        .iter::<MockSubsystem2>()
        .map(|(_, e)| e.stuff.clone())
        .collect();
    assert_eq!(entries_subsystem2, vec!["x"]);
}

#[test]
fn test_with_entry() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);

    descriptors.with_entry(&typed_fd, |e| {
        assert_eq!(e.data, "test");
    });

    descriptors.with_entry_mut(&typed_fd, |e| {
        e.data = "updated".to_string();
    });
    descriptors.with_entry(&typed_fd, |e| {
        assert_eq!(e.data, "updated");
    });
}

#[test]
fn test_lowest_slot_reuse() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    // Span more than one bitmap word to exercise the word-scan logic.
    let fds: Vec<TypedFd<MockSubsystem>> = (0..70)
        .map(|i| {
            let fd = descriptors.insert(MockEntry {
                data: i.to_string(),
            });
            assert_eq!(fd.as_internal_fd().raw, i);
            fd
        })
        .collect();

    // Free a couple of slots (one per bitmap word) and check that the lowest
    // free slot is always reused first (POSIX lowest-fd semantics).
    for &idx in &[3usize, 65] {
        assert!(descriptors.remove(&fds[idx]).is_some());
    }
    let fd: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "reused".to_string(),
    });
    assert_eq!(fd.as_internal_fd().raw, 3);
    let fd2 = descriptors.duplicate(&fd).unwrap();
    assert_eq!(fd2.as_internal_fd().raw, 65);
    // All lower slots are in use again, so the next insert extends the table.
    let fd3: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "appended".to_string(),
    });
    assert_eq!(fd3.as_internal_fd().raw, 70);

    // Clean up: close everything out (note `fd`/`fd2` share an entry, so only the
    // last removal returns it).
    assert!(descriptors.remove(&fd).is_none());
    assert!(descriptors.remove(&fd2).is_some());
    assert!(descriptors.remove(&fd3).is_some());
    for (i, fd) in fds.into_iter().enumerate() {
        if i != 3 && i != 65 {
            assert!(descriptors.remove(&fd).is_some());
        }
    }
}

#[test]
fn test_raw_integer_lowest_reuse() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();
    let mut rds = super::RawDescriptorStorage::new();

    let raw_fds: Vec<usize> = (0..3)
        .map(|i| {
            let fd: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
                data: i.to_string(),
            });
            rds.fd_into_raw_integer(fd)
        })
        .collect();
    assert_eq!(raw_fds, vec![0, 1, 2]);

    // Consuming a raw fd frees its integer for reuse, lowest-first.
    let _ = rds.fd_consume_raw_integer::<MockSubsystem>(1).unwrap();
    let fd: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "reused".to_string(),
    });
    assert_eq!(rds.fd_into_raw_integer(fd), 1);

    // A specifically-placed fd is skipped over by subsequent allocations.
    let fd: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "specific".to_string(),
    });
    assert!(rds.fd_into_specific_raw_integer(fd, 4));
    let fd: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "next".to_string(),
    });
    assert_eq!(rds.fd_into_raw_integer(fd), 3);
    assert!(rds.is_alive(4));
}

#[test]
fn test_fd_raw_integer() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let mut rds = super::RawDescriptorStorage::new();

    let result = rds.fd_from_raw_integer::<MockSubsystem>(999);
    assert!(matches!(result, Err(ErrRawIntFd::NotFound)));

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);
    let raw_fd = rds.fd_into_raw_integer(typed_fd);
    let result = rds.fd_from_raw_integer::<MockSubsystem2>(raw_fd);
    assert!(matches!(result, Err(ErrRawIntFd::InvalidSubsystem)));

    let fetched_fd = rds.fd_from_raw_integer::<MockSubsystem>(raw_fd).unwrap();
    let data = descriptors
        .with_entry(&fetched_fd, |e| e.data.clone())
        .unwrap();
    assert_eq!(data, "test");
    drop(fetched_fd);

    let consumed_fd = rds.fd_consume_raw_integer::<MockSubsystem>(raw_fd).unwrap();
    let data = descriptors
        .with_entry(&consumed_fd, |e| e.data.clone())
        .unwrap();
    assert_eq!(data, "test");
}
