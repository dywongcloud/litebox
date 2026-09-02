// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;
use core::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use crate::darwin::{KERN_SUCCESS, mach_task_self, mach_vm_deallocate, reserve_fixed};

pub(crate) const HVF_HOST_PAGE_SIZE: usize = 16 * 1024;
const MAX_HOST_RESOURCES: usize = 2_100_000;
const MAX_RELEASE_ATTEMPTS: u32 = 8;
const PRECLAIM_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const RESOURCE_REGISTERING: u8 = 0;
const RESOURCE_OWNED: u8 = 1;
const RESOURCE_ALIAS_INSTALLING: u8 = 2;
const RESOURCE_ALIAS_ACTIVE: u8 = 3;
const RESOURCE_CLOSING: u8 = 4;
const RESOURCE_RETRY_OWNED: u8 = 5;
const RESOURCE_RETRY_ALIAS: u8 = 6;
const RESOURCE_RESTORING: u8 = 7;
const RESOURCE_CLOSED: u8 = 8;

unsafe extern "C" {
    fn litebox_hvf_host_remap(source: usize, destination: usize, size: usize, copy: u8) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvfHostPermissions(u8);

impl HvfHostPermissions {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const READ: Self = Self(1 << 0);
    pub(crate) const WRITE: Self = Self(1 << 1);
    pub(crate) const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);

    fn prot(self) -> libc::c_int {
        let mut protection = libc::PROT_NONE;
        if self.0 & Self::READ.0 != 0 {
            protection |= libc::PROT_READ;
        }
        if self.0 & Self::WRITE.0 != 0 {
            protection |= libc::PROT_WRITE;
        }
        protection
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HvfHostBackingError {
    Empty,
    Unaligned {
        start: usize,
        length: usize,
    },
    OutOfRange {
        offset: usize,
        length: usize,
    },
    SameAddress(usize),
    Reservation,
    AddressConflict {
        requested: Range<usize>,
        existing: Range<usize>,
    },
    RegistryFull,
    RegistryAllocation,
    TokenExhausted,
    InvalidState {
        token: u64,
        state: u8,
    },
    AttemptLimit {
        token: u64,
        operation: &'static str,
        attempts: u32,
        limit: u32,
    },
    Remap(i32),
    Protect(i32),
    Restore(i32),
    Release(i32),
    WitnessThreadSpawn,
    WitnessThreadCoordination,
    WitnessThreadPanicked,
}

impl fmt::Display for HvfHostBackingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "an HVF host backing cannot be empty"),
            Self::Unaligned { start, length } => write!(
                f,
                "HVF host range start={start:#x} length={length:#x} is not 16 KiB aligned"
            ),
            Self::OutOfRange { offset, length } => write!(
                f,
                "HVF host backing slice offset={offset:#x} length={length:#x} is out of range"
            ),
            Self::SameAddress(address) => write!(
                f,
                "HVF hidden backing and active alias cannot both use {address:#x}"
            ),
            Self::Reservation => write!(f, "failed to reserve an exact HVF host resource"),
            Self::AddressConflict {
                requested,
                existing,
            } => write!(
                f,
                "HVF host range {:#x}..{:#x} overlaps managed range {:#x}..{:#x}",
                requested.start, requested.end, existing.start, existing.end
            ),
            Self::RegistryFull => write!(f, "the bounded HVF host-resource registry is full"),
            Self::RegistryAllocation => write!(f, "failed to reserve HVF host-resource metadata"),
            Self::TokenExhausted => write!(f, "the HVF host-resource token space is exhausted"),
            Self::InvalidState { token, state } => {
                write!(
                    f,
                    "HVF host resource {token} has invalid lifecycle state {state}"
                )
            }
            Self::AttemptLimit {
                token,
                operation,
                attempts,
                limit,
            } => write!(
                f,
                "HVF host resource {token} reached {operation} attempt {attempts} beyond limit {limit}"
            ),
            Self::Remap(code) => write!(
                f,
                "SDK-derived mach_vm_remap alias failed with kernel code {code}"
            ),
            Self::Protect(errno) => write!(
                f,
                "failed to apply HVF host data permissions (errno {errno})"
            ),
            Self::Restore(errno) => write!(
                f,
                "failed to atomically restore an HVF host slot reservation (errno {errno})"
            ),
            Self::Release(code) => write!(
                f,
                "failed to release an HVF host mapping with kernel code {code}"
            ),
            Self::WitnessThreadSpawn => {
                write!(f, "failed to create an HVF host preclaim worker")
            }
            Self::WitnessThreadCoordination => {
                write!(f, "an HVF host preclaim worker could not be coordinated")
            }
            Self::WitnessThreadPanicked => write!(f, "an HVF host preclaim worker panicked"),
        }
    }
}

impl std::error::Error for HvfHostBackingError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostResourceKind {
    Backing,
    Slot,
}

struct HostResourceRecord {
    token: u64,
    kind: HostResourceKind,
    start: AtomicUsize,
    length: AtomicUsize,
    state: AtomicU8,
    protection: AtomicU8,
    abandoned: AtomicBool,
    restore_attempts: AtomicU32,
    release_attempts: AtomicU32,
    last_error: AtomicI32,
}

struct HostResourceRegistry {
    next_token: u64,
    records: Vec<Arc<HostResourceRecord>>,
}

impl HostResourceRegistry {
    fn new() -> Self {
        Self {
            next_token: 1,
            records: Vec::new(),
        }
    }

    fn register(
        &mut self,
        kind: HostResourceKind,
        preclaim: Option<&Range<usize>>,
    ) -> Result<Arc<HostResourceRecord>, HvfHostBackingError> {
        self.records.retain(|record| {
            record.state.load(Ordering::Acquire) != RESOURCE_CLOSED
                || Arc::strong_count(record) != 1
        });
        if let Some(requested) = preclaim {
            for record in &self.records {
                if record.state.load(Ordering::Acquire) == RESOURCE_CLOSED {
                    continue;
                }
                let start = record.start.load(Ordering::Acquire);
                let length = record.length.load(Ordering::Acquire);
                if length == 0 {
                    continue;
                }
                let existing = start
                    ..start
                        .checked_add(length)
                        .ok_or(HvfHostBackingError::InvalidState {
                            token: record.token,
                            state: record.state.load(Ordering::Acquire),
                        })?;
                if requested.start < existing.end && existing.start < requested.end {
                    return Err(HvfHostBackingError::AddressConflict {
                        requested: requested.clone(),
                        existing,
                    });
                }
            }
        }
        if self.records.len() >= MAX_HOST_RESOURCES {
            return Err(HvfHostBackingError::RegistryFull);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        let token = self.next_token;
        self.next_token = token
            .checked_add(1)
            .ok_or(HvfHostBackingError::TokenExhausted)?;
        let record = Arc::new(HostResourceRecord {
            token,
            kind,
            start: AtomicUsize::new(preclaim.map_or(0, |range| range.start)),
            length: AtomicUsize::new(preclaim.map_or(0, Range::len)),
            state: AtomicU8::new(RESOURCE_REGISTERING),
            protection: AtomicU8::new(HvfHostPermissions::NONE.0),
            abandoned: AtomicBool::new(false),
            restore_attempts: AtomicU32::new(0),
            release_attempts: AtomicU32::new(0),
            last_error: AtomicI32::new(0),
        });
        self.records.push(Arc::clone(&record));
        Ok(record)
    }
}

static HOST_RESOURCES: OnceLock<Mutex<HostResourceRegistry>> = OnceLock::new();
static HOST_ADDRESS_ACQUISITION: OnceLock<Mutex<()>> = OnceLock::new();

fn host_resources() -> &'static Mutex<HostResourceRegistry> {
    HOST_RESOURCES.get_or_init(|| Mutex::new(HostResourceRegistry::new()))
}

fn host_address_acquisition() -> &'static Mutex<()> {
    HOST_ADDRESS_ACQUISITION.get_or_init(|| Mutex::new(()))
}

fn register_resource(
    kind: HostResourceKind,
    preclaim: Option<&Range<usize>>,
) -> Result<Arc<HostResourceRecord>, HvfHostBackingError> {
    host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .register(kind, preclaim)
}

fn close_unacquired(record: &HostResourceRecord) {
    record.state.store(RESOURCE_CLOSED, Ordering::Release);
}

fn acquired_resource(
    record: &HostResourceRecord,
    range: &Range<usize>,
    permissions: HvfHostPermissions,
) {
    record.start.store(range.start, Ordering::Release);
    record.length.store(range.len(), Ordering::Release);
    record.protection.store(permissions.0, Ordering::Release);
    record.state.store(RESOURCE_OWNED, Ordering::Release);
}

fn resource_range(record: &HostResourceRecord) -> Result<Range<usize>, HvfHostBackingError> {
    let start = record.start.load(Ordering::Acquire);
    let length = record.length.load(Ordering::Acquire);
    validate_range(start, length)?;
    Ok(start..start + length)
}

fn begin_attempt(
    record: &HostResourceRecord,
    counter: &AtomicU32,
    operation: &'static str,
    expected: u8,
    transition: u8,
    retry_state: u8,
) -> Result<(), HvfHostBackingError> {
    let attempts = counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |attempts| {
            attempts.checked_add(1)
        })
        .map_err(|attempts| HvfHostBackingError::AttemptLimit {
            token: record.token,
            operation,
            attempts,
            limit: MAX_RELEASE_ATTEMPTS,
        })?
        + 1;
    if attempts > MAX_RELEASE_ATTEMPTS {
        record.state.store(retry_state, Ordering::Release);
        return Err(HvfHostBackingError::AttemptLimit {
            token: record.token,
            operation,
            attempts,
            limit: MAX_RELEASE_ATTEMPTS,
        });
    }
    record
        .state
        .compare_exchange(expected, transition, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|state| HvfHostBackingError::InvalidState {
            token: record.token,
            state,
        })?;
    Ok(())
}

fn protect_record(
    record: &HostResourceRecord,
    permissions: HvfHostPermissions,
) -> Result<(), HvfHostBackingError> {
    let state = record.state.load(Ordering::Acquire);
    if state != RESOURCE_OWNED {
        return Err(HvfHostBackingError::InvalidState {
            token: record.token,
            state,
        });
    }
    let range = resource_range(record)?;
    if unsafe {
        libc::mprotect(
            range.start as *mut libc::c_void,
            range.len(),
            permissions.prot(),
        )
    } != 0
    {
        return Err(HvfHostBackingError::Protect(last_errno()));
    }
    record.protection.store(permissions.0, Ordering::Release);
    Ok(())
}

fn restore_record(record: &HostResourceRecord, expected: u8) -> Result<(), HvfHostBackingError> {
    begin_attempt(
        record,
        &record.restore_attempts,
        "restore",
        expected,
        RESOURCE_RESTORING,
        RESOURCE_RETRY_ALIAS,
    )?;
    let range = resource_range(record)?;
    let pointer = unsafe {
        libc::mmap(
            range.start as *mut libc::c_void,
            range.len(),
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if pointer == libc::MAP_FAILED || pointer as usize != range.start {
        let error = last_errno();
        record.last_error.store(error, Ordering::Release);
        record.state.store(RESOURCE_RETRY_ALIAS, Ordering::Release);
        return Err(HvfHostBackingError::Restore(error));
    }
    record
        .protection
        .store(HvfHostPermissions::NONE.0, Ordering::Release);
    record.last_error.store(0, Ordering::Release);
    record.state.store(RESOURCE_OWNED, Ordering::Release);
    Ok(())
}

fn release_record(record: &HostResourceRecord, expected: u8) -> Result<(), HvfHostBackingError> {
    begin_attempt(
        record,
        &record.release_attempts,
        "release",
        expected,
        RESOURCE_CLOSING,
        RESOURCE_RETRY_OWNED,
    )?;
    let range = resource_range(record)?;
    let result =
        unsafe { mach_vm_deallocate(mach_task_self(), range.start as u64, range.len() as u64) };
    if result != KERN_SUCCESS {
        record.last_error.store(result, Ordering::Release);
        record.state.store(RESOURCE_RETRY_OWNED, Ordering::Release);
        return Err(HvfHostBackingError::Release(result));
    }
    record.last_error.store(0, Ordering::Release);
    record.state.store(RESOURCE_CLOSED, Ordering::Release);
    Ok(())
}

fn queue_resource(record: &HostResourceRecord) {
    record.abandoned.store(true, Ordering::Release);
    let _ = record.state.compare_exchange(
        RESOURCE_OWNED,
        RESOURCE_RETRY_OWNED,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    let _ = record.state.compare_exchange(
        RESOURCE_ALIAS_INSTALLING,
        RESOURCE_RETRY_ALIAS,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    let _ = record.state.compare_exchange(
        RESOURCE_ALIAS_ACTIVE,
        RESOURCE_RETRY_ALIAS,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HvfHostResourceReport {
    pub logical_tokens: usize,
    pub registering: usize,
    pub backing_owned: usize,
    pub slot_owned: usize,
    pub alias_active: usize,
    pub retry_owned: usize,
    pub retry_alias: usize,
}

impl HvfHostResourceReport {
    pub const fn is_empty(&self) -> bool {
        self.logical_tokens == 0
    }
}

pub fn hvf_host_resource_report() -> Result<HvfHostResourceReport, HvfHostBackingError> {
    let registry = host_resources()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut report = HvfHostResourceReport::default();
    for record in &registry.records {
        let state = record.state.load(Ordering::Acquire);
        if state == RESOURCE_CLOSED {
            continue;
        }
        report.logical_tokens = report
            .logical_tokens
            .checked_add(1)
            .ok_or(HvfHostBackingError::RegistryFull)?;
        match state {
            RESOURCE_REGISTERING => report.registering += 1,
            RESOURCE_OWNED => match record.kind {
                HostResourceKind::Backing => report.backing_owned += 1,
                HostResourceKind::Slot => report.slot_owned += 1,
            },
            RESOURCE_ALIAS_INSTALLING | RESOURCE_ALIAS_ACTIVE | RESOURCE_RESTORING => {
                report.alias_active += 1;
            }
            RESOURCE_CLOSING | RESOURCE_RETRY_OWNED => report.retry_owned += 1,
            RESOURCE_RETRY_ALIAS => report.retry_alias += 1,
            _ => {
                return Err(HvfHostBackingError::InvalidState {
                    token: record.token,
                    state,
                });
            }
        }
    }
    Ok(report)
}

pub fn hvf_host_retry_residual() -> Result<usize, HvfHostBackingError> {
    let records = {
        let registry = host_resources()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut records = Vec::new();
        records
            .try_reserve(registry.records.len())
            .map_err(|_| HvfHostBackingError::RegistryAllocation)?;
        records.extend(registry.records.iter().cloned());
        records
    };
    let mut released = 0usize;
    let mut first_error = None;
    for record in records {
        if !record.abandoned.load(Ordering::Acquire) {
            continue;
        }
        let state = record.state.load(Ordering::Acquire);
        let restore = if state == RESOURCE_RETRY_ALIAS {
            restore_record(&record, RESOURCE_RETRY_ALIAS)
        } else {
            Ok(())
        };
        if let Err(error) = restore {
            first_error.get_or_insert(error);
            continue;
        }
        if matches!(
            record.state.load(Ordering::Acquire),
            RESOURCE_RETRY_OWNED | RESOURCE_OWNED
        ) {
            let state = record.state.load(Ordering::Acquire);
            match release_record(&record, state) {
                Ok(()) => released += 1,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(released)
    }
}

pub(crate) struct HvfHostBacking {
    range: Range<usize>,
    resource: Arc<HostResourceRecord>,
}

impl fmt::Debug for HvfHostBacking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfHostBacking")
            .field("token", &self.resource.token)
            .field("range", &self.range)
            .field("state", &self.resource.state.load(Ordering::Acquire))
            .finish()
    }
}

impl HvfHostBacking {
    pub(crate) fn allocate(length: usize) -> Result<Self, HvfHostBackingError> {
        validate_range(0, length)?;
        let (resource, range) = {
            let _acquisition = host_address_acquisition()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let resource = register_resource(HostResourceKind::Backing, None)?;
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                close_unacquired(&resource);
                return Err(HvfHostBackingError::Reservation);
            }
            let start = pointer as usize;
            let range = start..start + length;
            acquired_resource(&resource, &range, HvfHostPermissions::READ_WRITE);
            (resource, range)
        };
        let start = range.start;
        if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) {
            let cleanup = release_record(&resource, RESOURCE_OWNED);
            return match cleanup {
                Ok(()) => Err(HvfHostBackingError::Unaligned { start, length }),
                Err(error) => Err(error),
            };
        }
        Ok(Self { range, resource })
    }

    pub(crate) fn eager_copy(&self) -> Result<Self, HvfHostBackingError> {
        let copy = Self::allocate(self.range.len())?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.range.start as *const u8,
                copy.range.start as *mut u8,
                self.range.len(),
            );
        }
        Ok(copy)
    }

    pub(crate) fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub(crate) fn slice(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Range<usize>, HvfHostBackingError> {
        validate_range(offset, length)?;
        let start = self
            .range
            .start
            .checked_add(offset)
            .ok_or(HvfHostBackingError::OutOfRange { offset, length })?;
        let end = start
            .checked_add(length)
            .ok_or(HvfHostBackingError::OutOfRange { offset, length })?;
        if end > self.range.end {
            return Err(HvfHostBackingError::OutOfRange { offset, length });
        }
        Ok(start..end)
    }

    pub(crate) fn protect(
        &self,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfHostBackingError> {
        protect_record(&self.resource, permissions)
    }

    pub(crate) fn release(&mut self) -> Result<(), HvfHostBackingError> {
        let state = self.resource.state.load(Ordering::Acquire);
        match state {
            RESOURCE_OWNED | RESOURCE_RETRY_OWNED => release_record(&self.resource, state),
            RESOURCE_CLOSED => Ok(()),
            _ => Err(HvfHostBackingError::InvalidState {
                token: self.resource.token,
                state,
            }),
        }
    }
}

impl Drop for HvfHostBacking {
    fn drop(&mut self) {
        queue_resource(&self.resource);
    }
}

pub(crate) struct HvfHostSlot {
    range: Range<usize>,
    resource: Arc<HostResourceRecord>,
}

impl fmt::Debug for HvfHostSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfHostSlot")
            .field("token", &self.resource.token)
            .field("range", &self.range)
            .field("state", &self.resource.state.load(Ordering::Acquire))
            .finish()
    }
}

impl HvfHostSlot {
    pub(crate) fn reserve_exact(range: Range<usize>) -> Result<Self, HvfHostBackingError> {
        validate_range(range.start, range.len())?;
        let resource = {
            let _acquisition = host_address_acquisition()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let resource = register_resource(HostResourceKind::Slot, Some(&range))?;
            if let Err(error) = reserve_fixed(&range) {
                close_unacquired(&resource);
                let _ = error;
                return Err(HvfHostBackingError::Reservation);
            }
            acquired_resource(&resource, &range, HvfHostPermissions::NONE);
            resource
        };
        if unsafe {
            libc::mprotect(
                range.start as *mut libc::c_void,
                range.len(),
                libc::PROT_NONE,
            )
        } != 0
        {
            let error = last_errno();
            let cleanup = release_record(&resource, RESOURCE_OWNED);
            return match cleanup {
                Ok(()) => Err(HvfHostBackingError::Protect(error)),
                Err(cleanup) => Err(cleanup),
            };
        }
        Ok(Self { range, resource })
    }

    pub(crate) fn reserve_any(length: usize) -> Result<Self, HvfHostBackingError> {
        validate_range(0, length)?;
        let (resource, range) = {
            let _acquisition = host_address_acquisition()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let resource = register_resource(HostResourceKind::Slot, None)?;
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                close_unacquired(&resource);
                return Err(HvfHostBackingError::Reservation);
            }
            let start = pointer as usize;
            let range = start..start + length;
            acquired_resource(&resource, &range, HvfHostPermissions::NONE);
            (resource, range)
        };
        let start = range.start;
        if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) {
            let cleanup = release_record(&resource, RESOURCE_OWNED);
            return match cleanup {
                Ok(()) => Err(HvfHostBackingError::Unaligned { start, length }),
                Err(error) => Err(error),
            };
        }
        Ok(Self { range, resource })
    }

    pub(crate) fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub(crate) fn alias_from(
        &self,
        backing: &HvfHostBacking,
        offset: usize,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfHostBackingError> {
        let source = backing.slice(offset, self.range.len())?;
        if source.start == self.range.start {
            return Err(HvfHostBackingError::SameAddress(source.start));
        }
        self.resource
            .state
            .compare_exchange(
                RESOURCE_OWNED,
                RESOURCE_ALIAS_INSTALLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|state| HvfHostBackingError::InvalidState {
                token: self.resource.token,
                state,
            })?;
        let remap =
            unsafe { litebox_hvf_host_remap(source.start, self.range.start, self.range.len(), 0) };
        if remap != 0 {
            self.resource
                .state
                .store(RESOURCE_RETRY_ALIAS, Ordering::Release);
            return match restore_record(&self.resource, RESOURCE_RETRY_ALIAS) {
                Ok(()) => Err(HvfHostBackingError::Remap(remap)),
                Err(error) => Err(error),
            };
        }
        self.resource
            .state
            .store(RESOURCE_ALIAS_ACTIVE, Ordering::Release);
        if unsafe {
            libc::mprotect(
                self.range.start as *mut libc::c_void,
                self.range.len(),
                permissions.prot(),
            )
        } != 0
        {
            let error = last_errno();
            return match self.restore() {
                Ok(()) => Err(HvfHostBackingError::Protect(error)),
                Err(restore) => Err(restore),
            };
        }
        self.resource
            .protection
            .store(permissions.0, Ordering::Release);
        Ok(())
    }

    pub(crate) fn restore(&self) -> Result<(), HvfHostBackingError> {
        let state = self.resource.state.load(Ordering::Acquire);
        match state {
            RESOURCE_ALIAS_ACTIVE | RESOURCE_RETRY_ALIAS => restore_record(&self.resource, state),
            RESOURCE_OWNED => Ok(()),
            _ => Err(HvfHostBackingError::InvalidState {
                token: self.resource.token,
                state,
            }),
        }
    }

    pub(crate) fn release(&mut self) -> Result<(), HvfHostBackingError> {
        let state = self.resource.state.load(Ordering::Acquire);
        match state {
            RESOURCE_OWNED | RESOURCE_RETRY_OWNED => release_record(&self.resource, state),
            RESOURCE_CLOSED => Ok(()),
            _ => Err(HvfHostBackingError::InvalidState {
                token: self.resource.token,
                state,
            }),
        }
    }
}

impl Drop for HvfHostSlot {
    fn drop(&mut self) {
        queue_resource(&self.resource);
    }
}

#[derive(Clone, Debug)]
pub struct HvfHostBackingReport {
    pub hidden_backing: Range<usize>,
    pub coherent_alias: Range<usize>,
    pub private_backing: Range<usize>,
    pub reservation_restored: bool,
    pub coherent_alias_verified: bool,
    pub private_copy_verified: bool,
    pub exact_preclaim_overlap_rejected: bool,
    pub left_preclaim_overlap_rejected: bool,
    pub right_preclaim_overlap_rejected: bool,
    pub enclosing_preclaim_overlap_rejected: bool,
    pub adjacent_preclaims_accepted: bool,
    pub rejected_preclaims_had_no_effect: bool,
    pub registering_resources_reported: bool,
    pub concurrent_preclaim_single_winner: bool,
    pub final_resources: HvfHostResourceReport,
}

fn wait_for_preclaim_start(start: &Arc<(Mutex<bool>, Condvar)>) -> Result<(), HvfHostBackingError> {
    let deadline = Instant::now()
        .checked_add(PRECLAIM_WAIT_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let (gate, wake) = start.as_ref();
    let mut started = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while !*started {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HvfHostBackingError::WitnessThreadCoordination);
        }
        let (next, result) = wake
            .wait_timeout(started, remaining)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        started = next;
        if result.timed_out() && !*started {
            return Err(HvfHostBackingError::WitnessThreadCoordination);
        }
    }
    Ok(())
}

fn preclaim_worker(
    ready: mpsc::SyncSender<()>,
    start: Arc<(Mutex<bool>, Condvar)>,
    range: Range<usize>,
) -> Result<HvfHostSlot, HvfHostBackingError> {
    ready
        .send(())
        .map_err(|_| HvfHostBackingError::WitnessThreadCoordination)?;
    wait_for_preclaim_start(&start)?;
    HvfHostSlot::reserve_exact(range)
}

fn spawn_preclaim_worker(
    ready: mpsc::SyncSender<()>,
    start: Arc<(Mutex<bool>, Condvar)>,
    range: Range<usize>,
) -> Result<std::thread::JoinHandle<Result<HvfHostSlot, HvfHostBackingError>>, HvfHostBackingError>
{
    std::thread::Builder::new()
        .spawn(move || preclaim_worker(ready, start, range))
        .map_err(|_| HvfHostBackingError::WitnessThreadSpawn)
}

fn open_preclaim_start_gate(start: &Arc<(Mutex<bool>, Condvar)>) {
    let (gate, wake) = start.as_ref();
    let mut started = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *started = true;
    wake.notify_all();
}

fn finish_preclaim_worker(
    result: std::thread::Result<Result<HvfHostSlot, HvfHostBackingError>>,
    winners: &mut usize,
    conflicts: &mut usize,
    first_error: &mut Option<HvfHostBackingError>,
) {
    match result {
        Ok(Ok(mut slot)) => {
            *winners += 1;
            if let Err(error) = slot.release() {
                first_error.get_or_insert(error);
            }
        }
        Ok(Err(HvfHostBackingError::AddressConflict { .. })) => {
            *conflicts += 1;
        }
        Ok(Err(error)) => {
            first_error.get_or_insert(error);
        }
        Err(_) => {
            first_error.get_or_insert(HvfHostBackingError::WitnessThreadPanicked);
        }
    }
}

fn concurrent_preclaim_single_winner(mut guard: HvfHostSlot) -> Result<bool, HvfHostBackingError> {
    let range = guard.range();
    let start = Arc::new((Mutex::new(false), Condvar::new()));
    let (ready_send, ready_receive) = mpsc::sync_channel(2);

    let first = match spawn_preclaim_worker(ready_send.clone(), Arc::clone(&start), range.clone()) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = guard.release();
            return Err(error);
        }
    };
    let second = match spawn_preclaim_worker(ready_send, Arc::clone(&start), range) {
        Ok(worker) => worker,
        Err(error) => {
            let mut first_error = Some(error);
            if let Err(error) = guard.release() {
                first_error.get_or_insert(error);
            }
            open_preclaim_start_gate(&start);
            let mut winners = 0;
            let mut conflicts = 0;
            finish_preclaim_worker(first.join(), &mut winners, &mut conflicts, &mut first_error);
            return match first_error {
                Some(error) => Err(error),
                None => Err(HvfHostBackingError::WitnessThreadSpawn),
            };
        }
    };

    let deadline = Instant::now()
        .checked_add(PRECLAIM_WAIT_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut first_error = None;
    for _ in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || ready_receive.recv_timeout(remaining).is_err() {
            first_error = Some(HvfHostBackingError::WitnessThreadCoordination);
            break;
        }
    }
    if let Err(error) = guard.release() {
        first_error.get_or_insert(error);
    }
    open_preclaim_start_gate(&start);

    let mut winners = 0usize;
    let mut conflicts = 0usize;
    for result in [first.join(), second.join()] {
        finish_preclaim_worker(result, &mut winners, &mut conflicts, &mut first_error);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(winners == 1 && conflicts == 1),
    }
}

pub fn hvf_host_backing_probe() -> Result<HvfHostBackingReport, HvfHostBackingError> {
    let initial_resources = hvf_host_resource_report()?;
    let anchor_start = 0x0000_6000_0000_0000usize;
    let anchor_range = anchor_start..anchor_start + HVF_HOST_PAGE_SIZE;
    let anchor = register_resource(HostResourceKind::Slot, Some(&anchor_range))?;
    let anchor_resources = hvf_host_resource_report()?;
    let exact_preclaim_overlap_rejected = preclaim_overlap_rejected(anchor_range.clone())?;
    let left_preclaim_overlap_rejected =
        preclaim_overlap_rejected(anchor_start - HVF_HOST_PAGE_SIZE..anchor_range.end)?;
    let right_preclaim_overlap_rejected =
        preclaim_overlap_rejected(anchor_start..anchor_range.end + HVF_HOST_PAGE_SIZE)?;
    let enclosing_preclaim_overlap_rejected = preclaim_overlap_rejected(
        anchor_start - HVF_HOST_PAGE_SIZE..anchor_range.end + HVF_HOST_PAGE_SIZE,
    )?;
    let rejected_preclaims_had_no_effect = hvf_host_resource_report()? == anchor_resources;
    let left_adjacent = match register_resource(
        HostResourceKind::Slot,
        Some(&(anchor_start - HVF_HOST_PAGE_SIZE..anchor_start)),
    ) {
        Ok(record) => record,
        Err(error) => {
            close_unacquired(&anchor);
            return Err(error);
        }
    };
    let right_adjacent = match register_resource(
        HostResourceKind::Slot,
        Some(&(anchor_range.end..anchor_range.end + HVF_HOST_PAGE_SIZE)),
    ) {
        Ok(record) => record,
        Err(error) => {
            close_unacquired(&left_adjacent);
            close_unacquired(&anchor);
            return Err(error);
        }
    };
    let adjacent_resources = hvf_host_resource_report()?;
    let adjacent_preclaims_accepted = true;
    let registering_resources_reported = adjacent_resources.registering
        == initial_resources.registering + 3
        && adjacent_resources.logical_tokens == initial_resources.logical_tokens + 3;
    close_unacquired(&right_adjacent);
    close_unacquired(&left_adjacent);
    close_unacquired(&anchor);
    let rejected_preclaims_had_no_effect =
        rejected_preclaims_had_no_effect && hvf_host_resource_report()? == initial_resources;

    let mut backing = HvfHostBacking::allocate(HVF_HOST_PAGE_SIZE)?;
    let backing_range = backing.range();
    unsafe { (backing_range.start as *mut u64).write_volatile(0x484f_5354_4c42_4856) };
    let slot = HvfHostSlot::reserve_any(HVF_HOST_PAGE_SIZE)?;
    let slot_range = slot.range();
    slot.alias_from(&backing, 0, HvfHostPermissions::READ_WRITE)?;
    let initial_alias = unsafe { (slot_range.start as *const u64).read_volatile() };
    unsafe { (slot_range.start as *mut u64).write_volatile(0x434f_4845_5245_4e54) };
    let hidden_after_alias = unsafe { (backing_range.start as *const u64).read_volatile() };
    slot.restore()?;
    let reservation_restored = unsafe {
        libc::mprotect(
            slot_range.start as *mut libc::c_void,
            slot_range.len(),
            libc::PROT_READ,
        )
    } == 0;
    if reservation_restored {
        unsafe {
            libc::mprotect(
                slot_range.start as *mut libc::c_void,
                slot_range.len(),
                libc::PROT_NONE,
            )
        };
    }

    let mut private = backing.eager_copy()?;
    let private_range = private.range();
    unsafe { (private_range.start as *mut u64).write_volatile(0x5052_4956_4154_4543) };
    let original_after_private_write =
        unsafe { (backing_range.start as *const u64).read_volatile() };
    let private_after_write = unsafe { (private_range.start as *const u64).read_volatile() };

    let coherent_alias_verified =
        initial_alias == 0x484f_5354_4c42_4856 && hidden_after_alias == 0x434f_4845_5245_4e54;
    let private_copy_verified = original_after_private_write == 0x434f_4845_5245_4e54
        && private_after_write == 0x5052_4956_4154_4543;
    private.release()?;
    backing.release()?;
    let concurrent_preclaim_single_winner = concurrent_preclaim_single_winner(slot)?;
    let final_resources = hvf_host_resource_report()?;
    Ok(HvfHostBackingReport {
        hidden_backing: backing_range,
        coherent_alias: slot_range,
        private_backing: private_range,
        reservation_restored,
        coherent_alias_verified,
        private_copy_verified,
        exact_preclaim_overlap_rejected,
        left_preclaim_overlap_rejected,
        right_preclaim_overlap_rejected,
        enclosing_preclaim_overlap_rejected,
        adjacent_preclaims_accepted,
        rejected_preclaims_had_no_effect,
        registering_resources_reported,
        concurrent_preclaim_single_winner,
        final_resources,
    })
}

fn preclaim_overlap_rejected(range: Range<usize>) -> Result<bool, HvfHostBackingError> {
    match register_resource(HostResourceKind::Slot, Some(&range)) {
        Err(HvfHostBackingError::AddressConflict { .. }) => Ok(true),
        Err(error) => Err(error),
        Ok(record) => {
            close_unacquired(&record);
            Ok(false)
        }
    }
}

fn validate_range(start: usize, length: usize) -> Result<(), HvfHostBackingError> {
    if length == 0 {
        return Err(HvfHostBackingError::Empty);
    }
    if !start.is_multiple_of(HVF_HOST_PAGE_SIZE) || !length.is_multiple_of(HVF_HOST_PAGE_SIZE) {
        return Err(HvfHostBackingError::Unaligned { start, length });
    }
    start
        .checked_add(length)
        .ok_or(HvfHostBackingError::Unaligned { start, length })?;
    Ok(())
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
