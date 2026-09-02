// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{BitOr, BitOrAssign, Range};
use core::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const HVF_PAGE_SIZE: usize = 16 * 1024;
const MIN_IPA_BITS: u32 = 14;
const MAX_IPA_BITS: u32 = 40;
const MACOS_26_SDK_VERSION: u32 = 260_000;
const FEATURE_REGISTER_COUNT: usize = 11;
const MONITOR_SYSCALL_OFFSET: usize = 0x400;
const MONITOR_RESUME_OFFSET: usize = 0x404;
const OPERATION_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const OPERATION_WAIT_POLL: Duration = Duration::from_millis(10);

type HvReturn = i32;

unsafe extern "C" {
    fn litebox_hvf_sdk_max_allowed() -> u32;
    fn litebox_hvf_runtime_is_macos_26_or_newer() -> u8;
    fn litebox_hvf_return_is_success(result: HvReturn) -> u8;
    fn litebox_hvf_return_is_denied(result: HvReturn) -> u8;
    fn litebox_hvf_monitor_layout(
        start: *mut *const u8,
        length: *mut usize,
        syscall_offset: *mut usize,
        resume_offset: *mut usize,
    );
    fn litebox_hvf_vm_config_create() -> *mut c_void;
    fn litebox_hvf_vcpu_config_create() -> *mut c_void;
    fn litebox_hvf_vm_config_release(object: *mut c_void);
    fn litebox_hvf_vcpu_config_release(object: *mut c_void);
    fn litebox_hvf_vm_config_get_max_ipa_size(bits: *mut u32) -> HvReturn;
    fn litebox_hvf_vm_config_set_ipa_size(config: *mut c_void, bits: u32) -> HvReturn;
    fn litebox_hvf_vm_config_get_ipa_size(config: *mut c_void, bits: *mut u32) -> HvReturn;
    fn litebox_hvf_vm_config_set_ipa_granule_16k(config: *mut c_void) -> HvReturn;
    fn litebox_hvf_vm_config_get_ipa_granule(
        config: *mut c_void,
        raw: *mut u32,
        is_16k: *mut u8,
    ) -> HvReturn;
    fn litebox_hvf_vm_config_get_el2_supported(supported: *mut u8) -> HvReturn;
    fn litebox_hvf_vm_config_set_el2_disabled(config: *mut c_void) -> HvReturn;
    fn litebox_hvf_vm_config_get_el2_enabled(config: *mut c_void, enabled: *mut u8) -> HvReturn;
    fn litebox_hvf_vm_get_max_vcpu_count(count: *mut u32) -> HvReturn;
    fn litebox_hvf_vm_create(config: *mut c_void) -> HvReturn;
    fn litebox_hvf_vm_map(address: *mut c_void, ipa: u64, size: usize, permissions: u8)
    -> HvReturn;
    fn litebox_hvf_vm_protect(ipa: u64, size: usize, permissions: u8) -> HvReturn;
    fn litebox_hvf_vm_unmap(ipa: u64, size: usize) -> HvReturn;
    fn litebox_hvf_feature_reg_count() -> usize;
    fn litebox_hvf_vcpu_config_get_feature_regs(
        config: *mut c_void,
        values: *mut u64,
        count: usize,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_create(
        identifier: *mut u64,
        exit_area: *mut *mut c_void,
        config: *mut c_void,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_destroy(identifier: u64) -> HvReturn;
    fn litebox_hvf_vcpu_program_stage_one(
        identifier: u64,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
        ttbr0_readback: *mut u64,
        tcr_readback: *mut u64,
        mair_readback: *mut u64,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_verify_feature_regs(
        identifier: u64,
        expected: *const u64,
        count: usize,
        mismatch_index: *mut usize,
        actual_value: *mut u64,
    ) -> HvReturn;
}

#[derive(Clone, Debug)]
pub enum HvfError {
    SdkTooOld(u32),
    HostTooOld,
    HostPageSize(i64),
    NullVmConfiguration,
    NullVcpuConfiguration,
    NullVcpuExitArea,
    VcpuNotLive,
    HypervisorEntitlementMissing,
    Call {
        operation: &'static str,
        code: HvReturn,
    },
    IpaSizeOutOfRange(u32),
    IpaSizeReadback {
        requested: u32,
        configured: u32,
    },
    IpaGranuleReadback(u32),
    El2StillEnabled,
    NoVcpus,
    InvalidMonitor {
        length: usize,
        alignment: usize,
        syscall_offset: usize,
        resume_offset: usize,
    },
    FeatureRegisterCount(usize),
    FeatureConfigurationChanged {
        register: HvfFeatureRegister,
        admitted: u64,
        configured: u64,
    },
    FeatureRegisterMismatch {
        register: HvfFeatureRegister,
        expected: u64,
        actual: u64,
    },
    StageOneRegisterReadback {
        register: &'static str,
        expected: u64,
        actual: u64,
    },
    Poisoned,
    EmptyMapping,
    MappingNotLive,
    MappingUnaligned {
        host_address: usize,
        ipa: u64,
        length: usize,
    },
    MappingOutOfRange {
        ipa: u64,
        length: usize,
        ipa_bits: u32,
    },
    HostRangeGap(usize),
    MappingRollback {
        token: u64,
        trigger: &'static str,
        trigger_code: Option<HvReturn>,
        rollback_code: HvReturn,
    },
    VcpuCleanup {
        trigger: &'static str,
        trigger_code: Option<HvReturn>,
        stage_one_mismatch: bool,
        cleanup_code: HvReturn,
    },
    VcpuOwnershipCollision(u64),
    VcpuWrongOwner {
        identifier: u64,
    },
    ResourceReservation(&'static str),
    MappingTokenExhausted,
    MappingTokenMissing(u64),
    WriteExecuteMapping,
    ResidualAccounting,
    SmokeResidualOwnership,
    ZeroVcpuAdmission,
    OperationAbandoned,
    OperationWaitTimeout,
    ResidualOwnership(HvfSdkResidualReport),
}

impl HvfError {
    fn vcpu_cleanup(trigger: &Self, cleanup_code: HvReturn) -> Self {
        let (trigger, trigger_code, stage_one_mismatch) = match trigger {
            Self::Call { operation, code } => (*operation, Some(*code), false),
            Self::NullVcpuExitArea => ("vCPU exit-area validation failed", None, false),
            Self::VcpuNotLive => ("vCPU liveness validation failed", None, false),
            Self::FeatureConfigurationChanged { .. } => {
                ("vCPU feature configuration changed", None, false)
            }
            Self::FeatureRegisterMismatch { .. } => {
                ("vCPU feature register readback mismatched", None, false)
            }
            Self::StageOneRegisterReadback { .. } => {
                ("vCPU stage-one register readback mismatched", None, true)
            }
            Self::VcpuOwnershipCollision(_) => {
                ("vCPU ownership registration collided", None, false)
            }
            Self::VcpuWrongOwner { .. } => ("vCPU ownership validation failed", None, false),
            Self::ResidualAccounting => ("vCPU ownership accounting failed", None, false),
            Self::OperationAbandoned => ("vCPU operation was abandoned", None, false),
            Self::VcpuCleanup {
                trigger,
                trigger_code,
                stage_one_mismatch,
                ..
            } => (*trigger, *trigger_code, *stage_one_mismatch),
            _ => ("vCPU rejection failed", None, false),
        };
        Self::VcpuCleanup {
            trigger,
            trigger_code,
            stage_one_mismatch,
            cleanup_code,
        }
    }

    pub(crate) fn stage_one_mismatch(&self) -> bool {
        matches!(self, Self::StageOneRegisterReadback { .. })
            || matches!(
                self,
                Self::VcpuCleanup {
                    stage_one_mismatch: true,
                    ..
                }
            )
    }
}

impl fmt::Display for HvfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SdkTooOld(version) => write!(
                f,
                "the active SDK is {version}, but the HVF backend requires the macOS 26 SDK or newer"
            ),
            Self::HostTooOld => write!(f, "the HVF backend requires macOS 26 or newer"),
            Self::HostPageSize(size) => write!(
                f,
                "the host page size is {size}, but the HVF backend requires 16384 bytes"
            ),
            Self::NullVmConfiguration => write!(f, "hv_vm_config_create returned null"),
            Self::NullVcpuConfiguration => write!(f, "hv_vcpu_config_create returned null"),
            Self::NullVcpuExitArea => write!(f, "hv_vcpu_create returned a null exit area"),
            Self::VcpuNotLive => write!(f, "the HVF vCPU has been destroyed or quarantined"),
            Self::HypervisorEntitlementMissing => write!(
                f,
                "Hypervisor.framework denied VM creation; sign the final executable with com.apple.security.hypervisor=true (com.apple.vm.hypervisor is only for deployment targets through macOS 10.15)"
            ),
            Self::Call { operation, code } => {
                write!(
                    f,
                    "{operation} failed with Hypervisor.framework code {:#x}",
                    code.cast_unsigned()
                )
            }
            Self::IpaSizeOutOfRange(bits) => write!(
                f,
                "Hypervisor.framework reported {bits} maximum IPA bits, outside the supported 14..=40 range"
            ),
            Self::IpaSizeReadback {
                requested,
                configured,
            } => write!(
                f,
                "Hypervisor.framework configured {configured} IPA bits after {requested} were requested"
            ),
            Self::IpaGranuleReadback(raw) => write!(
                f,
                "Hypervisor.framework did not retain the requested 16 KiB IPA granule (active-SDK value {raw})"
            ),
            Self::El2StillEnabled => write!(
                f,
                "Hypervisor.framework reports EL2 enabled after the backend explicitly disabled it"
            ),
            Self::NoVcpus => write!(f, "Hypervisor.framework reports no available vCPUs"),
            Self::InvalidMonitor {
                length,
                alignment,
                syscall_offset,
                resume_offset,
            } => write!(
                f,
                "linked EL1 monitor has length {length}, alignment {alignment}, syscall offset {syscall_offset:#x}, and resume offset {resume_offset:#x}"
            ),
            Self::FeatureRegisterCount(count) => write!(
                f,
                "active-SDK feature register table has {count} entries instead of {FEATURE_REGISTER_COUNT}"
            ),
            Self::FeatureConfigurationChanged {
                register,
                admitted,
                configured,
            } => write!(
                f,
                "{} changed from admitted value {admitted:#x} to vCPU configuration value {configured:#x}",
                register.name()
            ),
            Self::FeatureRegisterMismatch {
                register,
                expected,
                actual,
            } => write!(
                f,
                "{} reads {actual:#x} from the vCPU after its configuration admitted {expected:#x}",
                register.name()
            ),
            Self::StageOneRegisterReadback {
                register,
                expected,
                actual,
            } => write!(
                f,
                "{register} read back as {actual:#x} after the HVF backend programmed {expected:#x}"
            ),
            Self::Poisoned => write!(f, "the process-global Hypervisor.framework VM is poisoned"),
            Self::EmptyMapping => write!(f, "an HVF mapping cannot be empty"),
            Self::MappingNotLive => {
                write!(
                    f,
                    "the HVF mapping is quarantined or has already been unmapped"
                )
            }
            Self::MappingUnaligned {
                host_address,
                ipa,
                length,
            } => write!(
                f,
                "HVF mapping host={host_address:#x} ipa={ipa:#x} length={length:#x} is not 16 KiB aligned"
            ),
            Self::MappingOutOfRange {
                ipa,
                length,
                ipa_bits,
            } => write!(
                f,
                "HVF mapping ipa={ipa:#x} length={length:#x} exceeds the configured {ipa_bits}-bit IPA space"
            ),
            Self::HostRangeGap(address) => write!(
                f,
                "host virtual range for an HVF mapping has no Mach VM region at {address:#x}"
            ),
            Self::MappingRollback {
                token,
                trigger,
                trigger_code,
                rollback_code,
            } => write!(
                f,
                "HVF mapping token {token} rollback after {trigger} (trigger code {trigger_code:?}) failed with {:#x}; the VM is poisoned",
                rollback_code.cast_unsigned()
            ),
            Self::VcpuCleanup {
                trigger,
                trigger_code,
                cleanup_code,
                ..
            } => match trigger_code {
                Some(trigger_code) => write!(
                    f,
                    "{trigger} with Hypervisor.framework code {:#x}; destroying the rejected vCPU then failed with {:#x}; the VM is poisoned",
                    trigger_code.cast_unsigned(),
                    cleanup_code.cast_unsigned()
                ),
                None => write!(
                    f,
                    "{trigger}; destroying the rejected vCPU then failed with {:#x}; the VM is poisoned",
                    cleanup_code.cast_unsigned()
                ),
            },
            Self::VcpuOwnershipCollision(identifier) => write!(
                f,
                "HVF vCPU identifier {identifier:#x} already has live or quarantined ownership"
            ),
            Self::VcpuWrongOwner { identifier } => write!(
                f,
                "HVF vCPU {identifier:#x} cleanup was attempted from a thread other than its creator"
            ),
            Self::ResourceReservation(resource) => {
                write!(
                    f,
                    "failed to reserve {resource} ownership before HVF mutation"
                )
            }
            Self::MappingTokenExhausted => write!(f, "HVF mapping token space is exhausted"),
            Self::MappingTokenMissing(token) => {
                write!(
                    f,
                    "HVF mapping token {token} has no authoritative registry record"
                )
            }
            Self::WriteExecuteMapping => {
                write!(
                    f,
                    "an HVF stage-two mapping cannot be writable and executable"
                )
            }
            Self::ResidualAccounting => write!(
                f,
                "the HVF SDK residual ledger is internally inconsistent or overflowed"
            ),
            Self::SmokeResidualOwnership => write!(
                f,
                "the bounded HVF smoke retains process-owned resources; production VM admission is blocked"
            ),
            Self::ZeroVcpuAdmission => {
                write!(f, "the operation requires exclusive zero-vCPU admission")
            }
            Self::OperationAbandoned => write!(
                f,
                "an HVF operation capability was abandoned without explicit finish"
            ),
            Self::OperationWaitTimeout => {
                write!(f, "timed out waiting for HVF operation ownership")
            }
            Self::ResidualOwnership(report) => {
                write!(
                    f,
                    "the HVF SDK retained exact residual ownership: {report:?}"
                )
            }
        }
    }
}

impl std::error::Error for HvfError {}

fn succeeded(code: HvReturn) -> bool {
    unsafe { litebox_hvf_return_is_success(code) != 0 }
}

fn denied(code: HvReturn) -> bool {
    unsafe { litebox_hvf_return_is_denied(code) != 0 }
}

fn check(operation: &'static str, code: HvReturn) -> Result<(), HvfError> {
    if succeeded(code) {
        Ok(())
    } else {
        Err(HvfError::Call { operation, code })
    }
}

fn checked_residual_add(value: &mut usize, amount: usize) -> Result<(), HvfError> {
    *value = value
        .checked_add(amount)
        .ok_or(HvfError::ResidualAccounting)?;
    Ok(())
}

fn with_hvf_configuration<T>(
    create: unsafe extern "C" fn() -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    null_error: HvfError,
    body: impl FnOnce(NonNull<c_void>) -> Result<T, HvfError>,
) -> Result<T, HvfError> {
    let object = NonNull::new(unsafe { create() }).ok_or(null_error)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(object)));
    // SAFETY: creation returned one retained object and no ownership left this
    // function. Release is explicit while control remains in this frame.
    unsafe { release(object.as_ptr()) };
    match result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn with_vm_configuration<T>(
    body: impl FnOnce(NonNull<c_void>) -> Result<T, HvfError>,
) -> Result<T, HvfError> {
    with_hvf_configuration(
        litebox_hvf_vm_config_create,
        litebox_hvf_vm_config_release,
        HvfError::NullVmConfiguration,
        body,
    )
}

fn with_vcpu_configuration<T>(
    body: impl FnOnce(NonNull<c_void>) -> Result<T, HvfError>,
) -> Result<T, HvfError> {
    with_hvf_configuration(
        litebox_hvf_vcpu_config_create,
        litebox_hvf_vcpu_config_release,
        HvfError::NullVcpuConfiguration,
        body,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum HvfFeatureRegister {
    IdAa64Dfr0El1,
    IdAa64Dfr1El1,
    IdAa64Isar0El1,
    IdAa64Isar1El1,
    IdAa64Mmfr0El1,
    IdAa64Mmfr1El1,
    IdAa64Mmfr2El1,
    IdAa64Pfr0El1,
    IdAa64Pfr1El1,
    IdAa64Zfr0El1,
    IdAa64Smfr0El1,
}

impl HvfFeatureRegister {
    pub const ALL: [Self; FEATURE_REGISTER_COUNT] = [
        Self::IdAa64Dfr0El1,
        Self::IdAa64Dfr1El1,
        Self::IdAa64Isar0El1,
        Self::IdAa64Isar1El1,
        Self::IdAa64Mmfr0El1,
        Self::IdAa64Mmfr1El1,
        Self::IdAa64Mmfr2El1,
        Self::IdAa64Pfr0El1,
        Self::IdAa64Pfr1El1,
        Self::IdAa64Zfr0El1,
        Self::IdAa64Smfr0El1,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::IdAa64Dfr0El1 => "ID_AA64DFR0_EL1",
            Self::IdAa64Dfr1El1 => "ID_AA64DFR1_EL1",
            Self::IdAa64Isar0El1 => "ID_AA64ISAR0_EL1",
            Self::IdAa64Isar1El1 => "ID_AA64ISAR1_EL1",
            Self::IdAa64Mmfr0El1 => "ID_AA64MMFR0_EL1",
            Self::IdAa64Mmfr1El1 => "ID_AA64MMFR1_EL1",
            Self::IdAa64Mmfr2El1 => "ID_AA64MMFR2_EL1",
            Self::IdAa64Pfr0El1 => "ID_AA64PFR0_EL1",
            Self::IdAa64Pfr1El1 => "ID_AA64PFR1_EL1",
            Self::IdAa64Zfr0El1 => "ID_AA64ZFR0_EL1",
            Self::IdAa64Smfr0El1 => "ID_AA64SMFR0_EL1",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HvfFeatureRegisters {
    values: [u64; FEATURE_REGISTER_COUNT],
}

impl fmt::Debug for HvfFeatureRegisters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut registers = f.debug_struct("HvfFeatureRegisters");
        for (register, value) in self.iter() {
            registers.field(register.name(), &format_args!("{value:#018x}"));
        }
        registers.finish()
    }
}

impl HvfFeatureRegisters {
    pub fn get(&self, register: HvfFeatureRegister) -> u64 {
        self.values[register as usize]
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (HvfFeatureRegister, u64)> + '_ {
        HvfFeatureRegister::ALL
            .into_iter()
            .map(|register| (register, self.get(register)))
    }

    fn from_vcpu_configuration(config: NonNull<c_void>) -> Result<Self, HvfError> {
        let count = unsafe { litebox_hvf_feature_reg_count() };
        if count != FEATURE_REGISTER_COUNT {
            return Err(HvfError::FeatureRegisterCount(count));
        }
        let mut values = [0; FEATURE_REGISTER_COUNT];
        check("hv_vcpu_config_get_feature_reg", unsafe {
            litebox_hvf_vcpu_config_get_feature_regs(
                config.as_ptr(),
                values.as_mut_ptr(),
                values.len(),
            )
        })?;
        Ok(Self { values })
    }

    fn changed_from(&self, admitted: &Self) -> Option<HvfError> {
        HvfFeatureRegister::ALL.into_iter().find_map(|register| {
            let configured = self.get(register);
            let admitted_value = admitted.get(register);
            (configured != admitted_value).then_some(HvfError::FeatureConfigurationChanged {
                register,
                admitted: admitted_value,
                configured,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfMapPermissions(u8);

impl HvfMapPermissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for HvfMapPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for HvfMapPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[repr(align(16384))]
struct HvfMonitorPage([u8; HVF_PAGE_SIZE]);

const _: () = {
    assert!(core::mem::size_of::<HvfMonitorPage>() == HVF_PAGE_SIZE);
    assert!(core::mem::align_of::<HvfMonitorPage>() == HVF_PAGE_SIZE);
};

pub struct HvfMonitor {
    page: Box<HvfMonitorPage>,
    syscall_offset: usize,
    resume_offset: usize,
}

impl fmt::Debug for HvfMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfMonitor")
            .field("bytes", &self.page.0.len())
            .field("syscall_offset", &self.syscall_offset)
            .field("resume_offset", &self.resume_offset)
            .finish()
    }
}

impl HvfMonitor {
    fn linked() -> Result<Self, HvfError> {
        let mut start = core::ptr::null();
        let mut length = 0;
        let mut syscall_offset = 0;
        let mut resume_offset = 0;
        unsafe {
            litebox_hvf_monitor_layout(
                &raw mut start,
                &raw mut length,
                &raw mut syscall_offset,
                &raw mut resume_offset,
            );
        }
        let alignment = (start as usize) % HVF_PAGE_SIZE;
        if start.is_null()
            || length != HVF_PAGE_SIZE
            || alignment != 0
            || syscall_offset != MONITOR_SYSCALL_OFFSET
            || resume_offset != MONITOR_RESUME_OFFSET
        {
            return Err(HvfError::InvalidMonitor {
                length,
                alignment,
                syscall_offset,
                resume_offset,
            });
        }
        let linked_bytes = unsafe { core::slice::from_raw_parts(start, length) };
        // HVF rejects file-backed Mach-O __TEXT pages as stage-two backing.
        // Keep linkage as the source of truth, then publish an aligned,
        // allocator-backed copy that it can map.
        let mut page = Box::new(HvfMonitorPage([0; HVF_PAGE_SIZE]));
        page.0.copy_from_slice(linked_bytes);
        Ok(Self {
            page,
            syscall_offset,
            resume_offset,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.page.0
    }

    pub const fn syscall_offset(&self) -> usize {
        self.syscall_offset
    }

    pub const fn resume_offset(&self) -> usize {
        self.resume_offset
    }
}

#[derive(Clone, Debug)]
pub struct HvfVmReport {
    pub sdk_max_allowed: u32,
    pub max_ipa_bits: u32,
    pub configured_ipa_bits: u32,
    pub ipa_granule_bytes: usize,
    pub el2_supported: bool,
    pub el2_enabled: bool,
    pub max_vcpu_count: u32,
    pub monitor_bytes: usize,
    pub monitor_syscall_offset: usize,
    pub monitor_resume_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfStageOneRegisterReport {
    pub ttbr0_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HvfSdkResidualReport {
    pub logical_mapping_tokens: usize,
    pub logical_mapping_fragments: usize,
    pub logical_mapping_pages: usize,
    pub logical_mapping_bytes: usize,
    pub known_present_fragments: usize,
    pub known_present_pages: usize,
    pub known_present_bytes: usize,
    pub unknown_fragments: usize,
    pub unknown_pages: usize,
    pub unknown_bytes: usize,
    pub permissions_unknown_mapping_tokens: usize,
    pub logical_vcpu_tokens: usize,
    pub active_vcpus: usize,
    pub quarantined_vcpus: usize,
    pub zero_vcpu_operation_active: bool,
    pub zero_vcpu_owned_by_current_thread: bool,
}

impl HvfSdkResidualReport {
    pub const fn has_mapping_residuals(&self) -> bool {
        self.logical_mapping_tokens != 0
            || self.logical_mapping_fragments != 0
            || self.logical_mapping_pages != 0
            || self.logical_mapping_bytes != 0
            || self.known_present_fragments != 0
            || self.known_present_pages != 0
            || self.known_present_bytes != 0
            || self.unknown_fragments != 0
            || self.unknown_pages != 0
            || self.unknown_bytes != 0
            || self.permissions_unknown_mapping_tokens != 0
    }

    pub const fn is_empty(&self) -> bool {
        !self.has_mapping_residuals()
            && self.logical_vcpu_tokens == 0
            && self.active_vcpus == 0
            && self.quarantined_vcpus == 0
    }
}

#[derive(Clone, Debug)]
pub struct HvfBoundaryReport {
    pub vm: HvfVmReport,
    pub monitor_mapping_fragments: usize,
    pub feature_registers: HvfFeatureRegisters,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

struct HvfVmOperationState {
    owner: Option<std::thread::ThreadId>,
    depth: usize,
    poison_requested: bool,
    poisoned: bool,
    zero_vcpu_owner: Option<std::thread::ThreadId>,
    zero_vcpu_depth: usize,
}

struct HvfVmOperationGate {
    state: Mutex<HvfVmOperationState>,
    idle: Condvar,
    abandoned: AtomicBool,
}

pub(crate) struct HvfVmOperation<'vm> {
    vm: &'vm HvfVm,
    owner: std::thread::ThreadId,
    finished: bool,
    not_send: PhantomData<Rc<()>>,
}

impl HvfVmOperation<'_> {
    pub(crate) fn require_live(&self) -> Result<(), HvfError> {
        if self.vm.operation_gate.abandoned.load(Ordering::Acquire) {
            return Err(HvfError::OperationAbandoned);
        }
        let current = std::thread::current().id();
        let state = self
            .vm
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.poison_requested || state.poisoned {
            return Err(HvfError::Poisoned);
        }
        if current != self.owner || state.owner.as_ref() != Some(&self.owner) || state.depth == 0 {
            return Err(HvfError::OperationAbandoned);
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), HvfError> {
        let current = std::thread::current().id();
        let mut state = self
            .vm
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current != self.owner || state.owner.as_ref() != Some(&self.owner) || state.depth == 0 {
            state.poison_requested = false;
            state.poisoned = true;
            state.owner = None;
            state.depth = 0;
            self.vm
                .operation_gate
                .abandoned
                .store(true, Ordering::Release);
            self.vm.operation_gate.idle.notify_all();
            self.finished = true;
            return Err(HvfError::OperationAbandoned);
        }
        state.depth -= 1;
        if state.depth == 0 {
            state.owner = None;
            self.vm.operation_gate.idle.notify_all();
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for HvfVmOperation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.vm
                .operation_gate
                .abandoned
                .store(true, Ordering::Release);
            self.vm.cleanup_required.store(true, Ordering::Release);
        }
    }
}

pub(crate) struct HvfVm {
    report: HvfVmReport,
    monitor: HvfMonitor,
    admitted_features: HvfFeatureRegisters,
    operation_gate: HvfVmOperationGate,
    mapping_registry: Mutex<HvfMappingRegistry>,
    cleanup_required: AtomicBool,
    vcpu_ownership: Mutex<HvfVcpuOwnership>,
}

impl fmt::Debug for HvfVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVm")
            .field("report", &self.report)
            .field("admitted_features", &self.admitted_features)
            .field("poisoned", &self.is_poisoned())
            .finish()
    }
}

impl HvfVm {
    fn create() -> Result<Self, HvfError> {
        let sdk_max_allowed = unsafe { litebox_hvf_sdk_max_allowed() };
        if sdk_max_allowed < MACOS_26_SDK_VERSION {
            return Err(HvfError::SdkTooOld(sdk_max_allowed));
        }
        if unsafe { litebox_hvf_runtime_is_macos_26_or_newer() } == 0 {
            return Err(HvfError::HostTooOld);
        }
        let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if host_page_size != HVF_PAGE_SIZE as i64 {
            return Err(HvfError::HostPageSize(host_page_size));
        }

        let monitor = HvfMonitor::linked()?;
        with_vm_configuration(move |vm_config| {
            let mut max_ipa_bits = 0;
            check("hv_vm_config_get_max_ipa_size", unsafe {
                litebox_hvf_vm_config_get_max_ipa_size(&raw mut max_ipa_bits)
            })?;
            if max_ipa_bits < MIN_IPA_BITS {
                return Err(HvfError::IpaSizeOutOfRange(max_ipa_bits));
            }
            let requested_ipa_bits = max_ipa_bits.min(MAX_IPA_BITS);
            check("hv_vm_config_set_ipa_size", unsafe {
                litebox_hvf_vm_config_set_ipa_size(vm_config.as_ptr(), requested_ipa_bits)
            })?;
            check("hv_vm_config_set_ipa_granule", unsafe {
                litebox_hvf_vm_config_set_ipa_granule_16k(vm_config.as_ptr())
            })?;
            check("hv_vm_config_set_el2_enabled(false)", unsafe {
                litebox_hvf_vm_config_set_el2_disabled(vm_config.as_ptr())
            })?;

            let mut configured_ipa_bits = 0;
            check("hv_vm_config_get_ipa_size", unsafe {
                litebox_hvf_vm_config_get_ipa_size(vm_config.as_ptr(), &raw mut configured_ipa_bits)
            })?;
            if configured_ipa_bits != requested_ipa_bits {
                return Err(HvfError::IpaSizeReadback {
                    requested: requested_ipa_bits,
                    configured: configured_ipa_bits,
                });
            }

            let mut raw_granule = 0;
            let mut is_16k = 0;
            check("hv_vm_config_get_ipa_granule", unsafe {
                litebox_hvf_vm_config_get_ipa_granule(
                    vm_config.as_ptr(),
                    &raw mut raw_granule,
                    &raw mut is_16k,
                )
            })?;
            if is_16k == 0 {
                return Err(HvfError::IpaGranuleReadback(raw_granule));
            }

            let mut el2_supported = 0;
            check("hv_vm_config_get_el2_supported", unsafe {
                litebox_hvf_vm_config_get_el2_supported(&raw mut el2_supported)
            })?;
            let mut el2_enabled = 0;
            check("hv_vm_config_get_el2_enabled", unsafe {
                litebox_hvf_vm_config_get_el2_enabled(vm_config.as_ptr(), &raw mut el2_enabled)
            })?;
            if el2_enabled != 0 {
                return Err(HvfError::El2StillEnabled);
            }

            let mut max_vcpu_count = 0;
            check("hv_vm_get_max_vcpu_count", unsafe {
                litebox_hvf_vm_get_max_vcpu_count(&raw mut max_vcpu_count)
            })?;
            if max_vcpu_count == 0 {
                return Err(HvfError::NoVcpus);
            }

            let admitted_features = with_vcpu_configuration(|config| {
                HvfFeatureRegisters::from_vcpu_configuration(config)
            })?;
            let create_result = unsafe { litebox_hvf_vm_create(vm_config.as_ptr()) };
            if denied(create_result) {
                return Err(HvfError::HypervisorEntitlementMissing);
            }
            check("hv_vm_create", create_result)?;

            Ok(Self {
                report: HvfVmReport {
                    sdk_max_allowed,
                    max_ipa_bits,
                    configured_ipa_bits,
                    ipa_granule_bytes: HVF_PAGE_SIZE,
                    el2_supported: el2_supported != 0,
                    el2_enabled: false,
                    max_vcpu_count,
                    monitor_bytes: monitor.bytes().len(),
                    monitor_syscall_offset: monitor.syscall_offset,
                    monitor_resume_offset: monitor.resume_offset,
                },
                monitor,
                admitted_features,
                operation_gate: HvfVmOperationGate {
                    state: Mutex::new(HvfVmOperationState {
                        owner: None,
                        depth: 0,
                        poison_requested: false,
                        poisoned: false,
                        zero_vcpu_owner: None,
                        zero_vcpu_depth: 0,
                    }),
                    idle: Condvar::new(),
                    abandoned: AtomicBool::new(false),
                },
                mapping_registry: Mutex::new(HvfMappingRegistry::default()),
                cleanup_required: AtomicBool::new(false),
                vcpu_ownership: Mutex::new(HvfVcpuOwnership::default()),
            })
        })
    }

    pub(crate) fn report(&self) -> &HvfVmReport {
        &self.report
    }

    pub(crate) fn monitor(&self) -> &HvfMonitor {
        &self.monitor
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.operation_gate.abandoned.load(Ordering::Acquire)
            || self
                .operation_gate
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .poisoned
            || self.cleanup_required.load(Ordering::Acquire)
    }

    pub(crate) fn poison_requested(&self) -> bool {
        self.operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poison_requested
    }

    fn wait_for_operation_state<'a>(
        &self,
        state: MutexGuard<'a, HvfVmOperationState>,
        deadline: Instant,
    ) -> (MutexGuard<'a, HvfVmOperationState>, bool) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return (state, true);
        }
        let (state, result) = self
            .operation_gate
            .idle
            .wait_timeout(state, remaining.min(OPERATION_WAIT_POLL))
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timed_out =
            result.timed_out() && deadline.saturating_duration_since(Instant::now()).is_zero();
        (state, timed_out)
    }

    pub(crate) fn wait_for_poison_request(&self) -> Result<(), HvfError> {
        let deadline = Instant::now()
            .checked_add(OPERATION_WAIT_TIMEOUT)
            .ok_or(HvfError::OperationWaitTimeout)?;
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.poison_requested && !state.poisoned {
            if self.operation_gate.abandoned.load(Ordering::Acquire) {
                return Err(HvfError::OperationAbandoned);
            }
            let (next, timed_out) = self.wait_for_operation_state(state, deadline);
            state = next;
            if timed_out {
                return Err(HvfError::OperationWaitTimeout);
            }
        }
        Ok(())
    }

    fn begin_operation_inner(
        &self,
        cleanup: bool,
        wait_timeout: Duration,
    ) -> Result<HvfVmOperation<'_>, HvfError> {
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            return Err(HvfError::OperationAbandoned);
        }
        if self.cleanup_required.load(Ordering::Acquire) && !cleanup {
            return Err(HvfError::Poisoned);
        }
        let deadline = Instant::now()
            .checked_add(wait_timeout)
            .ok_or(HvfError::OperationWaitTimeout)?;
        let current = std::thread::current().id();
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if self.operation_gate.abandoned.load(Ordering::Acquire) {
                return Err(HvfError::OperationAbandoned);
            }
            if self.cleanup_required.load(Ordering::Acquire) && !cleanup {
                return Err(HvfError::Poisoned);
            }
            if state.poisoned {
                if !cleanup {
                    return Err(HvfError::Poisoned);
                }
            } else if state.poison_requested {
                if !cleanup {
                    return Err(HvfError::Poisoned);
                }
                if state.owner.as_ref() != Some(&current) {
                    let (next, timed_out) = self.wait_for_operation_state(state, deadline);
                    state = next;
                    if timed_out {
                        return Err(HvfError::OperationWaitTimeout);
                    }
                    continue;
                }
            }
            match state.owner.as_ref() {
                None => {
                    state.owner = Some(current);
                    state.depth = 1;
                    return Ok(HvfVmOperation {
                        vm: self,
                        owner: current,
                        finished: false,
                        not_send: PhantomData,
                    });
                }
                Some(owner) if *owner == current => {
                    let Some(depth) = state.depth.checked_add(1) else {
                        state.poison_requested = false;
                        state.poisoned = true;
                        self.operation_gate.idle.notify_all();
                        return Err(HvfError::Poisoned);
                    };
                    state.depth = depth;
                    return Ok(HvfVmOperation {
                        vm: self,
                        owner: current,
                        finished: false,
                        not_send: PhantomData,
                    });
                }
                Some(_) => {
                    let (next, timed_out) = self.wait_for_operation_state(state, deadline);
                    state = next;
                    if timed_out {
                        return Err(HvfError::OperationWaitTimeout);
                    }
                }
            }
        }
    }

    fn finish_operation<T, E>(result: Result<T, E>, finish: Result<(), HvfError>) -> Result<T, E>
    where
        E: From<HvfError>,
    {
        match (result, finish) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error.into()),
            (Err(trigger), Err(_)) => Err(trigger),
        }
    }

    pub(crate) fn with_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<HvfError>,
    {
        self.with_operation_inner(false, OPERATION_WAIT_TIMEOUT, body)
    }

    pub(crate) fn with_operation_timeout<T, E>(
        &self,
        wait_timeout: Duration,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<HvfError>,
    {
        self.with_operation_inner(false, wait_timeout, body)
    }

    pub(crate) fn with_cleanup_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<HvfError>,
    {
        self.with_operation_inner(true, OPERATION_WAIT_TIMEOUT, body)
    }

    fn with_operation_inner<T, E>(
        &self,
        cleanup: bool,
        wait_timeout: Duration,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<HvfError>,
    {
        let operation = self
            .begin_operation_inner(cleanup, wait_timeout)
            .map_err(E::from)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&operation)));
        let finish = operation.finish();
        match result {
            Ok(result) => Self::finish_operation(result, finish),
            Err(payload) => {
                if finish.is_err() {
                    self.operation_gate.abandoned.store(true, Ordering::Release);
                }
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(crate) fn with_zero_vcpu_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<HvfError>,
    {
        self.with_operation(|operation| {
            {
                let ownership = self
                    .vcpu_ownership
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !ownership.pending.is_empty()
                    || !ownership.active.is_empty()
                    || !ownership.quarantined.is_empty()
                {
                    return Err(E::from(HvfError::ZeroVcpuAdmission));
                }
            }
            let current = std::thread::current().id();
            {
                let mut state = self
                    .operation_gate
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.zero_vcpu_owner.is_some() || state.zero_vcpu_depth != 0 {
                    return Err(E::from(HvfError::ZeroVcpuAdmission));
                }
                state.zero_vcpu_owner = Some(current);
                state.zero_vcpu_depth = 1;
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(operation)));
            let finish = self.finish_zero_vcpu_operation(current);
            match result {
                Ok(result) => Self::finish_operation(result, finish),
                Err(payload) => {
                    if finish.is_err() {
                        self.operation_gate.abandoned.store(true, Ordering::Release);
                        self.cleanup_required.store(true, Ordering::Release);
                    }
                    std::panic::resume_unwind(payload)
                }
            }
        })
    }

    fn finish_zero_vcpu_operation(&self, owner: std::thread::ThreadId) -> Result<(), HvfError> {
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.zero_vcpu_owner.as_ref() != Some(&owner) || state.zero_vcpu_depth != 1 {
            state.zero_vcpu_owner = None;
            state.zero_vcpu_depth = 0;
            state.poison_requested = false;
            state.poisoned = true;
            self.operation_gate.abandoned.store(true, Ordering::Release);
            self.cleanup_required.store(true, Ordering::Release);
            self.operation_gate.idle.notify_all();
            return Err(HvfError::OperationAbandoned);
        }
        state.zero_vcpu_owner = None;
        state.zero_vcpu_depth = 0;
        self.operation_gate.idle.notify_all();
        Ok(())
    }

    fn require_vcpu_creation_admitted(&self) -> Result<(), HvfError> {
        let state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (state.zero_vcpu_owner.as_ref(), state.zero_vcpu_depth) {
            (None, 0) => Ok(()),
            (Some(_), 1) => Err(HvfError::ZeroVcpuAdmission),
            _ => Err(HvfError::OperationAbandoned),
        }
    }

    pub(crate) fn poison(&self) {
        let deadline = Instant::now().checked_add(OPERATION_WAIT_TIMEOUT);
        let current = std::thread::current().id();
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.poisoned {
            return;
        }
        state.poison_requested = true;
        self.operation_gate.idle.notify_all();
        while state.owner.as_ref().is_some_and(|owner| *owner != current) {
            let Some(deadline) = deadline else {
                state.poison_requested = false;
                state.poisoned = true;
                self.operation_gate.abandoned.store(true, Ordering::Release);
                self.cleanup_required.store(true, Ordering::Release);
                self.operation_gate.idle.notify_all();
                return;
            };
            let (next, timed_out) = self.wait_for_operation_state(state, deadline);
            state = next;
            if timed_out {
                state.poison_requested = false;
                state.poisoned = true;
                self.operation_gate.abandoned.store(true, Ordering::Release);
                self.cleanup_required.store(true, Ordering::Release);
                self.operation_gate.idle.notify_all();
                return;
            }
        }
        state.poison_requested = false;
        state.poisoned = true;
        self.operation_gate.idle.notify_all();
    }

    pub(crate) fn create_vcpu(&'static self) -> Result<HvfVcpu, HvfError> {
        self.with_operation(|_| {
            self.require_vcpu_creation_admitted()?;
            let reservation = self.begin_vcpu_creation()?;
            let creation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_vcpu_configuration(|config| {
                    let configured_features = HvfFeatureRegisters::from_vcpu_configuration(config)?;
                    if let Some(error) = configured_features.changed_from(&self.admitted_features) {
                        return Err(error);
                    }
                    let mut identifier = 0;
                    let mut exit_area = core::ptr::null_mut();
                    check("hv_vcpu_create", unsafe {
                        litebox_hvf_vcpu_create(
                            &raw mut identifier,
                            &raw mut exit_area,
                            config.as_ptr(),
                        )
                    })?;
                    Ok((configured_features, identifier, exit_area))
                })
            }));
            let (configured_features, identifier, exit_area) = match creation {
                Ok(Ok(created)) => created,
                Ok(Err(error)) => {
                    self.cancel_vcpu_creation(&reservation)?;
                    return Err(error);
                }
                Err(payload) => {
                    if self.cancel_vcpu_creation(&reservation).is_err() {
                        self.cleanup_required.store(true, Ordering::Release);
                        self.poison();
                    }
                    std::panic::resume_unwind(payload);
                }
            };
            if let Err(error) = self.register_vcpu(&reservation, identifier) {
                let cleanup = unsafe { litebox_hvf_vcpu_destroy(identifier) };
                if succeeded(cleanup) {
                    self.cancel_vcpu_creation(&reservation)?;
                    return Err(error);
                }
                self.record_vcpu_cleanup(
                    identifier,
                    reservation.owner,
                    &reservation.handle_state,
                    Some(cleanup),
                );
                self.cleanup_required.store(true, Ordering::Release);
                self.poison();
                return Err(HvfError::vcpu_cleanup(&error, cleanup));
            }
            let Some(exit_area) = NonNull::new(exit_area) else {
                return self.reject_vcpu(
                    identifier,
                    reservation.owner,
                    &reservation.handle_state,
                    HvfError::NullVcpuExitArea,
                );
            };
            let vcpu = HvfVcpu {
                identifier,
                exit_area,
                features: configured_features,
                vm: self,
                owner: reservation.owner,
                handle_state: Arc::clone(&reservation.handle_state),
                live: true,
                not_send: PhantomData,
            };
            if let Err(error) = vcpu.verify_feature_registers_at_creation() {
                return vcpu.reject(error);
            }
            Ok(vcpu)
        })
    }

    fn begin_vcpu_creation(&self) -> Result<HvfVcpuCreationReservation, HvfError> {
        let owner = std::thread::current().id();
        let handle_state = Arc::new(AtomicU8::new(VCPU_HANDLE_LIVE));
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ownership
            .pending
            .try_reserve(1)
            .map_err(|_| HvfError::ResourceReservation("pending vCPU registry"))?;
        ownership
            .active
            .try_reserve(1)
            .map_err(|_| HvfError::ResourceReservation("active vCPU registry"))?;
        ownership
            .quarantined
            .try_reserve(1)
            .map_err(|_| HvfError::ResourceReservation("vCPU quarantine registry"))?;
        let token = ownership.next_token;
        ownership.next_token = token
            .checked_add(1)
            .ok_or(HvfError::ResourceReservation("vCPU creation token"))?;
        ownership.pending.push(HvfPendingVcpu {
            token,
            owner,
            handle_state: Arc::clone(&handle_state),
        });
        Ok(HvfVcpuCreationReservation {
            token,
            owner,
            handle_state,
        })
    }

    fn cancel_vcpu_creation(
        &self,
        reservation: &HvfVcpuCreationReservation,
    ) -> Result<(), HvfError> {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = ownership.pending.iter().position(|pending| {
            pending.token == reservation.token
                && pending.owner == reservation.owner
                && Arc::ptr_eq(&pending.handle_state, &reservation.handle_state)
        }) else {
            return Err(HvfError::ResidualAccounting);
        };
        ownership.pending.remove(index);
        reservation
            .handle_state
            .store(VCPU_HANDLE_CLOSED, Ordering::Release);
        Ok(())
    }

    fn register_vcpu(
        &self,
        reservation: &HvfVcpuCreationReservation,
        identifier: u64,
    ) -> Result<(), HvfError> {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if ownership
            .active
            .iter()
            .any(|record| record.identifier == identifier)
            || ownership
                .quarantined
                .iter()
                .any(|record| record.identifier == identifier)
        {
            return Err(HvfError::VcpuOwnershipCollision(identifier));
        }
        let Some(index) = ownership.pending.iter().position(|pending| {
            pending.token == reservation.token
                && pending.owner == reservation.owner
                && Arc::ptr_eq(&pending.handle_state, &reservation.handle_state)
        }) else {
            return Err(HvfError::ResidualAccounting);
        };
        let pending = ownership.pending.remove(index);
        ownership.active.push(HvfOwnedVcpu {
            identifier,
            owner: pending.owner,
            handle_state: pending.handle_state,
        });
        Ok(())
    }

    fn record_vcpu_cleanup(
        &self,
        identifier: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<AtomicU8>,
        cleanup_code: Option<HvReturn>,
    ) {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ownership
            .active
            .retain(|record| record.identifier != identifier);
        ownership
            .pending
            .retain(|record| !Arc::ptr_eq(&record.handle_state, handle_state));
        if let Some(cleanup_code) = cleanup_code {
            handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            if let Some(record) = ownership
                .quarantined
                .iter_mut()
                .find(|record| record.identifier == identifier)
            {
                record.owner = owner;
                record.cleanup_code = Some(cleanup_code);
                record.handle_state = Arc::clone(handle_state);
            } else {
                ownership.quarantined.push(HvfQuarantinedVcpu {
                    identifier,
                    owner,
                    cleanup_code: Some(cleanup_code),
                    handle_state: Arc::clone(handle_state),
                });
            }
        } else {
            handle_state.store(VCPU_HANDLE_CLOSED, Ordering::Release);
            ownership
                .quarantined
                .retain(|record| record.identifier != identifier);
        }
    }

    fn quarantine_vcpu_without_cleanup(
        &self,
        identifier: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<AtomicU8>,
    ) {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ownership
            .active
            .retain(|record| record.identifier != identifier);
        handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
        if !ownership
            .quarantined
            .iter()
            .any(|record| record.identifier == identifier)
        {
            ownership.quarantined.push(HvfQuarantinedVcpu {
                identifier,
                owner,
                cleanup_code: None,
                handle_state: Arc::clone(handle_state),
            });
        }
        self.cleanup_required.store(true, Ordering::Release);
    }

    fn reject_vcpu<T>(
        &self,
        identifier: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<AtomicU8>,
        trigger: HvfError,
    ) -> Result<T, HvfError> {
        handle_state.store(VCPU_HANDLE_CLOSING, Ordering::Release);
        let cleanup = unsafe { litebox_hvf_vcpu_destroy(identifier) };
        if succeeded(cleanup) {
            self.record_vcpu_cleanup(identifier, owner, handle_state, None);
            Err(trigger)
        } else {
            self.record_vcpu_cleanup(identifier, owner, handle_state, Some(cleanup));
            self.cleanup_required.store(true, Ordering::Release);
            self.poison();
            Err(HvfError::vcpu_cleanup(&trigger, cleanup))
        }
    }

    pub(crate) fn active_vcpu_count(&self) -> usize {
        self.vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .iter()
            .filter(|record| {
                matches!(
                    record.handle_state.load(Ordering::Acquire),
                    VCPU_HANDLE_LIVE | VCPU_HANDLE_CLOSING
                )
            })
            .count()
    }

    pub(crate) fn active_vcpu_count_for_current_thread(&self) -> usize {
        let current = std::thread::current().id();
        self.vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .iter()
            .filter(|record| {
                record.owner == current
                    && matches!(
                        record.handle_state.load(Ordering::Acquire),
                        VCPU_HANDLE_LIVE | VCPU_HANDLE_CLOSING
                    )
            })
            .count()
    }

    pub(crate) fn quarantined_vcpu_count(&self) -> usize {
        let ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ownership.quarantined.len()
            + ownership
                .active
                .iter()
                .filter(|record| {
                    record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_RETRY_QUEUED
                })
                .count()
    }

    pub(crate) fn retry_quarantined_vcpus_for_current_thread(&self) -> Result<usize, HvfError> {
        self.with_cleanup_operation(|_| {
            let current = std::thread::current().id();
            let mut ownership = self
                .vcpu_ownership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut released = 0;

            let mut index = ownership.quarantined.len();
            while index != 0 {
                index -= 1;
                if ownership.quarantined[index].owner != current {
                    continue;
                }
                ownership.quarantined[index].cleanup_code = None;
                ownership.quarantined[index]
                    .handle_state
                    .store(VCPU_HANDLE_CLOSING, Ordering::Release);
                let result =
                    unsafe { litebox_hvf_vcpu_destroy(ownership.quarantined[index].identifier) };
                if succeeded(result) {
                    let record = ownership.quarantined.remove(index);
                    record
                        .handle_state
                        .store(VCPU_HANDLE_CLOSED, Ordering::Release);
                    checked_residual_add(&mut released, 1)?;
                } else {
                    ownership.quarantined[index].cleanup_code = Some(result);
                    ownership.quarantined[index]
                        .handle_state
                        .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                }
            }

            let mut index = ownership.active.len();
            while index != 0 {
                index -= 1;
                if ownership.active[index].owner != current
                    || ownership.active[index].handle_state.load(Ordering::Acquire)
                        != VCPU_HANDLE_RETRY_QUEUED
                {
                    continue;
                }
                let record = ownership.active.remove(index);
                record
                    .handle_state
                    .store(VCPU_HANDLE_CLOSING, Ordering::Release);
                let result = unsafe { litebox_hvf_vcpu_destroy(record.identifier) };
                if succeeded(result) {
                    record
                        .handle_state
                        .store(VCPU_HANDLE_CLOSED, Ordering::Release);
                    checked_residual_add(&mut released, 1)?;
                } else {
                    record
                        .handle_state
                        .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                    ownership.quarantined.push(HvfQuarantinedVcpu {
                        identifier: record.identifier,
                        owner: record.owner,
                        cleanup_code: Some(result),
                        handle_state: record.handle_state,
                    });
                }
            }
            Ok(released)
        })
    }

    /// Maps a host virtual range into the process-global VM.
    ///
    /// # Safety
    ///
    /// The caller must keep every byte in `host_range` allocated at the same
    /// virtual address until this mapping token is explicitly closed or its
    /// exact per-resource quarantine record reports every fragment absent.
    pub(crate) unsafe fn map_host_range(
        &self,
        host_range: Range<usize>,
        ipa: u64,
        permissions: HvfMapPermissions,
    ) -> Result<HvfMapping<'_>, HvfError> {
        self.with_operation(|_| {
            let length = host_range
                .end
                .checked_sub(host_range.start)
                .ok_or(HvfError::EmptyMapping)?;
            if length == 0 {
                return Err(HvfError::EmptyMapping);
            }
            if permissions.contains(HvfMapPermissions::WRITE)
                && permissions.contains(HvfMapPermissions::EXECUTE)
            {
                return Err(HvfError::WriteExecuteMapping);
            }
            if !host_range.start.is_multiple_of(HVF_PAGE_SIZE)
                || !length.is_multiple_of(HVF_PAGE_SIZE)
                || !ipa.is_multiple_of(HVF_PAGE_SIZE as u64)
            {
                return Err(HvfError::MappingUnaligned {
                    host_address: host_range.start,
                    ipa,
                    length,
                });
            }
            let ipa_limit = 1u64 << self.report.configured_ipa_bits;
            let ipa_end = ipa
                .checked_add(length as u64)
                .ok_or(HvfError::MappingOutOfRange {
                    ipa,
                    length,
                    ipa_bits: self.report.configured_ipa_bits,
                })?;
            if ipa_end > ipa_limit {
                return Err(HvfError::MappingOutOfRange {
                    ipa,
                    length,
                    ipa_bits: self.report.configured_ipa_bits,
                });
            }

            let mut fragments = Vec::new();
            let mut cursor = host_range.start;
            for region in crate::darwin::mach_vm_region_iter() {
                if region.end <= cursor {
                    continue;
                }
                if region.start > cursor {
                    break;
                }
                let fragment_end = region.end.min(host_range.end);
                fragments
                    .try_reserve(1)
                    .map_err(|_| HvfError::ResourceReservation("mapping fragments"))?;
                fragments.push(HvfMappingFragment {
                    ipa: ipa + (cursor - host_range.start) as u64,
                    length: fragment_end - cursor,
                    state: HvfMappingFragmentState::NotMapped,
                    last_unmap_error: None,
                });
                cursor = fragment_end;
                if cursor == host_range.end {
                    break;
                }
            }
            if cursor != host_range.end {
                return Err(HvfError::HostRangeGap(cursor));
            }

            let mut registry = self
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .records
                .try_reserve(1)
                .map_err(|_| HvfError::ResourceReservation("mapping registry"))?;
            let token = registry.next_token;
            registry.next_token = token
                .checked_add(1)
                .ok_or(HvfError::MappingTokenExhausted)?;
            let handle_state = Arc::new(AtomicU8::new(MAPPING_HANDLE_LIVE));
            registry.records.push(HvfMappingRecord {
                token,
                host_range: host_range.clone(),
                ipa,
                permissions,
                permissions_unknown: false,
                fragments,
                lifecycle: HvfMappingLifecycle::Provisioning,
                handle_state: Arc::clone(&handle_state),
            });
            let record_index = registry.records.len() - 1;

            let mut map_failure = None;
            {
                let record = &mut registry.records[record_index];
                for fragment in &mut record.fragments {
                    let host_address = host_range.start + (fragment.ipa - ipa) as usize;
                    let result = unsafe {
                        litebox_hvf_vm_map(
                            host_address as *mut c_void,
                            fragment.ipa,
                            fragment.length,
                            permissions.0,
                        )
                    };
                    if !succeeded(result) {
                        map_failure = Some(result);
                        break;
                    }
                    fragment.state = HvfMappingFragmentState::KnownPresent;
                }
            }

            if let Some(trigger_code) = map_failure {
                let record = &mut registry.records[record_index];
                let rollback_code = Self::unmap_mapping_record(record);
                let residual = record.fragments.iter().any(|fragment| {
                    fragment.state != HvfMappingFragmentState::Absent
                        && fragment.state != HvfMappingFragmentState::NotMapped
                });
                if residual {
                    record.lifecycle = HvfMappingLifecycle::Quarantined;
                    handle_state.store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
                } else {
                    registry.records.remove(record_index);
                    handle_state.store(MAPPING_HANDLE_CLOSED, Ordering::Release);
                }
                drop(registry);
                if let Some(rollback_code) = rollback_code {
                    self.cleanup_required.store(true, Ordering::Release);
                    self.poison();
                    return Err(HvfError::MappingRollback {
                        token,
                        trigger: "hv_vm_map",
                        trigger_code: Some(trigger_code),
                        rollback_code,
                    });
                }
                return Err(HvfError::Call {
                    operation: "hv_vm_map",
                    code: trigger_code,
                });
            }

            registry.records[record_index].lifecycle = HvfMappingLifecycle::Live;
            let fragment_count = registry.records[record_index].fragments.len();
            drop(registry);
            Ok(HvfMapping {
                vm: self,
                token,
                host_range,
                ipa,
                permissions,
                fragment_count,
                handle_state,
                live: true,
            })
        })
    }

    fn unmap_mapping_record(record: &mut HvfMappingRecord) -> Option<HvReturn> {
        let mut first_failure = None;
        for fragment in record.fragments.iter_mut().rev() {
            if !matches!(
                fragment.state,
                HvfMappingFragmentState::KnownPresent
                    | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
            ) {
                continue;
            }
            let result = unsafe { litebox_hvf_vm_unmap(fragment.ipa, fragment.length) };
            if succeeded(result) {
                fragment.state = HvfMappingFragmentState::Absent;
                fragment.last_unmap_error = None;
            } else {
                fragment.state = HvfMappingFragmentState::UnknownAfterFailedExactUnmap;
                fragment.last_unmap_error = Some(result);
                if first_failure.is_none() {
                    first_failure = Some(result);
                }
            }
        }
        first_failure
    }

    fn quarantine_mapping_token(&self, token: u64, permissions_unknown: bool) {
        let mut registry = self
            .mapping_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = registry
            .records
            .iter_mut()
            .find(|record| record.token == token)
        {
            record.lifecycle = HvfMappingLifecycle::Quarantined;
            record.permissions_unknown |= permissions_unknown;
            record
                .handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
        }
        self.cleanup_required.store(true, Ordering::Release);
    }

    fn cleanup_mapping_token(&self, token: u64) -> Result<usize, HvfError> {
        let mut registry = self
            .mapping_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = registry
            .records
            .iter()
            .position(|record| record.token == token)
        else {
            return Err(HvfError::MappingTokenMissing(token));
        };
        let before = registry.records[index]
            .fragments
            .iter()
            .filter(|fragment| {
                matches!(
                    fragment.state,
                    HvfMappingFragmentState::KnownPresent
                        | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
                )
            })
            .count();
        let failure = Self::unmap_mapping_record(&mut registry.records[index]);
        let after = registry.records[index]
            .fragments
            .iter()
            .filter(|fragment| {
                matches!(
                    fragment.state,
                    HvfMappingFragmentState::KnownPresent
                        | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
                )
            })
            .count();
        let released = before - after;
        if after == 0 {
            let record = registry.records.remove(index);
            record
                .handle_state
                .store(MAPPING_HANDLE_CLOSED, Ordering::Release);
        } else {
            let record = &mut registry.records[index];
            record.lifecycle = HvfMappingLifecycle::Quarantined;
            record
                .handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
        }
        drop(registry);
        if after != 0 {
            self.cleanup_required.store(true, Ordering::Release);
        }
        if let Some(code) = failure {
            Err(HvfError::Call {
                operation: "hv_vm_unmap",
                code,
            })
        } else {
            Ok(released)
        }
    }

    pub(crate) fn residual_report(&self) -> Result<HvfSdkResidualReport, HvfError> {
        self.with_cleanup_operation(|_| {
            let current = std::thread::current().id();
            let (zero_vcpu_operation_active, zero_vcpu_owned_by_current_thread) = {
                let state = self
                    .operation_gate
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match (state.zero_vcpu_owner.as_ref(), state.zero_vcpu_depth) {
                    (None, 0) => (false, false),
                    (Some(owner), 1) => (true, *owner == current),
                    _ => return Err(HvfError::ResidualAccounting),
                }
            };
            let mut report = HvfSdkResidualReport {
                zero_vcpu_operation_active,
                zero_vcpu_owned_by_current_thread,
                ..HvfSdkResidualReport::default()
            };
            {
                let registry = self
                    .mapping_registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for record in registry.records.iter().filter(|record| {
                    record.lifecycle == HvfMappingLifecycle::Quarantined
                        || record.handle_state.load(Ordering::Acquire)
                            == MAPPING_HANDLE_RETRY_QUEUED
                }) {
                    let bytes = record
                        .host_range
                        .end
                        .checked_sub(record.host_range.start)
                        .ok_or(HvfError::ResidualAccounting)?;
                    if bytes == 0
                        || !record.host_range.start.is_multiple_of(HVF_PAGE_SIZE)
                        || !bytes.is_multiple_of(HVF_PAGE_SIZE)
                        || !record.ipa.is_multiple_of(HVF_PAGE_SIZE as u64)
                    {
                        return Err(HvfError::ResidualAccounting);
                    }
                    let ipa_end = record
                        .ipa
                        .checked_add(
                            u64::try_from(bytes).map_err(|_| HvfError::ResidualAccounting)?,
                        )
                        .ok_or(HvfError::ResidualAccounting)?;
                    checked_residual_add(&mut report.logical_mapping_tokens, 1)?;
                    checked_residual_add(
                        &mut report.logical_mapping_fragments,
                        record.fragments.len(),
                    )?;
                    checked_residual_add(&mut report.logical_mapping_pages, bytes / HVF_PAGE_SIZE)?;
                    checked_residual_add(&mut report.logical_mapping_bytes, bytes)?;
                    if record.permissions_unknown {
                        checked_residual_add(&mut report.permissions_unknown_mapping_tokens, 1)?;
                    }
                    for fragment in &record.fragments {
                        if fragment.length == 0
                            || !fragment.ipa.is_multiple_of(HVF_PAGE_SIZE as u64)
                            || !fragment.length.is_multiple_of(HVF_PAGE_SIZE)
                        {
                            return Err(HvfError::ResidualAccounting);
                        }
                        let fragment_end = fragment
                            .ipa
                            .checked_add(
                                u64::try_from(fragment.length)
                                    .map_err(|_| HvfError::ResidualAccounting)?,
                            )
                            .ok_or(HvfError::ResidualAccounting)?;
                        if fragment.ipa < record.ipa || fragment_end > ipa_end {
                            return Err(HvfError::ResidualAccounting);
                        }
                        let (fragments, pages, bytes) = match fragment.state {
                            HvfMappingFragmentState::KnownPresent => (
                                &mut report.known_present_fragments,
                                &mut report.known_present_pages,
                                &mut report.known_present_bytes,
                            ),
                            HvfMappingFragmentState::UnknownAfterFailedExactUnmap => (
                                &mut report.unknown_fragments,
                                &mut report.unknown_pages,
                                &mut report.unknown_bytes,
                            ),
                            HvfMappingFragmentState::NotMapped
                            | HvfMappingFragmentState::Absent => continue,
                        };
                        checked_residual_add(fragments, 1)?;
                        checked_residual_add(pages, fragment.length / HVF_PAGE_SIZE)?;
                        checked_residual_add(bytes, fragment.length)?;
                    }
                }
            }
            {
                let ownership = self
                    .vcpu_ownership
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for record in &ownership.pending {
                    checked_residual_add(&mut report.logical_vcpu_tokens, 1)?;
                    if record.handle_state.load(Ordering::Acquire) != VCPU_HANDLE_LIVE {
                        return Err(HvfError::ResidualAccounting);
                    }
                    checked_residual_add(&mut report.active_vcpus, 1)?;
                }
                for record in &ownership.active {
                    checked_residual_add(&mut report.logical_vcpu_tokens, 1)?;
                    match record.handle_state.load(Ordering::Acquire) {
                        VCPU_HANDLE_LIVE | VCPU_HANDLE_CLOSING => {
                            checked_residual_add(&mut report.active_vcpus, 1)?;
                        }
                        VCPU_HANDLE_RETRY_QUEUED => {
                            checked_residual_add(&mut report.quarantined_vcpus, 1)?;
                        }
                        _ => return Err(HvfError::ResidualAccounting),
                    }
                }
                for record in &ownership.quarantined {
                    if ownership
                        .active
                        .iter()
                        .any(|active| active.identifier == record.identifier)
                    {
                        return Err(HvfError::ResidualAccounting);
                    }
                    checked_residual_add(&mut report.logical_vcpu_tokens, 1)?;
                    match record.handle_state.load(Ordering::Acquire) {
                        VCPU_HANDLE_CLOSING | VCPU_HANDLE_RETRY_QUEUED => {
                            checked_residual_add(&mut report.quarantined_vcpus, 1)?;
                        }
                        _ => return Err(HvfError::ResidualAccounting),
                    }
                }
            }
            Ok(report)
        })
    }

    pub(crate) fn mapping_token_has_residual(&self, token: u64) -> bool {
        self.mapping_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .iter()
            .any(|record| record.token == token)
    }

    pub(crate) fn retry_quarantined_mapping(&self, token: u64) -> Result<usize, HvfError> {
        self.with_cleanup_operation(|_| {
            if !self.mapping_token_has_residual(token) {
                return Ok(0);
            }
            self.cleanup_mapping_token(token)
        })
    }

    pub(crate) fn retry_quarantined_mappings(&self) -> Result<usize, HvfError> {
        self.with_cleanup_operation(|_| {
            let registry = self
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let token_count = registry
                .records
                .iter()
                .filter(|record| {
                    record.lifecycle == HvfMappingLifecycle::Quarantined
                        || record.handle_state.load(Ordering::Acquire)
                            == MAPPING_HANDLE_RETRY_QUEUED
                })
                .count();
            let mut tokens = Vec::new();
            tokens
                .try_reserve_exact(token_count)
                .map_err(|_| HvfError::ResourceReservation("mapping retry plan"))?;
            tokens.extend(
                registry
                    .records
                    .iter()
                    .filter(|record| {
                        record.lifecycle == HvfMappingLifecycle::Quarantined
                            || record.handle_state.load(Ordering::Acquire)
                                == MAPPING_HANDLE_RETRY_QUEUED
                    })
                    .map(|record| record.token),
            );
            drop(registry);
            let mut released = 0;
            let mut first_error = None;
            for token in tokens {
                match self.cleanup_mapping_token(token) {
                    Ok(count) => checked_residual_add(&mut released, count)?,
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                }
            }
            if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(released)
            }
        })
    }

    pub(crate) fn publish_executable_bytes(&self, bytes: &[u8]) -> Result<(), HvfError> {
        self.with_operation(|_| {
            publish_hvf_executable_bytes(bytes);
            Ok(())
        })
    }
}

static PROCESS_HVF_VM: OnceLock<Result<HvfVm, HvfError>> = OnceLock::new();
static PRODUCTION_VM_LIVE: AtomicBool = AtomicBool::new(false);

pub(crate) fn process_hvf_vm() -> Result<&'static HvfVm, HvfError> {
    let result = PROCESS_HVF_VM.get_or_init(|| {
        let _exclusive = super::HVF_SMOKE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if super::smoke_residual_is_live() {
            return Err(HvfError::SmokeResidualOwnership);
        }
        let vm = HvfVm::create();
        if vm.is_ok() {
            PRODUCTION_VM_LIVE.store(true, Ordering::Release);
        }
        vm
    });
    result.as_ref().map_err(Clone::clone)
}

pub fn hvf_boundary_probe() -> Result<HvfBoundaryReport, HvfError> {
    let vm = process_hvf_vm()?;
    vm.publish_executable_bytes(vm.monitor().bytes())?;
    let monitor_start = vm.monitor().bytes().as_ptr() as usize;
    let monitor_end = monitor_start + vm.monitor().bytes().len();
    let mapping = unsafe {
        vm.map_host_range(
            monitor_start..monitor_end,
            0,
            HvfMapPermissions::READ | HvfMapPermissions::EXECUTE,
        )
    }?;
    let monitor_mapping_fragments = mapping.fragment_count();
    mapping.unmap()?;

    let vcpu = vm.create_vcpu()?;
    let feature_registers = vcpu.features().clone();
    vcpu.destroy()?;
    vm.with_operation(|operation| operation.require_live())?;
    let sdk_residuals = vm.residual_report()?;
    if !sdk_residuals.is_empty() {
        return Err(HvfError::ResidualOwnership(sdk_residuals));
    }
    Ok(HvfBoundaryReport {
        vm: vm.report().clone(),
        monitor_mapping_fragments,
        feature_registers,
        sdk_residuals,
        vm_poisoned: vm.is_poisoned(),
    })
}

pub(super) fn production_vm_is_live() -> bool {
    PRODUCTION_VM_LIVE.load(Ordering::Acquire)
}

pub fn publish_hvf_executable_bytes(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe {
            crate::darwin::sys_icache_invalidate(bytes.as_ptr().cast_mut().cast(), bytes.len());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvfMappingFragmentState {
    NotMapped,
    KnownPresent,
    Absent,
    UnknownAfterFailedExactUnmap,
}

#[derive(Clone, Copy, Debug)]
struct HvfMappingFragment {
    ipa: u64,
    length: usize,
    state: HvfMappingFragmentState,
    last_unmap_error: Option<HvReturn>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvfMappingLifecycle {
    Provisioning,
    Live,
    Quarantined,
}

const MAPPING_HANDLE_LIVE: u8 = 0;
const MAPPING_HANDLE_CLOSING: u8 = 1;
const MAPPING_HANDLE_CLOSED: u8 = 2;
const MAPPING_HANDLE_RETRY_QUEUED: u8 = 3;

struct HvfMappingRecord {
    token: u64,
    host_range: Range<usize>,
    ipa: u64,
    permissions: HvfMapPermissions,
    permissions_unknown: bool,
    fragments: Vec<HvfMappingFragment>,
    lifecycle: HvfMappingLifecycle,
    handle_state: Arc<std::sync::atomic::AtomicU8>,
}

struct HvfMappingRegistry {
    next_token: u64,
    records: Vec<HvfMappingRecord>,
}

impl Default for HvfMappingRegistry {
    fn default() -> Self {
        Self {
            next_token: 1,
            records: Vec::new(),
        }
    }
}

const VCPU_HANDLE_LIVE: u8 = 0;
const VCPU_HANDLE_CLOSING: u8 = 1;
const VCPU_HANDLE_CLOSED: u8 = 2;
const VCPU_HANDLE_RETRY_QUEUED: u8 = 3;

struct HvfVcpuCreationReservation {
    token: u64,
    owner: std::thread::ThreadId,
    handle_state: Arc<AtomicU8>,
}

struct HvfPendingVcpu {
    token: u64,
    owner: std::thread::ThreadId,
    handle_state: Arc<AtomicU8>,
}

#[derive(Clone)]
struct HvfOwnedVcpu {
    identifier: u64,
    owner: std::thread::ThreadId,
    handle_state: Arc<AtomicU8>,
}

struct HvfQuarantinedVcpu {
    identifier: u64,
    owner: std::thread::ThreadId,
    cleanup_code: Option<HvReturn>,
    handle_state: Arc<AtomicU8>,
}

struct HvfVcpuOwnership {
    next_token: u64,
    pending: Vec<HvfPendingVcpu>,
    active: Vec<HvfOwnedVcpu>,
    quarantined: Vec<HvfQuarantinedVcpu>,
}

impl Default for HvfVcpuOwnership {
    fn default() -> Self {
        Self {
            next_token: 1,
            pending: Vec::new(),
            active: Vec::new(),
            quarantined: Vec::new(),
        }
    }
}

pub(crate) struct HvfMapping<'vm> {
    vm: &'vm HvfVm,
    token: u64,
    host_range: Range<usize>,
    ipa: u64,
    permissions: HvfMapPermissions,
    fragment_count: usize,
    handle_state: Arc<AtomicU8>,
    live: bool,
}

impl fmt::Debug for HvfMapping<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfMapping")
            .field("token", &self.token)
            .field("host_range", &self.host_range)
            .field("ipa", &self.ipa)
            .field("permissions", &self.permissions)
            .field("fragment_count", &self.fragment_count)
            .finish()
    }
}

impl HvfMapping<'_> {
    pub(crate) const fn token(&self) -> u64 {
        self.token
    }

    pub(crate) const fn ipa(&self) -> u64 {
        self.ipa
    }

    pub(crate) fn protect(&mut self, permissions: HvfMapPermissions) -> Result<(), HvfError> {
        if !self.live {
            return Err(HvfError::MappingNotLive);
        }
        if permissions.contains(HvfMapPermissions::WRITE)
            && permissions.contains(HvfMapPermissions::EXECUTE)
        {
            return Err(HvfError::WriteExecuteMapping);
        }
        let vm = self.vm;
        vm.with_operation(|_| {
            let mut registry = vm
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = registry
                .records
                .iter_mut()
                .find(|record| record.token == self.token)
            else {
                return Err(HvfError::MappingTokenMissing(self.token));
            };
            let result =
                unsafe { litebox_hvf_vm_protect(self.ipa, self.host_range.len(), permissions.0) };
            if !succeeded(result) {
                record.lifecycle = HvfMappingLifecycle::Quarantined;
                record.permissions_unknown = true;
                record
                    .handle_state
                    .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
                drop(registry);
                self.live = false;
                vm.cleanup_required.store(true, Ordering::Release);
                vm.poison();
                return Err(HvfError::Call {
                    operation: "hv_vm_protect",
                    code: result,
                });
            }
            record.permissions = permissions;
            record.permissions_unknown = false;
            self.permissions = permissions;
            Ok(())
        })
    }

    pub(crate) fn induce_protect_failure(&mut self) -> Result<(), HvfError> {
        self.protect(HvfMapPermissions(1 << 7))
    }

    pub(crate) fn induce_unmap_failure(mut self) -> Result<(), HvfError> {
        let vm = self.vm;
        vm.with_cleanup_operation(|_| {
            let result = unsafe { litebox_hvf_vm_unmap(self.ipa + 1, self.host_range.len()) };
            if succeeded(result) {
                return Ok(());
            }
            vm.quarantine_mapping_token(self.token, false);
            self.handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
            self.live = false;
            vm.poison();
            Err(HvfError::Call {
                operation: "hv_vm_unmap",
                code: result,
            })
        })
    }

    pub(crate) const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    pub(crate) fn unmap(mut self) -> Result<(), HvfError> {
        if !self.live {
            return Err(HvfError::MappingNotLive);
        }
        let vm = self.vm;
        let result = vm.with_cleanup_operation(|_| {
            self.handle_state
                .store(MAPPING_HANDLE_CLOSING, Ordering::Release);
            vm.cleanup_mapping_token(self.token).map(|_| ())
        });
        self.live = false;
        if result.is_err() {
            self.handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
            vm.cleanup_required.store(true, Ordering::Release);
            vm.poison();
        }
        result
    }
}

impl Drop for HvfMapping<'_> {
    fn drop(&mut self) {
        if self.live {
            self.handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
            self.vm.cleanup_required.store(true, Ordering::Release);
            self.live = false;
        }
    }
}

pub(crate) struct HvfVcpu {
    identifier: u64,
    exit_area: NonNull<c_void>,
    features: HvfFeatureRegisters,
    vm: &'static HvfVm,
    owner: std::thread::ThreadId,
    handle_state: Arc<AtomicU8>,
    live: bool,
    not_send: PhantomData<Rc<()>>,
}

impl fmt::Debug for HvfVcpu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpu")
            .field("identifier", &self.identifier)
            .field("exit_area", &self.exit_area)
            .field("features", &self.features)
            .finish()
    }
}

impl HvfVcpu {
    fn reject<T>(mut self, trigger: HvfError) -> Result<T, HvfError> {
        let cleanup = unsafe { litebox_hvf_vcpu_destroy(self.identifier) };
        self.live = false;
        if succeeded(cleanup) {
            self.vm
                .record_vcpu_cleanup(self.identifier, self.owner, &self.handle_state, None);
            Err(trigger)
        } else {
            self.vm.record_vcpu_cleanup(
                self.identifier,
                self.owner,
                &self.handle_state,
                Some(cleanup),
            );
            self.vm.poison();
            Err(HvfError::vcpu_cleanup(&trigger, cleanup))
        }
    }

    fn quarantine(&mut self, trigger: HvfError) -> HvfError {
        self.vm.poison();
        let cleanup = unsafe { litebox_hvf_vcpu_destroy(self.identifier) };
        self.live = false;
        if succeeded(cleanup) {
            self.vm
                .record_vcpu_cleanup(self.identifier, self.owner, &self.handle_state, None);
            trigger
        } else {
            self.vm.record_vcpu_cleanup(
                self.identifier,
                self.owner,
                &self.handle_state,
                Some(cleanup),
            );
            HvfError::vcpu_cleanup(&trigger, cleanup)
        }
    }

    pub(crate) fn features(&self) -> &HvfFeatureRegisters {
        &self.features
    }

    pub(crate) fn program_stage_one(
        &mut self,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        self.program_stage_one_expected(ttbr0_el1, ttbr0_el1, tcr_el1, tcr_el1, mair_el1, mair_el1)
    }

    pub(crate) fn induce_stage_one_readback_mismatch(
        &mut self,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        self.program_stage_one_expected(
            ttbr0_el1,
            ttbr0_el1,
            tcr_el1,
            tcr_el1,
            mair_el1,
            mair_el1 ^ 1,
        )
    }

    fn program_stage_one_expected(
        &mut self,
        ttbr0_el1: u64,
        expected_ttbr0_el1: u64,
        tcr_el1: u64,
        expected_tcr_el1: u64,
        mair_el1: u64,
        expected_mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        if !self.live {
            return Err(HvfError::VcpuNotLive);
        }
        let vm = self.vm;
        vm.with_operation(|operation| {
            let mut ttbr0_readback = 0;
            let mut tcr_readback = 0;
            let mut mair_readback = 0;
            let result = unsafe {
                litebox_hvf_vcpu_program_stage_one(
                    self.identifier,
                    ttbr0_el1,
                    tcr_el1,
                    mair_el1,
                    &raw mut ttbr0_readback,
                    &raw mut tcr_readback,
                    &raw mut mair_readback,
                )
            };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_set/get_sys_reg(stage-one)",
                    code: result,
                };
                return Err(self.quarantine(trigger));
            }
            for (register, expected, actual) in [
                ("TTBR0_EL1", expected_ttbr0_el1, ttbr0_readback),
                ("TCR_EL1", expected_tcr_el1, tcr_readback),
                ("MAIR_EL1", expected_mair_el1, mair_readback),
            ] {
                if actual != expected {
                    let trigger = HvfError::StageOneRegisterReadback {
                        register,
                        expected,
                        actual,
                    };
                    return Err(self.quarantine(trigger));
                }
            }
            operation.require_live()?;
            Ok(HvfStageOneRegisterReport {
                ttbr0_el1: ttbr0_readback,
                tcr_el1: tcr_readback,
                mair_el1: mair_readback,
            })
        })
    }

    fn verify_feature_registers_at_creation(&self) -> Result<(), HvfError> {
        if !self.live {
            return Err(HvfError::VcpuNotLive);
        }
        self.vm.with_operation(|_| {
            let mut mismatch_index = usize::MAX;
            let mut actual_value = 0;
            check("hv_vcpu_get_sys_reg(feature)", unsafe {
                litebox_hvf_vcpu_verify_feature_regs(
                    self.identifier,
                    self.features.values.as_ptr(),
                    self.features.values.len(),
                    &raw mut mismatch_index,
                    &raw mut actual_value,
                )
            })?;
            if mismatch_index == usize::MAX {
                return Ok(());
            }
            let Some(&register) = HvfFeatureRegister::ALL.get(mismatch_index) else {
                return Err(HvfError::FeatureRegisterCount(mismatch_index));
            };
            Err(HvfError::FeatureRegisterMismatch {
                register,
                expected: self.features.get(register),
                actual: actual_value,
            })
        })
    }

    pub(crate) fn destroy(mut self) -> Result<(), HvfError> {
        if !self.live {
            return Err(HvfError::VcpuNotLive);
        }
        if std::thread::current().id() != self.owner {
            self.vm.quarantine_vcpu_without_cleanup(
                self.identifier,
                self.owner,
                &self.handle_state,
            );
            self.live = false;
            self.vm.poison();
            return Err(HvfError::VcpuWrongOwner {
                identifier: self.identifier,
            });
        }
        let vm = self.vm;
        let result = vm.with_cleanup_operation(|_| {
            self.handle_state
                .store(VCPU_HANDLE_CLOSING, Ordering::Release);
            let result = unsafe { litebox_hvf_vcpu_destroy(self.identifier) };
            self.live = false;
            if succeeded(result) {
                vm.record_vcpu_cleanup(self.identifier, self.owner, &self.handle_state, None);
                Ok(())
            } else {
                vm.record_vcpu_cleanup(
                    self.identifier,
                    self.owner,
                    &self.handle_state,
                    Some(result),
                );
                vm.cleanup_required.store(true, Ordering::Release);
                vm.poison();
                Err(HvfError::Call {
                    operation: "hv_vcpu_destroy",
                    code: result,
                })
            }
        });
        if result.is_err() && self.live {
            self.handle_state
                .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            vm.cleanup_required.store(true, Ordering::Release);
        }
        result
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        if self.live {
            self.handle_state
                .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            self.vm.cleanup_required.store(true, Ordering::Release);
            self.live = false;
        }
    }
}
