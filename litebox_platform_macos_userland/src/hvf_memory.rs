// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::cell::Cell;
use core::fmt;
use core::ops::{BitOr, BitOrAssign, Range};
use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, Mutex, OnceLock};

use crate::hvf::{
    HvfError, HvfMapPermissions, HvfMapping, HvfSdkResidualReport, HvfStageOneRegisterReport,
    HvfVm, process_hvf_vm,
};
use crate::hvf_backing::{
    HVF_HOST_PAGE_SIZE, HvfHostBacking, HvfHostBackingError, HvfHostBackingReport,
    HvfHostPermissions, HvfHostSlot, hvf_host_backing_probe, hvf_host_retry_residual,
};

const PAGE_SIZE: usize = HVF_HOST_PAGE_SIZE;
const TABLE_ENTRIES: usize = PAGE_SIZE / core::mem::size_of::<u64>();
const VA_BITS: u8 = 48;
const VA_LIMIT: usize = 1usize << VA_BITS;
const ASID_BITS: u8 = 8;
const MAX_ASIDS: u16 = 1 << ASID_BITS;
const MAIR_ATTR0_NORMAL_WB: u64 = 0xff;
const DESCRIPTOR_VALID_TABLE_OR_PAGE: u64 = 0b11;
const DESCRIPTOR_AP_EL0_RW: u64 = 0b01 << 6;
const DESCRIPTOR_AP_EL0_NONE_EL1_RO: u64 = 0b10 << 6;
const DESCRIPTOR_AP_EL0_RO: u64 = 0b11 << 6;
const DESCRIPTOR_INNER_SHAREABLE: u64 = 0b11 << 8;
const DESCRIPTOR_ACCESS_FLAG: u64 = 1 << 10;
const DESCRIPTOR_NOT_GLOBAL: u64 = 1 << 11;
const DESCRIPTOR_PXN: u64 = 1 << 53;
const DESCRIPTOR_UXN: u64 = 1 << 54;
const DESCRIPTOR_OUTPUT_MASK: u64 = 0x0000_ffff_ffff_c000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HvfAddressSpaceId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfAsid {
    pub value: u8,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfRootGeneration(u64);

impl HvfRootGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfWriteEpoch(u64);

impl HvfWriteEpoch {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfPublicationEpoch(u64);

impl HvfPublicationEpoch {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfExecutableGeneration(u64);

impl HvfExecutableGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HvfBackingIdentity(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfSharing {
    Private,
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfTranslationRegime {
    pub va_bits: u8,
    pub tbi0: bool,
    pub asid_bits: u8,
    pub ipa_bits: u32,
    pub tcr_el1: u64,
    pub mair_attr0: u8,
}

impl HvfTranslationRegime {
    fn for_ipa_bits(ipa_bits: u32) -> Result<Self, HvfMemoryError> {
        if !(32..=52).contains(&ipa_bits) {
            return Err(HvfMemoryError::UnsupportedIpaWidth(ipa_bits));
        }
        Ok(Self {
            va_bits: VA_BITS,
            tbi0: false,
            asid_bits: ASID_BITS,
            ipa_bits,
            tcr_el1: tcr_el1(ipa_bits),
            mair_attr0: MAIR_ATTR0_NORMAL_WB as u8,
        })
    }

    fn validate_address(self, gva: usize) -> Result<(), HvfMemoryError> {
        if self.tbi0 || self.va_bits != VA_BITS || gva >= VA_LIMIT {
            return Err(HvfMemoryError::NoncanonicalAddress {
                address: gva,
                va_bits: self.va_bits,
                tbi0: self.tbi0,
            });
        }
        Ok(())
    }

    fn validate_range(self, range: &Range<usize>) -> Result<usize, HvfMemoryError> {
        if range.is_empty() {
            return Err(HvfMemoryError::EmptyRange);
        }
        self.validate_address(range.start)?;
        if range.end > VA_LIMIT {
            return Err(HvfMemoryError::NoncanonicalRange {
                range: range.clone(),
                va_bits: self.va_bits,
                tbi0: self.tbi0,
            });
        }
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or(HvfMemoryError::EmptyRange)?;
        if !range.start.is_multiple_of(PAGE_SIZE) || !length.is_multiple_of(PAGE_SIZE) {
            return Err(HvfMemoryError::Unaligned {
                start: range.start,
                length,
            });
        }
        if range.start < PAGE_SIZE {
            return Err(HvfMemoryError::MonitorOverlap(range.clone()));
        }
        Ok(length / PAGE_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfGuestPermissions(u8);

impl HvfGuestPermissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn validate(self) -> Result<(), HvfMemoryError> {
        if self.contains(Self::WRITE) && !self.contains(Self::READ) {
            return Err(HvfMemoryError::WriteWithoutRead);
        }
        if self.contains(Self::WRITE) && self.contains(Self::EXECUTE) {
            return Err(HvfMemoryError::WriteExecute);
        }
        if self.0 & !(Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0) != 0 {
            return Err(HvfMemoryError::InvalidPermissions(self.0));
        }
        Ok(())
    }

    fn stage_two(self) -> HvfMapPermissions {
        let mut permissions = HvfMapPermissions::NONE;
        if self.contains(Self::READ) || self.contains(Self::EXECUTE) {
            permissions |= HvfMapPermissions::READ;
        }
        if self.contains(Self::WRITE) {
            permissions |= HvfMapPermissions::WRITE;
        }
        if self.contains(Self::EXECUTE) {
            permissions |= HvfMapPermissions::EXECUTE;
        }
        permissions
    }

    fn stage_one_descriptor(self, ipa: u64) -> u64 {
        let access = if self.contains(Self::WRITE) {
            DESCRIPTOR_AP_EL0_RW
        } else if self.contains(Self::READ) {
            DESCRIPTOR_AP_EL0_RO
        } else {
            DESCRIPTOR_AP_EL0_NONE_EL1_RO
        };
        let execute_never = if self.contains(Self::EXECUTE) {
            0
        } else {
            DESCRIPTOR_UXN
        };
        (ipa & DESCRIPTOR_OUTPUT_MASK)
            | DESCRIPTOR_VALID_TABLE_OR_PAGE
            | access
            | DESCRIPTOR_INNER_SHAREABLE
            | DESCRIPTOR_ACCESS_FLAG
            | DESCRIPTOR_NOT_GLOBAL
            | DESCRIPTOR_PXN
            | execute_never
    }
}

impl BitOr for HvfGuestPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for HvfGuestPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfMemoryLimits {
    pub max_address_spaces: usize,
    pub max_claimed_pages: usize,
    pub max_live_data_pages: usize,
    pub max_table_pages: usize,
    pub max_host_slots: usize,
    pub max_retired_generations: usize,
    pub max_retired_pages: usize,
    pub max_retired_bytes: usize,
    pub max_mutation_pages: usize,
}

impl Default for HvfMemoryLimits {
    fn default() -> Self {
        Self {
            max_address_spaces: 254,
            max_claimed_pages: 1 << 20,
            max_live_data_pages: 1 << 19,
            max_table_pages: 1 << 18,
            max_host_slots: 1 << 20,
            max_retired_generations: 1 << 14,
            max_retired_pages: 1 << 20,
            max_retired_bytes: 16 * 1024 * 1024 * 1024,
            max_mutation_pages: 1 << 16,
        }
    }
}

#[derive(Clone, Debug)]
pub enum HvfMemoryError {
    Hvf(HvfError),
    HostBacking(HvfHostBackingError),
    UnsupportedIpaWidth(u32),
    EmptyRange,
    Unaligned {
        start: usize,
        length: usize,
    },
    NoncanonicalAddress {
        address: usize,
        va_bits: u8,
        tbi0: bool,
    },
    NoncanonicalRange {
        range: Range<usize>,
        va_bits: u8,
        tbi0: bool,
    },
    MonitorOverlap(Range<usize>),
    InvalidPermissions(u8),
    WriteWithoutRead,
    WriteExecute,
    InitialExecute(Range<usize>),
    BackingWriteExecute {
        backing: HvfBackingIdentity,
        offset: usize,
    },
    WrongMemoryManager,
    AddressSpaceDestroyed(HvfAddressSpaceId),
    AddressOverlap(Range<usize>),
    ClaimStale,
    RangeOutsideClaim(Range<usize>),
    SparseAlias(Range<usize>),
    AliasBusy(Range<usize>),
    AliasReentrant(Range<usize>),
    AliasRestore(Range<usize>),
    PublicationRequired(Range<usize>),
    PublicationStale(Range<usize>),
    RetirementStale,
    RetirementsPending(HvfAddressSpaceId),
    ResourceLimit {
        resource: &'static str,
        requested: usize,
        limit: usize,
    },
    IpaExhausted(usize),
    IpaOwnership,
    TableOwnership,
    StageOneWalkFailed(usize),
    AsidExhausted,
    AsidOwnership,
    MetadataAllocation(&'static str),
    InjectedFailure(&'static str),
    Witness(&'static str),
    WitnessReport(Box<HvfMemoryReport>),
    FailureWitnessReport(Box<HvfMemoryFailureReport>),
}

impl fmt::Display for HvfMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::HostBacking(error) => write!(f, "{error}"),
            Self::UnsupportedIpaWidth(bits) => write!(f, "unsupported HVF IPA width {bits}"),
            Self::EmptyRange => write!(f, "a compact HVF range cannot be empty"),
            Self::Unaligned { start, length } => write!(
                f,
                "compact HVF range start={start:#x} length={length:#x} is not 16 KiB aligned"
            ),
            Self::NoncanonicalAddress {
                address,
                va_bits,
                tbi0,
            } => write!(
                f,
                "GVA {address:#x} is outside the admitted {va_bits}-bit TBI0={tbi0} TTBR0 regime"
            ),
            Self::NoncanonicalRange {
                range,
                va_bits,
                tbi0,
            } => write!(
                f,
                "GVA range {:#x}..{:#x} crosses the admitted {va_bits}-bit TBI0={tbi0} TTBR0 limit",
                range.start, range.end
            ),
            Self::MonitorOverlap(range) => write!(
                f,
                "guest range {:#x}..{:#x} overlaps the EL1 monitor page",
                range.start, range.end
            ),
            Self::InvalidPermissions(bits) => write!(f, "invalid guest permission bits {bits:#x}"),
            Self::WriteWithoutRead => write!(f, "a writable guest mapping must include read"),
            Self::WriteExecute => write!(f, "compact HVF guest mappings enforce W^X"),
            Self::InitialExecute(range) => write!(
                f,
                "initial executable claim {:#x}..{:#x} must be non-executable and published first",
                range.start, range.end
            ),
            Self::BackingWriteExecute { backing, offset } => write!(
                f,
                "backing page {backing:?}+{offset:#x} has conflicting write and execute authority"
            ),
            Self::WrongMemoryManager => {
                write!(f, "the capability belongs to another HVF memory manager")
            }
            Self::AddressSpaceDestroyed(id) => write!(f, "HVF address space {id:?} is destroyed"),
            Self::AddressOverlap(range) => write!(
                f,
                "guest range {:#x}..{:#x} overlaps an existing logical claim",
                range.start, range.end
            ),
            Self::ClaimStale => write!(f, "the logical GVA claim is stale or foreign"),
            Self::RangeOutsideClaim(range) => write!(
                f,
                "range {:#x}..{:#x} is outside the logical GVA claim",
                range.start, range.end
            ),
            Self::SparseAlias(range) => write!(
                f,
                "range {:#x}..{:#x} contains a deferred PROT_NONE page",
                range.start, range.end
            ),
            Self::AliasBusy(range) => write!(
                f,
                "host slot {:#x}..{:#x} already has an active alias",
                range.start, range.end
            ),
            Self::AliasReentrant(range) => write!(
                f,
                "thread already owns a host alias while requesting {:#x}..{:#x}",
                range.start, range.end
            ),
            Self::AliasRestore(range) => write!(
                f,
                "host slot {:#x}..{:#x} could not return to PROT_NONE ownership",
                range.start, range.end
            ),
            Self::PublicationRequired(range) => write!(
                f,
                "executable range {:#x}..{:#x} needs an explicit cache-publication ticket",
                range.start, range.end
            ),
            Self::PublicationStale(range) => write!(
                f,
                "cache-publication ticket for {:#x}..{:#x} predates a backing write",
                range.start, range.end
            ),
            Self::RetirementStale => write!(f, "the retirement ticket is stale or foreign"),
            Self::RetirementsPending(id) => {
                write!(f, "address space {id:?} still has retirement tickets")
            }
            Self::ResourceLimit {
                resource,
                requested,
                limit,
            } => write!(
                f,
                "compact HVF {resource} request {requested} exceeds bound {limit}"
            ),
            Self::IpaExhausted(pages) => {
                write!(f, "compact IPA aperture cannot allocate {pages} pages")
            }
            Self::IpaOwnership => write!(f, "compact IPA token ownership is inconsistent"),
            Self::TableOwnership => write!(f, "stage-one table ownership is inconsistent"),
            Self::StageOneWalkFailed(gva) => {
                write!(f, "software stage-one walk failed for GVA {gva:#x}")
            }
            Self::AsidExhausted => write!(f, "all admitted 8-bit ASIDs are in use"),
            Self::AsidOwnership => write!(f, "8-bit ASID ownership is inconsistent"),
            Self::MetadataAllocation(resource) => {
                write!(f, "failed to reserve compact HVF {resource} metadata")
            }
            Self::InjectedFailure(point) => write!(f, "injected compact-memory failure at {point}"),
            Self::Witness(message) => write!(f, "compact HVF memory witness failed: {message}"),
            Self::WitnessReport(report) => {
                write!(f, "compact HVF memory witness report:\n{report:#?}")
            }
            Self::FailureWitnessReport(report) => {
                write!(f, "compact HVF memory failure witness report:\n{report:#?}")
            }
        }
    }
}

impl std::error::Error for HvfMemoryError {}

impl From<HvfError> for HvfMemoryError {
    fn from(value: HvfError) -> Self {
        Self::Hvf(value)
    }
}

impl From<HvfHostBackingError> for HvfMemoryError {
    fn from(value: HvfHostBackingError) -> Self {
        Self::HostBacking(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct TableToken(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct HostSlotToken(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IpaToken {
    id: u64,
    start: u64,
    pages: usize,
}

impl IpaToken {
    fn range(self) -> Range<u64> {
        self.start..self.start + (self.pages * PAGE_SIZE) as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackingPage {
    identity: HvfBackingIdentity,
    offset: usize,
}

#[derive(Clone, Debug)]
pub struct HvfClaim {
    manager: u64,
    address_space: HvfAddressSpaceId,
    id: u64,
    version: u64,
    range: Range<usize>,
}

impl HvfClaim {
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
}

#[derive(Clone, Debug)]
pub struct HvfPublicationTicket {
    manager: u64,
    address_space: HvfAddressSpaceId,
    claim_id: u64,
    claim_version: u64,
    range: Range<usize>,
    pages: Vec<PublishedPage>,
}

#[derive(Clone, Debug)]
struct PublishedPage {
    backing: BackingPage,
    write_epoch: HvfWriteEpoch,
    publication_epoch: HvfPublicationEpoch,
}

#[derive(Clone, Debug)]
pub struct HvfRetirementTicket {
    manager: u64,
    address_space: HvfAddressSpaceId,
    id: u64,
    generation: HvfRootGeneration,
}

#[derive(Clone, Debug)]
pub struct HvfMutation {
    pub claim: HvfClaim,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub retirement: HvfRetirementTicket,
}

#[derive(Clone, Debug)]
pub struct HvfUnmapResult {
    pub surviving_claims: Vec<HvfClaim>,
    pub root_generation: HvfRootGeneration,
    pub retirement: HvfRetirementTicket,
}

pub struct HvfForkResult {
    pub address_space: HvfAddressSpace,
    pub claims: Vec<HvfClaim>,
}

impl core::ops::Deref for HvfForkResult {
    type Target = HvfAddressSpace;

    fn deref(&self) -> &Self::Target {
        &self.address_space
    }
}

impl fmt::Debug for HvfForkResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfForkResult")
            .field("address_space", &self.address_space)
            .field("claims", &self.claims)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct HvfRetirementReport {
    pub generation: HvfRootGeneration,
    pub charged_pages: usize,
    pub charged_bytes: usize,
    pub data_pages: usize,
    pub slot_pages: usize,
    pub backing_pages: usize,
    pub table_pages: usize,
    pub released_data_pages: usize,
    pub released_table_pages: usize,
    pub released_host_slots: usize,
    pub released_backing_references: usize,
    pub quarantined_resources: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfLedgerEntry {
    pub gva: Range<usize>,
    pub permissions: HvfGuestPermissions,
    pub sharing: HvfSharing,
    pub backing_identity: Option<HvfBackingIdentity>,
    pub backing_offset: usize,
    pub ipa: Vec<Range<u64>>,
    pub write_epoch: HvfWriteEpoch,
    pub publication_epoch: HvfPublicationEpoch,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HvfMemoryUsage {
    pub address_spaces: usize,
    pub claimed_pages: usize,
    pub live_data_pages: usize,
    pub table_pages: usize,
    pub host_slots: usize,
    pub backing_objects: usize,
    pub physical_backing_pages: usize,
    pub physical_backing_bytes: usize,
    pub ipa_owned_pages: usize,
    pub ipa_capacity_pages: usize,
    pub asids_owned: usize,
    pub active_alias_pages: usize,
    pub alias_quarantine_reservations: usize,
    pub data_quarantine_reservations: usize,
    pub retired_generations: usize,
    pub retired_pages: usize,
    pub retired_bytes: usize,
    pub quarantined_resources: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfAddressSpaceReport {
    pub id: HvfAddressSpaceId,
    pub asid: HvfAsid,
    pub regime: HvfTranslationRegime,
    pub root_ipa: u64,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub stage_one_table_pages: usize,
    pub monitor_leaf_ipa: u64,
    pub mappings: Vec<HvfLedgerEntry>,
    pub usage: HvfMemoryUsage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfVcpuMemorySnapshot {
    pub address_space_id: HvfAddressSpaceId,
    pub asid: HvfAsid,
    pub regime: HvfTranslationRegime,
    pub ttbr0_el1: u64,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
}

#[derive(Clone, Debug)]
pub struct HvfPoisonConcurrencyReport {
    pub poison_requested_while_owner_live: bool,
    pub normal_rejected_while_owner_live: bool,
    pub contender_timed_out_while_owner_live: bool,
    pub poison_waited_for_owner_release: bool,
    pub cleanup_admitted_after_poison: bool,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
pub struct HvfRegisterFailureReport {
    pub programmed_stage_one: HvfStageOneRegisterReport,
    pub stage_one_programming_verified: bool,
    pub mismatch_rejected: bool,
    pub vcpu_registered_to_current_thread: bool,
    pub vcpu_destroyed_without_residual: bool,
    pub cleanup_retry_released_vcpus: usize,
    pub active_vcpu_count: usize,
    pub quarantined_vcpu_count: usize,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
pub struct HvfUnmapFailureReport {
    pub explicit_unmap_succeeded: bool,
    pub protect_failure_observed: bool,
    pub protect_failure_quarantined: bool,
    pub quarantined_handle_rejected_cleanup: bool,
    pub unmap_failure_observed: bool,
    pub unmap_failure_quarantined: bool,
    pub sdk_residuals_before_retry: HvfSdkResidualReport,
    pub cleanup_retry_cleared_fragments: usize,
    pub sdk_residuals_after_retry: HvfSdkResidualReport,
    pub final_sdk_residuals: HvfSdkResidualReport,
    pub post_poison_cleanup_succeeded: bool,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
pub struct HvfMemoryReport {
    pub configured_ipa_bits: u32,
    pub monitor_ipa: u64,
    pub regime: HvfTranslationRegime,
    pub monitor_leaf_verified: bool,
    pub dynamic_tcr_ips_verified: bool,
    pub sparse_claim_verified: bool,
    pub split_verified: bool,
    pub coalesce_verified: bool,
    pub all_stage_one_boundaries_verified: bool,
    pub nonzero_offsets_verified: bool,
    pub compact_nonidentity_ipa_verified: bool,
    pub exact_ipa_reuse_verified: bool,
    pub retired_ipa_held_until_ack_verified: bool,
    pub overlap_rejection_verified: bool,
    pub adjacent_claims_verified: bool,
    pub independent_roots_verified: bool,
    pub competitor_isolation_verified: bool,
    pub asid_reuse_verified: bool,
    pub alias_reservation_verified: bool,
    pub alias_preflight_verified: bool,
    pub alias_reentry_verified: bool,
    pub alias_concurrency_verified: bool,
    pub alias_panic_cleanup_verified: bool,
    pub private_fork_verified: bool,
    pub fork_capability_order_verified: bool,
    pub shared_coherence_verified: bool,
    pub global_wx_fork_retirement_verified: bool,
    pub initial_execute_rejected: bool,
    pub publication_epoch_verified: bool,
    pub stale_publication_rejected: bool,
    pub all_resource_limits_verified: bool,
    pub rollback_verified: bool,
    pub retirement_verified: bool,
    pub retirement_checkpoints_verified: bool,
    pub physical_accounting_verified: bool,
    pub allocator_conservation_verified: bool,
    pub zero_vcpus_verified: bool,
    pub final_usage: HvfMemoryUsage,
    pub sdk_residuals: HvfSdkResidualReport,
    pub host_backing: HvfHostBackingReport,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
pub struct HvfQuarantineRetryReport {
    pub sdk_mapping_fragments_released: usize,
    pub host_resources_released: usize,
    pub aliases_restored: usize,
    pub data_pages_released: usize,
    pub table_pages_released: usize,
    pub host_slots_released: usize,
    pub backings_released: usize,
    pub sdk_residuals: HvfSdkResidualReport,
    pub remaining: HvfMemoryUsage,
}

#[derive(Clone, Debug)]
pub struct HvfMemoryFailureReport {
    pub rollback_preserved_root: bool,
    pub alias_restore_failure_observed: bool,
    pub data_unmap_failure_observed: bool,
    pub table_unmap_failure_observed: bool,
    pub quarantine_count_before_retry: usize,
    pub quarantine_retry: HvfQuarantineRetryReport,
    pub final_quarantine_count: usize,
    pub post_poison_destroy_succeeded: bool,
    pub zero_vcpus_verified: bool,
    pub final_usage: HvfMemoryUsage,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

#[repr(align(16384))]
struct StageOneTable([u64; TABLE_ENTRIES]);

struct IpaAllocator {
    base: u64,
    owners: Vec<u64>,
    next_id: u64,
}

impl IpaAllocator {
    fn new(range: Range<u64>, max_pages: usize) -> Result<Self, HvfMemoryError> {
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or(HvfMemoryError::IpaExhausted(max_pages))?;
        if !range.start.is_multiple_of(PAGE_SIZE as u64) || !length.is_multiple_of(PAGE_SIZE as u64)
        {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let available_pages = usize::try_from(length / PAGE_SIZE as u64)
            .map_err(|_| HvfMemoryError::IpaExhausted(max_pages))?;
        let capacity = available_pages.min(max_pages);
        if capacity == 0 {
            return Err(HvfMemoryError::IpaExhausted(max_pages));
        }
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(capacity)
            .map_err(|_| HvfMemoryError::MetadataAllocation("IPA ownership"))?;
        owners.resize(capacity, 0);
        Ok(Self {
            base: range.start,
            owners,
            next_id: 1,
        })
    }

    fn allocate(&mut self, pages: usize) -> Result<IpaToken, HvfMemoryError> {
        if pages == 0 || pages > self.owners.len() {
            return Err(HvfMemoryError::IpaExhausted(pages));
        }
        let index = self
            .owners
            .windows(pages)
            .position(|owners| owners.iter().all(|owner| *owner == 0))
            .ok_or(HvfMemoryError::IpaExhausted(pages))?;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or(HvfMemoryError::IpaOwnership)?;
        let start = self
            .base
            .checked_add((index * PAGE_SIZE) as u64)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        self.owners[index..index + pages].fill(id);
        self.next_id = next_id;
        Ok(IpaToken { id, start, pages })
    }

    fn release(&mut self, token: IpaToken) -> Result<(), HvfMemoryError> {
        let offset = token
            .start
            .checked_sub(self.base)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if token.id == 0 || token.pages == 0 || !offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let index =
            usize::try_from(offset / PAGE_SIZE as u64).map_err(|_| HvfMemoryError::IpaOwnership)?;
        let end = index
            .checked_add(token.pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let owners = self
            .owners
            .get_mut(index..end)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if owners.iter().any(|owner| *owner != token.id) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        owners.fill(0);
        Ok(())
    }

    fn owned_pages(&self) -> usize {
        self.owners.iter().filter(|owner| **owner != 0).count()
    }

    fn capacity_pages(&self) -> usize {
        self.owners.len()
    }

    fn owns(&self, token: IpaToken) -> bool {
        let Some(offset) = token.start.checked_sub(self.base) else {
            return false;
        };
        if token.id == 0 || token.pages == 0 || !offset.is_multiple_of(PAGE_SIZE as u64) {
            return false;
        }
        let Ok(index) = usize::try_from(offset / PAGE_SIZE as u64) else {
            return false;
        };
        let Some(end) = index.checked_add(token.pages) else {
            return false;
        };
        self.owners
            .get(index..end)
            .is_some_and(|owners| owners.iter().all(|owner| *owner == token.id))
    }
}

struct AsidAllocator {
    free: [bool; MAX_ASIDS as usize],
    epochs: [u64; MAX_ASIDS as usize],
}

impl AsidAllocator {
    fn new() -> Self {
        let mut free = [true; MAX_ASIDS as usize];
        free[0] = false;
        Self {
            free,
            epochs: [0; MAX_ASIDS as usize],
        }
    }

    fn allocate(&mut self) -> Result<HvfAsid, HvfMemoryError> {
        let index = self
            .free
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, free)| free.then_some(index))
            .ok_or(HvfMemoryError::AsidExhausted)?;
        self.free[index] = false;
        Ok(HvfAsid {
            value: index as u8,
            epoch: self.epochs[index],
        })
    }

    fn release(&mut self, asid: HvfAsid) -> Result<(), HvfMemoryError> {
        let index = usize::from(asid.value);
        if asid.value == 0 || self.free[index] || self.epochs[index] != asid.epoch {
            return Err(HvfMemoryError::AsidOwnership);
        }
        let epoch = self.epochs[index]
            .checked_add(1)
            .ok_or(HvfMemoryError::AsidOwnership)?;
        self.epochs[index] = epoch;
        self.free[index] = true;
        Ok(())
    }

    fn owned(&self) -> usize {
        self.free.iter().skip(1).filter(|free| !**free).count()
    }
}

struct TableRecord {
    level: u8,
    ipa: IpaToken,
    bytes: Box<StageOneTable>,
    children: HashMap<usize, TableToken>,
    references: usize,
    mapping: Option<HvfMapping<'static>>,
}

struct TableQuarantine {
    ipa: Option<IpaToken>,
    bytes: Box<StageOneTable>,
    sdk_token: Option<u64>,
    retryable: bool,
}

struct TableArena {
    records: HashMap<TableToken, TableRecord>,
    next_token: u64,
    quarantined: Vec<TableQuarantine>,
    abandoned_roots: Vec<TableToken>,
}

impl TableArena {
    fn new(limit: usize) -> Result<Self, HvfMemoryError> {
        let mut records = HashMap::new();
        records
            .try_reserve(limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table ownership"))?;
        let mut quarantined = Vec::new();
        quarantined
            .try_reserve_exact(limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
        let mut abandoned_roots = Vec::new();
        abandoned_roots
            .try_reserve_exact(limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table root quarantine"))?;
        Ok(Self {
            records,
            next_token: 1,
            quarantined,
            abandoned_roots,
        })
    }

    fn allocate(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
        level: u8,
        bytes: Box<StageOneTable>,
        children: HashMap<usize, TableToken>,
        limit: usize,
    ) -> Result<TableToken, HvfMemoryError> {
        let owned = self
            .records
            .len()
            .checked_add(self.quarantined.len())
            .ok_or(HvfMemoryError::TableOwnership)?;
        admit_resource("stage-one table pages", owned, 1, limit)?;
        self.records
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table ownership"))?;
        self.quarantined
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
        let token = TableToken(self.next_token);
        let next_token = self
            .next_token
            .checked_add(1)
            .ok_or(HvfMemoryError::TableOwnership)?;
        if self.records.contains_key(&token) {
            return Err(HvfMemoryError::TableOwnership);
        }

        let mut child_increments = HashMap::<TableToken, usize>::new();
        child_increments
            .try_reserve(children.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table child ownership"))?;
        for child in children.values() {
            let increment = child_increments.entry(*child).or_default();
            *increment = increment
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
        }
        let mut child_references = Vec::new();
        child_references
            .try_reserve_exact(child_increments.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table child ownership"))?;
        for (child, increment) in child_increments {
            let references = self
                .records
                .get(&child)
                .ok_or(HvfMemoryError::TableOwnership)?
                .references;
            let updated = references
                .checked_add(increment)
                .ok_or(HvfMemoryError::TableOwnership)?;
            child_references.push((child, references, updated));
        }
        let ipa = allocator.allocate(1)?;
        for (child, _, updated) in &child_references {
            self.records
                .get_mut(child)
                .ok_or(HvfMemoryError::TableOwnership)?
                .references = *updated;
        }
        let start = bytes.0.as_ptr() as usize;
        let mapping = unsafe {
            vm.map_host_range(start..start + PAGE_SIZE, ipa.start, HvfMapPermissions::READ)
        };
        let mapping = match mapping {
            Ok(mapping) => mapping,
            Err(error) => {
                for (child, original, _) in &child_references {
                    if let Some(record) = self.records.get_mut(child) {
                        record.references = *original;
                    } else {
                        vm.poison();
                    }
                }
                let sdk_token = match &error {
                    HvfError::MappingRollback { token, .. } => Some(*token),
                    _ => None,
                };
                if sdk_token.is_some() {
                    self.quarantined.push(TableQuarantine {
                        ipa: Some(ipa),
                        bytes,
                        sdk_token,
                        retryable: true,
                    });
                } else if let Err(release_error) = allocator.release(ipa) {
                    self.quarantined.push(TableQuarantine {
                        ipa: Some(ipa),
                        bytes,
                        sdk_token: None,
                        retryable: true,
                    });
                    vm.poison();
                    return Err(release_error);
                }
                return Err(error.into());
            }
        };
        match self.records.entry(token) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(TableRecord {
                    level,
                    ipa,
                    bytes,
                    children,
                    references: 0,
                    mapping: Some(mapping),
                });
                self.next_token = next_token;
                Ok(token)
            }
            std::collections::hash_map::Entry::Occupied(entry) => {
                drop(entry);
                let mut cleanup_error = None;
                for (child, original, _) in &child_references {
                    if let Some(record) = self.records.get_mut(child) {
                        record.references = *original;
                    } else {
                        vm.poison();
                        cleanup_error.get_or_insert(HvfMemoryError::TableOwnership);
                    }
                }
                let sdk_token = mapping.token();
                if let Err(error) = mapping.unmap() {
                    self.quarantined.push(TableQuarantine {
                        ipa: Some(ipa),
                        bytes,
                        sdk_token: Some(sdk_token),
                        retryable: true,
                    });
                    vm.poison();
                    cleanup_error.get_or_insert(error.into());
                } else if let Err(error) = allocator.release(ipa) {
                    self.quarantined.push(TableQuarantine {
                        ipa: Some(ipa),
                        bytes,
                        sdk_token: None,
                        retryable: true,
                    });
                    vm.poison();
                    cleanup_error.get_or_insert(error);
                }
                vm.poison();
                Err(cleanup_error.unwrap_or(HvfMemoryError::TableOwnership))
            }
        }
    }

    fn abandon_root(&mut self, token: TableToken) -> Result<(), HvfMemoryError> {
        if !self.records.contains_key(&token) {
            return Err(HvfMemoryError::TableOwnership);
        }
        if !self.abandoned_roots.contains(&token) {
            // Capacity for every possible table token was reserved before any SDK mapping.
            self.abandoned_roots.push(token);
        }
        Ok(())
    }

    fn abandon_unreferenced(&mut self, created: &[TableToken]) -> Result<(), HvfMemoryError> {
        for token in created {
            if !self.records.contains_key(token) {
                return Err(HvfMemoryError::TableOwnership);
            }
        }
        for token in created {
            if self
                .records
                .get(token)
                .is_some_and(|record| record.references == 0)
                && !self.abandoned_roots.contains(token)
            {
                self.abandoned_roots.push(*token);
            }
        }
        Ok(())
    }

    fn ipa(&self, token: TableToken) -> Result<u64, HvfMemoryError> {
        self.records
            .get(&token)
            .map(|record| record.ipa.start)
            .ok_or(HvfMemoryError::TableOwnership)
    }

    fn retain(&mut self, token: TableToken) -> Result<(), HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::TableOwnership)?;
        record.references = record
            .references
            .checked_add(1)
            .ok_or(HvfMemoryError::TableOwnership)?;
        Ok(())
    }

    fn release(&mut self, token: TableToken) -> Result<Vec<TableRecord>, HvfMemoryError> {
        if self
            .records
            .get(&token)
            .ok_or(HvfMemoryError::TableOwnership)?
            .references
            == 0
        {
            return Err(HvfMemoryError::TableOwnership);
        }
        let edge_count = self.records.values().try_fold(0usize, |count, record| {
            count
                .checked_add(record.children.len())
                .ok_or(HvfMemoryError::TableOwnership)
        })?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(edge_count.saturating_add(1))
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release plan"))?;
        let mut decrements = HashMap::<TableToken, usize>::new();
        decrements
            .try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release plan"))?;
        let mut free = HashSet::<TableToken>::new();
        free.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release plan"))?;
        pending.push(token);
        while let Some(current) = pending.pop() {
            let decrement = decrements.entry(current).or_default();
            *decrement = decrement
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
            let record = self
                .records
                .get(&current)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
            if *decrement == record.references && free.insert(current) {
                pending.extend(record.children.values().copied());
            }
        }
        self.detach_planned(decrements, free)
    }

    fn release_count(&self, token: TableToken) -> Result<usize, HvfMemoryError> {
        if self
            .records
            .get(&token)
            .ok_or(HvfMemoryError::TableOwnership)?
            .references
            == 0
        {
            return Err(HvfMemoryError::TableOwnership);
        }
        let edge_count = self.records.values().try_fold(0usize, |count, record| {
            count
                .checked_add(record.children.len())
                .ok_or(HvfMemoryError::TableOwnership)
        })?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(edge_count.saturating_add(1))
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release count"))?;
        let mut decrements = HashMap::<TableToken, usize>::new();
        decrements
            .try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release count"))?;
        let mut free = HashSet::<TableToken>::new();
        free.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release count"))?;
        pending.push(token);
        while let Some(current) = pending.pop() {
            let decrement = decrements.entry(current).or_default();
            *decrement = decrement
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
            let record = self
                .records
                .get(&current)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
            if *decrement == record.references && free.insert(current) {
                pending.extend(record.children.values().copied());
            }
        }
        Ok(free.len())
    }

    fn discard_unreferenced(
        &mut self,
        created: &mut Vec<TableToken>,
    ) -> Result<Vec<TableRecord>, HvfMemoryError> {
        let edge_count = self.records.values().try_fold(0usize, |count, record| {
            count
                .checked_add(record.children.len())
                .ok_or(HvfMemoryError::TableOwnership)
        })?;
        let mut created_set = HashSet::<TableToken>::new();
        created_set
            .try_reserve(created.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        let mut free = HashSet::<TableToken>::new();
        free.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(edge_count)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        for token in created.iter().copied() {
            if !created_set.insert(token) {
                return Err(HvfMemoryError::TableOwnership);
            }
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if record.references == 0 && free.insert(token) {
                pending.extend(record.children.values().copied());
            }
        }
        let mut decrements = HashMap::<TableToken, usize>::new();
        decrements
            .try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        while let Some(current) = pending.pop() {
            let decrement = decrements.entry(current).or_default();
            *decrement = decrement
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
            let record = self
                .records
                .get(&current)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
            if *decrement == record.references && free.insert(current) {
                pending.extend(record.children.values().copied());
            }
        }
        if created_set.iter().any(|token| !free.contains(token)) {
            return Err(HvfMemoryError::TableOwnership);
        }
        let released = self.detach_planned(decrements, free)?;
        created.clear();
        Ok(released)
    }

    fn detach_planned(
        &mut self,
        decrements: HashMap<TableToken, usize>,
        free: HashSet<TableToken>,
    ) -> Result<Vec<TableRecord>, HvfMemoryError> {
        let mut removed_tokens = Vec::new();
        removed_tokens
            .try_reserve_exact(free.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("detached table ownership"))?;
        removed_tokens.extend(free.iter().copied());
        removed_tokens.sort_unstable();
        let mut released = Vec::new();
        released
            .try_reserve_exact(removed_tokens.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("detached table ownership"))?;
        for (token, decrement) in &decrements {
            if free.contains(token) {
                continue;
            }
            let record = self
                .records
                .get(token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
        }
        for token in &removed_tokens {
            if !self.records.contains_key(token) {
                return Err(HvfMemoryError::TableOwnership);
            }
        }
        for (token, decrement) in decrements {
            if !free.contains(&token) {
                let record = self
                    .records
                    .get_mut(&token)
                    .ok_or(HvfMemoryError::TableOwnership)?;
                record.references -= decrement;
            }
        }
        for token in removed_tokens {
            released.push(
                self.records
                    .remove(&token)
                    .ok_or(HvfMemoryError::TableOwnership)?,
            );
        }
        Ok(released)
    }

    fn cow_leaf(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
        root: TableToken,
        gva: usize,
        descriptor: u64,
        limit: usize,
    ) -> Result<(TableToken, Vec<TableToken>), HvfMemoryError> {
        let indexes = stage_one_indexes(gva);
        let mut created = Vec::new();
        created
            .try_reserve_exact(4)
            .map_err(|_| HvfMemoryError::MetadataAllocation("stage-one COW ownership"))?;
        let result = self.cow_level(
            vm,
            allocator,
            Some(root),
            0,
            &indexes,
            descriptor,
            limit,
            &mut created,
        );
        match result {
            Ok(Some(root)) => Ok((root, created)),
            Ok(None) => Err(HvfMemoryError::TableOwnership),
            Err(error) => {
                let records = match self.discard_unreferenced(&mut created) {
                    Ok(records) => records,
                    Err(cleanup) => {
                        let quarantine = self.abandon_unreferenced(&created);
                        vm.poison();
                        quarantine?;
                        return Err(cleanup);
                    }
                };
                if let Err(cleanup) =
                    cleanup_detached_table_records(vm, self, allocator, records, false)
                {
                    return Err(cleanup);
                }
                Err(error)
            }
        }
    }

    fn cow_level(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
        current: Option<TableToken>,
        level: u8,
        indexes: &[usize; 4],
        descriptor: u64,
        limit: usize,
        created: &mut Vec<TableToken>,
    ) -> Result<Option<TableToken>, HvfMemoryError> {
        let (mut bytes, mut children) = if let Some(token) = current {
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if record.level != level {
                return Err(HvfMemoryError::TableOwnership);
            }
            let mut children = HashMap::new();
            children
                .try_reserve(record.children.len().saturating_add(1))
                .map_err(|_| HvfMemoryError::MetadataAllocation("table child copy"))?;
            children.extend(
                record
                    .children
                    .iter()
                    .map(|(&index, &child)| (index, child)),
            );
            (Box::new(StageOneTable(record.bytes.0)), children)
        } else {
            let mut children = HashMap::new();
            children
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("table children"))?;
            (Box::new(StageOneTable([0; TABLE_ENTRIES])), children)
        };
        let index = indexes[level as usize];
        if level == 3 {
            bytes.0[index] = descriptor;
        } else {
            let old_child = children.get(&index).copied();
            let new_child = self.cow_level(
                vm,
                allocator,
                old_child,
                level + 1,
                indexes,
                descriptor,
                limit,
                created,
            )?;
            match new_child {
                Some(child) => {
                    bytes.0[index] = table_descriptor(self.ipa(child)?);
                    children.insert(index, child);
                }
                None => {
                    bytes.0[index] = 0;
                    children.remove(&index);
                }
            }
        }
        if level != 0 && bytes.0.iter().all(|entry| *entry == 0) {
            return Ok(None);
        }
        let token = self.allocate(vm, allocator, level, bytes, children, limit)?;
        created.push(token);
        Ok(Some(token))
    }

    fn walk(&self, root: TableToken, gva: usize) -> Result<(u64, u64), HvfMemoryError> {
        let indexes = stage_one_indexes(gva);
        let mut token = root;
        for (level, index) in indexes.into_iter().enumerate() {
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::StageOneWalkFailed(gva))?;
            let descriptor = record.bytes.0[index];
            if descriptor & 0b11 != DESCRIPTOR_VALID_TABLE_OR_PAGE {
                return Err(HvfMemoryError::StageOneWalkFailed(gva));
            }
            if level == 3 {
                let ipa =
                    (descriptor & DESCRIPTOR_OUTPUT_MASK) | (gva as u64 & (PAGE_SIZE as u64 - 1));
                return Ok((ipa, descriptor));
            }
            token = *record
                .children
                .get(&index)
                .ok_or(HvfMemoryError::StageOneWalkFailed(gva))?;
        }
        Err(HvfMemoryError::StageOneWalkFailed(gva))
    }

    fn reachable_count(&self, root: TableToken) -> Result<usize, HvfMemoryError> {
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table walk"))?;
        let mut seen = HashSet::new();
        seen.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table walk"))?;
        pending.push(root);
        while let Some(token) = pending.pop() {
            if !seen.insert(token) {
                continue;
            }
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            pending.extend(record.children.values().copied());
        }
        Ok(seen.len())
    }
}

struct HostSlotRecord {
    gva: usize,
    slot: Option<HvfHostSlot>,
    references: usize,
    active: bool,
    quarantined: bool,
}

struct HostSlotArena {
    records: HashMap<HostSlotToken, HostSlotRecord>,
    by_gva: HashMap<usize, HostSlotToken>,
    next_token: u64,
}

impl HostSlotArena {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            by_gva: HashMap::new(),
            next_token: 1,
        }
    }

    fn claim(&mut self, gva: usize, limit: usize) -> Result<HostSlotToken, HvfMemoryError> {
        if let Some(token) = self.by_gva.get(&gva).copied() {
            let record = self
                .records
                .get_mut(&token)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if record.quarantined {
                return Err(HvfMemoryError::AliasRestore(gva..gva + PAGE_SIZE));
            }
            record.references = record
                .references
                .checked_add(1)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            return Ok(token);
        }
        admit_resource("host slots", self.records.len(), 1, limit)?;
        self.records
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("host slot ownership"))?;
        self.by_gva
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("host slot address index"))?;
        let token = HostSlotToken(self.next_token);
        let next_token = self
            .next_token
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let record_entry = match self.records.entry(token) {
            std::collections::hash_map::Entry::Vacant(entry) => entry,
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(HvfMemoryError::IpaOwnership);
            }
        };
        let address_entry = match self.by_gva.entry(gva) {
            std::collections::hash_map::Entry::Vacant(entry) => entry,
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(HvfMemoryError::IpaOwnership);
            }
        };
        let slot = HvfHostSlot::reserve_exact(gva..gva + PAGE_SIZE)?;
        record_entry.insert(HostSlotRecord {
            gva,
            slot: Some(slot),
            references: 1,
            active: false,
            quarantined: false,
        });
        address_entry.insert(token);
        self.next_token = next_token;
        Ok(token)
    }

    fn retain(&mut self, token: HostSlotToken) -> Result<(), HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        record.references = record
            .references
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release(&mut self, token: HostSlotToken) -> Result<bool, HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.references == 0 || record.active || record.quarantined {
            return Err(HvfMemoryError::IpaOwnership);
        }
        record.references -= 1;
        if record.references != 0 {
            return Ok(false);
        }
        let slot = record.slot.as_mut().ok_or(HvfMemoryError::IpaOwnership)?;
        if let Err(error) = slot.release() {
            record.quarantined = true;
            return Err(error.into());
        }
        let record = self
            .records
            .remove(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        self.by_gva.remove(&record.gva);
        Ok(true)
    }

    fn retry_quarantined_releases(&mut self) -> (usize, Option<HvfMemoryError>) {
        let count = self
            .records
            .values()
            .filter(|record| record.references == 0 && !record.active && record.quarantined)
            .count();
        let mut tokens = Vec::new();
        if tokens.try_reserve_exact(count).is_err() {
            return (
                0,
                Some(HvfMemoryError::MetadataAllocation("host slot retry")),
            );
        }
        tokens.extend(self.records.iter().filter_map(|(&token, record)| {
            (record.references == 0 && !record.active && record.quarantined).then_some(token)
        }));
        let mut released = 0;
        let mut first_error = None;
        for token in tokens {
            let Some(record) = self.records.get_mut(&token) else {
                first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                continue;
            };
            let result = record
                .slot
                .as_mut()
                .ok_or(HvfMemoryError::IpaOwnership)
                .and_then(|slot| slot.release().map_err(Into::into));
            match result {
                Ok(()) => {
                    let Some(record) = self.records.remove(&token) else {
                        first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                        continue;
                    };
                    self.by_gva.remove(&record.gva);
                    released += 1;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        (released, first_error)
    }
}

#[derive(Clone, Copy)]
struct PageEpoch {
    write: HvfWriteEpoch,
    publication: HvfPublicationEpoch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageTwoAuthority {
    ReadOnly,
    Writer,
    Executor,
}

impl StageTwoAuthority {
    fn for_permissions(permissions: HvfGuestPermissions) -> Self {
        if permissions.contains(HvfGuestPermissions::WRITE) {
            Self::Writer
        } else if permissions.contains(HvfGuestPermissions::EXECUTE) {
            Self::Executor
        } else {
            Self::ReadOnly
        }
    }
}

#[derive(Clone, Copy)]
struct BackingPageAuthority {
    stage_two_writers: usize,
    stage_two_executors: usize,
    host_writers: usize,
    hidden_writable: bool,
}

impl BackingPageAuthority {
    const fn new() -> Self {
        Self {
            stage_two_writers: 0,
            stage_two_executors: 0,
            host_writers: 0,
            hidden_writable: true,
        }
    }
}

struct BackingRecord {
    storage: Vec<Option<HvfHostBacking>>,
    sharing: HvfSharing,
    references: Vec<usize>,
    epochs: Vec<PageEpoch>,
    authorities: Vec<BackingPageAuthority>,
    mapping_quarantines: Vec<usize>,
    release_quarantined: Vec<bool>,
}

struct BackingRegistry {
    records: HashMap<HvfBackingIdentity, BackingRecord>,
    next_identity: u64,
    physical_pages: usize,
    max_physical_pages: usize,
}

fn fallible_filled_vec<T: Clone>(
    length: usize,
    value: T,
    resource: &'static str,
) -> Result<Vec<T>, HvfMemoryError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| HvfMemoryError::MetadataAllocation(resource))?;
    values.resize(length, value);
    Ok(values)
}

fn fallible_copy_vec<T: Clone>(
    source: &[T],
    resource: &'static str,
) -> Result<Vec<T>, HvfMemoryError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(source.len())
        .map_err(|_| HvfMemoryError::MetadataAllocation(resource))?;
    values.extend_from_slice(source);
    Ok(values)
}

fn empty_backing_storage(pages: usize) -> Result<Vec<Option<HvfHostBacking>>, HvfMemoryError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(pages)
        .map_err(|_| HvfMemoryError::MetadataAllocation("physical backing ownership"))?;
    storage.resize_with(pages, || None);
    Ok(storage)
}

impl BackingRegistry {
    fn new(max_physical_pages: usize) -> Self {
        Self {
            records: HashMap::new(),
            next_identity: 1,
            physical_pages: 0,
            max_physical_pages,
        }
    }

    fn insert_empty(
        &mut self,
        pages: usize,
        sharing: HvfSharing,
        references: usize,
        epochs: Vec<PageEpoch>,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        if pages == 0 || epochs.len() != pages {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let storage = empty_backing_storage(pages)?;
        let references = fallible_filled_vec(pages, references, "backing references")?;
        let authorities =
            fallible_filled_vec(pages, BackingPageAuthority::new(), "backing authorities")?;
        let mapping_quarantines = fallible_filled_vec(pages, 0, "backing mapping quarantines")?;
        let release_quarantined = fallible_filled_vec(pages, false, "backing release quarantines")?;
        self.records
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("backing ownership"))?;
        let identity = HvfBackingIdentity(self.next_identity);
        let next_identity = self
            .next_identity
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let record = BackingRecord {
            storage,
            sharing,
            references,
            epochs,
            authorities,
            mapping_quarantines,
            release_quarantined,
        };
        match self.records.entry(identity) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(record);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(HvfMemoryError::IpaOwnership);
            }
        }
        self.next_identity = next_identity;
        Ok(identity)
    }

    fn allocate(
        &mut self,
        pages: usize,
        sharing: HvfSharing,
        references: usize,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        self.admit_physical_pages(pages)?;
        let epochs = fallible_filled_vec(
            pages,
            PageEpoch {
                write: HvfWriteEpoch(0),
                publication: HvfPublicationEpoch(0),
            },
            "backing epochs",
        )?;
        let identity = self.insert_empty(pages, sharing, references, epochs)?;
        for index in 0..pages {
            match HvfHostBacking::allocate(PAGE_SIZE) {
                Ok(storage) => {
                    self.records
                        .get_mut(&identity)
                        .ok_or(HvfMemoryError::IpaOwnership)?
                        .storage[index] = Some(storage);
                    self.physical_pages = self
                        .physical_pages
                        .checked_add(1)
                        .ok_or(HvfMemoryError::IpaOwnership)?;
                }
                Err(trigger) => {
                    return match self.discard_unreferenced(identity) {
                        Ok(_) => Err(trigger.into()),
                        Err(cleanup) => Err(cleanup),
                    };
                }
            }
        }
        Ok(identity)
    }

    fn eager_copy_backing(
        &mut self,
        source: HvfBackingIdentity,
        references: usize,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        let source_record = self
            .records
            .get(&source)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let pages = source_record.storage.len();
        let epochs = fallible_copy_vec(&source_record.epochs, "private backing epochs")?;
        self.admit_physical_pages(pages)?;
        let identity = self.insert_empty(pages, HvfSharing::Private, references, epochs)?;
        for index in 0..pages {
            let copy = self
                .records
                .get(&source)
                .and_then(|record| record.storage[index].as_ref())
                .ok_or(HvfMemoryError::IpaOwnership)?
                .eager_copy();
            match copy {
                Ok(storage) => {
                    self.records
                        .get_mut(&identity)
                        .ok_or(HvfMemoryError::IpaOwnership)?
                        .storage[index] = Some(storage);
                    self.physical_pages = self
                        .physical_pages
                        .checked_add(1)
                        .ok_or(HvfMemoryError::IpaOwnership)?;
                }
                Err(trigger) => {
                    return match self.discard_unreferenced(identity) {
                        Ok(_) => Err(trigger.into()),
                        Err(cleanup) => Err(cleanup),
                    };
                }
            }
        }
        Ok(identity)
    }

    fn page_index(&self, page: BackingPage) -> Result<usize, HvfMemoryError> {
        if !page.offset.is_multiple_of(PAGE_SIZE) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let index = page.offset / PAGE_SIZE;
        let pages = self
            .records
            .get(&page.identity)
            .map(|record| record.storage.len())
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if index >= pages {
            return Err(HvfMemoryError::IpaOwnership);
        }
        Ok(index)
    }

    fn page(&self, identity: HvfBackingIdentity, index: usize) -> BackingPage {
        BackingPage {
            identity,
            offset: index * PAGE_SIZE,
        }
    }

    fn retain(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let references = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .references[index];
        *references = references
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release(&mut self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        let index = self.page_index(page)?;
        let releasable = {
            let record = self
                .records
                .get_mut(&page.identity)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if record.references[index] == 0 {
                return Err(HvfMemoryError::IpaOwnership);
            }
            record.references[index] -= 1;
            record.references[index] == 0
                && record.mapping_quarantines[index] == 0
                && record.authorities[index].stage_two_writers == 0
                && record.authorities[index].stage_two_executors == 0
                && record.authorities[index].host_writers == 0
        };
        if releasable {
            self.release_page_storage(page)
        } else {
            Ok(false)
        }
    }

    fn release_page_storage(&mut self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        let index = self.page_index(page)?;
        let record = self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let storage = record.storage[index]
            .as_mut()
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if let Err(error) = storage.release() {
            record.release_quarantined[index] = true;
            return Err(error.into());
        }
        record.storage[index] = None;
        record.release_quarantined[index] = false;
        self.physical_pages = self
            .physical_pages
            .checked_sub(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.storage.iter().all(Option::is_none) {
            self.records.remove(&page.identity);
        }
        Ok(true)
    }

    fn discard_unreferenced(
        &mut self,
        identity: HvfBackingIdentity,
    ) -> Result<bool, HvfMemoryError> {
        let pages = self
            .records
            .get(&identity)
            .map(|record| record.storage.len())
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let mut released_all = true;
        let mut first_error = None;
        for index in 0..pages {
            if !self.records.contains_key(&identity) {
                break;
            }
            let page = self.page(identity, index);
            let releasable = {
                let record = self
                    .records
                    .get(&identity)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                record.storage[index].is_some()
                    && record.references[index] == 0
                    && record.mapping_quarantines[index] == 0
                    && record.authorities[index].stage_two_writers == 0
                    && record.authorities[index].stage_two_executors == 0
                    && record.authorities[index].host_writers == 0
            };
            if !releasable {
                released_all = false;
            } else if let Err(error) = self.release_page_storage(page) {
                first_error.get_or_insert(error);
                released_all = false;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(released_all),
        }
    }

    fn page_storage(&self, page: BackingPage) -> Result<&HvfHostBacking, HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get(&page.identity)
            .and_then(|record| record.storage[index].as_ref())
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn page_range(&self, page: BackingPage) -> Result<Range<usize>, HvfMemoryError> {
        self.page_storage(page)?
            .slice(0, PAGE_SIZE)
            .map_err(Into::into)
    }

    fn page_has_reference(&self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get(&page.identity)
            .and_then(|record| record.references.get(index))
            .map(|references| *references != 0)
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn page_epoch(&self, page: BackingPage) -> Result<PageEpoch, HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get(&page.identity)
            .and_then(|record| record.epochs.get(index).copied())
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn write_epoch(
        &mut self,
        page: BackingPage,
        epoch: HvfWriteEpoch,
    ) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get_mut(&page.identity)
            .and_then(|record| record.epochs.get_mut(index))
            .ok_or(HvfMemoryError::IpaOwnership)?
            .write = epoch;
        Ok(())
    }

    fn publish(&mut self, page: BackingPage) -> Result<PageEpoch, HvfMemoryError> {
        let index = self.page_index(page)?;
        let epoch = self
            .records
            .get_mut(&page.identity)
            .and_then(|record| record.epochs.get_mut(index))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        epoch.publication = HvfPublicationEpoch(epoch.write.0);
        Ok(*epoch)
    }

    fn sharing(&self, identity: HvfBackingIdentity) -> Result<HvfSharing, HvfMemoryError> {
        self.records
            .get(&identity)
            .map(|record| record.sharing)
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn preflight_stage_two_replacement(
        &self,
        page: BackingPage,
        target: StageTwoAuthority,
        retiring: Option<StageTwoAuthority>,
    ) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let current = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        let conflict = match target {
            StageTwoAuthority::Writer => {
                let retiring_executors = usize::from(retiring == Some(StageTwoAuthority::Executor));
                current
                    .stage_two_executors
                    .checked_sub(retiring_executors)
                    .ok_or(HvfMemoryError::IpaOwnership)?
                    != 0
            }
            StageTwoAuthority::Executor => {
                let retiring_writers = usize::from(retiring == Some(StageTwoAuthority::Writer));
                current
                    .stage_two_writers
                    .checked_sub(retiring_writers)
                    .ok_or(HvfMemoryError::IpaOwnership)?
                    != 0
                    || current.host_writers != 0
            }
            StageTwoAuthority::ReadOnly => false,
        };
        if conflict {
            Err(HvfMemoryError::BackingWriteExecute {
                backing: page.identity,
                offset: page.offset,
            })
        } else {
            Ok(())
        }
    }

    fn prepare_executable_host(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let hidden_writable = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index]
            .hidden_writable;
        if hidden_writable {
            self.page_storage(page)?.protect(HvfHostPermissions::READ)?;
            self.records
                .get_mut(&page.identity)
                .ok_or(HvfMemoryError::IpaOwnership)?
                .authorities[index]
                .hidden_writable = false;
        }
        Ok(())
    }

    fn authorize_stage_two(
        &mut self,
        page: BackingPage,
        permissions: HvfGuestPermissions,
    ) -> Result<StageTwoAuthority, HvfMemoryError> {
        let index = self.page_index(page)?;
        let authority = StageTwoAuthority::for_permissions(permissions);
        let current = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        let conflict = match authority {
            StageTwoAuthority::Writer => current.stage_two_executors != 0,
            StageTwoAuthority::Executor => {
                current.stage_two_writers != 0 || current.host_writers != 0
            }
            StageTwoAuthority::ReadOnly => false,
        };
        if conflict {
            return Err(HvfMemoryError::BackingWriteExecute {
                backing: page.identity,
                offset: page.offset,
            });
        }
        if authority == StageTwoAuthority::Executor && current.hidden_writable {
            self.page_storage(page)?.protect(HvfHostPermissions::READ)?;
            let current = &mut self
                .records
                .get_mut(&page.identity)
                .ok_or(HvfMemoryError::IpaOwnership)?
                .authorities[index];
            current.hidden_writable = false;
        }
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        match authority {
            StageTwoAuthority::Writer => {
                current.stage_two_writers = current
                    .stage_two_writers
                    .checked_add(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::Executor => {
                current.stage_two_executors = current
                    .stage_two_executors
                    .checked_add(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::ReadOnly => {}
        }
        Ok(authority)
    }

    fn release_stage_two(
        &mut self,
        page: BackingPage,
        authority: StageTwoAuthority,
    ) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        match authority {
            StageTwoAuthority::Writer => {
                current.stage_two_writers = current
                    .stage_two_writers
                    .checked_sub(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::Executor => {
                current.stage_two_executors = current
                    .stage_two_executors
                    .checked_sub(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::ReadOnly => {}
        }
        Ok(())
    }

    fn reserve_host_alias(&mut self, page: BackingPage, write: bool) -> Result<(), HvfMemoryError> {
        if !write {
            return Ok(());
        }
        let index = self.page_index(page)?;
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        if current.stage_two_executors != 0 {
            return Err(HvfMemoryError::BackingWriteExecute {
                backing: page.identity,
                offset: page.offset,
            });
        }
        current.host_writers = current
            .host_writers
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release_host_alias(&mut self, page: BackingPage, write: bool) -> Result<(), HvfMemoryError> {
        if !write {
            return Ok(());
        }
        let index = self.page_index(page)?;
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        current.host_writers = current
            .host_writers
            .checked_sub(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn quarantine_mapping(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let count = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .mapping_quarantines[index];
        *count = count.checked_add(1).ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn resolve_mapping_quarantine(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let count = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .mapping_quarantines[index];
        *count = count.checked_sub(1).ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn retry_quarantined_releases(&mut self) -> (usize, Option<HvfMemoryError>) {
        let count = self
            .records
            .values()
            .map(|record| {
                record
                    .release_quarantined
                    .iter()
                    .filter(|release| **release)
                    .count()
            })
            .sum();
        let mut pages = Vec::new();
        if pages.try_reserve_exact(count).is_err() {
            return (
                0,
                Some(HvfMemoryError::MetadataAllocation("backing retry plan")),
            );
        }
        pages.extend(self.records.iter().flat_map(|(&identity, record)| {
            record
                .release_quarantined
                .iter()
                .enumerate()
                .filter(|(_, release)| **release)
                .map(move |(index, release)| {
                    (
                        BackingPage {
                            identity,
                            offset: index * PAGE_SIZE,
                        },
                        *release,
                    )
                })
        }));
        let mut released = 0;
        let mut first_error = None;
        for (page, release_storage) in pages {
            if release_storage {
                match self.release_page_storage(page) {
                    Ok(true) => released += 1,
                    Ok(false) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        (released, first_error)
    }

    fn release_quarantine_count(&self) -> usize {
        self.records
            .values()
            .map(|record| {
                record
                    .release_quarantined
                    .iter()
                    .filter(|release| **release)
                    .count()
            })
            .sum()
    }

    fn admit_physical_pages(&self, pages: usize) -> Result<(), HvfMemoryError> {
        let requested =
            self.physical_pages
                .checked_add(pages)
                .ok_or(HvfMemoryError::ResourceLimit {
                    resource: "physical backing pages",
                    requested: usize::MAX,
                    limit: self.max_physical_pages,
                })?;
        if requested > self.max_physical_pages {
            return Err(HvfMemoryError::ResourceLimit {
                resource: "physical backing pages",
                requested,
                limit: self.max_physical_pages,
            });
        }
        Ok(())
    }

    fn physical_pages(&self) -> usize {
        self.physical_pages
    }
}

struct DataMapping {
    backing: BackingPage,
    ipa: IpaToken,
    authority: StageTwoAuthority,
    mapping: Option<HvfMapping<'static>>,
    quarantine_reservation: DataQuarantineReservation,
}

struct PageState {
    permissions: HvfGuestPermissions,
    sharing: HvfSharing,
    backing: Option<BackingPage>,
    mapping: Option<DataMapping>,
    slot: HostSlotToken,
}

struct ClaimRecord {
    id: u64,
    version: u64,
    range: Range<usize>,
    pages: HashMap<usize, PageState>,
}

struct AddressSpaceState {
    live: bool,
    root: TableToken,
    root_generation: HvfRootGeneration,
    executable_generation: HvfExecutableGeneration,
    claims: HashMap<usize, ClaimRecord>,
}

struct AddressSpaceCell {
    id: HvfAddressSpaceId,
    asid: HvfAsid,
    regime: HvfTranslationRegime,
    state: Mutex<AddressSpaceState>,
}

struct RetiredData {
    mapping: DataMapping,
    release_backing_reference: bool,
}

struct RetiredGeneration {
    address_space: HvfAddressSpaceId,
    generation: HvfRootGeneration,
    root: TableToken,
    data: Vec<RetiredData>,
    slots: Vec<HostSlotToken>,
    backings: Vec<BackingPage>,
    charged_pages: usize,
    charged_bytes: usize,
    data_pages: usize,
    slot_pages: usize,
    backing_pages: usize,
    table_pages: usize,
}

struct RetirementReservation {
    id: u64,
    charged_pages: usize,
    charged_bytes: usize,
    data_pages: usize,
    slot_pages: usize,
    backing_pages: usize,
    table_pages: usize,
}

#[derive(Clone)]
struct AliasLeasePage {
    slot: HostSlotToken,
    backing: BackingPage,
    range: Range<usize>,
    write: bool,
}

struct AliasLease {
    range: Range<usize>,
    write_epoch: Option<HvfWriteEpoch>,
    pages: Vec<AliasLeasePage>,
}

struct AliasQuarantine {
    slot: HostSlotToken,
    backing: BackingPage,
    range: Range<usize>,
    restore_pending: bool,
    host_writer: bool,
}

thread_local! {
    static HVF_ALIAS_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

struct AliasThreadGuard;

impl AliasThreadGuard {
    fn enter(range: Range<usize>) -> Result<Self, HvfMemoryError> {
        HVF_ALIAS_ACTIVE.with(|active| {
            if active.replace(true) {
                Err(HvfMemoryError::AliasReentrant(range))
            } else {
                Ok(Self)
            }
        })
    }
}

impl Drop for AliasThreadGuard {
    fn drop(&mut self) {
        HVF_ALIAS_ACTIVE.with(|active| active.set(false));
    }
}

struct DataQuarantineReservation {
    _private: (),
}

struct DataQuarantine {
    ipa: Option<IpaToken>,
    backing: BackingPage,
    authority: Option<StageTwoAuthority>,
    sdk_token: Option<u64>,
    mapping_quarantine: bool,
    release_backing_reference: bool,
    retryable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    BeforeRootPublish,
    AuthorityTransition,
    AliasRestore,
    DataUnmap,
    TableUnmap,
}

struct Acknowledgements {
    retirements: HashMap<u64, RetiredGeneration>,
    next_ticket: u64,
    retired_pages: usize,
    retired_bytes: usize,
    alias_quarantine: Vec<AliasQuarantine>,
    alias_quarantine_reservations: usize,
    data_quarantine: Vec<DataQuarantine>,
    data_quarantine_reservations: usize,
}

impl Acknowledgements {
    fn new() -> Self {
        Self {
            retirements: HashMap::new(),
            next_ticket: 1,
            retired_pages: 0,
            retired_bytes: 0,
            alias_quarantine: Vec::new(),
            alias_quarantine_reservations: 0,
            data_quarantine: Vec::new(),
            data_quarantine_reservations: 0,
        }
    }

    fn reserve_alias_quarantine(&mut self, pages: usize) -> Result<(), HvfMemoryError> {
        let required = self
            .alias_quarantine
            .len()
            .checked_add(self.alias_quarantine_reservations)
            .and_then(|reserved| reserved.checked_add(pages))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if required > self.alias_quarantine.capacity() {
            self.alias_quarantine
                .try_reserve(required - self.alias_quarantine.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("alias quarantine"))?;
        }
        self.alias_quarantine_reservations = self
            .alias_quarantine_reservations
            .checked_add(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release_alias_quarantine_reservation(&mut self, pages: usize) -> Result<(), HvfMemoryError> {
        self.alias_quarantine_reservations = self
            .alias_quarantine_reservations
            .checked_sub(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn reserve_data_quarantine(&mut self) -> Result<DataQuarantineReservation, HvfMemoryError> {
        let required = self
            .data_quarantine
            .len()
            .checked_add(self.data_quarantine_reservations)
            .and_then(|reserved| reserved.checked_add(1))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if required > self.data_quarantine.capacity() {
            self.data_quarantine
                .try_reserve(required - self.data_quarantine.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("data quarantine"))?;
        }
        self.data_quarantine_reservations = self
            .data_quarantine_reservations
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(DataQuarantineReservation { _private: () })
    }

    fn release_data_quarantine_reservation(&mut self, _reservation: DataQuarantineReservation) {
        // The non-Copy capability is created only after capacity and the count are reserved.
        self.data_quarantine_reservations = self.data_quarantine_reservations.saturating_sub(1);
    }

    fn commit_data_quarantine(
        &mut self,
        reservation: DataQuarantineReservation,
        quarantine: DataQuarantine,
    ) -> usize {
        let index = self.data_quarantine.len();
        self.release_data_quarantine_reservation(reservation);
        // Every live capability owns one unit of spare capacity, including across retry replans.
        self.data_quarantine.push(quarantine);
        index
    }
}

struct Arenas {
    ipa: IpaAllocator,
    tables: TableArena,
    slots: HostSlotArena,
    next_address_space: u64,
    asids: AsidAllocator,
    next_claim: u64,
    next_root_generation: u64,
    next_executable_generation: u64,
    next_write_epoch: u64,
    address_spaces: usize,
    claimed_pages: usize,
    live_data_pages: usize,
    failure: Option<FailurePoint>,
}

impl Arenas {
    fn next_root_generation(&mut self) -> Result<HvfRootGeneration, HvfMemoryError> {
        take_counter(&mut self.next_root_generation).map(HvfRootGeneration)
    }

    fn next_executable_generation(&mut self) -> Result<HvfExecutableGeneration, HvfMemoryError> {
        take_counter(&mut self.next_executable_generation).map(HvfExecutableGeneration)
    }

    fn next_write_epoch(&mut self) -> Result<HvfWriteEpoch, HvfMemoryError> {
        take_counter(&mut self.next_write_epoch).map(HvfWriteEpoch)
    }

    fn take_failure(&mut self, point: FailurePoint) -> bool {
        if self.failure == Some(point) {
            self.failure = None;
            true
        } else {
            false
        }
    }
}

pub struct HvfMemory {
    vm: &'static HvfVm,
    manager: u64,
    limits: HvfMemoryLimits,
    regime: HvfTranslationRegime,
    _monitor_mapping: HvfMapping<'static>,
    spaces: Mutex<HashMap<HvfAddressSpaceId, Arc<AddressSpaceCell>>>,
    arenas: Mutex<Arenas>,
    backings: Mutex<BackingRegistry>,
    acknowledgements: Mutex<Acknowledgements>,
}

impl fmt::Debug for HvfMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfMemory")
            .field("manager", &self.manager)
            .field("limits", &self.limits)
            .field("regime", &self.regime)
            .field("vm_poisoned", &self.vm.is_poisoned())
            .finish_non_exhaustive()
    }
}

pub struct HvfAddressSpace {
    memory: &'static HvfMemory,
    cell: Arc<AddressSpaceCell>,
}

impl fmt::Debug for HvfAddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfAddressSpace")
            .field("id", &self.cell.id)
            .field("asid", &self.cell.asid)
            .field("regime", &self.cell.regime)
            .finish_non_exhaustive()
    }
}

impl Clone for HvfAddressSpace {
    fn clone(&self) -> Self {
        Self {
            memory: self.memory,
            cell: Arc::clone(&self.cell),
        }
    }
}

impl HvfMemory {
    fn create() -> Result<Self, HvfMemoryError> {
        let vm = process_hvf_vm()?;
        vm.with_operation(|operation| {
            let limits = HvfMemoryLimits::default();
            let regime = HvfTranslationRegime::for_ipa_bits(vm.report().configured_ipa_bits)?;
            let ipa_limit = 1u64 << vm.report().configured_ipa_bits;
            let compact_ipa_pages = limits
                .max_live_data_pages
                .checked_add(limits.max_table_pages)
                .ok_or(HvfMemoryError::IpaExhausted(usize::MAX))?;
            let max_physical_pages = limits
                .max_live_data_pages
                .checked_add(limits.max_retired_pages)
                .ok_or(HvfMemoryError::ResourceLimit {
                    resource: "physical backing pages",
                    requested: usize::MAX,
                    limit: usize::MAX,
                })?;
            let arenas = Arenas {
                ipa: IpaAllocator::new(PAGE_SIZE as u64..ipa_limit, compact_ipa_pages)?,
                tables: TableArena::new(limits.max_table_pages)?,
                slots: HostSlotArena::new(),
                next_address_space: 1,
                asids: AsidAllocator::new(),
                next_claim: 1,
                next_root_generation: 1,
                next_executable_generation: 1,
                next_write_epoch: 1,
                address_spaces: 0,
                claimed_pages: 0,
                live_data_pages: 0,
                failure: None,
            };
            let monitor = vm.monitor().bytes();
            if monitor.len() != PAGE_SIZE {
                return Err(HvfMemoryError::Witness(
                    "the linked EL1 monitor is not exactly one page",
                ));
            }
            vm.publish_executable_bytes(monitor)?;
            let start = monitor.as_ptr() as usize;
            let monitor_mapping = unsafe {
                vm.map_host_range(
                    start..start + PAGE_SIZE,
                    0,
                    HvfMapPermissions::READ | HvfMapPermissions::EXECUTE,
                )
            }?;
            if let Err(error) = operation.require_live() {
                return match monitor_mapping.unmap() {
                    Ok(()) => Err(error.into()),
                    Err(cleanup) => Err(cleanup.into()),
                };
            }
            Ok(Self {
                vm,
                manager: vm as *const HvfVm as usize as u64,
                limits,
                regime,
                _monitor_mapping: monitor_mapping,
                spaces: Mutex::new(HashMap::new()),
                arenas: Mutex::new(arenas),
                backings: Mutex::new(BackingRegistry::new(max_physical_pages)),
                acknowledgements: Mutex::new(Acknowledgements::new()),
            })
        })
    }

    pub const fn limits(&self) -> HvfMemoryLimits {
        self.limits
    }

    pub const fn regime(&self) -> HvfTranslationRegime {
        self.regime
    }

    pub fn create_address_space(&'static self) -> Result<HvfAddressSpace, HvfMemoryError> {
        self.vm.with_operation(|operation| {
            let mut spaces = self
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            admit_resource(
                "address spaces",
                arenas.address_spaces,
                1,
                self.limits.max_address_spaces,
            )?;
            spaces
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("address-space ownership"))?;
            let id = HvfAddressSpaceId(take_counter(&mut arenas.next_address_space)?);
            let root_generation = arenas.next_root_generation()?;
            let asid = arenas.asids.allocate()?;
            let cell = Arc::new(AddressSpaceCell {
                id,
                asid,
                regime: self.regime,
                state: Mutex::new(AddressSpaceState {
                    live: false,
                    root: TableToken(0),
                    root_generation,
                    executable_generation: HvfExecutableGeneration(0),
                    claims: HashMap::new(),
                }),
            });
            let root = match create_monitor_root(self.vm, &mut arenas, self.limits.max_table_pages)
            {
                Ok(root) => root,
                Err(error) => {
                    if let Err(cleanup) = arenas.asids.release(asid) {
                        self.vm.poison();
                        return Err(cleanup);
                    }
                    return Err(error);
                }
            };
            if let Err(error) = operation.require_live() {
                let root_cleanup = cleanup_candidate_root(self.vm, &mut arenas, root);
                let asid_cleanup = arenas.asids.release(asid);
                root_cleanup?;
                asid_cleanup?;
                return Err(error.into());
            }
            {
                let mut state = cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.root = root;
                state.live = true;
            }
            if let Some(previous) = spaces.insert(id, cell.clone()) {
                if spaces.insert(id, previous).is_none() {
                    self.vm.poison();
                }
                let root_cleanup = cleanup_candidate_root(self.vm, &mut arenas, root);
                let asid_cleanup = arenas.asids.release(asid);
                cell.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live = false;
                self.vm.poison();
                if let Err(cleanup) = root_cleanup.and(asid_cleanup) {
                    return Err(cleanup);
                }
                return Err(HvfMemoryError::IpaOwnership);
            }
            arenas.address_spaces += 1;
            Ok(HvfAddressSpace { memory: self, cell })
        })
    }

    fn validate_claim<'a>(
        &self,
        address_space: &HvfAddressSpace,
        state: &'a AddressSpaceState,
        claim: &HvfClaim,
    ) -> Result<&'a ClaimRecord, HvfMemoryError> {
        if !core::ptr::eq(self, address_space.memory)
            || claim.manager != self.manager
            || claim.address_space != address_space.cell.id
        {
            return Err(HvfMemoryError::WrongMemoryManager);
        }
        if !state.live {
            return Err(HvfMemoryError::AddressSpaceDestroyed(address_space.cell.id));
        }
        state
            .claims
            .get(&claim.range.start)
            .filter(|record| {
                record.id == claim.id
                    && record.version == claim.version
                    && record.range == claim.range
            })
            .ok_or(HvfMemoryError::ClaimStale)
    }

    fn reserve_retirement(
        &self,
        acknowledgements: &mut Acknowledgements,
        data_pages: usize,
        slot_pages: usize,
        backing_pages: usize,
        table_pages: usize,
    ) -> Result<RetirementReservation, HvfMemoryError> {
        let charged_pages = table_pages
            .checked_add(data_pages)
            .and_then(|value| value.checked_add(slot_pages))
            .and_then(|value| value.checked_add(backing_pages))
            .ok_or(HvfMemoryError::ResourceLimit {
                resource: "retired pages",
                requested: usize::MAX,
                limit: self.limits.max_retired_pages,
            })?;
        let charged_bytes =
            charged_pages
                .checked_mul(PAGE_SIZE)
                .ok_or(HvfMemoryError::ResourceLimit {
                    resource: "retired bytes",
                    requested: usize::MAX,
                    limit: self.limits.max_retired_bytes,
                })?;
        admit_resource(
            "retired generations",
            acknowledgements.retirements.len(),
            1,
            self.limits.max_retired_generations,
        )?;
        let requested_pages = admit_resource(
            "retired pages",
            acknowledgements.retired_pages,
            charged_pages,
            self.limits.max_retired_pages,
        )?;
        let requested_bytes = admit_resource(
            "retired bytes",
            acknowledgements.retired_bytes,
            charged_bytes,
            self.limits.max_retired_bytes,
        )?;
        acknowledgements
            .retirements
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("retirement ownership"))?;
        let id = take_counter(&mut acknowledgements.next_ticket)?;
        acknowledgements.retired_pages = requested_pages;
        acknowledgements.retired_bytes = requested_bytes;
        Ok(RetirementReservation {
            id,
            charged_pages,
            charged_bytes,
            data_pages,
            slot_pages,
            backing_pages,
            table_pages,
        })
    }

    fn cancel_retirement_reservation(
        &self,
        acknowledgements: &mut Acknowledgements,
        reservation: RetirementReservation,
    ) -> Result<(), HvfMemoryError> {
        acknowledgements.retired_pages = acknowledgements
            .retired_pages
            .checked_sub(reservation.charged_pages)
            .ok_or(HvfMemoryError::RetirementStale)?;
        acknowledgements.retired_bytes = acknowledgements
            .retired_bytes
            .checked_sub(reservation.charged_bytes)
            .ok_or(HvfMemoryError::RetirementStale)?;
        Ok(())
    }

    fn commit_retirement(
        &self,
        acknowledgements: &mut Acknowledgements,
        reservation: RetirementReservation,
        address_space: HvfAddressSpaceId,
        generation: HvfRootGeneration,
        root: TableToken,
        data: Vec<RetiredData>,
        slots: Vec<HostSlotToken>,
        backings: Vec<BackingPage>,
    ) -> HvfRetirementTicket {
        let mut id = reservation.id;
        let retired = RetiredGeneration {
            address_space,
            generation,
            root,
            data,
            slots,
            backings,
            charged_pages: reservation.charged_pages,
            charged_bytes: reservation.charged_bytes,
            data_pages: reservation.data_pages,
            slot_pages: reservation.slot_pages,
            backing_pages: reservation.backing_pages,
            table_pages: reservation.table_pages,
        };
        loop {
            match acknowledgements.retirements.entry(id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(retired);
                    break;
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    id = if id == u64::MAX { 1 } else { id + 1 };
                }
            }
        }
        HvfRetirementTicket {
            manager: self.manager,
            address_space,
            id,
            generation,
        }
    }

    fn inject_failure(&self, point: FailurePoint) {
        let mut arenas = self
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        arenas.failure = Some(point);
    }

    fn usage_locked(
        &self,
        arenas: &Arenas,
        backings: &BackingRegistry,
        acknowledgements: &Acknowledgements,
    ) -> HvfMemoryUsage {
        HvfMemoryUsage {
            address_spaces: arenas.address_spaces,
            claimed_pages: arenas.claimed_pages,
            live_data_pages: arenas.live_data_pages,
            table_pages: arenas.tables.records.len(),
            host_slots: arenas.slots.records.len(),
            backing_objects: backings.records.len(),
            physical_backing_pages: backings.physical_pages(),
            physical_backing_bytes: backings.physical_pages().saturating_mul(PAGE_SIZE),
            ipa_owned_pages: arenas.ipa.owned_pages(),
            ipa_capacity_pages: arenas.ipa.capacity_pages(),
            asids_owned: arenas.asids.owned(),
            active_alias_pages: arenas
                .slots
                .records
                .values()
                .filter(|record| record.active)
                .count(),
            alias_quarantine_reservations: acknowledgements.alias_quarantine_reservations,
            data_quarantine_reservations: acknowledgements.data_quarantine_reservations,
            retired_generations: acknowledgements.retirements.len(),
            retired_pages: acknowledgements.retired_pages,
            retired_bytes: acknowledgements.retired_bytes,
            quarantined_resources: arenas.tables.quarantined.len()
                + arenas.tables.abandoned_roots.len()
                + acknowledgements.alias_quarantine.len()
                + acknowledgements.data_quarantine.len()
                + arenas
                    .slots
                    .records
                    .iter()
                    .filter(|(token, record)| {
                        record.quarantined
                            && !acknowledgements
                                .alias_quarantine
                                .iter()
                                .any(|quarantine| quarantine.slot == **token)
                    })
                    .count()
                + backings.release_quarantine_count(),
        }
    }

    pub fn usage(&self) -> HvfMemoryUsage {
        let arenas = self
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let backings = self
            .backings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let acknowledgements = self
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.usage_locked(&arenas, &backings, &acknowledgements)
    }

    pub fn retry_quarantined_aliases(&self) -> Result<usize, HvfMemoryError> {
        self.vm.with_cleanup_operation(|_operation| {
            let mut arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            retry_aliases_locked(&mut arenas, &mut backings, &mut acknowledgements)
        })
    }

    pub fn retry_quarantined_resources(&self) -> Result<HvfQuarantineRetryReport, HvfMemoryError> {
        let sdk_tokens = self.vm.with_cleanup_operation(|_operation| {
            let arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let acknowledgements = self
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = arenas
                .tables
                .quarantined
                .len()
                .checked_add(acknowledgements.data_quarantine.len())
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let mut tokens = Vec::new();
            tokens
                .try_reserve_exact(count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("SDK retry tokens"))?;
            tokens.extend(
                arenas
                    .tables
                    .quarantined
                    .iter()
                    .filter_map(|quarantine| quarantine.sdk_token),
            );
            tokens.extend(
                acknowledgements
                    .data_quarantine
                    .iter()
                    .filter_map(|quarantine| quarantine.sdk_token),
            );
            tokens.sort_unstable();
            tokens.dedup();
            Ok::<_, HvfMemoryError>(tokens)
        })?;
        let mut sdk_mapping_fragments_released = 0usize;
        for token in sdk_tokens {
            sdk_mapping_fragments_released = sdk_mapping_fragments_released
                .checked_add(self.vm.retry_quarantined_mapping(token)?)
                .ok_or(HvfMemoryError::IpaOwnership)?;
        }
        let mut report = self.vm.with_cleanup_operation(|_operation| {
            let mut arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let aliases_restored =
                retry_aliases_locked(&mut arenas, &mut backings, &mut acknowledgements)?;
            let mut data_pages_released = 0;
            let mut table_pages_released = 0usize;
            let mut first_error = None;
            arenas.tables.abandoned_roots.sort_unstable();
            let mut root_index = 0;
            while root_index < arenas.tables.abandoned_roots.len() {
                let root = arenas.tables.abandoned_roots[root_index];
                match arenas.tables.release(root) {
                    Ok(records) => {
                        arenas.tables.abandoned_roots.remove(root_index);
                        let released = records.len();
                        if let Err(error) = cleanup_table_records(self.vm, &mut arenas, records) {
                            first_error.get_or_insert(error);
                        } else {
                            table_pages_released = table_pages_released
                                .checked_add(released)
                                .ok_or(HvfMemoryError::TableOwnership)?;
                        }
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                        root_index += 1;
                    }
                }
            }
            let retained_data_capacity = acknowledgements
                .data_quarantine
                .len()
                .checked_add(acknowledgements.data_quarantine_reservations)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let mut retained_data = Vec::new();
            retained_data
                .try_reserve(retained_data_capacity)
                .map_err(|_| HvfMemoryError::MetadataAllocation("data quarantine retry"))?;
            for mut quarantine in core::mem::take(&mut acknowledgements.data_quarantine) {
                if !quarantine.retryable {
                    retained_data.push(quarantine);
                    continue;
                }
                if let Some(token) = quarantine.sdk_token {
                    if self.vm.mapping_token_has_residual(token) {
                        retained_data.push(quarantine);
                        continue;
                    }
                    quarantine.sdk_token = None;
                    if quarantine.mapping_quarantine {
                        if let Err(error) = backings.resolve_mapping_quarantine(quarantine.backing)
                        {
                            first_error.get_or_insert(error);
                            retained_data.push(quarantine);
                            continue;
                        }
                        quarantine.mapping_quarantine = false;
                    }
                } else if quarantine.mapping_quarantine {
                    retained_data.push(quarantine);
                    continue;
                }
                if let Some(ipa) = quarantine.ipa.take() {
                    if let Err(error) = arenas.ipa.release(ipa) {
                        quarantine.ipa = Some(ipa);
                        first_error.get_or_insert(error);
                        retained_data.push(quarantine);
                        continue;
                    }
                    data_pages_released += 1;
                }
                if let Some(authority) = quarantine.authority.take()
                    && let Err(error) = backings.release_stage_two(quarantine.backing, authority)
                {
                    quarantine.authority = Some(authority);
                    first_error.get_or_insert(error);
                }
                if quarantine.release_backing_reference {
                    match backings.release(quarantine.backing) {
                        Ok(_) => quarantine.release_backing_reference = false,
                        Err(error) => {
                            if matches!(backings.page_has_reference(quarantine.backing), Ok(false))
                            {
                                quarantine.release_backing_reference = false;
                            }
                            first_error.get_or_insert(error);
                        }
                    }
                }
                if quarantine.ipa.is_some()
                    || quarantine.authority.is_some()
                    || quarantine.sdk_token.is_some()
                    || quarantine.mapping_quarantine
                    || quarantine.release_backing_reference
                {
                    retained_data.push(quarantine);
                }
            }
            acknowledgements.data_quarantine = retained_data;

            let mut retained_tables = Vec::new();
            retained_tables
                .try_reserve(arenas.tables.quarantined.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine retry"))?;
            for mut quarantine in core::mem::take(&mut arenas.tables.quarantined) {
                if !quarantine.retryable {
                    retained_tables.push(quarantine);
                    continue;
                }
                if let Some(token) = quarantine.sdk_token {
                    if self.vm.mapping_token_has_residual(token) {
                        retained_tables.push(quarantine);
                        continue;
                    }
                    quarantine.sdk_token = None;
                }
                if let Some(ipa) = quarantine.ipa.take() {
                    if let Err(error) = arenas.ipa.release(ipa) {
                        quarantine.ipa = Some(ipa);
                        first_error.get_or_insert(error);
                        retained_tables.push(quarantine);
                        continue;
                    }
                    table_pages_released += 1;
                }
                drop(quarantine.bytes);
            }
            arenas.tables.quarantined = retained_tables;
            let (host_slots_released, slot_error) = arenas.slots.retry_quarantined_releases();
            if let Some(error) = slot_error {
                first_error.get_or_insert(error);
            }
            let (backings_released, backing_error) = backings.retry_quarantined_releases();
            if let Some(error) = backing_error {
                first_error.get_or_insert(error);
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            let sdk_residuals = self.vm.residual_report()?;
            let remaining = self.usage_locked(&arenas, &backings, &acknowledgements);
            Ok(HvfQuarantineRetryReport {
                sdk_mapping_fragments_released,
                host_resources_released: 0,
                aliases_restored,
                data_pages_released,
                table_pages_released,
                host_slots_released,
                backings_released,
                sdk_residuals,
                remaining,
            })
        })?;
        let host_resources_released = hvf_host_retry_residual()?;
        report.host_resources_released = host_resources_released;
        Ok(report)
    }
}

impl HvfAddressSpace {
    pub fn id(&self) -> HvfAddressSpaceId {
        self.cell.id
    }

    pub fn asid(&self) -> HvfAsid {
        self.cell.asid
    }

    pub fn regime(&self) -> HvfTranslationRegime {
        self.cell.regime
    }

    pub fn claim(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        sharing: HvfSharing,
    ) -> Result<HvfMutation, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = self.cell.regime.validate_range(&range)?;
            permissions.validate()?;
            if permissions.contains(HvfGuestPermissions::EXECUTE) {
                return Err(HvfMemoryError::InitialExecute(range.clone()));
            }
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            ensure_claim_gap(&state.claims, &range)?;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let usage = self
                .memory
                .usage_locked(&arenas, &backings, &acknowledgements);
            let next_claimed_pages = admit_resource(
                "claimed pages",
                usage.claimed_pages,
                page_count,
                self.memory.limits.max_claimed_pages,
            )?;
            let next_live_data_pages = admit_resource(
                "live data pages",
                usage.live_data_pages,
                usize::from(permissions != HvfGuestPermissions::NONE) * page_count,
                self.memory.limits.max_live_data_pages,
            )?;
            state
                .claims
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim ownership"))?;
            let mut pages = HashMap::new();
            pages
                .try_reserve(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim pages"))?;
            let mut claimed_slots = Vec::new();
            claimed_slots
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim slots"))?;
            let mut updates = Vec::new();
            updates
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim stage-one updates"))?;
            let claim_id = take_counter(&mut arenas.next_claim)?;
            let backing = if permissions == HvfGuestPermissions::NONE {
                None
            } else {
                Some(backings.allocate(page_count, sharing, 0)?)
            };
            let preparation = (|| {
                for index in 0..page_count {
                    let gva = range.start + index * PAGE_SIZE;
                    let slot = arenas.slots.claim(gva, self.memory.limits.max_host_slots)?;
                    claimed_slots.push(slot);
                    let backing_page = backing.map(|identity| BackingPage {
                        identity,
                        offset: index * PAGE_SIZE,
                    });
                    let mapping = match backing_page {
                        Some(backing_page) => {
                            backings.retain(backing_page)?;
                            let mapping = map_data_page(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                backing_page,
                                permissions,
                                true,
                            )?;
                            updates
                                .push((gva, permissions.stage_one_descriptor(mapping.ipa.start)));
                            Some(mapping)
                        }
                        None => {
                            updates.push((gva, 0));
                            None
                        }
                    };
                    pages.insert(
                        gva,
                        PageState {
                            permissions,
                            sharing,
                            backing: backing_page,
                            mapping,
                            slot,
                        },
                    );
                }
                Ok::<(), HvfMemoryError>(())
            })();
            if let Err(error) = preparation {
                cleanup_claim_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    pages,
                    claimed_slots,
                    backing,
                )?;
                return Err(error);
            }
            let candidate = match build_candidate_root(
                self.memory.vm,
                &mut arenas,
                state.root,
                &updates,
                self.memory.limits.max_table_pages,
            ) {
                Ok(root) => root,
                Err(error) => {
                    cleanup_claim_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        pages,
                        claimed_slots,
                        backing,
                    )?;
                    return Err(error);
                }
            };
            if arenas.take_failure(FailurePoint::BeforeRootPublish) {
                let candidate_cleanup =
                    cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                let preparation_cleanup = cleanup_claim_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    pages,
                    claimed_slots,
                    backing,
                );
                candidate_cleanup?;
                preparation_cleanup?;
                return Err(HvfMemoryError::InjectedFailure("before root publication"));
            }
            let metadata = (|| {
                let generation = arenas.next_root_generation()?;
                let old_root = state.root;
                let old_table_pages = arenas.tables.release_count(old_root)?;
                operation.require_live()?;
                Ok::<_, HvfMemoryError>((generation, old_root, old_table_pages))
            })();
            let (generation, old_root, old_table_pages) = match metadata {
                Ok(metadata) => metadata,
                Err(error) => {
                    let candidate_cleanup =
                        cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                    let preparation_cleanup = cleanup_claim_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        pages,
                        claimed_slots,
                        backing,
                    );
                    candidate_cleanup?;
                    preparation_cleanup?;
                    return Err(error);
                }
            };
            let reservation = match self.memory.reserve_retirement(
                &mut acknowledgements,
                0,
                0,
                0,
                old_table_pages,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    let candidate_cleanup =
                        cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                    let preparation_cleanup = cleanup_claim_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        pages,
                        claimed_slots,
                        backing,
                    );
                    candidate_cleanup?;
                    preparation_cleanup?;
                    return Err(error);
                }
            };
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                generation,
                old_root,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            state.root = candidate;
            state.root_generation = generation;
            let claim = ClaimRecord {
                id: claim_id,
                version: 1,
                range: range.clone(),
                pages,
            };
            state.claims.insert(range.start, claim);
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            Ok(HvfMutation {
                claim: HvfClaim {
                    manager: self.memory.manager,
                    address_space: self.cell.id,
                    id: claim_id,
                    version: 1,
                    range,
                },
                root_generation: generation,
                executable_generation: state.executable_generation,
                retirement,
            })
        })
    }

    pub fn publish_executable(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
    ) -> Result<HvfPublicationTicket, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = self.memory.validate_claim(self, &state, claim)?;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure_aliases_inactive(record, &range, &arenas.slots)?;
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut published_pages = Vec::new();
            published_pages
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("publication ticket"))?;
            for gva in page_addresses(&range) {
                let page = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                let backing = page
                    .backing
                    .ok_or_else(|| HvfMemoryError::PublicationRequired(range.clone()))?;
                let bytes = backings.page_range(backing)?;
                self.memory.vm.publish_executable_bytes(unsafe {
                    core::slice::from_raw_parts(bytes.start as *const u8, PAGE_SIZE)
                })?;
                let epoch = backings.publish(backing)?;
                published_pages.push(PublishedPage {
                    backing,
                    write_epoch: epoch.write,
                    publication_epoch: epoch.publication,
                });
            }
            let _ = arenas.next_executable_generation()?;
            operation.require_live()?;
            Ok(HvfPublicationTicket {
                manager: self.memory.manager,
                address_space: self.cell.id,
                claim_id: record.id,
                claim_version: record.version,
                range,
                pages: published_pages,
            })
        })
    }

    pub fn protect(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        publication: Option<&HvfPublicationTicket>,
    ) -> Result<HvfMutation, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            permissions.validate()?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = self.memory.validate_claim(self, &state, claim)?;
            let claim_start = record.range.start;
            let mut old_backings = HashMap::new();
            old_backings
                .try_reserve(record.pages.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("protect backing snapshot"))?;
            old_backings.extend(record.pages.iter().map(|(&gva, page)| (gva, page.backing)));
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure_aliases_inactive(record, &range, &arenas.slots)?;
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if permissions.contains(HvfGuestPermissions::EXECUTE) {
                validate_publication(
                    self.memory.manager,
                    self.cell.id,
                    record,
                    &range,
                    publication,
                    &backings,
                )?;
            }
            if permissions != HvfGuestPermissions::NONE {
                let target = StageTwoAuthority::for_permissions(permissions);
                for gva in page_addresses(&range) {
                    let old = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                    if let Some(backing) = old.backing {
                        backings.preflight_stage_two_replacement(
                            backing,
                            target,
                            old.mapping.as_ref().map(|mapping| mapping.authority),
                        )?;
                    }
                }
            }
            let old_live_pages = record
                .pages
                .iter()
                .filter(|(gva, page)| range.contains(gva) && page.mapping.is_some())
                .count();
            let new_live_pages = if permissions == HvfGuestPermissions::NONE {
                0
            } else {
                page_count
            };
            let next_live_data_pages = arenas
                .live_data_pages
                .checked_sub(old_live_pages)
                .and_then(|value| value.checked_add(new_live_pages))
                .ok_or(HvfMemoryError::IpaOwnership)?;
            admit_resource(
                "live data pages",
                0,
                next_live_data_pages,
                self.memory.limits.max_live_data_pages,
            )?;
            let mut replacements = HashMap::new();
            replacements
                .try_reserve(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("protect replacements"))?;
            let mut updates = Vec::new();
            updates
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("protect stage-one updates"))?;
            let preparation = (|| {
                for gva in page_addresses(&range) {
                    let old = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                    let (backing, release_backing_on_failure) = match old.backing {
                        Some(backing) => (Some(backing), false),
                        None if permissions == HvfGuestPermissions::NONE => (None, false),
                        None => {
                            let identity = backings.allocate(1, old.sharing, 0)?;
                            let backing = BackingPage {
                                identity,
                                offset: 0,
                            };
                            backings.retain(backing)?;
                            (Some(backing), true)
                        }
                    };
                    let mapping = match backing {
                        Some(backing) if permissions != HvfGuestPermissions::NONE => {
                            let mapping = map_data_page(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                backing,
                                HvfGuestPermissions::READ,
                                release_backing_on_failure,
                            )?;
                            updates
                                .push((gva, permissions.stage_one_descriptor(mapping.ipa.start)));
                            Some(mapping)
                        }
                        _ => {
                            updates.push((gva, 0));
                            None
                        }
                    };
                    replacements.insert(
                        gva,
                        PageState {
                            permissions,
                            sharing: old.sharing,
                            backing,
                            mapping,
                            slot: old.slot,
                        },
                    );
                }
                Ok::<(), HvfMemoryError>(())
            })();
            if let Err(error) = preparation {
                cleanup_replacements(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    &old_backings,
                    replacements,
                )?;
                return Err(error);
            }
            let candidate = match build_candidate_root(
                self.memory.vm,
                &mut arenas,
                state.root,
                &updates,
                self.memory.limits.max_table_pages,
            ) {
                Ok(root) => root,
                Err(error) => {
                    cleanup_replacements(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        &old_backings,
                        replacements,
                    )?;
                    return Err(error);
                }
            };
            if arenas.take_failure(FailurePoint::BeforeRootPublish) {
                cleanup_protect_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    candidate,
                    &old_backings,
                    replacements,
                )?;
                return Err(HvfMemoryError::InjectedFailure("before root publication"));
            }
            let metadata = (|| {
                let generation = arenas.next_root_generation()?;
                let executable_generation = if permissions.contains(HvfGuestPermissions::EXECUTE) {
                    arenas.next_executable_generation()?
                } else {
                    state.executable_generation
                };
                let old_root = state.root;
                let old_table_pages = arenas.tables.release_count(old_root)?;
                let new_version = record
                    .version
                    .checked_add(1)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                operation.require_live()?;
                Ok::<_, HvfMemoryError>((
                    generation,
                    executable_generation,
                    old_root,
                    old_table_pages,
                    new_version,
                ))
            })();
            let (generation, executable_generation, old_root, old_table_pages, new_version) =
                match metadata {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        cleanup_protect_preparation(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            candidate,
                            &old_backings,
                            replacements,
                        )?;
                        return Err(error);
                    }
                };
            let mut retired_backings = Vec::new();
            retired_backings
                .try_reserve_exact(old_live_pages)
                .map_err(|_| HvfMemoryError::MetadataAllocation("retired backing plan"))?;
            retired_backings.extend(
                record
                    .pages
                    .iter()
                    .filter(|(gva, _)| range.contains(gva))
                    .filter_map(|(_, page)| page.mapping.as_ref())
                    .map(|mapping| mapping.backing),
            );
            let mut retained_backings = Vec::new();
            retained_backings
                .try_reserve_exact(retired_backings.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("retained backing plan"))?;
            for backing in retired_backings {
                if let Err(error) = backings.retain(backing) {
                    cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        None,
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    )?;
                    return Err(error);
                }
                retained_backings.push(backing);
            }
            let buffers = (|| {
                let mut retired_data = Vec::new();
                retired_data
                    .try_reserve_exact(old_live_pages)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("retired data ownership"))?;
                let mut old_pages = Vec::new();
                old_pages
                    .try_reserve_exact(page_count)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("replaced claim pages"))?;
                Ok::<_, HvfMemoryError>((retired_data, old_pages))
            })();
            let (mut retired_data, old_pages) = match buffers {
                Ok(buffers) => buffers,
                Err(error) => {
                    cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        None,
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    )?;
                    return Err(error);
                }
            };
            let reservation = match self.memory.reserve_retirement(
                &mut acknowledgements,
                old_live_pages,
                0,
                0,
                old_table_pages,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        None,
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    )?;
                    return Err(error);
                }
            };
            let claim_record = match state.claims.get_mut(&claim_start) {
                Some(record) => record,
                None => {
                    cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        Some(reservation),
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    )?;
                    return Err(HvfMemoryError::ClaimStale);
                }
            };
            let inject_authority_failure = arenas.take_failure(FailurePoint::AuthorityTransition);
            if let Err(error) = apply_protect_authorities(
                self.memory.vm,
                &mut backings,
                claim_record,
                &range,
                permissions,
                &mut replacements,
                inject_authority_failure,
            ) {
                cleanup_failed_protect(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    Some(reservation),
                    retained_backings,
                    candidate,
                    &old_backings,
                    replacements,
                )?;
                return Err(error);
            }
            let old_pages = match swap_claim_pages(claim_record, &range, replacements, old_pages) {
                Ok(old_pages) => old_pages,
                Err((error, replacements)) => {
                    self.memory.vm.poison();
                    cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        Some(reservation),
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    )?;
                    return Err(error);
                }
            };
            for (_, mut old) in old_pages {
                if let Some(mapping) = old.mapping.take() {
                    retired_data.push(RetiredData {
                        mapping,
                        release_backing_reference: true,
                    });
                }
            }
            claim_record.version = new_version;
            let new_claim = HvfClaim {
                manager: self.memory.manager,
                address_space: self.cell.id,
                id: claim_record.id,
                version: claim_record.version,
                range: claim_record.range.clone(),
            };
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                generation,
                old_root,
                retired_data,
                Vec::new(),
                Vec::new(),
            );
            state.root = candidate;
            state.root_generation = generation;
            state.executable_generation = executable_generation;
            arenas.live_data_pages = next_live_data_pages;
            Ok(HvfMutation {
                claim: new_claim,
                root_generation: generation,
                executable_generation,
                retirement,
            })
        })
    }

    pub fn unmap(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
    ) -> Result<HvfUnmapResult, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = self.memory.validate_claim(self, &state, claim)?;
            let claim_start = record.range.start;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure_aliases_inactive(record, &range, &arenas.slots)?;
            let _backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let removed_live_pages = record
                .pages
                .iter()
                .filter(|(gva, page)| range.contains(gva) && page.mapping.is_some())
                .count();
            let removed_backing_pages = record
                .pages
                .iter()
                .filter(|(gva, page)| {
                    range.contains(gva) && page.mapping.is_none() && page.backing.is_some()
                })
                .count();
            let next_claimed_pages = arenas
                .claimed_pages
                .checked_sub(page_count)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let next_live_data_pages = arenas
                .live_data_pages
                .checked_sub(removed_live_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let mut updates = Vec::new();
            updates
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("unmap stage-one updates"))?;
            updates.extend(page_addresses(&range).map(|gva| (gva, 0)));
            let candidate = build_candidate_root(
                self.memory.vm,
                &mut arenas,
                state.root,
                &updates,
                self.memory.limits.max_table_pages,
            )?;
            if arenas.take_failure(FailurePoint::BeforeRootPublish) {
                cleanup_candidate_root(self.memory.vm, &mut arenas, candidate)?;
                return Err(HvfMemoryError::InjectedFailure("before root publication"));
            }
            let survivor_ranges = match split_survivors(&record.range, &range) {
                Ok(ranges) => ranges,
                Err(error) => {
                    cleanup_candidate_root(self.memory.vm, &mut arenas, candidate)?;
                    return Err(error);
                }
            };
            let metadata = (|| {
                let generation = arenas.next_root_generation()?;
                let old_root = state.root;
                let old_table_pages = arenas.tables.release_count(old_root)?;
                let mut survivors = Vec::new();
                survivors
                    .try_reserve_exact(survivor_ranges.len())
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap survivor plan"))?;
                for survivor_range in survivor_ranges {
                    survivors.push((survivor_range, take_counter(&mut arenas.next_claim)?));
                }
                operation.require_live()?;
                Ok::<_, HvfMemoryError>((generation, old_root, old_table_pages, survivors))
            })();
            let (generation, old_root, old_table_pages, survivors) = match metadata {
                Ok(metadata) => metadata,
                Err(error) => {
                    cleanup_candidate_root(self.memory.vm, &mut arenas, candidate)?;
                    return Err(error);
                }
            };
            if survivors.iter().any(|(survivor, _)| {
                survivor.start != claim_start && state.claims.contains_key(&survivor.start)
            }) {
                cleanup_candidate_root(self.memory.vm, &mut arenas, candidate)?;
                return Err(HvfMemoryError::AddressOverlap(range));
            }
            let reservation = match self.memory.reserve_retirement(
                &mut acknowledgements,
                removed_live_pages,
                page_count,
                removed_backing_pages,
                old_table_pages,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    cleanup_candidate_root(self.memory.vm, &mut arenas, candidate)?;
                    return Err(error);
                }
            };
            let buffers = (|| {
                state
                    .claims
                    .try_reserve(2)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap survivor ownership"))?;
                let mut retired_data = Vec::new();
                retired_data
                    .try_reserve_exact(removed_live_pages)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap retired data"))?;
                let mut retired_slots = Vec::new();
                retired_slots
                    .try_reserve_exact(page_count)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap retired slots"))?;
                let mut retired_backings = Vec::new();
                retired_backings
                    .try_reserve_exact(page_count - removed_live_pages)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap retired backings"))?;
                let mut surviving_claims = Vec::new();
                surviving_claims
                    .try_reserve_exact(survivors.len())
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap surviving claims"))?;
                Ok::<_, HvfMemoryError>((
                    retired_data,
                    retired_slots,
                    retired_backings,
                    surviving_claims,
                ))
            })();
            let (mut retired_data, mut retired_slots, mut retired_backings, mut surviving_claims) =
                match buffers {
                    Ok(buffers) => buffers,
                    Err(error) => {
                        let cancellation = self
                            .memory
                            .cancel_retirement_reservation(&mut acknowledgements, reservation);
                        let cleanup =
                            cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                        cancellation?;
                        cleanup?;
                        return Err(error);
                    }
                };
            let record = match state.claims.remove(&claim_start) {
                Some(record) => record,
                None => {
                    let cancellation = self
                        .memory
                        .cancel_retirement_reservation(&mut acknowledgements, reservation);
                    let cleanup = cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                    cancellation?;
                    cleanup?;
                    return Err(HvfMemoryError::ClaimStale);
                }
            };
            let transform = match split_claim_for_unmap(record, &range, &survivors) {
                Ok(transform) => transform,
                Err((error, record)) => {
                    state.claims.insert(record.range.start, record);
                    let cancellation = self
                        .memory
                        .cancel_retirement_reservation(&mut acknowledgements, reservation);
                    let cleanup = cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                    cancellation?;
                    cleanup?;
                    return Err(error);
                }
            };

            for page in transform.removed_pages {
                retired_slots.push(page.slot);
                match (page.mapping, page.backing) {
                    (Some(mapping), _) => retired_data.push(RetiredData {
                        mapping,
                        release_backing_reference: true,
                    }),
                    (None, Some(backing)) => retired_backings.push(backing),
                    (None, None) => {}
                }
            }

            for survivor in transform.survivors {
                surviving_claims.push(HvfClaim {
                    manager: self.memory.manager,
                    address_space: self.cell.id,
                    id: survivor.id,
                    version: survivor.version,
                    range: survivor.range.clone(),
                });
                state
                    .claims
                    .extend(core::iter::once((survivor.range.start, survivor)));
            }
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                generation,
                old_root,
                retired_data,
                retired_slots,
                retired_backings,
            );
            state.root = candidate;
            state.root_generation = generation;
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            Ok(HvfUnmapResult {
                surviving_claims,
                root_generation: generation,
                retirement,
            })
        })
    }

    /// Exposes a temporary range-scoped alias for the duration of `access`.
    /// The callback must not block or re-enter the memory manager; no pointer
    /// derived from the slice may outlive the callback.
    pub fn read_alias<R>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        access: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, HvfMemoryError> {
        self.with_alias(claim, range, false, |bytes| access(bytes))
    }

    /// Exposes a temporary writable range-scoped alias for `access`, then
    /// restores exact `PROT_NONE` slot ownership before returning. The callback
    /// must not block, re-enter the manager, or retain a derived pointer.
    pub fn write_alias<R>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        access: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, HvfMemoryError> {
        self.with_alias(claim, range, true, access)
    }

    fn with_alias<R>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        write: bool,
        access: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, HvfMemoryError> {
        let alias_guard = AliasThreadGuard::enter(range.clone())?;
        let lease = self.begin_alias(claim, range, write)?;
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            let bytes =
                core::slice::from_raw_parts_mut(lease.range.start as *mut u8, lease.range.len());
            access(bytes)
        }));
        let finish = self.finish_alias(lease);
        drop(alias_guard);
        if let Err(error) = finish {
            return Err(error);
        }
        match result {
            Ok(value) => Ok(value),
            Err(payload) => resume_unwind(payload),
        }
    }

    fn begin_alias(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        write: bool,
    ) -> Result<AliasLease, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = self.memory.validate_claim(self, &state, claim)?;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let permissions = if write {
                HvfHostPermissions::READ_WRITE
            } else {
                HvfHostPermissions::READ
            };
            let mut pages = Vec::new();
            pages
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("alias lease"))?;
            for gva in page_addresses(&range) {
                let page = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                if write && !page.permissions.contains(HvfGuestPermissions::WRITE) {
                    return Err(HvfMemoryError::WriteWithoutRead);
                }
                if !write && !page.permissions.contains(HvfGuestPermissions::READ) {
                    return Err(HvfMemoryError::SparseAlias(range.clone()));
                }
                let backing = page
                    .backing
                    .ok_or_else(|| HvfMemoryError::SparseAlias(range.clone()))?;
                let slot_record = arenas
                    .slots
                    .records
                    .get(&page.slot)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                if slot_record.active || slot_record.quarantined {
                    return Err(HvfMemoryError::AliasBusy(gva..gva + PAGE_SIZE));
                }
                if slot_record.slot.is_none() {
                    return Err(HvfMemoryError::IpaOwnership);
                }
                backings.page_storage(backing)?;
                pages.push(AliasLeasePage {
                    slot: page.slot,
                    backing,
                    range: gva..gva + PAGE_SIZE,
                    write,
                });
            }
            acknowledgements.reserve_alias_quarantine(page_count)?;
            let write_epoch = if write {
                Some(arenas.next_write_epoch()?)
            } else {
                None
            };
            let mut authorized = 0usize;
            for page in &pages {
                if let Err(error) = backings.reserve_host_alias(page.backing, page.write) {
                    let rollback = release_alias_authorities(&mut backings, &pages[..authorized]);
                    acknowledgements.release_alias_quarantine_reservation(page_count)?;
                    if let Err(cleanup) = rollback {
                        return Err(cleanup);
                    }
                    return Err(error);
                }
                authorized += 1;
            }
            let mut installed = Vec::new();
            if let Err(_) = installed.try_reserve_exact(page_count) {
                let cleanup = release_alias_authorities(&mut backings, &pages);
                acknowledgements.release_alias_quarantine_reservation(page_count)?;
                cleanup?;
                return Err(HvfMemoryError::MetadataAllocation("installed aliases"));
            }
            for (index, page) in pages.iter().enumerate() {
                let alias = {
                    let storage = backings.page_storage(page.backing)?;
                    let slot_record = arenas
                        .slots
                        .records
                        .get_mut(&page.slot)
                        .ok_or(HvfMemoryError::IpaOwnership)?;
                    if slot_record.active || slot_record.quarantined {
                        return Err(HvfMemoryError::AliasBusy(page.range.clone()));
                    }
                    let slot = slot_record
                        .slot
                        .as_ref()
                        .ok_or(HvfMemoryError::IpaOwnership)?;
                    slot_record.active = true;
                    installed.push(page.clone());
                    slot.alias_from(storage, 0, permissions)
                };
                if let Err(error) = alias {
                    let restore = restore_installed_aliases(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        &installed,
                        false,
                    );
                    let release = release_alias_authorities(&mut backings, &pages[index + 1..]);
                    acknowledgements.release_alias_quarantine_reservation(page_count)?;
                    if let Err(cleanup) = restore.and(release) {
                        return Err(cleanup);
                    }
                    return Err(error.into());
                }
            }
            if let Err(error) = operation.require_live() {
                let restore = restore_installed_aliases(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    &installed,
                    false,
                );
                acknowledgements.release_alias_quarantine_reservation(page_count)?;
                if let Err(cleanup) = restore {
                    return Err(cleanup);
                }
                return Err(error.into());
            }
            Ok(AliasLease {
                range,
                write_epoch,
                pages: installed,
            })
        })
    }

    fn finish_alias(&self, lease: AliasLease) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|_operation| {
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut first_error = None;
            if let Some(epoch) = lease.write_epoch {
                for page in &lease.pages {
                    if let Err(error) = backings.write_epoch(page.backing, epoch) {
                        first_error.get_or_insert(error);
                    }
                }
            }
            let inject_restore = arenas.take_failure(FailurePoint::AliasRestore);
            if let Err(error) = restore_installed_aliases(
                self.memory.vm,
                &mut arenas,
                &mut backings,
                &mut acknowledgements,
                &lease.pages,
                inject_restore,
            ) {
                first_error.get_or_insert(error);
            }
            if let Err(error) =
                acknowledgements.release_alias_quarantine_reservation(lease.pages.len())
            {
                first_error.get_or_insert(error);
            }
            match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }

    pub fn software_walk(&self, gva: usize) -> Result<(u64, u64), HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            self.cell.regime.validate_address(gva)?;
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let result = arenas.tables.walk(state.root, gva)?;
            operation.require_live()?;
            Ok(result)
        })
    }

    pub fn report(&self) -> Result<HvfAddressSpaceReport, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mappings = coalesced_ledger(&state, &backings)?;
            let (monitor_leaf_ipa, _) = arenas.tables.walk(state.root, 0)?;
            let report = HvfAddressSpaceReport {
                id: self.cell.id,
                asid: self.cell.asid,
                regime: self.cell.regime,
                root_ipa: arenas.tables.ipa(state.root)?,
                root_generation: state.root_generation,
                executable_generation: state.executable_generation,
                stage_one_table_pages: arenas.tables.reachable_count(state.root)?,
                monitor_leaf_ipa,
                mappings,
                usage: self
                    .memory
                    .usage_locked(&arenas, &backings, &acknowledgements),
            };
            operation.require_live()?;
            Ok(report)
        })
    }

    pub fn vcpu_snapshot(&self) -> Result<HvfVcpuMemorySnapshot, HvfMemoryError> {
        let report = self.report()?;
        Ok(HvfVcpuMemorySnapshot {
            address_space_id: report.id,
            asid: report.asid,
            regime: report.regime,
            ttbr0_el1: (u64::from(report.asid.value) << 48) | report.root_ipa,
            root_generation: report.root_generation,
            executable_generation: report.executable_generation,
        })
    }

    pub fn acknowledge_retirement(
        &self,
        ticket: HvfRetirementTicket,
    ) -> Result<HvfRetirementReport, HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|_operation| {
            if ticket.manager != self.memory.manager || ticket.address_space != self.cell.id {
                return Err(HvfMemoryError::WrongMemoryManager);
            }
            let _state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (next_retired_pages, next_retired_bytes, retired_root) = {
                let retired = acknowledgements
                    .retirements
                    .get(&ticket.id)
                    .filter(|retired| {
                        retired.address_space == ticket.address_space
                            && retired.generation == ticket.generation
                    })
                    .ok_or(HvfMemoryError::RetirementStale)?;
                (
                    acknowledgements
                        .retired_pages
                        .checked_sub(retired.charged_pages)
                        .ok_or(HvfMemoryError::RetirementStale)?,
                    acknowledgements
                        .retired_bytes
                        .checked_sub(retired.charged_bytes)
                        .ok_or(HvfMemoryError::RetirementStale)?,
                    retired.root,
                )
            };
            let table_records = match arenas.tables.release(retired_root) {
                Ok(records) => records,
                Err(error @ HvfMemoryError::MetadataAllocation(_)) => return Err(error),
                Err(error) => {
                    self.memory.vm.poison();
                    return Err(error);
                }
            };
            let retired = acknowledgements
                .retirements
                .remove(&ticket.id)
                .ok_or(HvfMemoryError::RetirementStale)?;
            let mut released_data_pages = 0;
            let mut released_backing_references = 0;
            let released_table_pages = table_records.len();
            let mut first_error =
                cleanup_table_records(self.memory.vm, &mut arenas, table_records).err();
            for data in retired.data {
                let release_backing_reference = data.release_backing_reference;
                if let Err(error) = cleanup_data_mapping(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    data.mapping,
                    release_backing_reference,
                ) {
                    first_error.get_or_insert(error);
                } else {
                    released_data_pages += 1;
                    if release_backing_reference {
                        released_backing_references += 1;
                    }
                }
            }
            for backing in retired.backings {
                match backings.release(backing) {
                    Ok(_) => released_backing_references += 1,
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            let mut released_host_slots = 0;
            for slot in retired.slots {
                match arenas.slots.release(slot) {
                    Ok(true) => released_host_slots += 1,
                    Ok(false) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if first_error.is_some() {
                self.memory.vm.poison();
            }
            acknowledgements.retired_pages = next_retired_pages;
            acknowledgements.retired_bytes = next_retired_bytes;
            if let Some(error) = first_error {
                return Err(error);
            }
            let quarantined_resources = self
                .memory
                .usage_locked(&arenas, &backings, &acknowledgements)
                .quarantined_resources;
            Ok(HvfRetirementReport {
                generation: ticket.generation,
                charged_pages: retired.charged_pages,
                charged_bytes: retired.charged_bytes,
                data_pages: retired.data_pages,
                slot_pages: retired.slot_pages,
                backing_pages: retired.backing_pages,
                table_pages: retired.table_pages,
                released_data_pages,
                released_table_pages,
                released_host_slots,
                released_backing_references,
                quarantined_resources,
            })
        })
    }

    pub fn fork_private(&self) -> Result<HvfForkResult, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let parent_state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !parent_state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let mut spaces = self
                .memory
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut parent_claim_starts = Vec::new();
            parent_claim_starts
                .try_reserve_exact(parent_state.claims.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("fork claim order"))?;
            parent_claim_starts.extend(parent_state.claims.keys().copied());
            parent_claim_starts.sort_unstable();
            for start in &parent_claim_starts {
                let claim = parent_state
                    .claims
                    .get(start)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                ensure_aliases_inactive(claim, &claim.range, &arenas.slots)?;
            }
            admit_resource(
                "address spaces",
                arenas.address_spaces,
                1,
                self.memory.limits.max_address_spaces,
            )?;
            let child_claimed_pages =
                parent_claim_starts
                    .iter()
                    .try_fold(0usize, |count, start| {
                        count
                            .checked_add(
                                parent_state
                                    .claims
                                    .get(start)
                                    .ok_or(HvfMemoryError::ClaimStale)?
                                    .pages
                                    .len(),
                            )
                            .ok_or(HvfMemoryError::IpaOwnership)
                    })?;
            check_mutation_bound(child_claimed_pages, self.memory.limits.max_mutation_pages)?;
            let child_live_data_pages =
                parent_claim_starts
                    .iter()
                    .try_fold(0usize, |count, start| {
                        let claim = parent_state
                            .claims
                            .get(start)
                            .ok_or(HvfMemoryError::ClaimStale)?;
                        let live = page_addresses(&claim.range).try_fold(0usize, |live, gva| {
                            let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                            live.checked_add(usize::from(page.mapping.is_some()))
                                .ok_or(HvfMemoryError::IpaOwnership)
                        })?;
                        count.checked_add(live).ok_or(HvfMemoryError::IpaOwnership)
                    })?;
            let next_claimed_pages = admit_resource(
                "claimed pages",
                arenas.claimed_pages,
                child_claimed_pages,
                self.memory.limits.max_claimed_pages,
            )?;
            let next_live_data_pages = admit_resource(
                "live data pages",
                arenas.live_data_pages,
                child_live_data_pages,
                self.memory.limits.max_live_data_pages,
            )?;
            spaces
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("fork address space"))?;
            let id = HvfAddressSpaceId(take_counter(&mut arenas.next_address_space)?);
            if spaces.contains_key(&id) {
                return Err(HvfMemoryError::IpaOwnership);
            }
            let root_generation = arenas.next_root_generation()?;
            let asid = arenas.asids.allocate()?;
            let cell = Arc::new(AddressSpaceCell {
                id,
                asid,
                regime: self.cell.regime,
                state: Mutex::new(AddressSpaceState {
                    live: false,
                    root: TableToken(0),
                    root_generation,
                    executable_generation: parent_state.executable_generation,
                    claims: HashMap::new(),
                }),
            });
            let mut private_sources = Vec::new();
            if private_sources
                .try_reserve_exact(child_live_data_pages)
                .is_err()
            {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork private sources"));
            }
            for start in &parent_claim_starts {
                let claim = parent_state
                    .claims
                    .get(start)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                for gva in page_addresses(&claim.range) {
                    let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                    if page.sharing == HvfSharing::Private
                        && let Some(backing) = page.backing
                    {
                        private_sources.push(backing.identity);
                    }
                }
            }
            private_sources.sort_unstable();
            private_sources.dedup();
            let mut private_copies = HashMap::new();
            if private_copies.try_reserve(private_sources.len()).is_err() {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork private copies"));
            }
            let mut child_claims = HashMap::new();
            if child_claims.try_reserve(parent_state.claims.len()).is_err() {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork child claims"));
            }
            let mut updates = Vec::new();
            if updates.try_reserve_exact(child_claimed_pages).is_err() {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork stage-one updates"));
            }
            let mut claim_capabilities = Vec::new();
            if claim_capabilities
                .try_reserve_exact(parent_state.claims.len())
                .is_err()
            {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation(
                    "fork claim capabilities",
                ));
            }
            if let Err(error) = operation.require_live() {
                arenas.asids.release(asid)?;
                return Err(error.into());
            }
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let initial_root = match create_monitor_root(
                self.memory.vm,
                &mut arenas,
                self.memory.limits.max_table_pages,
            ) {
                Ok(root) => root,
                Err(error) => {
                    arenas.asids.release(asid)?;
                    return Err(error);
                }
            };
            for &source in &private_sources {
                match backings.eager_copy_backing(source, 0) {
                    Ok(copy) => {
                        private_copies.insert(source, copy);
                    }
                    Err(error) => {
                        cleanup_fork_preparation(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            child_claims,
                            private_copies,
                            [initial_root],
                            Some(asid),
                        )?;
                        return Err(error);
                    }
                }
            }
            for start in parent_claim_starts {
                let parent_claim = parent_state
                    .claims
                    .get(&start)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                let claim_id = match take_counter(&mut arenas.next_claim) {
                    Ok(id) => id,
                    Err(error) => {
                        cleanup_fork_preparation(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            child_claims,
                            private_copies,
                            [initial_root],
                            Some(asid),
                        )?;
                        return Err(error);
                    }
                };
                let mut pages = HashMap::new();
                if pages.try_reserve(parent_claim.pages.len()).is_err() {
                    cleanup_fork_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        child_claims,
                        private_copies,
                        [initial_root],
                        Some(asid),
                    )?;
                    return Err(HvfMemoryError::MetadataAllocation("fork claim pages"));
                }
                for gva in page_addresses(&parent_claim.range) {
                    let parent_page = parent_claim
                        .pages
                        .get(&gva)
                        .ok_or(HvfMemoryError::ClaimStale)?;
                    let page = match prepare_fork_page(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        parent_page,
                        &private_copies,
                    ) {
                        Ok(page) => page,
                        Err(error) => {
                            child_claims.insert(
                                parent_claim.range.start,
                                ClaimRecord {
                                    id: claim_id,
                                    version: 1,
                                    range: parent_claim.range.clone(),
                                    pages,
                                },
                            );
                            cleanup_fork_preparation(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                child_claims,
                                private_copies,
                                [initial_root],
                                Some(asid),
                            )?;
                            return Err(error);
                        }
                    };
                    let descriptor = page.mapping.as_ref().map_or(0, |mapping| {
                        page.permissions.stage_one_descriptor(mapping.ipa.start)
                    });
                    updates.push((gva, descriptor));
                    pages.insert(gva, page);
                }
                claim_capabilities.push(HvfClaim {
                    manager: self.memory.manager,
                    address_space: id,
                    id: claim_id,
                    version: 1,
                    range: parent_claim.range.clone(),
                });
                child_claims.insert(
                    parent_claim.range.start,
                    ClaimRecord {
                        id: claim_id,
                        version: 1,
                        range: parent_claim.range.clone(),
                        pages,
                    },
                );
            }
            let candidate = match build_candidate_root(
                self.memory.vm,
                &mut arenas,
                initial_root,
                &updates,
                self.memory.limits.max_table_pages,
            ) {
                Ok(candidate) => candidate,
                Err(error) => {
                    cleanup_fork_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        child_claims,
                        private_copies,
                        [initial_root],
                        Some(asid),
                    )?;
                    return Err(error);
                }
            };
            if let Err(error) = cleanup_candidate_root(self.memory.vm, &mut arenas, initial_root) {
                cleanup_fork_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    child_claims,
                    private_copies,
                    [candidate],
                    Some(asid),
                )?;
                return Err(error);
            }
            if let Err(error) = operation.require_live() {
                cleanup_fork_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    child_claims,
                    private_copies,
                    [candidate],
                    Some(asid),
                )?;
                return Err(error.into());
            }
            {
                let mut state = cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.live = true;
                state.root = candidate;
                state.claims = child_claims;
            }
            if let Some(previous) = spaces.insert(id, cell.clone()) {
                if spaces.insert(id, previous).is_none() {
                    self.memory.vm.poison();
                }
                let mut child_state = cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let child_claims = core::mem::take(&mut child_state.claims);
                let root_cleanup =
                    cleanup_candidate_root(self.memory.vm, &mut arenas, child_state.root);
                let claims_cleanup = cleanup_claim_records(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    child_claims,
                );
                let asid_cleanup = arenas.asids.release(asid);
                child_state.live = false;
                self.memory.vm.poison();
                if let Err(cleanup) = root_cleanup.and(claims_cleanup).and(asid_cleanup) {
                    return Err(cleanup);
                }
                return Err(HvfMemoryError::IpaOwnership);
            }
            arenas.address_spaces += 1;
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            Ok(HvfForkResult {
                address_space: HvfAddressSpace {
                    memory: self.memory,
                    cell,
                },
                claims: claim_capabilities,
            })
        })
    }

    pub fn destroy(&self) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|_operation| {
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let mut spaces = self
                .memory
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !spaces.contains_key(&self.cell.id) {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for claim in state.claims.values() {
                ensure_aliases_inactive(claim, &claim.range, &arenas.slots)?;
            }
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if acknowledgements
                .retirements
                .values()
                .any(|retired| retired.address_space == self.cell.id)
            {
                return Err(HvfMemoryError::RetirementsPending(self.cell.id));
            }
            let destroyed_claimed_pages = state
                .claims
                .values()
                .map(|claim| claim.pages.len())
                .sum::<usize>();
            let destroyed_live_data_pages = state
                .claims
                .values()
                .flat_map(|claim| claim.pages.values())
                .filter(|page| page.mapping.is_some())
                .count();
            let next_address_spaces = arenas
                .address_spaces
                .checked_sub(1)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let next_claimed_pages = arenas
                .claimed_pages
                .checked_sub(destroyed_claimed_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let next_live_data_pages = arenas
                .live_data_pages
                .checked_sub(destroyed_live_data_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let table_records = match arenas.tables.release(state.root) {
                Ok(records) => records,
                Err(error @ HvfMemoryError::MetadataAllocation(_)) => return Err(error),
                Err(error) => {
                    self.memory.vm.poison();
                    return Err(error);
                }
            };
            let claims = core::mem::take(&mut state.claims);
            let mut first_error =
                cleanup_table_records(self.memory.vm, &mut arenas, table_records).err();
            if let Err(error) = cleanup_claim_records(
                self.memory.vm,
                &mut arenas,
                &mut backings,
                &mut acknowledgements,
                claims,
            ) {
                first_error.get_or_insert(error);
            }
            if let Err(error) = arenas.asids.release(self.cell.asid) {
                self.memory.vm.poison();
                first_error.get_or_insert(error);
            }
            if first_error.is_some() {
                self.memory.vm.poison();
            }
            arenas.address_spaces = next_address_spaces;
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            state.live = false;
            if spaces.remove(&self.cell.id).is_none() {
                self.memory.vm.poison();
                first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            }
            if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(())
            }
        })
    }
}

static PROCESS_HVF_MEMORY: OnceLock<Result<HvfMemory, HvfMemoryError>> = OnceLock::new();

pub(crate) fn process_hvf_memory() -> Result<&'static HvfMemory, HvfMemoryError> {
    PROCESS_HVF_MEMORY
        .get_or_init(HvfMemory::create)
        .as_ref()
        .map_err(Clone::clone)
}

#[repr(align(16384))]
struct ProbeFailurePages([u8; 4 * PAGE_SIZE]);

static PROCESS_HVF_FAILURE_PROBE_PAGES: OnceLock<Box<ProbeFailurePages>> = OnceLock::new();

pub fn hvf_memory_probe() -> Result<HvfMemoryReport, HvfMemoryError> {
    with_hvf_memory_probe(|report| report.clone())
}

pub fn with_hvf_memory_probe<T>(
    consume: impl FnOnce(&HvfMemoryReport) -> T,
) -> Result<T, HvfMemoryError> {
    let memory = process_hvf_memory()?;
    memory.vm.with_zero_vcpu_operation(|_| {
        let report = hvf_memory_probe_inner(memory)?;
        Ok(consume(&report))
    })
}

fn hvf_memory_probe_inner(memory: &'static HvfMemory) -> Result<HvfMemoryReport, HvfMemoryError> {
    let mut spaces = Vec::new();
    spaces
        .try_reserve_exact(4)
        .map_err(|_| HvfMemoryError::MetadataAllocation("memory probe spaces"))?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        hvf_memory_probe_tracked(memory, &mut spaces)
    }));
    let cleanup = finish_probe_spaces(memory, &spaces);
    match result {
        Ok(result) => {
            cleanup?;
            result
        }
        Err(payload) => {
            cleanup?;
            resume_unwind(payload)
        }
    }
}

fn hvf_memory_probe_tracked(
    memory: &'static HvfMemory,
    spaces: &mut Vec<HvfAddressSpace>,
) -> Result<HvfMemoryReport, HvfMemoryError> {
    let host_backing = hvf_host_backing_probe()?;
    if !host_backing.coherent_alias_verified
        || !host_backing.private_copy_verified
        || !host_backing.reservation_restored
        || !host_backing.exact_preclaim_overlap_rejected
        || !host_backing.left_preclaim_overlap_rejected
        || !host_backing.right_preclaim_overlap_rejected
        || !host_backing.enclosing_preclaim_overlap_rejected
        || !host_backing.adjacent_preclaims_accepted
        || !host_backing.rejected_preclaims_had_no_effect
        || !host_backing.registering_resources_reported
        || !host_backing.concurrent_preclaim_single_winner
        || !host_backing.final_resources.is_empty()
    {
        return Err(HvfMemoryError::Witness(
            "host backing primitive witness failed",
        ));
    }
    let initial_vcpus = memory.vm.active_vcpu_count();
    let parent = memory.create_address_space()?;
    spaces.push(parent.clone());
    let competitor = memory.create_address_space()?;
    spaces.push(competitor.clone());
    let independent_roots_verified = parent.report()?.root_ipa != competitor.report()?.root_ipa;
    let monitor_walk = parent.software_walk(0)?;
    let monitor_leaf_verified = monitor_walk.0 == 0
        && monitor_walk.1 & DESCRIPTOR_UXN != 0
        && monitor_walk.1 & DESCRIPTOR_PXN == 0
        && monitor_walk.1 & (0b11 << 6) == DESCRIPTOR_AP_EL0_NONE_EL1_RO;
    let dynamic_tcr_ips_verified = parent.regime().ipa_bits
        == memory.vm.report().configured_ipa_bits
        && ((parent.regime().tcr_el1 >> 32) & 0b111)
            == u64::from(tcr_ips(parent.regime().ipa_bits));

    let base = 0x0000_0100_0000_0000usize;
    let exact_ipa_reuse_verified = ipa_allocator_reuse_witness()?;
    let all_resource_limits_verified = all_resource_limits_witness(memory.limits);
    let initial_execute_before = parent.report()?;
    let initial_execute_rejected = matches!(
        parent.claim(
            base + 0x0100_0000..base + 0x0100_0000 + PAGE_SIZE,
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::InitialExecute(_))
    ) && parent.report()? == initial_execute_before;

    let overlap_base = base + 0x0120_0000;
    let retirement_before = memory.usage();
    let overlap_anchor = parent.claim(
        overlap_base..overlap_base + 2 * PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    let retirement_pending = memory.usage();
    let overlap_ticket = overlap_anchor.retirement.clone();
    let retirement_report = parent.acknowledge_retirement(overlap_anchor.retirement)?;
    let retirement_after = memory.usage();
    let retirement_checkpoints_verified = retirement_pending.retired_generations
        == retirement_before.retired_generations + 1
        && retirement_pending.retired_pages
            == retirement_before.retired_pages + retirement_report.charged_pages
        && retirement_pending.retired_bytes
            == retirement_before.retired_bytes + retirement_report.charged_bytes
        && retirement_report.generation == overlap_ticket.generation
        && retirement_report.charged_pages == retirement_report.table_pages
        && retirement_report.charged_bytes == retirement_report.charged_pages * PAGE_SIZE
        && retirement_report.data_pages == 0
        && retirement_report.slot_pages == 0
        && retirement_report.backing_pages == 0
        && retirement_report.released_table_pages == retirement_report.table_pages
        && retirement_after.retired_generations == retirement_before.retired_generations
        && retirement_after.retired_pages == retirement_before.retired_pages
        && retirement_after.retired_bytes == retirement_before.retired_bytes;
    let overlap_snapshot = parent.report()?;
    let exact_overlap = matches!(
        parent.claim(
            overlap_base..overlap_base + 2 * PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let left_overlap = matches!(
        parent.claim(
            overlap_base - PAGE_SIZE..overlap_base + PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let right_overlap = matches!(
        parent.claim(
            overlap_base + PAGE_SIZE..overlap_base + 3 * PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let enclosing_overlap = matches!(
        parent.claim(
            overlap_base - PAGE_SIZE..overlap_base + 3 * PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let overlap_rejection_verified = exact_overlap
        && left_overlap
        && right_overlap
        && enclosing_overlap
        && parent.report()? == overlap_snapshot;
    let left_adjacent = parent.claim(
        overlap_base - PAGE_SIZE..overlap_base,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(left_adjacent.retirement)?;
    let right_adjacent = parent.claim(
        overlap_base + 2 * PAGE_SIZE..overlap_base + 3 * PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(right_adjacent.retirement)?;
    let adjacent_claims_verified = left_adjacent.claim.range.end
        == overlap_anchor.claim.range.start
        && overlap_anchor.claim.range.end == right_adjacent.claim.range.start;
    for claim in [
        left_adjacent.claim,
        overlap_anchor.claim,
        right_adjacent.claim,
    ] {
        let unmap = parent.unmap(&claim, claim.range())?;
        parent.acknowledge_retirement(unmap.retirement)?;
    }

    let sparse = parent.claim(
        base..base + 3 * PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(sparse.retirement)?;
    let sparse_claim_verified = parent.report()?.mappings.len() == 1
        && parent.report()?.mappings[0].permissions == HvfGuestPermissions::NONE
        && parent.report()?.mappings[0].ipa.is_empty();
    let sparse_middle = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
    let materialized = parent.protect(
        &sparse.claim,
        sparse_middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        None,
    )?;
    parent.acknowledge_retirement(materialized.retirement)?;
    parent.write_alias(&materialized.claim, sparse_middle.clone(), |bytes| {
        bytes[..8].copy_from_slice(&0x5041_5245_4e54_3031u64.to_le_bytes());
    })?;
    let alias_reservation_verified =
        parent.read_alias(&materialized.claim, sparse_middle, |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? == 0x5041_5245_4e54_3031;
    let sparse_unmap = parent.unmap(&materialized.claim, materialized.claim.range())?;
    parent.acknowledge_retirement(sparse_unmap.retirement)?;

    let private_base = base + 0x0200_0000;
    let private = parent.claim(
        private_base..private_base + 3 * PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(private.retirement)?;
    let middle = private_base + PAGE_SIZE..private_base + 2 * PAGE_SIZE;
    let split = parent.protect(
        &private.claim,
        middle.clone(),
        HvfGuestPermissions::READ,
        None,
    )?;
    parent.acknowledge_retirement(split.retirement)?;
    let split_verified = parent.report()?.mappings.len() == 3;
    let alias_preflight_verified = matches!(
        parent.write_alias(&split.claim, split.claim.range(), |_| {}),
        Err(HvfMemoryError::WriteWithoutRead)
    ) && memory.usage().active_alias_pages == 0;
    let coalesced = parent.protect(
        &split.claim,
        private_base..private_base + 3 * PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        None,
    )?;
    parent.acknowledge_retirement(coalesced.retirement)?;
    let coalesce_verified = parent.report()?.mappings.len() == 1;
    parent.write_alias(&coalesced.claim, middle.clone(), |bytes| {
        bytes[..8].copy_from_slice(&0x5041_5245_4e54_3031u64.to_le_bytes());
    })?;
    let (alias_reentry_verified, alias_concurrency_verified, alias_panic_cleanup_verified) =
        alias_behavior_witness(
            &parent,
            &coalesced.claim,
            private_base..private_base + PAGE_SIZE,
            middle.clone(),
        )?;

    let competitor_mutation = competitor.claim(
        middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Private,
    )?;
    competitor.acknowledge_retirement(competitor_mutation.retirement)?;
    competitor.write_alias(
        &competitor_mutation.claim,
        competitor_mutation.claim.range(),
        |bytes| {
            bytes[..8].copy_from_slice(&0x434f_4d50_4554_3031u64.to_le_bytes());
        },
    )?;
    let parent_value = parent.read_alias(&coalesced.claim, middle.clone(), |bytes| {
        u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
    })?;
    let competitor_value = competitor.read_alias(
        &competitor_mutation.claim,
        competitor_mutation.claim.range(),
        |bytes| u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
    )?;
    let parent_isolation_report = parent.report()?;
    let competitor_isolation_report = competitor.report()?;
    let parent_isolation_page = parent_isolation_report
        .mappings
        .iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("parent isolation page missing"))?;
    let competitor_isolation_page = competitor_isolation_report
        .mappings
        .iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("competitor isolation page missing"))?;
    let compact_nonidentity_ipa_verified = parent_isolation_page
        .ipa
        .iter()
        .all(|ipa| ipa.start != parent_isolation_page.gva.start as u64)
        && !parent_isolation_page.ipa.is_empty();
    let competitor_isolation_verified = parent_isolation_report.id
        != competitor_isolation_report.id
        && parent_isolation_report.asid != competitor_isolation_report.asid
        && parent_isolation_report.root_ipa != competitor_isolation_report.root_ipa
        && parent_isolation_page.backing_identity != competitor_isolation_page.backing_identity
        && parent_isolation_page.ipa != competitor_isolation_page.ipa
        && parent_isolation_page.write_epoch != competitor_isolation_page.write_epoch
        && parent_value == 0x5041_5245_4e54_3031
        && competitor_value == 0x434f_4d50_4554_3031;
    let active_physical_usage = memory.usage();
    let physical_accounting_verified = active_physical_usage.physical_backing_pages > 0
        && active_physical_usage.physical_backing_bytes
            == active_physical_usage.physical_backing_pages * PAGE_SIZE;
    let competitor_unmap = competitor.unmap(
        &competitor_mutation.claim,
        competitor_mutation.claim.range(),
    )?;
    competitor.acknowledge_retirement(competitor_unmap.retirement)?;

    let boundary_anchor = 0x0000_0200_0000_0000usize;
    let boundary_bases = [
        boundary_anchor + 0x1000_0000,
        boundary_anchor + 0x0200_0000 - PAGE_SIZE,
        boundary_anchor + 0x0010_0000_0000 - PAGE_SIZE,
    ];
    let mut boundary_claims = Vec::new();
    let mut boundary_tickets = Vec::new();
    for start in boundary_bases {
        let mutation = parent.claim(
            start..start + 2 * PAGE_SIZE,
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
            HvfSharing::Private,
        )?;
        boundary_tickets.push(mutation.retirement.clone());
        boundary_claims.push(mutation.claim);
    }
    for ticket in boundary_tickets {
        parent.acknowledge_retirement(ticket)?;
    }
    let offsets = [0x123usize, PAGE_SIZE + 0x321];
    let nonzero_offsets_verified = boundary_claims.iter().all(|claim| {
        offsets.iter().all(|offset| {
            parent
                .software_walk(claim.range.start + offset)
                .is_ok_and(|(ipa, _)| {
                    ipa & (PAGE_SIZE as u64 - 1) == *offset as u64 & (PAGE_SIZE as u64 - 1)
                })
        })
    });
    let l0_boundary_verified = software_l0_boundary_witness(memory)?;
    let all_stage_one_boundaries_verified = nonzero_offsets_verified
        && stage_one_indexes(boundary_claims[0].range.start)[3]
            != stage_one_indexes(boundary_claims[0].range.start + PAGE_SIZE)[3]
        && stage_one_indexes(boundary_claims[1].range.start)[2]
            != stage_one_indexes(boundary_claims[1].range.start + PAGE_SIZE)[2]
        && stage_one_indexes(boundary_claims[2].range.start)[1]
            != stage_one_indexes(boundary_claims[2].range.start + PAGE_SIZE)[1]
        && l0_boundary_verified;

    let shared_mutation = parent.claim(
        base + 0x1000_0000..base + 0x1000_0000 + PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Shared,
    )?;
    parent.acknowledge_retirement(shared_mutation.retirement)?;
    let mut parent_shared_claim = shared_mutation.claim;
    parent.write_alias(&parent_shared_claim, parent_shared_claim.range(), |bytes| {
        bytes[..8].copy_from_slice(&0x5348_4152_4544_3031u64.to_le_bytes());
    })?;
    let child = parent.fork_private()?;
    spaces.push(child.address_space.clone());
    let fork_capability_order_verified = child
        .claims
        .windows(2)
        .all(|claims| claims[0].range.start < claims[1].range.start);
    let child_report = child.report()?;
    let child_private = child_report
        .mappings
        .iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("child private claim missing"))?;
    let parent_private = parent
        .report()?
        .mappings
        .into_iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("parent private claim missing"))?;
    let private_fork_verified = child_private.backing_identity != parent_private.backing_identity;
    let mut child_shared_claim = child
        .claims
        .iter()
        .find(|claim| claim.range == parent_shared_claim.range)
        .cloned()
        .ok_or(HvfMemoryError::Witness("child shared claim missing"))?;
    child.write_alias(&child_shared_claim, child_shared_claim.range(), |bytes| {
        bytes[..8].copy_from_slice(&0x5348_4152_4544_3032u64.to_le_bytes());
    })?;
    let shared_coherence_verified =
        parent.read_alias(&parent_shared_claim, parent_shared_claim.range(), |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? == 0x5348_4152_4544_3032;
    let child_readonly = child.protect(
        &child_shared_claim,
        child_shared_claim.range(),
        HvfGuestPermissions::READ,
        None,
    )?;
    let shared_publication =
        parent.publish_executable(&parent_shared_claim, parent_shared_claim.range())?;
    let wx_before = parent.report()?;
    let wx_usage_before = memory.usage();
    let parent_execute_blocked = matches!(
        parent.protect(
            &parent_shared_claim,
            parent_shared_claim.range(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            Some(&shared_publication),
        ),
        Err(HvfMemoryError::BackingWriteExecute { .. })
    );
    let wx_after = parent.report()?;
    let wx_rejection_had_no_effect = wx_after == wx_before && memory.usage() == wx_usage_before;
    let child_writer_retirement = child.acknowledge_retirement(child_readonly.retirement)?;
    child_shared_claim = child_readonly.claim;
    let parent_shared_executable = parent.protect(
        &parent_shared_claim,
        parent_shared_claim.range(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        Some(&shared_publication),
    )?;
    let parent_writer_retirement =
        parent.acknowledge_retirement(parent_shared_executable.retirement)?;
    parent_shared_claim = parent_shared_executable.claim;
    let parent_wx_report = parent.report()?;
    let child_wx_report = child.report()?;
    let parent_wx_page = parent_wx_report
        .mappings
        .iter()
        .find(|entry| entry.gva == parent_shared_claim.range)
        .ok_or(HvfMemoryError::Witness("parent shared executable missing"))?;
    let child_wx_page = child_wx_report
        .mappings
        .iter()
        .find(|entry| entry.gva == child_shared_claim.range)
        .ok_or(HvfMemoryError::Witness(
            "child shared read-only mapping missing",
        ))?;
    let global_wx_fork_retirement_verified = parent_execute_blocked
        && wx_rejection_had_no_effect
        && child_writer_retirement.data_pages == 1
        && child_writer_retirement.released_data_pages == 1
        && parent_writer_retirement.data_pages == 1
        && parent_writer_retirement.released_data_pages == 1
        && parent_wx_page.backing_identity == child_wx_page.backing_identity
        && parent_wx_page.permissions == HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE
        && child_wx_page.permissions == HvfGuestPermissions::READ
        && memory.usage().quarantined_resources == 0;
    let child_private_claim = child
        .claims
        .iter()
        .find(|claim| claim.range == coalesced.claim.range)
        .cloned()
        .ok_or(HvfMemoryError::Witness("child private claim missing"))?;
    child.write_alias(&child_private_claim, middle.clone(), |bytes| {
        bytes[..8].copy_from_slice(&0x4348_494c_4430_3031u64.to_le_bytes());
    })?;
    let private_fork_verified = private_fork_verified
        && parent.read_alias(&coalesced.claim, middle.clone(), |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? != 0x4348_494c_4430_3031;

    parent.write_alias(&coalesced.claim, middle.clone(), |bytes| {
        bytes[..4].copy_from_slice(&0xd503_201fu32.to_le_bytes());
    })?;
    let before_stale = parent.report()?.root_generation;
    let stale_publication_rejected = matches!(
        parent.protect(
            &coalesced.claim,
            middle.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            None,
        ),
        Err(HvfMemoryError::PublicationRequired(_))
    ) && parent.report()?.root_generation == before_stale;
    let publication = parent.publish_executable(&coalesced.claim, middle.clone())?;
    let authority_rollback_before = parent.report()?;
    let authority_rollback_usage_before = memory.usage();
    memory.inject_failure(FailurePoint::AuthorityTransition);
    let authority_rollback_verified = matches!(
        parent.protect(
            &coalesced.claim,
            middle.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            Some(&publication),
        ),
        Err(HvfMemoryError::InjectedFailure(
            "during protect authority transition"
        ))
    ) && parent.report()? == authority_rollback_before
        && memory.usage() == authority_rollback_usage_before
        && !memory.vm.is_poisoned();
    let retired_data_ipa = parent.software_walk(middle.start)?.0 & !(PAGE_SIZE as u64 - 1);
    let executable = parent.protect(
        &coalesced.claim,
        middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        Some(&publication),
    )?;
    let executable_retirement = executable.retirement.clone();
    let replacement_data_ipa = parent.software_walk(middle.start)?.0 & !(PAGE_SIZE as u64 - 1);
    let (retired_data_token, retired_ipa_owned_before_ack) = {
        let arenas = memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let acknowledgements = memory
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retired = acknowledgements
            .retirements
            .get(&executable_retirement.id)
            .ok_or(HvfMemoryError::RetirementStale)?;
        if retired.address_space != parent.id()
            || retired.generation != executable_retirement.generation
            || retired.data.len() != 1
        {
            return Err(HvfMemoryError::RetirementStale);
        }
        let token = retired.data[0].mapping.ipa;
        (
            token,
            token.start == retired_data_ipa && arenas.ipa.owns(token),
        )
    };
    let executable_retirement_report = parent.acknowledge_retirement(executable.retirement)?;
    let retired_ipa_released_after_ack = {
        let arenas = memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !arenas.ipa.owns(retired_data_token)
    };
    let retired_ipa_held_until_ack_verified = retired_ipa_owned_before_ack
        && replacement_data_ipa != retired_data_ipa
        && executable_retirement_report.data_pages == 1
        && executable_retirement_report.released_data_pages == 1
        && retired_ipa_released_after_ack;
    let publication_epoch_verified = parent
        .report()?
        .mappings
        .iter()
        .find(|entry| entry.gva == middle)
        .is_some_and(|entry| entry.publication_epoch.0 == entry.write_epoch.0);

    let before_rollback = parent.report()?.root_generation;
    memory.inject_failure(FailurePoint::BeforeRootPublish);
    let rollback_verified = authority_rollback_verified
        && matches!(
            parent.protect(
                &executable.claim,
                middle.clone(),
                HvfGuestPermissions::READ,
                None,
            ),
            Err(HvfMemoryError::InjectedFailure(_))
        )
        && parent.report()?.root_generation == before_rollback;
    let oversized_start = 0x0000_a000_0000_0000usize;
    let oversized_pages = memory.limits.max_mutation_pages + 1;
    let oversized_end = oversized_start + oversized_pages * PAGE_SIZE;
    let all_resource_limits_verified = all_resource_limits_verified
        && matches!(
            parent.claim(
                oversized_start..oversized_end,
                HvfGuestPermissions::NONE,
                HvfSharing::Private,
            ),
            Err(HvfMemoryError::ResourceLimit {
                resource: "mutation pages",
                ..
            })
        );

    let unmap_exec = parent.unmap(&executable.claim, executable.claim.range())?;
    parent.acknowledge_retirement(unmap_exec.retirement)?;
    let unmap_shared = parent.unmap(&parent_shared_claim, parent_shared_claim.range())?;
    parent.acknowledge_retirement(unmap_shared.retirement)?;
    for claim in boundary_claims {
        let unmap = parent.unmap(&claim, claim.range())?;
        parent.acknowledge_retirement(unmap.retirement)?;
    }
    for claim in &child.claims {
        let claim = if claim.range == child_shared_claim.range {
            &child_shared_claim
        } else {
            claim
        };
        let unmap = child.unmap(claim, claim.range())?;
        child.acknowledge_retirement(unmap.retirement)?;
    }
    let retirement_verified = memory.usage().retired_generations == 0;
    let parent_asid = parent.asid();
    child.destroy()?;
    parent.destroy()?;
    competitor.destroy()?;
    let recycled = memory.create_address_space()?;
    spaces.push(recycled.clone());
    let recycled_asid = recycled.asid();
    let asid_reuse_verified =
        recycled_asid.value == parent_asid.value && recycled_asid.epoch == parent_asid.epoch + 1;
    recycled.destroy()?;
    let final_usage = memory.usage();
    let physical_accounting_verified = physical_accounting_verified
        && final_usage.physical_backing_pages == 0
        && final_usage.physical_backing_bytes == 0;
    let allocator_conservation_verified = final_usage.ipa_owned_pages == 0
        && final_usage.asids_owned == 0
        && final_usage.ipa_capacity_pages
            == memory
                .limits
                .max_live_data_pages
                .checked_add(memory.limits.max_table_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
    let sdk_residuals = memory.vm.residual_report()?;
    let zero_vcpus_verified = initial_vcpus == 0
        && sdk_residuals.active_vcpus == 0
        && sdk_residuals.quarantined_vcpus == 0
        && sdk_residuals.zero_vcpu_operation_active
        && sdk_residuals.zero_vcpu_owned_by_current_thread;
    let report = HvfMemoryReport {
        configured_ipa_bits: memory.vm.report().configured_ipa_bits,
        monitor_ipa: memory._monitor_mapping.ipa(),
        regime: memory.regime,
        monitor_leaf_verified,
        dynamic_tcr_ips_verified,
        sparse_claim_verified,
        split_verified,
        coalesce_verified,
        all_stage_one_boundaries_verified,
        nonzero_offsets_verified,
        compact_nonidentity_ipa_verified,
        exact_ipa_reuse_verified,
        retired_ipa_held_until_ack_verified,
        overlap_rejection_verified,
        adjacent_claims_verified,
        independent_roots_verified,
        competitor_isolation_verified,
        asid_reuse_verified,
        alias_reservation_verified,
        alias_preflight_verified,
        alias_reentry_verified,
        alias_concurrency_verified,
        alias_panic_cleanup_verified,
        private_fork_verified,
        fork_capability_order_verified,
        shared_coherence_verified,
        global_wx_fork_retirement_verified,
        initial_execute_rejected,
        publication_epoch_verified,
        stale_publication_rejected,
        all_resource_limits_verified,
        rollback_verified,
        retirement_verified,
        retirement_checkpoints_verified,
        physical_accounting_verified,
        allocator_conservation_verified,
        zero_vcpus_verified,
        final_usage,
        sdk_residuals,
        host_backing,
        vm_poisoned: memory.vm.is_poisoned(),
    };
    if !report.monitor_leaf_verified
        || !report.dynamic_tcr_ips_verified
        || !report.sparse_claim_verified
        || !report.split_verified
        || !report.coalesce_verified
        || !report.all_stage_one_boundaries_verified
        || !report.nonzero_offsets_verified
        || !report.compact_nonidentity_ipa_verified
        || !report.exact_ipa_reuse_verified
        || !report.retired_ipa_held_until_ack_verified
        || !report.overlap_rejection_verified
        || !report.adjacent_claims_verified
        || !report.independent_roots_verified
        || !report.competitor_isolation_verified
        || !report.asid_reuse_verified
        || !report.alias_reservation_verified
        || !report.alias_preflight_verified
        || !report.alias_reentry_verified
        || !report.alias_concurrency_verified
        || !report.alias_panic_cleanup_verified
        || !report.private_fork_verified
        || !report.fork_capability_order_verified
        || !report.shared_coherence_verified
        || !report.global_wx_fork_retirement_verified
        || !report.initial_execute_rejected
        || !report.publication_epoch_verified
        || !report.stale_publication_rejected
        || !report.all_resource_limits_verified
        || !report.rollback_verified
        || !report.retirement_verified
        || !report.retirement_checkpoints_verified
        || !report.physical_accounting_verified
        || !report.allocator_conservation_verified
        || !report.zero_vcpus_verified
        || report.final_usage.address_spaces != 0
        || report.final_usage.claimed_pages != 0
        || report.final_usage.live_data_pages != 0
        || report.final_usage.table_pages != 0
        || report.final_usage.host_slots != 0
        || report.final_usage.backing_objects != 0
        || report.final_usage.physical_backing_pages != 0
        || report.final_usage.physical_backing_bytes != 0
        || report.final_usage.ipa_owned_pages != 0
        || report.final_usage.asids_owned != 0
        || report.final_usage.active_alias_pages != 0
        || report.final_usage.alias_quarantine_reservations != 0
        || report.final_usage.data_quarantine_reservations != 0
        || report.final_usage.retired_generations != 0
        || report.final_usage.retired_pages != 0
        || report.final_usage.retired_bytes != 0
        || report.final_usage.quarantined_resources != 0
        || !report.sdk_residuals.is_empty()
        || !report.sdk_residuals.zero_vcpu_operation_active
        || !report.sdk_residuals.zero_vcpu_owned_by_current_thread
        || report.vm_poisoned
    {
        return Err(HvfMemoryError::WitnessReport(Box::new(report)));
    }
    Ok(report)
}

pub fn hvf_memory_failure_probe() -> Result<HvfMemoryFailureReport, HvfMemoryError> {
    with_hvf_memory_failure_probe(|report| report.clone())
}

pub fn with_hvf_memory_failure_probe<T>(
    consume: impl FnOnce(&HvfMemoryFailureReport) -> T,
) -> Result<T, HvfMemoryError> {
    let memory = process_hvf_memory()?;
    memory.vm.with_zero_vcpu_operation(|_| {
        let report = hvf_memory_failure_probe_inner(memory)?;
        Ok(consume(&report))
    })
}

fn hvf_memory_failure_probe_inner(
    memory: &'static HvfMemory,
) -> Result<HvfMemoryFailureReport, HvfMemoryError> {
    let mut spaces = Vec::new();
    spaces
        .try_reserve_exact(1)
        .map_err(|_| HvfMemoryError::MetadataAllocation("failure probe spaces"))?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        hvf_memory_failure_probe_tracked(memory, &mut spaces)
    }));
    let cleanup = finish_probe_spaces(memory, &spaces);
    match result {
        Ok(result) => {
            cleanup?;
            result
        }
        Err(payload) => {
            cleanup?;
            resume_unwind(payload)
        }
    }
}

fn hvf_memory_failure_probe_tracked(
    memory: &'static HvfMemory,
    spaces: &mut Vec<HvfAddressSpace>,
) -> Result<HvfMemoryFailureReport, HvfMemoryError> {
    let initial_vcpus = memory.vm.active_vcpu_count();
    let space = memory.create_address_space()?;
    spaces.push(space.clone());
    let start = 0x0000_0300_0000_0000usize;
    let mutation = space.claim(
        start..start + PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Private,
    )?;
    space.acknowledge_retirement(mutation.retirement)?;
    let before = space.report()?.root_generation;
    memory.inject_failure(FailurePoint::BeforeRootPublish);
    let rollback_preserved_root = matches!(
        space.protect(
            &mutation.claim,
            mutation.claim.range(),
            HvfGuestPermissions::READ,
            None,
        ),
        Err(HvfMemoryError::InjectedFailure(_))
    ) && space.report()?.root_generation == before;

    let first = space.protect(
        &mutation.claim,
        mutation.claim.range(),
        HvfGuestPermissions::READ,
        None,
    )?;
    let second = space.protect(
        &first.claim,
        first.claim.range(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        None,
    )?;
    memory.inject_failure(FailurePoint::AliasRestore);
    let alias_restore_failure_observed = matches!(
        space.write_alias(&second.claim, second.claim.range(), |bytes| {
            bytes[0] = 1;
        }),
        Err(HvfMemoryError::AliasRestore(_))
    );

    memory.inject_failure(FailurePoint::DataUnmap);
    let data_unmap_failure_observed = space.acknowledge_retirement(first.retirement).is_err();
    memory.inject_failure(FailurePoint::TableUnmap);
    let table_unmap_failure_observed = space.acknowledge_retirement(second.retirement).is_err();
    let quarantine_count_before_retry = memory.usage().quarantined_resources;
    let quarantine_retry = memory.retry_quarantined_resources()?;
    let final_quarantine_count = quarantine_retry.remaining.quarantined_resources;
    let post_poison_destroy_succeeded = space.destroy().is_ok();
    let final_usage = memory.usage();
    let sdk_residuals = memory.vm.residual_report()?;
    let zero_vcpus_verified = initial_vcpus == 0
        && sdk_residuals.active_vcpus == 0
        && sdk_residuals.quarantined_vcpus == 0
        && sdk_residuals.zero_vcpu_operation_active
        && sdk_residuals.zero_vcpu_owned_by_current_thread;
    let report = HvfMemoryFailureReport {
        rollback_preserved_root,
        alias_restore_failure_observed,
        data_unmap_failure_observed,
        table_unmap_failure_observed,
        quarantine_count_before_retry,
        quarantine_retry,
        final_quarantine_count,
        post_poison_destroy_succeeded,
        zero_vcpus_verified,
        final_usage,
        sdk_residuals,
        vm_poisoned: memory.vm.is_poisoned(),
    };
    if !report.rollback_preserved_root
        || !report.alias_restore_failure_observed
        || !report.data_unmap_failure_observed
        || !report.table_unmap_failure_observed
        || report.quarantine_count_before_retry != 3
        || report.quarantine_retry.aliases_restored != 1
        || report.quarantine_retry.data_pages_released != 1
        || report.quarantine_retry.table_pages_released != 1
        || report.final_quarantine_count != 0
        || !report.post_poison_destroy_succeeded
        || !report.zero_vcpus_verified
        || report.final_usage.address_spaces != 0
        || report.final_usage.claimed_pages != 0
        || report.final_usage.live_data_pages != 0
        || report.final_usage.table_pages != 0
        || report.final_usage.host_slots != 0
        || report.final_usage.backing_objects != 0
        || report.final_usage.active_alias_pages != 0
        || report.final_usage.retired_generations != 0
        || report.final_usage.retired_pages != 0
        || report.final_usage.retired_bytes != 0
        || report.final_usage.quarantined_resources != 0
        || !report.sdk_residuals.is_empty()
        || !report.sdk_residuals.zero_vcpu_operation_active
        || !report.sdk_residuals.zero_vcpu_owned_by_current_thread
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::FailureWitnessReport(Box::new(report)));
    }
    Ok(report)
}

fn finish_probe_spaces(
    memory: &'static HvfMemory,
    spaces: &[HvfAddressSpace],
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for space in spaces.iter().rev() {
        loop {
            let ticket = {
                let acknowledgements = memory
                    .acknowledgements
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                acknowledgements
                    .retirements
                    .iter()
                    .find(|(_, retired)| retired.address_space == space.id())
                    .map(|(&id, retired)| HvfRetirementTicket {
                        manager: memory.manager,
                        address_space: space.id(),
                        id,
                        generation: retired.generation,
                    })
            };
            let Some(ticket) = ticket else {
                break;
            };
            if let Err(error) = space.acknowledge_retirement(ticket) {
                first_error.get_or_insert(error);
            }
        }
        match space.destroy() {
            Ok(()) | Err(HvfMemoryError::AddressSpaceDestroyed(_)) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if memory.usage().quarantined_resources != 0
        && let Err(error) = memory.retry_quarantined_resources()
    {
        first_error.get_or_insert(error);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub fn hvf_poison_concurrency_probe() -> Result<HvfPoisonConcurrencyReport, HvfMemoryError> {
    let vm = process_hvf_vm()?;
    std::thread::scope(|scope| {
        let (
            (
                poison_requested_while_owner_live,
                normal_rejected_while_owner_live,
                contender_timed_out_while_owner_live,
                poison_waited_for_owner_release,
            ),
            poisoner,
        ) = vm.with_operation(|_| {
            let contender = std::thread::Builder::new()
                .spawn_scoped(scope, || {
                    vm.with_operation_timeout(std::time::Duration::ZERO, |_| Ok::<_, HvfError>(()))
                })
                .map_err(|_| HvfMemoryError::Witness("failed to create operation worker"))?;
            let contender_timed_out_while_owner_live = matches!(
                contender
                    .join()
                    .map_err(|_| HvfMemoryError::Witness("operation worker panicked"))?,
                Err(HvfError::OperationWaitTimeout)
            );
            let poisoner = std::thread::Builder::new()
                .spawn_scoped(scope, || vm.poison())
                .map_err(|_| HvfMemoryError::Witness("failed to create poison worker"))?;
            vm.wait_for_poison_request()?;
            Ok::<_, HvfMemoryError>((
                (
                    vm.poison_requested(),
                    matches!(
                        vm.with_operation(|_| Ok::<_, HvfError>(())),
                        Err(HvfError::Poisoned)
                    ),
                    contender_timed_out_while_owner_live,
                    !vm.is_poisoned(),
                ),
                poisoner,
            ))
        })?;
        poisoner
            .join()
            .map_err(|_| HvfMemoryError::Witness("poison worker panicked"))?;
        let cleanup_admitted_after_poison =
            vm.with_cleanup_operation(|_| Ok::<_, HvfError>(())).is_ok();
        let report = HvfPoisonConcurrencyReport {
            poison_requested_while_owner_live,
            normal_rejected_while_owner_live,
            contender_timed_out_while_owner_live,
            poison_waited_for_owner_release,
            cleanup_admitted_after_poison,
            vm_poisoned: vm.is_poisoned(),
        };
        if !report.poison_requested_while_owner_live
            || !report.normal_rejected_while_owner_live
            || !report.contender_timed_out_while_owner_live
            || !report.poison_waited_for_owner_release
            || !report.cleanup_admitted_after_poison
            || !report.vm_poisoned
        {
            return Err(HvfMemoryError::Witness(
                "poison serialization witness failed",
            ));
        }
        Ok(report)
    })
}

pub fn hvf_register_failure_probe() -> Result<HvfRegisterFailureReport, HvfMemoryError> {
    let vm = process_hvf_vm()?;
    let mut vcpu = vm.create_vcpu()?;
    let vcpu_registered_to_current_thread =
        vm.active_vcpu_count() == 1 && vm.active_vcpu_count_for_current_thread() == 1;
    let expected_ttbr0 = PAGE_SIZE as u64;
    let expected_tcr = tcr_el1(vm.report().configured_ipa_bits);
    let programmed_stage_one =
        vcpu.program_stage_one(expected_ttbr0, expected_tcr, MAIR_ATTR0_NORMAL_WB)?;
    let stage_one_programming_verified = programmed_stage_one.ttbr0_el1 == expected_ttbr0
        && programmed_stage_one.tcr_el1 == expected_tcr
        && programmed_stage_one.mair_el1 == MAIR_ATTR0_NORMAL_WB;
    let result =
        vcpu.induce_stage_one_readback_mismatch(expected_ttbr0, expected_tcr, MAIR_ATTR0_NORMAL_WB);
    let mismatch_rejected = result.as_ref().err().is_some_and(stage_one_mismatch_error);
    drop(vcpu);
    let cleanup_retry_released_vcpus = vm.retry_quarantined_vcpus_for_current_thread()?;
    let active_vcpu_count = vm.active_vcpu_count();
    let quarantined_vcpu_count = vm.quarantined_vcpu_count();
    let report = HvfRegisterFailureReport {
        programmed_stage_one,
        stage_one_programming_verified,
        mismatch_rejected,
        vcpu_registered_to_current_thread,
        vcpu_destroyed_without_residual: active_vcpu_count == 0 && quarantined_vcpu_count == 0,
        cleanup_retry_released_vcpus,
        active_vcpu_count,
        quarantined_vcpu_count,
        vm_poisoned: vm.is_poisoned(),
    };
    if !report.stage_one_programming_verified
        || !report.mismatch_rejected
        || !report.vcpu_registered_to_current_thread
        || !report.vcpu_destroyed_without_residual
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::Witness("register failure witness failed"));
    }
    Ok(report)
}

pub fn hvf_unmap_failure_probe() -> Result<HvfUnmapFailureReport, HvfMemoryError> {
    let process_lifetime_pages = PROCESS_HVF_FAILURE_PROBE_PAGES
        .get_or_init(|| Box::new(ProbeFailurePages([0; 4 * PAGE_SIZE])));
    let vm = process_hvf_vm()?;
    let start = process_lifetime_pages.0.as_ptr() as usize;
    let explicit = unsafe {
        vm.map_host_range(
            start..start + PAGE_SIZE,
            PAGE_SIZE as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let cleanup = unsafe {
        vm.map_host_range(
            start + PAGE_SIZE..start + 2 * PAGE_SIZE,
            (2 * PAGE_SIZE) as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let mut protect = unsafe {
        vm.map_host_range(
            start + 2 * PAGE_SIZE..start + 3 * PAGE_SIZE,
            (3 * PAGE_SIZE) as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let unmap = unsafe {
        vm.map_host_range(
            start + 3 * PAGE_SIZE..start + 4 * PAGE_SIZE,
            (4 * PAGE_SIZE) as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let explicit_unmap_succeeded = explicit.unmap().is_ok();
    let protect_failure_observed = matches!(
        protect.induce_protect_failure(),
        Err(HvfError::Call {
            operation: "hv_vm_protect",
            ..
        })
    );
    let protect_residuals = vm.residual_report()?;
    let protect_failure_quarantined = protect_residuals.logical_mapping_tokens == 1
        && protect_residuals.known_present_fragments == 1
        && protect_residuals.unknown_fragments == 0
        && protect_residuals.permissions_unknown_mapping_tokens == 1;
    let quarantined_handle_rejected_cleanup =
        matches!(protect.unmap(), Err(HvfError::MappingNotLive));
    let unmap_failure_observed = matches!(
        unmap.induce_unmap_failure(),
        Err(HvfError::Call {
            operation: "hv_vm_unmap",
            ..
        })
    );
    let sdk_residuals_before_retry = vm.residual_report()?;
    let unmap_failure_quarantined = sdk_residuals_before_retry.logical_mapping_tokens == 2
        && sdk_residuals_before_retry.known_present_fragments == 1
        && sdk_residuals_before_retry.unknown_fragments == 1
        && sdk_residuals_before_retry.permissions_unknown_mapping_tokens == 1;
    let cleanup_retry_cleared_fragments = vm.retry_quarantined_mappings()?;
    let sdk_residuals_after_retry = vm.residual_report()?;
    let post_poison_cleanup_succeeded = cleanup.unmap().is_ok();
    let final_sdk_residuals = vm.residual_report()?;
    let report = HvfUnmapFailureReport {
        explicit_unmap_succeeded,
        protect_failure_observed,
        protect_failure_quarantined,
        quarantined_handle_rejected_cleanup,
        unmap_failure_observed,
        unmap_failure_quarantined,
        sdk_residuals_before_retry,
        cleanup_retry_cleared_fragments,
        sdk_residuals_after_retry,
        final_sdk_residuals,
        post_poison_cleanup_succeeded,
        vm_poisoned: vm.is_poisoned(),
    };
    if !report.explicit_unmap_succeeded
        || !report.protect_failure_observed
        || !report.protect_failure_quarantined
        || !report.quarantined_handle_rejected_cleanup
        || !report.unmap_failure_observed
        || !report.unmap_failure_quarantined
        || report.cleanup_retry_cleared_fragments != 2
        || !report.sdk_residuals_after_retry.is_empty()
        || !report.final_sdk_residuals.is_empty()
        || !report.post_poison_cleanup_succeeded
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::Witness("unmap failure witness failed"));
    }
    Ok(report)
}

fn create_monitor_root(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    table_limit: usize,
) -> Result<TableToken, HvfMemoryError> {
    let mut created = Vec::new();
    created
        .try_reserve_exact(1)
        .map_err(|_| HvfMemoryError::MetadataAllocation("monitor root rollback"))?;
    let bytes = Box::new(StageOneTable([0; TABLE_ENTRIES]));
    let root =
        arenas
            .tables
            .allocate(vm, &mut arenas.ipa, 0, bytes, HashMap::new(), table_limit)?;
    if let Err(error) = arenas.tables.retain(root) {
        created.push(root);
        if let Err(cleanup) = cleanup_created_tables(vm, arenas, &mut created) {
            return Err(cleanup);
        }
        return Err(error);
    }
    let descriptor = DESCRIPTOR_VALID_TABLE_OR_PAGE
        | DESCRIPTOR_AP_EL0_NONE_EL1_RO
        | DESCRIPTOR_INNER_SHAREABLE
        | DESCRIPTOR_ACCESS_FLAG
        | DESCRIPTOR_NOT_GLOBAL
        | DESCRIPTOR_UXN;
    let candidate = match build_candidate_root(vm, arenas, root, &[(0, descriptor)], table_limit) {
        Ok(candidate) => candidate,
        Err(error) => {
            cleanup_candidate_root(vm, arenas, root)?;
            return Err(error);
        }
    };
    if let Err(error) = cleanup_candidate_root(vm, arenas, root) {
        cleanup_candidate_root(vm, arenas, candidate)?;
        return Err(error);
    }
    Ok(candidate)
}

fn build_candidate_root(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    current: TableToken,
    updates: &[(usize, u64)],
    table_limit: usize,
) -> Result<TableToken, HvfMemoryError> {
    arenas.tables.retain(current)?;
    let mut candidate = current;
    for &(gva, descriptor) in updates {
        let result =
            arenas
                .tables
                .cow_leaf(vm, &mut arenas.ipa, candidate, gva, descriptor, table_limit);
        let (next, mut created) = match result {
            Ok(value) => value,
            Err(error) => {
                cleanup_candidate_root(vm, arenas, candidate)?;
                return Err(error);
            }
        };
        if let Err(error) = arenas.tables.retain(next) {
            let created_cleanup = cleanup_created_tables(vm, arenas, &mut created);
            let candidate_cleanup = cleanup_candidate_root(vm, arenas, candidate);
            created_cleanup?;
            candidate_cleanup?;
            return Err(error);
        }
        if let Err(error) = cleanup_candidate_root(vm, arenas, candidate) {
            let next_cleanup = cleanup_candidate_root(vm, arenas, next);
            next_cleanup?;
            return Err(error);
        }
        candidate = next;
    }
    Ok(candidate)
}

fn cleanup_created_tables(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    created: &mut Vec<TableToken>,
) -> Result<(), HvfMemoryError> {
    let records = match arenas.tables.discard_unreferenced(created) {
        Ok(records) => records,
        Err(error) => {
            let quarantine = arenas.tables.abandon_unreferenced(created);
            vm.poison();
            quarantine?;
            return Err(error);
        }
    };
    cleanup_table_records(vm, arenas, records)
}

fn cleanup_candidate_root(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    root: TableToken,
) -> Result<(), HvfMemoryError> {
    let records = match arenas.tables.release(root) {
        Ok(records) => records,
        Err(error) => {
            let quarantine = arenas.tables.abandon_root(root);
            vm.poison();
            quarantine?;
            return Err(error);
        }
    };
    cleanup_table_records(vm, arenas, records)
}

fn cleanup_table_records(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    records: Vec<TableRecord>,
) -> Result<(), HvfMemoryError> {
    let inject_failure = arenas.take_failure(FailurePoint::TableUnmap);
    cleanup_detached_table_records(
        vm,
        &mut arenas.tables,
        &mut arenas.ipa,
        records,
        inject_failure,
    )
}

fn cleanup_detached_table_records(
    vm: &'static HvfVm,
    tables: &mut TableArena,
    ipa: &mut IpaAllocator,
    records: Vec<TableRecord>,
    inject_first_failure: bool,
) -> Result<(), HvfMemoryError> {
    tables
        .quarantined
        .try_reserve(records.len())
        .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
    let mut first_error = None;
    let mut injected = false;
    for mut record in records {
        let Some(mapping) = record.mapping.take() else {
            tables.quarantined.push(TableQuarantine {
                ipa: Some(record.ipa),
                bytes: record.bytes,
                sdk_token: None,
                retryable: false,
            });
            vm.poison();
            first_error.get_or_insert(HvfMemoryError::TableOwnership);
            continue;
        };
        let sdk_token = mapping.token();
        let unmap = if inject_first_failure && !injected {
            injected = true;
            mapping.induce_unmap_failure()
        } else {
            mapping.unmap()
        };
        if let Err(error) = unmap {
            tables.quarantined.push(TableQuarantine {
                ipa: Some(record.ipa),
                bytes: record.bytes,
                sdk_token: Some(sdk_token),
                retryable: true,
            });
            vm.poison();
            first_error.get_or_insert(error.into());
            continue;
        }
        if let Err(error) = ipa.release(record.ipa) {
            tables.quarantined.push(TableQuarantine {
                ipa: Some(record.ipa),
                bytes: record.bytes,
                sdk_token: None,
                retryable: true,
            });
            vm.poison();
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn map_data_page(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    backing: BackingPage,
    permissions: HvfGuestPermissions,
    release_backing_on_failure: bool,
) -> Result<DataMapping, HvfMemoryError> {
    let quarantine_reservation = acknowledgements.reserve_data_quarantine()?;
    let ipa = match arenas.ipa.allocate(1) {
        Ok(ipa) => ipa,
        Err(error) => {
            acknowledgements.release_data_quarantine_reservation(quarantine_reservation);
            if release_backing_on_failure && let Err(cleanup) = backings.release(backing) {
                vm.poison();
                return Err(cleanup);
            }
            return Err(error);
        }
    };
    let host = match backings.page_range(backing) {
        Ok(host) => host,
        Err(error) => {
            if let Err(cleanup) = cleanup_data_allocation(
                vm,
                arenas,
                backings,
                acknowledgements,
                quarantine_reservation,
                backing,
                ipa,
                None,
                release_backing_on_failure,
            ) {
                return Err(cleanup);
            }
            return Err(error);
        }
    };
    let authority = match backings.authorize_stage_two(backing, permissions) {
        Ok(authority) => authority,
        Err(error) => {
            if let Err(cleanup) = cleanup_data_allocation(
                vm,
                arenas,
                backings,
                acknowledgements,
                quarantine_reservation,
                backing,
                ipa,
                None,
                release_backing_on_failure,
            ) {
                return Err(cleanup);
            }
            return Err(error);
        }
    };
    match unsafe { vm.map_host_range(host, ipa.start, permissions.stage_two()) } {
        Ok(mapping) => Ok(DataMapping {
            backing,
            ipa,
            authority,
            mapping: Some(mapping),
            quarantine_reservation,
        }),
        Err(error) => {
            let sdk_token = match &error {
                HvfError::MappingRollback { token, .. } => Some(*token),
                _ => None,
            };
            if let Some(sdk_token) = sdk_token {
                if let Err(cleanup) = commit_failed_data_mapping(
                    vm,
                    backings,
                    acknowledgements,
                    quarantine_reservation,
                    backing,
                    ipa,
                    authority,
                    Some(sdk_token),
                    release_backing_on_failure,
                    true,
                ) {
                    return Err(cleanup);
                }
            } else if let Err(cleanup) = cleanup_data_allocation(
                vm,
                arenas,
                backings,
                acknowledgements,
                quarantine_reservation,
                backing,
                ipa,
                Some(authority),
                release_backing_on_failure,
            ) {
                return Err(cleanup);
            }
            Err(error.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cleanup_data_allocation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    quarantine_reservation: DataQuarantineReservation,
    backing: BackingPage,
    ipa: IpaToken,
    authority: Option<StageTwoAuthority>,
    release_backing_reference: bool,
) -> Result<(), HvfMemoryError> {
    let mut quarantine = DataQuarantine {
        ipa: Some(ipa),
        backing,
        authority,
        sdk_token: None,
        mapping_quarantine: false,
        release_backing_reference,
        retryable: true,
    };
    let mut first_error = None;
    if let Some(ipa) = quarantine.ipa {
        match arenas.ipa.release(ipa) {
            Ok(()) => quarantine.ipa = None,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if let Some(authority) = quarantine.authority {
        match backings.release_stage_two(quarantine.backing, authority) {
            Ok(()) => quarantine.authority = None,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if quarantine.release_backing_reference {
        match backings.release(quarantine.backing) {
            Ok(_) => quarantine.release_backing_reference = false,
            Err(error) => {
                if matches!(backings.page_has_reference(quarantine.backing), Ok(false)) {
                    quarantine.release_backing_reference = false;
                }
                first_error.get_or_insert(error);
            }
        }
    }
    let ownership_remains = quarantine.ipa.is_some()
        || quarantine.authority.is_some()
        || quarantine.release_backing_reference;
    if ownership_remains {
        acknowledgements.commit_data_quarantine(quarantine_reservation, quarantine);
        vm.poison();
        return Err(first_error.unwrap_or(HvfMemoryError::IpaOwnership));
    }
    acknowledgements.release_data_quarantine_reservation(quarantine_reservation);
    if let Some(error) = first_error {
        vm.poison();
        Err(error)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_failed_data_mapping(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    quarantine_reservation: DataQuarantineReservation,
    backing: BackingPage,
    ipa: IpaToken,
    authority: StageTwoAuthority,
    sdk_token: Option<u64>,
    release_backing_reference: bool,
    retryable: bool,
) -> Result<(), HvfMemoryError> {
    let index = acknowledgements.commit_data_quarantine(
        quarantine_reservation,
        DataQuarantine {
            ipa: Some(ipa),
            backing,
            authority: Some(authority),
            sdk_token,
            mapping_quarantine: false,
            release_backing_reference,
            retryable,
        },
    );
    if let Err(error) = backings.quarantine_mapping(backing) {
        vm.poison();
        return Err(error);
    }
    let Some(quarantine) = acknowledgements.data_quarantine.get_mut(index) else {
        vm.poison();
        return Err(HvfMemoryError::IpaOwnership);
    };
    quarantine.mapping_quarantine = true;
    Ok(())
}

fn demote_data_mapping(
    backings: &mut BackingRegistry,
    mapping: &mut DataMapping,
) -> Result<(), HvfMemoryError> {
    let authority = mapping.authority;
    if authority == StageTwoAuthority::ReadOnly {
        return Ok(());
    }
    let handle = mapping
        .mapping
        .as_mut()
        .ok_or(HvfMemoryError::IpaOwnership)?;
    handle.protect(HvfMapPermissions::READ)?;
    backings.release_stage_two(mapping.backing, authority)?;
    mapping.authority = StageTwoAuthority::ReadOnly;
    Ok(())
}

fn promote_data_mapping(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    mapping: &mut DataMapping,
    permissions: HvfGuestPermissions,
) -> Result<(), HvfMemoryError> {
    let target = StageTwoAuthority::for_permissions(permissions);
    if target == StageTwoAuthority::ReadOnly {
        return Ok(());
    }
    if mapping.authority != StageTwoAuthority::ReadOnly {
        return Err(HvfMemoryError::IpaOwnership);
    }
    let authority = backings.authorize_stage_two(mapping.backing, permissions)?;
    mapping.authority = authority;
    let Some(handle) = mapping.mapping.as_mut() else {
        vm.poison();
        return Err(HvfMemoryError::IpaOwnership);
    };
    handle.protect(permissions.stage_two())?;
    Ok(())
}

fn rollback_protect_authorities(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    replacements: &mut HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for gva in page_addresses(range) {
        let Some(mapping) = replacements
            .get_mut(&gva)
            .and_then(|page| page.mapping.as_mut())
        else {
            continue;
        };
        if mapping.authority != StageTwoAuthority::ReadOnly
            && let Err(error) = demote_data_mapping(backings, mapping)
        {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_none() {
        for gva in page_addresses(range) {
            let Some(old) = claim.pages.get_mut(&gva) else {
                first_error.get_or_insert(HvfMemoryError::ClaimStale);
                continue;
            };
            let expected = StageTwoAuthority::for_permissions(old.permissions);
            match old.mapping.as_mut() {
                Some(mapping) if mapping.authority == expected => {}
                Some(mapping)
                    if mapping.authority == StageTwoAuthority::ReadOnly
                        && expected != StageTwoAuthority::ReadOnly =>
                {
                    if let Err(error) = promote_data_mapping(vm, backings, mapping, old.permissions)
                    {
                        first_error.get_or_insert(error);
                    }
                }
                Some(_) => {
                    first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                }
                None if old.permissions == HvfGuestPermissions::NONE => {}
                None => {
                    first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                }
            }
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn protect_authority_failure(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    replacements: &mut HashMap<usize, PageState>,
    trigger: HvfMemoryError,
) -> HvfMemoryError {
    if vm.is_poisoned() {
        return trigger;
    }
    match rollback_protect_authorities(vm, backings, claim, range, replacements) {
        Ok(()) => trigger,
        Err(cleanup) => cleanup,
    }
}

fn apply_protect_authorities(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    permissions: HvfGuestPermissions,
    replacements: &mut HashMap<usize, PageState>,
    inject_failure: bool,
) -> Result<(), HvfMemoryError> {
    let target = StageTwoAuthority::for_permissions(permissions);
    if target == StageTwoAuthority::Executor {
        for gva in page_addresses(range) {
            let mapping = replacements
                .get(&gva)
                .and_then(|page| page.mapping.as_ref())
                .ok_or(HvfMemoryError::IpaOwnership)?;
            backings.prepare_executable_host(mapping.backing)?;
        }
    }
    for gva in page_addresses(range) {
        let Some(old) = claim.pages.get_mut(&gva) else {
            let trigger = HvfMemoryError::ClaimStale;
            return Err(protect_authority_failure(
                vm,
                backings,
                claim,
                range,
                replacements,
                trigger,
            ));
        };
        let Some(mapping) = old.mapping.as_mut() else {
            continue;
        };
        let opposing = matches!(
            (mapping.authority, target),
            (StageTwoAuthority::Writer, StageTwoAuthority::Executor)
                | (StageTwoAuthority::Executor, StageTwoAuthority::Writer)
        );
        if opposing && let Err(error) = demote_data_mapping(backings, mapping) {
            return Err(protect_authority_failure(
                vm,
                backings,
                claim,
                range,
                replacements,
                error,
            ));
        }
    }
    if inject_failure {
        return Err(protect_authority_failure(
            vm,
            backings,
            claim,
            range,
            replacements,
            HvfMemoryError::InjectedFailure("during protect authority transition"),
        ));
    }
    for gva in page_addresses(range) {
        let Some(replacement) = replacements.get_mut(&gva) else {
            let trigger = HvfMemoryError::ClaimStale;
            return Err(protect_authority_failure(
                vm,
                backings,
                claim,
                range,
                replacements,
                trigger,
            ));
        };
        let Some(mapping) = replacement.mapping.as_mut() else {
            continue;
        };
        if let Err(error) = promote_data_mapping(vm, backings, mapping, permissions) {
            return Err(protect_authority_failure(
                vm,
                backings,
                claim,
                range,
                replacements,
                error,
            ));
        }
    }
    Ok(())
}

fn prepare_fork_page(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    parent: &PageState,
    private_copies: &HashMap<HvfBackingIdentity, HvfBackingIdentity>,
) -> Result<PageState, HvfMemoryError> {
    arenas.slots.retain(parent.slot)?;
    let backing = match parent.backing {
        Some(backing) => {
            let identity = if parent.sharing == HvfSharing::Shared {
                backing.identity
            } else {
                *private_copies
                    .get(&backing.identity)
                    .ok_or(HvfMemoryError::IpaOwnership)?
            };
            let child_backing = BackingPage {
                identity,
                offset: backing.offset,
            };
            if let Err(error) = backings.retain(child_backing) {
                arenas.slots.release(parent.slot)?;
                return Err(error);
            }
            Some(child_backing)
        }
        None => None,
    };
    let mapping = match backing {
        Some(backing) if parent.permissions != HvfGuestPermissions::NONE => {
            if parent.permissions.contains(HvfGuestPermissions::EXECUTE) {
                let publication = (|| {
                    let bytes = backings.page_range(backing)?;
                    vm.publish_executable_bytes(unsafe {
                        core::slice::from_raw_parts(bytes.start as *const u8, PAGE_SIZE)
                    })?;
                    Ok::<(), HvfMemoryError>(())
                })();
                if let Err(error) = publication {
                    let backing_cleanup = backings.release(backing).map(|_| ());
                    let slot_cleanup = arenas.slots.release(parent.slot).map(|_| ());
                    backing_cleanup?;
                    slot_cleanup?;
                    return Err(error);
                }
            }
            match map_data_page(
                vm,
                arenas,
                backings,
                acknowledgements,
                backing,
                parent.permissions,
                true,
            ) {
                Ok(mapping) => Some(mapping),
                Err(error) => {
                    arenas.slots.release(parent.slot)?;
                    return Err(error);
                }
            }
        }
        _ => None,
    };
    Ok(PageState {
        permissions: parent.permissions,
        sharing: parent.sharing,
        backing,
        mapping,
        slot: parent.slot,
    })
}

fn cleanup_data_mapping(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mapping: DataMapping,
    release_backing_reference: bool,
) -> Result<(), HvfMemoryError> {
    let DataMapping {
        backing,
        ipa,
        authority,
        mapping,
        quarantine_reservation,
    } = mapping;
    let Some(handle) = mapping else {
        commit_failed_data_mapping(
            vm,
            backings,
            acknowledgements,
            quarantine_reservation,
            backing,
            ipa,
            authority,
            None,
            release_backing_reference,
            false,
        )?;
        vm.poison();
        return Err(HvfMemoryError::IpaOwnership);
    };
    let sdk_token = handle.token();
    let unmap = if arenas.take_failure(FailurePoint::DataUnmap) {
        handle.induce_unmap_failure()
    } else {
        handle.unmap()
    };
    if let Err(error) = unmap {
        commit_failed_data_mapping(
            vm,
            backings,
            acknowledgements,
            quarantine_reservation,
            backing,
            ipa,
            authority,
            Some(sdk_token),
            release_backing_reference,
            true,
        )?;
        vm.poison();
        return Err(error.into());
    }
    cleanup_data_allocation(
        vm,
        arenas,
        backings,
        acknowledgements,
        quarantine_reservation,
        backing,
        ipa,
        Some(authority),
        release_backing_reference,
    )
}

fn cleanup_unpublished_pages(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    pages: impl IntoIterator<Item = PageState>,
    release_slots: bool,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for page in pages {
        let backing = page.backing;
        if let Some(mapping) = page.mapping {
            if let Err(error) = cleanup_data_mapping(
                vm,
                arenas,
                backings,
                acknowledgements,
                mapping,
                backing.is_some(),
            ) {
                first_error.get_or_insert(error);
            }
        } else if let Some(backing) = backing
            && let Err(error) = backings.release(backing)
        {
            first_error.get_or_insert(error);
        }
        if release_slots && let Err(error) = arenas.slots.release(page.slot) {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_unpublished_page_map(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mut pages: HashMap<usize, PageState>,
    release_slots: bool,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(gva) = pages.keys().copied().min() {
        let Some(page) = pages.remove(&gva) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        if let Err(error) = cleanup_unpublished_pages(
            vm,
            arenas,
            backings,
            acknowledgements,
            core::iter::once(page),
            release_slots,
        ) {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_replacements(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    old_backings: &HashMap<usize, Option<BackingPage>>,
    mut pages: HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(gva) = pages.keys().copied().min() {
        let Some(page) = pages.remove(&gva) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        let old_backing = match old_backings.get(&gva) {
            Some(backing) => Some(*backing),
            None => {
                first_error.get_or_insert(HvfMemoryError::ClaimStale);
                None
            }
        };
        let release_backing_reference = old_backing
            .is_some_and(|old_backing| page.backing.is_some() && page.backing != old_backing);
        if let Some(mapping) = page.mapping {
            if let Err(error) = cleanup_data_mapping(
                vm,
                arenas,
                backings,
                acknowledgements,
                mapping,
                release_backing_reference,
            ) {
                first_error.get_or_insert(error);
            }
        } else if release_backing_reference
            && let Some(backing) = page.backing
            && let Err(error) = backings.release(backing)
        {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn release_host_slots(
    slots: &mut HostSlotArena,
    tokens: impl IntoIterator<Item = HostSlotToken>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for token in tokens {
        if let Err(error) = slots.release(token) {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn release_backing_references(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    references: impl IntoIterator<Item = BackingPage>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for backing in references {
        if let Err(error) = backings.release(backing) {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_claim_preparation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    pages: HashMap<usize, PageState>,
    slots: impl IntoIterator<Item = HostSlotToken>,
    backing: Option<HvfBackingIdentity>,
) -> Result<(), HvfMemoryError> {
    let pages_cleanup =
        cleanup_unpublished_page_map(vm, arenas, backings, acknowledgements, pages, false);
    let slots_cleanup = release_host_slots(&mut arenas.slots, slots);
    let backing_cleanup = match backing {
        Some(identity) if backings.records.contains_key(&identity) => {
            backings.discard_unreferenced(identity).map(|_| ())
        }
        _ => Ok(()),
    };
    if pages_cleanup.is_err() || slots_cleanup.is_err() || backing_cleanup.is_err() {
        vm.poison();
    }
    pages_cleanup?;
    slots_cleanup?;
    backing_cleanup
}

fn cleanup_failed_protect(
    memory: &HvfMemory,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    reservation: Option<RetirementReservation>,
    retained_backings: Vec<BackingPage>,
    candidate: TableToken,
    old_backings: &HashMap<usize, Option<BackingPage>>,
    replacements: HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let reservation_cleanup = match reservation {
        Some(reservation) => memory.cancel_retirement_reservation(acknowledgements, reservation),
        None => Ok(()),
    };
    let backing_cleanup = release_backing_references(memory.vm, backings, retained_backings);
    let preparation_cleanup = cleanup_protect_preparation(
        memory.vm,
        arenas,
        backings,
        acknowledgements,
        candidate,
        old_backings,
        replacements,
    );
    if reservation_cleanup.is_err() || backing_cleanup.is_err() || preparation_cleanup.is_err() {
        memory.vm.poison();
    }
    reservation_cleanup?;
    backing_cleanup?;
    preparation_cleanup
}

fn cleanup_protect_preparation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    candidate: TableToken,
    old_backings: &HashMap<usize, Option<BackingPage>>,
    pages: HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let table_cleanup = cleanup_candidate_root(vm, arenas, candidate);
    let data_cleanup =
        cleanup_replacements(vm, arenas, backings, acknowledgements, old_backings, pages);
    table_cleanup?;
    data_cleanup
}

fn cleanup_claim_records(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mut claims: HashMap<usize, ClaimRecord>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(start) = claims.keys().copied().min() {
        let Some(mut claim) = claims.remove(&start) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        for gva in page_addresses(&claim.range) {
            let Some(page) = claim.pages.remove(&gva) else {
                first_error.get_or_insert(HvfMemoryError::ClaimStale);
                continue;
            };
            if let Err(error) = cleanup_unpublished_pages(
                vm,
                arenas,
                backings,
                acknowledgements,
                core::iter::once(page),
                true,
            ) {
                first_error.get_or_insert(error);
            }
        }
        while let Some(gva) = claim.pages.keys().copied().min() {
            let page = claim.pages.remove(&gva).ok_or(HvfMemoryError::ClaimStale)?;
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            if let Err(error) = cleanup_unpublished_pages(
                vm,
                arenas,
                backings,
                acknowledgements,
                core::iter::once(page),
                true,
            ) {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_private_copies(
    backings: &mut BackingRegistry,
    mut copies: HashMap<HvfBackingIdentity, HvfBackingIdentity>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(source) = copies.keys().copied().min() {
        let copy = copies.remove(&source).ok_or(HvfMemoryError::IpaOwnership)?;
        if backings.records.contains_key(&copy)
            && let Err(error) = backings.discard_unreferenced(copy)
        {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_fork_preparation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    child_claims: HashMap<usize, ClaimRecord>,
    private_copies: HashMap<HvfBackingIdentity, HvfBackingIdentity>,
    roots: impl IntoIterator<Item = TableToken>,
    asid: Option<HvfAsid>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for root in roots {
        if let Err(error) = cleanup_candidate_root(vm, arenas, root) {
            first_error.get_or_insert(error);
        }
    }
    if let Err(error) = cleanup_claim_records(vm, arenas, backings, acknowledgements, child_claims)
    {
        first_error.get_or_insert(error);
    }
    if let Err(error) = cleanup_private_copies(backings, private_copies) {
        first_error.get_or_insert(error);
    }
    if let Some(asid) = asid
        && let Err(error) = arenas.asids.release(asid)
    {
        first_error.get_or_insert(error);
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn retry_aliases_locked(
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
) -> Result<usize, HvfMemoryError> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(acknowledgements.alias_quarantine.len())
        .map_err(|_| HvfMemoryError::MetadataAllocation("alias retry"))?;
    let mut restored = 0;
    let mut first_error = None;
    for mut quarantine in core::mem::take(&mut acknowledgements.alias_quarantine) {
        let Some(record) = arenas.slots.records.get_mut(&quarantine.slot) else {
            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            retained.push(quarantine);
            continue;
        };
        if record.gva != quarantine.range.start
            || quarantine.range.end != quarantine.range.start + PAGE_SIZE
        {
            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            retained.push(quarantine);
            continue;
        }
        if quarantine.restore_pending {
            let Some(slot) = record.slot.as_ref() else {
                first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                retained.push(quarantine);
                continue;
            };
            if slot.restore().is_err() {
                first_error
                    .get_or_insert_with(|| HvfMemoryError::AliasRestore(quarantine.range.clone()));
                retained.push(quarantine);
                continue;
            }
            quarantine.restore_pending = false;
        }
        if quarantine.host_writer {
            if let Err(error) = backings.release_host_alias(quarantine.backing, true) {
                first_error.get_or_insert(error);
                retained.push(quarantine);
                continue;
            }
        }
        record.active = false;
        record.quarantined = false;
        restored += 1;
    }
    acknowledgements.alias_quarantine = retained;
    match first_error {
        Some(error) => Err(error),
        None => Ok(restored),
    }
}

fn release_alias_authorities(
    backings: &mut BackingRegistry,
    pages: &[AliasLeasePage],
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for page in pages.iter().rev() {
        if let Err(error) = backings.release_host_alias(page.backing, page.write) {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn restore_installed_aliases(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    installed: &[AliasLeasePage],
    inject_first_failure: bool,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for (index, page) in installed.iter().enumerate().rev() {
        let Some(record) = arenas.slots.records.get_mut(&page.slot) else {
            vm.poison();
            acknowledgements.alias_quarantine.push(AliasQuarantine {
                slot: page.slot,
                backing: page.backing,
                range: page.range.clone(),
                restore_pending: true,
                host_writer: page.write,
            });
            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            continue;
        };
        let result = match record.slot.as_ref() {
            Some(_) if inject_first_failure && index == 0 => Err(HvfHostBackingError::Restore(-1)),
            Some(slot) => slot.restore(),
            None => Err(HvfHostBackingError::Restore(-1)),
        };
        if result.is_err() {
            record.quarantined = true;
            acknowledgements.alias_quarantine.push(AliasQuarantine {
                slot: page.slot,
                backing: page.backing,
                range: page.range.clone(),
                restore_pending: true,
                host_writer: page.write,
            });
            vm.poison();
            first_error.get_or_insert_with(|| HvfMemoryError::AliasRestore(page.range.clone()));
            continue;
        }
        if let Err(error) = backings.release_host_alias(page.backing, page.write) {
            record.quarantined = true;
            acknowledgements.alias_quarantine.push(AliasQuarantine {
                slot: page.slot,
                backing: page.backing,
                range: page.range.clone(),
                restore_pending: false,
                host_writer: page.write,
            });
            vm.poison();
            first_error.get_or_insert(error);
            continue;
        }
        record.active = false;
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn ensure_aliases_inactive(
    claim: &ClaimRecord,
    range: &Range<usize>,
    slots: &HostSlotArena,
) -> Result<(), HvfMemoryError> {
    for gva in page_addresses(range) {
        let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
        let slot = slots
            .records
            .get(&page.slot)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if slot.active || slot.quarantined {
            return Err(HvfMemoryError::AliasBusy(gva..gva + PAGE_SIZE));
        }
    }
    Ok(())
}

fn validate_publication(
    manager: u64,
    address_space: HvfAddressSpaceId,
    claim: &ClaimRecord,
    range: &Range<usize>,
    publication: Option<&HvfPublicationTicket>,
    backings: &BackingRegistry,
) -> Result<(), HvfMemoryError> {
    let ticket = publication.ok_or_else(|| HvfMemoryError::PublicationRequired(range.clone()))?;
    if ticket.manager != manager
        || ticket.address_space != address_space
        || ticket.claim_id != claim.id
        || ticket.claim_version != claim.version
        || ticket.range != *range
    {
        return Err(HvfMemoryError::PublicationStale(range.clone()));
    }
    if ticket.pages.len() != range.len() / PAGE_SIZE {
        return Err(HvfMemoryError::PublicationStale(range.clone()));
    }
    for (gva, published) in page_addresses(range).zip(&ticket.pages) {
        let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
        let backing = page
            .backing
            .ok_or_else(|| HvfMemoryError::PublicationRequired(range.clone()))?;
        let epoch = backings.page_epoch(backing)?;
        if published.backing != backing
            || published.write_epoch != epoch.write
            || published.publication_epoch != epoch.publication
            || epoch.publication.0 < epoch.write.0
            || published.publication_epoch.0 != published.write_epoch.0
        {
            return Err(HvfMemoryError::PublicationStale(range.clone()));
        }
    }
    Ok(())
}

fn coalesced_ledger(
    state: &AddressSpaceState,
    backings: &BackingRegistry,
) -> Result<Vec<HvfLedgerEntry>, HvfMemoryError> {
    let page_count = state.claims.values().try_fold(0usize, |count, claim| {
        count
            .checked_add(claim.pages.len())
            .ok_or(HvfMemoryError::IpaOwnership)
    })?;
    let mut pages = Vec::<(usize, &PageState)>::new();
    pages
        .try_reserve_exact(page_count)
        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger page order"))?;
    pages.extend(
        state
            .claims
            .values()
            .flat_map(|claim| claim.pages.iter().map(|(&gva, page)| (gva, page))),
    );
    pages.sort_unstable_by_key(|(gva, _)| *gva);
    let mut entries = Vec::<HvfLedgerEntry>::new();
    entries
        .try_reserve_exact(page_count)
        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger entries"))?;
    for (gva, page) in pages {
        let epoch = match page.backing {
            Some(backing) => backings.page_epoch(backing)?,
            None => PageEpoch {
                write: HvfWriteEpoch(0),
                publication: HvfPublicationEpoch(0),
            },
        };
        let sharing = match page.backing {
            Some(backing) => backings.sharing(backing.identity)?,
            None => page.sharing,
        };
        let entry = HvfLedgerEntry {
            gva: gva..gva + PAGE_SIZE,
            permissions: page.permissions,
            sharing,
            backing_identity: page.backing.map(|backing| backing.identity),
            backing_offset: page.backing.map_or(0, |backing| backing.offset),
            ipa: {
                let mut ipa = Vec::new();
                if let Some(mapping) = page.mapping.as_ref() {
                    ipa.try_reserve_exact(1)
                        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger IPA ranges"))?;
                    ipa.push(mapping.ipa.range());
                }
                ipa
            },
            write_epoch: epoch.write,
            publication_epoch: epoch.publication,
        };
        if let Some(previous) = entries.last_mut()
            && can_coalesce(previous, &entry)
        {
            previous.gva.end = entry.gva.end;
            for ipa in entry.ipa {
                if let Some(previous_ipa) = previous.ipa.last_mut()
                    && previous_ipa.end == ipa.start
                {
                    previous_ipa.end = ipa.end;
                } else {
                    previous
                        .ipa
                        .try_reserve(1)
                        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger IPA ranges"))?;
                    previous.ipa.push(ipa);
                }
            }
            continue;
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn can_coalesce(left: &HvfLedgerEntry, right: &HvfLedgerEntry) -> bool {
    left.gva.end == right.gva.start
        && left.permissions == right.permissions
        && left.sharing == right.sharing
        && left.backing_identity == right.backing_identity
        && match left.backing_identity {
            Some(_) => left.backing_offset + left.gva.len() == right.backing_offset,
            None => true,
        }
        && left.write_epoch == right.write_epoch
        && left.publication_epoch == right.publication_epoch
}

fn swap_claim_pages(
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    mut replacements: HashMap<usize, PageState>,
    mut old_pages: Vec<(usize, PageState)>,
) -> Result<Vec<(usize, PageState)>, (HvfMemoryError, HashMap<usize, PageState>)> {
    if old_pages.capacity() < replacements.len()
        || page_addresses(range).any(|gva| !claim.pages.contains_key(&gva))
    {
        return Err((HvfMemoryError::ClaimStale, replacements));
    }
    for gva in page_addresses(range) {
        let Some(replacement) = replacements.remove(&gva) else {
            return Err((HvfMemoryError::ClaimStale, replacements));
        };
        let Some(old) = claim.pages.insert(gva, replacement) else {
            let Some(inserted) = claim.pages.remove(&gva) else {
                return Err((HvfMemoryError::ClaimStale, replacements));
            };
            replacements.insert(gva, inserted);
            return Err((HvfMemoryError::ClaimStale, replacements));
        };
        old_pages.push((gva, old));
    }
    if !replacements.is_empty() {
        return Err((HvfMemoryError::ClaimStale, replacements));
    }
    Ok(old_pages)
}

struct UnmapTransform {
    survivors: Vec<ClaimRecord>,
    removed_pages: Vec<PageState>,
}

fn split_claim_for_unmap(
    mut record: ClaimRecord,
    removed: &Range<usize>,
    survivor_specs: &[(Range<usize>, u64)],
) -> Result<UnmapTransform, (HvfMemoryError, ClaimRecord)> {
    let expected_ranges = match split_survivors(&record.range, removed) {
        Ok(ranges) => ranges,
        Err(error) => return Err((error, record)),
    };
    if expected_ranges.len() != survivor_specs.len()
        || expected_ranges
            .iter()
            .zip(survivor_specs)
            .any(|(expected, (actual, _))| expected != actual)
        || page_addresses(removed).any(|gva| !record.pages.contains_key(&gva))
    {
        return Err((HvfMemoryError::ClaimStale, record));
    }
    let removed_count = removed.len() / PAGE_SIZE;
    let mut removed_pages = Vec::new();
    if removed_pages.try_reserve_exact(removed_count).is_err() {
        return Err((
            HvfMemoryError::MetadataAllocation("removed claim pages"),
            record,
        ));
    }
    let mut removed_result = Vec::new();
    if removed_result.try_reserve_exact(removed_count).is_err() {
        return Err((
            HvfMemoryError::MetadataAllocation("removed page ownership"),
            record,
        ));
    }
    let mut survivor_pages = Vec::new();
    if survivor_pages
        .try_reserve_exact(survivor_specs.len())
        .is_err()
    {
        return Err((
            HvfMemoryError::MetadataAllocation("survivor page maps"),
            record,
        ));
    }
    for (range, _) in survivor_specs {
        let mut pages = HashMap::new();
        if pages.try_reserve(range.len() / PAGE_SIZE).is_err() {
            return Err((
                HvfMemoryError::MetadataAllocation("survivor claim pages"),
                record,
            ));
        }
        survivor_pages.push(pages);
    }
    let mut survivors = Vec::new();
    if survivors.try_reserve_exact(survivor_specs.len()).is_err() {
        return Err((
            HvfMemoryError::MetadataAllocation("survivor claims"),
            record,
        ));
    }
    for gva in page_addresses(removed) {
        let Some(page) = record.pages.remove(&gva) else {
            for (restored_gva, page) in removed_pages {
                record.pages.insert(restored_gva, page);
            }
            return Err((HvfMemoryError::ClaimStale, record));
        };
        removed_pages.push((gva, page));
    }
    let mut remaining = core::mem::take(&mut record.pages);
    while let Some(gva) = remaining.keys().copied().min() {
        let Some(page) = remaining.remove(&gva) else {
            record.pages.extend(remaining);
            for pages in survivor_pages {
                record.pages.extend(pages);
            }
            for (restored_gva, page) in removed_pages {
                record.pages.insert(restored_gva, page);
            }
            return Err((HvfMemoryError::ClaimStale, record));
        };
        let Some(index) = survivor_specs
            .iter()
            .position(|(range, _)| range.contains(&gva))
        else {
            record.pages.insert(gva, page);
            record.pages.extend(remaining);
            for pages in survivor_pages {
                record.pages.extend(pages);
            }
            for (restored_gva, page) in removed_pages {
                record.pages.insert(restored_gva, page);
            }
            return Err((HvfMemoryError::ClaimStale, record));
        };
        survivor_pages[index].insert(gva, page);
    }
    for ((range, id), pages) in survivor_specs.iter().cloned().zip(survivor_pages) {
        survivors.push(ClaimRecord {
            id,
            version: 1,
            range,
            pages,
        });
    }
    removed_result.extend(removed_pages.into_iter().map(|(_, page)| page));
    Ok(UnmapTransform {
        survivors,
        removed_pages: removed_result,
    })
}

fn ensure_claim_gap(
    claims: &HashMap<usize, ClaimRecord>,
    range: &Range<usize>,
) -> Result<(), HvfMemoryError> {
    if claims
        .values()
        .any(|claim| claim.range.start < range.end && range.start < claim.range.end)
    {
        Err(HvfMemoryError::AddressOverlap(range.clone()))
    } else {
        Ok(())
    }
}

fn validate_subrange(
    regime: HvfTranslationRegime,
    claim: &Range<usize>,
    range: &Range<usize>,
) -> Result<usize, HvfMemoryError> {
    let pages = regime.validate_range(range)?;
    if range.start < claim.start || range.end > claim.end {
        return Err(HvfMemoryError::RangeOutsideClaim(range.clone()));
    }
    Ok(pages)
}

fn admit_resource(
    resource: &'static str,
    current: usize,
    additional: usize,
    limit: usize,
) -> Result<usize, HvfMemoryError> {
    let requested = current
        .checked_add(additional)
        .ok_or(HvfMemoryError::ResourceLimit {
            resource,
            requested: usize::MAX,
            limit,
        })?;
    if requested > limit {
        Err(HvfMemoryError::ResourceLimit {
            resource,
            requested,
            limit,
        })
    } else {
        Ok(requested)
    }
}

fn check_mutation_bound(pages: usize, limit: usize) -> Result<(), HvfMemoryError> {
    admit_resource("mutation pages", 0, pages, limit).map(|_| ())
}

fn page_addresses(range: &Range<usize>) -> impl Iterator<Item = usize> {
    (range.start..range.end).step_by(PAGE_SIZE)
}

fn split_survivors(
    claim: &Range<usize>,
    removed: &Range<usize>,
) -> Result<Vec<Range<usize>>, HvfMemoryError> {
    let mut survivors = Vec::new();
    survivors
        .try_reserve_exact(2)
        .map_err(|_| HvfMemoryError::MetadataAllocation("split survivors"))?;
    if claim.start < removed.start {
        survivors.push(claim.start..removed.start);
    }
    if removed.end < claim.end {
        survivors.push(removed.end..claim.end);
    }
    Ok(survivors)
}

fn all_resource_limits_witness(limits: HvfMemoryLimits) -> bool {
    let cases = [
        ("address spaces", limits.max_address_spaces),
        ("claimed pages", limits.max_claimed_pages),
        ("live data pages", limits.max_live_data_pages),
        ("stage-one table pages", limits.max_table_pages),
        ("host slots", limits.max_host_slots),
        ("retired generations", limits.max_retired_generations),
        ("retired pages", limits.max_retired_pages),
        ("retired bytes", limits.max_retired_bytes),
        ("mutation pages", limits.max_mutation_pages),
    ];
    cases.into_iter().all(|(resource, limit)| {
        limit != 0
            && admit_resource(resource, limit - 1, 1, limit).is_ok_and(|value| value == limit)
            && matches!(
                admit_resource(resource, limit, 1, limit),
                Err(HvfMemoryError::ResourceLimit {
                    resource: actual_resource,
                    requested,
                    limit: actual_limit,
                }) if actual_resource == resource
                    && requested == limit.saturating_add(1)
                    && actual_limit == limit
            )
    }) && matches!(
        admit_resource("mutation pages", usize::MAX, 1, limits.max_mutation_pages),
        Err(HvfMemoryError::ResourceLimit {
            resource: "mutation pages",
            requested: usize::MAX,
            limit,
        }) if limit == limits.max_mutation_pages
    )
}

fn ipa_allocator_reuse_witness() -> Result<bool, HvfMemoryError> {
    let mut allocator = IpaAllocator::new(PAGE_SIZE as u64..5 * PAGE_SIZE as u64, 4)?;
    let first = allocator.allocate(2)?;
    let second = allocator.allocate(1)?;
    allocator.release(first)?;
    let replacement = allocator.allocate(2)?;
    let stale_rejected_without_effect =
        allocator.release(first).is_err() && allocator.owned_pages() == 3;
    let exact_reuse = replacement.start == first.start
        && replacement.pages == first.pages
        && replacement.id != first.id;
    allocator.release(replacement)?;
    allocator.release(second)?;
    Ok(exact_reuse && stale_rejected_without_effect && allocator.owned_pages() == 0)
}

fn alias_behavior_witness(
    space: &HvfAddressSpace,
    claim: &HvfClaim,
    first: Range<usize>,
    second: Range<usize>,
) -> Result<(bool, bool, bool), HvfMemoryError> {
    let alias_reentry_verified = space.read_alias(claim, first.clone(), |_| {
        matches!(
            space.read_alias(claim, first.clone(), |_| ()),
            Err(HvfMemoryError::AliasReentrant(_))
        )
    })?;
    let first_lease = space.begin_alias(claim, first.clone(), false)?;
    let conflicting_lease = space.begin_alias(claim, first.clone(), false);
    let disjoint_lease = space.begin_alias(claim, second.clone(), false);
    let alias_conflict_verified = matches!(&conflicting_lease, Err(HvfMemoryError::AliasBusy(_)));
    let alias_progress_verified = disjoint_lease.is_ok();
    let simultaneous_alias_pages = first.len() / PAGE_SIZE + second.len() / PAGE_SIZE;
    let simultaneous_usage = space.memory.usage();
    let simultaneous_accounting_verified = simultaneous_usage.active_alias_pages
        == simultaneous_alias_pages
        && simultaneous_usage.alias_quarantine_reservations == simultaneous_alias_pages
        && simultaneous_usage.quarantined_resources == 0;
    let mut cleanup_error = None;
    for lease in [disjoint_lease, conflicting_lease]
        .into_iter()
        .filter_map(Result::ok)
    {
        if let Err(error) = space.finish_alias(lease) {
            cleanup_error.get_or_insert(error);
        }
    }
    if let Err(error) = space.finish_alias(first_lease) {
        cleanup_error.get_or_insert(error);
    }
    if let Some(error) = cleanup_error {
        return Err(error);
    }
    let usage_after_concurrency = space.memory.usage();
    let alias_concurrency_verified = alias_conflict_verified
        && alias_progress_verified
        && simultaneous_accounting_verified
        && usage_after_concurrency.active_alias_pages == 0
        && usage_after_concurrency.alias_quarantine_reservations == 0
        && usage_after_concurrency.quarantined_resources == 0;
    let panic_observed = catch_unwind(AssertUnwindSafe(|| {
        let _ = space.write_alias(claim, first.clone(), |_| -> () {
            resume_unwind(Box::new(()));
        });
    }))
    .is_err();
    let usage_after_panic = space.memory.usage();
    let alias_panic_cleanup_verified = panic_observed
        && usage_after_panic.active_alias_pages == 0
        && usage_after_panic.alias_quarantine_reservations == 0
        && usage_after_panic.quarantined_resources == 0
        && space.read_alias(claim, first, |_| ()).is_ok();
    Ok((
        alias_reentry_verified,
        alias_concurrency_verified,
        alias_panic_cleanup_verified,
    ))
}

fn software_l0_boundary_witness(memory: &HvfMemory) -> Result<bool, HvfMemoryError> {
    memory.vm.with_operation(|operation| {
        let mut arenas = memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = create_monitor_root(memory.vm, &mut arenas, memory.limits.max_table_pages)?;
        let upper = 0x0000_8000_0000_0000usize;
        let lower = upper - PAGE_SIZE;
        let permissions = HvfGuestPermissions::READ;
        let updates = [
            (lower, permissions.stage_one_descriptor(PAGE_SIZE as u64)),
            (
                upper,
                permissions.stage_one_descriptor((2 * PAGE_SIZE) as u64),
            ),
        ];
        let candidate = match build_candidate_root(
            memory.vm,
            &mut arenas,
            root,
            &updates,
            memory.limits.max_table_pages,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                cleanup_candidate_root(memory.vm, &mut arenas, root)?;
                return Err(error);
            }
        };
        if let Err(error) = cleanup_candidate_root(memory.vm, &mut arenas, root) {
            cleanup_candidate_root(memory.vm, &mut arenas, candidate)?;
            return Err(error);
        }
        let witness = (|| {
            let lower_walk = arenas.tables.walk(candidate, lower)?;
            let upper_walk = arenas.tables.walk(candidate, upper)?;
            Ok::<_, HvfMemoryError>(
                stage_one_indexes(lower)[0] != stage_one_indexes(upper)[0]
                    && lower_walk.0 == PAGE_SIZE as u64
                    && upper_walk.0 == (2 * PAGE_SIZE) as u64,
            )
        })();
        let cleanup = cleanup_candidate_root(memory.vm, &mut arenas, candidate);
        cleanup?;
        let verified = witness?;
        operation.require_live()?;
        Ok(verified)
    })
}

fn stage_one_indexes(gva: usize) -> [usize; 4] {
    [
        (gva >> 47) & 0x1,
        (gva >> 36) & 0x7ff,
        (gva >> 25) & 0x7ff,
        (gva >> 14) & 0x7ff,
    ]
}

fn table_descriptor(ipa: u64) -> u64 {
    (ipa & DESCRIPTOR_OUTPUT_MASK) | DESCRIPTOR_VALID_TABLE_OR_PAGE
}

fn tcr_ips(ipa_bits: u32) -> u8 {
    match ipa_bits {
        0..=32 => 0,
        33..=36 => 1,
        37..=40 => 2,
        41..=42 => 3,
        43..=44 => 4,
        45..=48 => 5,
        _ => 6,
    }
}

fn tcr_el1(ipa_bits: u32) -> u64 {
    let base = 16
        | (0b01 << 8)
        | (0b01 << 10)
        | (0b11 << 12)
        | (0b10 << 14)
        | (16 << 16)
        | (1 << 23)
        | (0b01 << 24)
        | (0b01 << 26)
        | (0b11 << 28)
        | (0b01 << 30);
    base | (u64::from(tcr_ips(ipa_bits)) << 32)
}

fn take_counter(next: &mut u64) -> Result<u64, HvfMemoryError> {
    let value = *next;
    *next = next.checked_add(1).ok_or(HvfMemoryError::IpaOwnership)?;
    Ok(value)
}

fn stage_one_mismatch_error(error: &HvfError) -> bool {
    error.stage_one_mismatch()
}
