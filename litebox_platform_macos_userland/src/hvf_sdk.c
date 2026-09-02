// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <Hypervisor/Hypervisor.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <os/object.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__arm64__)
#error "the LiteBox Hypervisor.framework boundary requires arm64"
#endif

#if __MAC_OS_X_VERSION_MAX_ALLOWED < 260000
#error "the LiteBox Hypervisor.framework boundary requires the macOS 26 SDK"
#endif

_Static_assert(sizeof(uintptr_t) <= sizeof(size_t),
               "monitor address deltas must fit in size_t");

extern const uint8_t litebox_hvf_monitor_start[];
extern const uint8_t litebox_hvf_monitor_syscall[];
extern const uint8_t litebox_hvf_monitor_resume[];
extern const uint8_t litebox_hvf_monitor_end[];

static const hv_feature_reg_t litebox_feature_regs[] API_AVAILABLE(macos(26.0)) = {
    HV_FEATURE_REG_ID_AA64DFR0_EL1,
    HV_FEATURE_REG_ID_AA64DFR1_EL1,
    HV_FEATURE_REG_ID_AA64ISAR0_EL1,
    HV_FEATURE_REG_ID_AA64ISAR1_EL1,
    HV_FEATURE_REG_ID_AA64MMFR0_EL1,
    HV_FEATURE_REG_ID_AA64MMFR1_EL1,
    HV_FEATURE_REG_ID_AA64MMFR2_EL1,
    HV_FEATURE_REG_ID_AA64PFR0_EL1,
    HV_FEATURE_REG_ID_AA64PFR1_EL1,
    HV_FEATURE_REG_ID_AA64ZFR0_EL1,
    HV_FEATURE_REG_ID_AA64SMFR0_EL1,
};

static const hv_sys_reg_t litebox_feature_sys_regs[] API_AVAILABLE(macos(26.0)) = {
    HV_SYS_REG_ID_AA64DFR0_EL1,
    HV_SYS_REG_ID_AA64DFR1_EL1,
    HV_SYS_REG_ID_AA64ISAR0_EL1,
    HV_SYS_REG_ID_AA64ISAR1_EL1,
    HV_SYS_REG_ID_AA64MMFR0_EL1,
    HV_SYS_REG_ID_AA64MMFR1_EL1,
    HV_SYS_REG_ID_AA64MMFR2_EL1,
    HV_SYS_REG_ID_AA64PFR0_EL1,
    HV_SYS_REG_ID_AA64PFR1_EL1,
    HV_SYS_REG_ID_AA64ZFR0_EL1,
    HV_SYS_REG_ID_AA64SMFR0_EL1,
};

uint32_t litebox_hvf_sdk_max_allowed(void) {
    return __MAC_OS_X_VERSION_MAX_ALLOWED;
}

uint8_t litebox_hvf_runtime_is_macos_26_or_newer(void) {
    if (__builtin_available(macOS 26.0, *)) {
        return 1;
    }
    return 0;
}

uint8_t litebox_hvf_return_is_success(hv_return_t result) {
    return result == HV_SUCCESS;
}

uint8_t litebox_hvf_return_is_denied(hv_return_t result) {
    return result == HV_DENIED;
}

void litebox_hvf_monitor_layout(const uint8_t **start, size_t *length,
                                size_t *syscall_offset, size_t *resume_offset) {
    const uintptr_t start_address = (uintptr_t)litebox_hvf_monitor_start;
    const uintptr_t syscall_address = (uintptr_t)litebox_hvf_monitor_syscall;
    const uintptr_t resume_address = (uintptr_t)litebox_hvf_monitor_resume;
    const uintptr_t end_address = (uintptr_t)litebox_hvf_monitor_end;
    *start = litebox_hvf_monitor_start;
    if (end_address < start_address || syscall_address < start_address ||
        syscall_address >= end_address || resume_address < start_address ||
        resume_address >= end_address) {
        *length = SIZE_MAX;
        *syscall_offset = SIZE_MAX;
        *resume_offset = SIZE_MAX;
        return;
    }
    *length = (size_t)(end_address - start_address);
    *syscall_offset = (size_t)(syscall_address - start_address);
    *resume_offset = (size_t)(resume_address - start_address);
}

int32_t litebox_hvf_host_remap(uintptr_t source, uintptr_t destination,
                               size_t size, uint8_t copy) {
    mach_vm_address_t target = (mach_vm_address_t)destination;
    vm_prot_t current_protection = VM_PROT_NONE;
    vm_prot_t maximum_protection = VM_PROT_NONE;
    kern_return_t result = mach_vm_remap(
        mach_task_self(), &target, (mach_vm_size_t)size, 0,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
        (mach_vm_address_t)source, copy != 0, &current_protection,
        &maximum_protection, VM_INHERIT_NONE);
    if (result == KERN_SUCCESS && target != (mach_vm_address_t)destination) {
        (void)mach_vm_deallocate(mach_task_self(), target,
                                 (mach_vm_size_t)size);
        return KERN_FAILURE;
    }
    return result;
}

#pragma clang attribute push(__attribute__((availability(macos, introduced = 26.0))), \
                             apply_to = function)

void *litebox_hvf_vm_config_create(void) {
    return hv_vm_config_create();
}

void *litebox_hvf_vcpu_config_create(void) {
    return hv_vcpu_config_create();
}

void litebox_hvf_vm_config_release(void *object) {
    os_release((hv_vm_config_t)object);
}

void litebox_hvf_vcpu_config_release(void *object) {
    os_release((hv_vcpu_config_t)object);
}

hv_return_t litebox_hvf_vm_config_get_max_ipa_size(uint32_t *bits) {
    return hv_vm_config_get_max_ipa_size(bits);
}

hv_return_t litebox_hvf_vm_config_set_ipa_size(void *config, uint32_t bits) {
    return hv_vm_config_set_ipa_size((hv_vm_config_t)config, bits);
}

hv_return_t litebox_hvf_vm_config_get_ipa_size(void *config, uint32_t *bits) {
    return hv_vm_config_get_ipa_size((hv_vm_config_t)config, bits);
}

hv_return_t litebox_hvf_vm_config_set_ipa_granule_16k(void *config) {
    return hv_vm_config_set_ipa_granule((hv_vm_config_t)config, HV_IPA_GRANULE_16KB);
}

hv_return_t litebox_hvf_vm_config_get_ipa_granule(void *config, uint32_t *raw,
                                                   uint8_t *is_16k) {
    hv_ipa_granule_t granule = HV_IPA_GRANULE_4KB;
    hv_return_t result = hv_vm_config_get_ipa_granule((hv_vm_config_t)config, &granule);
    if (result == HV_SUCCESS) {
        *raw = (uint32_t)granule;
        *is_16k = granule == HV_IPA_GRANULE_16KB;
    }
    return result;
}

hv_return_t litebox_hvf_vm_config_get_el2_supported(uint8_t *supported) {
    bool value = false;
    hv_return_t result = hv_vm_config_get_el2_supported(&value);
    if (result == HV_SUCCESS) {
        *supported = value;
    }
    return result;
}

hv_return_t litebox_hvf_vm_config_set_el2_disabled(void *config) {
    return hv_vm_config_set_el2_enabled((hv_vm_config_t)config, false);
}

hv_return_t litebox_hvf_vm_config_get_el2_enabled(void *config, uint8_t *enabled) {
    bool value = false;
    hv_return_t result = hv_vm_config_get_el2_enabled((hv_vm_config_t)config, &value);
    if (result == HV_SUCCESS) {
        *enabled = value;
    }
    return result;
}

hv_return_t litebox_hvf_vm_get_max_vcpu_count(uint32_t *count) {
    return hv_vm_get_max_vcpu_count(count);
}

hv_return_t litebox_hvf_vm_create(void *config) {
    return hv_vm_create((hv_vm_config_t)config);
}

hv_return_t litebox_hvf_vm_destroy(void) {
    return hv_vm_destroy();
}

static hv_return_t litebox_hvf_memory_flags(uint8_t permissions,
                                             hv_memory_flags_t *flags) {
    if ((permissions & (uint8_t)~0x7u) != 0) {
        return HV_BAD_ARGUMENT;
    }
    *flags = 0;
    if ((permissions & 0x1u) != 0) {
        *flags |= HV_MEMORY_READ;
    }
    if ((permissions & 0x2u) != 0) {
        *flags |= HV_MEMORY_WRITE;
    }
    if ((permissions & 0x4u) != 0) {
        *flags |= HV_MEMORY_EXEC;
    }
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vm_map(void *address, uint64_t ipa, size_t size,
                               uint8_t permissions) {
    hv_memory_flags_t flags = 0;
    hv_return_t result = litebox_hvf_memory_flags(permissions, &flags);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vm_map(address, ipa, size, flags);
}

hv_return_t litebox_hvf_vm_protect(uint64_t ipa, size_t size,
                                   uint8_t permissions) {
    hv_memory_flags_t flags = 0;
    hv_return_t result = litebox_hvf_memory_flags(permissions, &flags);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vm_protect(ipa, size, flags);
}

hv_return_t litebox_hvf_vm_unmap(uint64_t ipa, size_t size) {
    return hv_vm_unmap(ipa, size);
}

size_t litebox_hvf_feature_reg_count(void) {
    _Static_assert(sizeof(litebox_feature_regs) / sizeof(litebox_feature_regs[0]) ==
                       sizeof(litebox_feature_sys_regs) / sizeof(litebox_feature_sys_regs[0]),
                   "feature register tables must match");
    return sizeof(litebox_feature_regs) / sizeof(litebox_feature_regs[0]);
}

hv_return_t litebox_hvf_vcpu_config_get_feature_regs(void *config, uint64_t *values,
                                                      size_t count) {
    if (count != litebox_hvf_feature_reg_count()) {
        return HV_BAD_ARGUMENT;
    }
    for (size_t i = 0; i < count; ++i) {
        hv_return_t result = hv_vcpu_config_get_feature_reg(
            (hv_vcpu_config_t)config, litebox_feature_regs[i], &values[i]);
        if (result != HV_SUCCESS) {
            return result;
        }
    }
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vcpu_create(uint64_t *identifier, void **exit_area,
                                    void *config) {
    hv_vcpu_t vcpu = 0;
    hv_vcpu_exit_t *exit = NULL;
    hv_return_t result = hv_vcpu_create(&vcpu, &exit, (hv_vcpu_config_t)config);
    if (result == HV_SUCCESS) {
        *identifier = (uint64_t)vcpu;
        *exit_area = exit;
    }
    return result;
}

hv_return_t litebox_hvf_vcpu_destroy(uint64_t identifier) {
    return hv_vcpu_destroy((hv_vcpu_t)identifier);
}

hv_return_t litebox_hvf_vcpu_program_stage_one(
    uint64_t identifier, uint64_t ttbr0_el1, uint64_t tcr_el1,
    uint64_t mair_el1, uint64_t *ttbr0_readback, uint64_t *tcr_readback,
    uint64_t *mair_readback) {
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    hv_return_t result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1,
                                             mair_el1);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr_el1);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, ttbr0_el1);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1,
                                 mair_readback);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr_readback);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1,
                               ttbr0_readback);
}

hv_return_t litebox_hvf_vcpu_verify_feature_regs(uint64_t identifier,
                                                 const uint64_t *expected,
                                                 size_t count,
                                                 size_t *mismatch_index,
                                                 uint64_t *actual_value) {
    if (count != litebox_hvf_feature_reg_count()) {
        return HV_BAD_ARGUMENT;
    }
    *mismatch_index = SIZE_MAX;
    *actual_value = 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t actual = 0;
        hv_return_t result = hv_vcpu_get_sys_reg(
            (hv_vcpu_t)identifier, litebox_feature_sys_regs[i], &actual);
        if (result != HV_SUCCESS) {
            *mismatch_index = i;
            return result;
        }
        if (actual != expected[i]) {
            *mismatch_index = i;
            *actual_value = actual;
            return HV_SUCCESS;
        }
    }
    return HV_SUCCESS;
}

#pragma clang attribute pop
