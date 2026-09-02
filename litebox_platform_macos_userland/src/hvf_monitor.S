// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

.section __TEXT,__const
.balign 16384
.globl _litebox_hvf_monitor_start
.globl _litebox_hvf_monitor_syscall
.globl _litebox_hvf_monitor_resume
.globl _litebox_hvf_monitor_end

.macro LITEBOX_VECTOR immediate
    hvc #\immediate
    b .
    .space 120
.endm

_litebox_hvf_monitor_start:
    LITEBOX_VECTOR 0x4c00
    LITEBOX_VECTOR 0x4c01
    LITEBOX_VECTOR 0x4c02
    LITEBOX_VECTOR 0x4c03
    LITEBOX_VECTOR 0x4c04
    LITEBOX_VECTOR 0x4c05
    LITEBOX_VECTOR 0x4c06
    LITEBOX_VECTOR 0x4c07
_litebox_hvf_monitor_syscall:
    hvc #0x4c42
_litebox_hvf_monitor_resume:
    eret
    .space 120
    LITEBOX_VECTOR 0x4c09
    LITEBOX_VECTOR 0x4c0a
    LITEBOX_VECTOR 0x4c0b
    LITEBOX_VECTOR 0x4c0c
    LITEBOX_VECTOR 0x4c0d
    LITEBOX_VECTOR 0x4c0e
    LITEBOX_VECTOR 0x4c0f
    .space 14336
_litebox_hvf_monitor_end:
