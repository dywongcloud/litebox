// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.
//!
//! Nothing in here is architecture-specific: segment mapping, the auxiliary
//! vector and the initial stack layout are all defined by the generic
//! System V/Linux ABI, and the ELF machine type is carried by the image rather
//! than assumed. The module is therefore built for every architecture the rest
//! of the shim supports, so an aarch64 host gets the same loader an x86-64 host
//! does.

pub mod auxv;
pub mod elf;
mod stack;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// A default low address is used for the binary (which grows upwards) to avoid
/// conflicts with the kernel's memory mappings (which grows downwards).
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1000_0000;
