// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Struct-layout conformance probe for the hand-written arm64 Mach/BSD structs
// in `src/darwin.rs` (`ArmExceptionState64`, `ArmThreadState64`,
// `McontextPrefix64`). Those types exist because Rust has no binding for
// Darwin's `<mach/arm/_structs.h>` / `<sys/_types/_mcontext64.h>`; nothing in
// this crate had ever checked them against the real system headers before
// this file. It is not part of the crate's own build -- it is compiled and
// run as a standalone step in the macOS CI job, specifically so it can
// `#include` the real SDK headers on the runner and fail loudly at compile
// (or run) time if this ABI is ever different from what was assumed here.
//
// A failure in this file means `src/darwin.rs`'s struct definitions are
// wrong for the SDK that built it -- fix the Rust struct, not this probe,
// unless the mismatch is in this probe's own field names (see the note on
// `_STRUCT_MCONTEXT64` below).

#include <mach/arm/thread_status.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/ucontext.h>

_Static_assert(sizeof(uint64_t) == 8, "sanity check: uint64_t is 8 bytes");

// `ArmExceptionState64` <-> `_STRUCT_ARM_EXCEPTION_STATE64`
_Static_assert(sizeof(_STRUCT_ARM_EXCEPTION_STATE64) == 16,
               "ArmExceptionState64: size mismatch");
_Static_assert(offsetof(_STRUCT_ARM_EXCEPTION_STATE64, far) == 0,
               "ArmExceptionState64::far: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_EXCEPTION_STATE64, esr) == 8,
               "ArmExceptionState64::esr: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_EXCEPTION_STATE64, exception) == 12,
               "ArmExceptionState64::exception: offset mismatch");

// `ArmThreadState64` <-> `_STRUCT_ARM_THREAD_STATE64`
_Static_assert(sizeof(_STRUCT_ARM_THREAD_STATE64) == 29 * 8 + 4 * 8 + 8,
               "ArmThreadState64: size mismatch");
_Static_assert(offsetof(_STRUCT_ARM_THREAD_STATE64, x) == 0,
               "ArmThreadState64::x: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_THREAD_STATE64, fp) == 29 * 8,
               "ArmThreadState64::fp: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_THREAD_STATE64, lr) == 30 * 8,
               "ArmThreadState64::lr: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_THREAD_STATE64, sp) == 31 * 8,
               "ArmThreadState64::sp: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_THREAD_STATE64, pc) == 32 * 8,
               "ArmThreadState64::pc: offset mismatch");
_Static_assert(offsetof(_STRUCT_ARM_THREAD_STATE64, cpsr) == 33 * 8,
               "ArmThreadState64::cpsr: offset mismatch");
_Static_assert(sizeof(_STRUCT_ARM_THREAD_STATE64) == 33 * 8 + 8,
               "ArmThreadState64: total size mismatch (includes trailing pad)");

// `McontextPrefix64` <-> the leading two members of `_STRUCT_MCONTEXT64`
// (`mcontext_t`'s pointee on this architecture). The exception-state member is
// documented as `__es` and the thread-state member as `__ss` in XNU's
// `osfmk/mach/arm/_structs.h`; unlike the two checks above, this one depends
// on those exact field names, which were not independently re-fetched for
// this probe. If *this* assertion is the one that fails to compile (a "no
// member named '__es'/'__ss'" error, not a static-assert failure), the field
// names moved -- open `<sys/ucontext.h>` / `<mach/arm/_structs.h>` on the
// runner's SDK and update them here rather than assuming the Rust side is
// wrong.
_Static_assert(offsetof(struct __darwin_mcontext64, __es) == 0,
               "McontextPrefix64::exception_state: offset mismatch");
_Static_assert(offsetof(struct __darwin_mcontext64, __ss) ==
                   sizeof(_STRUCT_ARM_EXCEPTION_STATE64),
               "McontextPrefix64::thread_state: offset mismatch");
_Static_assert(sizeof(mcontext_t) == sizeof(void *),
               "mcontext_t is expected to be a pointer, matching how "
               "litebox casts ucontext_t::uc_mcontext directly");

int main(void) {
    return 0;
}
