// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Log backend implementation.
//!
//! This module provides the backend implementation when using the `log` crate
//! with proper structured key-value logging via the `kv` feature.
//!
//! Since `log` does not have native span support, spans are emulated by:
//! - Logging a `[SPAN ENTER]` message when the span is created
//! - Logging a `[SPAN EXIT]` message when the span guard is dropped
//!
//! This allows log subscribers to correlate related log messages, though it
//! lacks the full hierarchical context that `tracing` provides.

impl crate::Level {
    /// Converts this level to the corresponding `log::Level`.
    #[doc(hidden)]
    pub const fn to_log_level(self) -> log::Level {
        match self {
            crate::Level::Error => log::Level::Error,
            crate::Level::Warn => log::Level::Warn,
            crate::Level::Info => log::Level::Info,
            crate::Level::Debug => log::Level::Debug,
            crate::Level::Trace => log::Level::Trace,
        }
    }
}

/// RAII guard that logs span exit when dropped.
///
/// This type is returned by span macros (e.g., [`info_span!`](crate::info_span)) when
/// using the `backend_log` feature. Holding this guard keeps the logical span "active".
/// When the guard is dropped (either explicitly or when it goes out of scope),
/// a `[SPAN EXIT]` message is logged at the same level as the span entry.
///
/// # Example
///
/// ```ignore
/// let _guard = info_span!("my_operation");
/// // ... do work ...
/// // [SPAN EXIT] is logged here when _guard goes out of scope
/// ```
pub struct SpanGuard {
    /// The name of the span, used in the exit log message.
    #[doc(hidden)]
    pub name: &'static str,
    /// The log level at which to emit the exit message.
    #[doc(hidden)]
    pub level: crate::Level,
    /// The module path for the log target.
    #[doc(hidden)]
    pub module_path: &'static str,
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        log::log!(target: self.module_path, self.level.to_log_level(), span = self.name; "[SPAN EXIT]");
    }
}

/// Internal macro for log backend implementation.
///
/// This macro dispatches log events to the `log` crate, properly using log's `kv`
/// feature to pass structured key-value pairs. Key-value pairs are first
/// normalized by [`__log_kv!`](crate::__log_kv) so that capture modes `log`
/// has no native support for (currently `:x` for hexadecimal) are rewritten
/// in terms of ones it does.
///
/// Not intended for direct use; called by the public logging macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_impl {
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_kv!([$level] [$msg] [] [$($key $(:$cap)? $(= $value)?),+])
    };
    ($level:expr, $msg:literal) => {
        $crate::__private::log::log!($crate::Level::to_log_level($level), $msg)
    };
}

/// Internal tt-muncher that normalizes key-value pairs for the log backend.
///
/// Processes fields one at a time, rewriting capture modes that `log` lacks
/// native support for:
///
/// - `key:x [= value]` becomes `key:% = Hex(value)`, rendering the value as
///   `0x`-prefixed lowercase hexadecimal.
///
/// All other fields are passed through to `log` untouched. Each processed
/// field is accumulated as a `[...]`-bracketed group so the final arm can
/// join the groups with commas.
///
/// Arguments: `[level] [msg] [accumulated_fields] [remaining_input]`
#[doc(hidden)]
#[macro_export]
macro_rules! __log_kv {
    // Field: key:x = value (0x-prefixed lowercase hex, via Display)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :x = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__log_kv!(
            [$level] [$msg]
            [$($acc)* [$key:% = $crate::__private::Hex($value)]]
            [$($($rest)*)?]
        )
    };
    // Field: key:x (shorthand) -> delegates to key:x = key
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :x $(, $($rest:tt)*)?]) => {
        $crate::__log_kv!([$level] [$msg] [$($acc)*] [$key :x = $key $(, $($rest)*)?])
    };
    // Field: key:cap = value (capture mode natively supported by log)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :$cap:tt = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__log_kv!([$level] [$msg] [$($acc)* [$key:$cap = $value]] [$($($rest)*)?])
    };
    // Field: key = value (no capture mode)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__log_kv!([$level] [$msg] [$($acc)* [$key = $value]] [$($($rest)*)?])
    };
    // Field: key:cap (shorthand with capture mode natively supported by log)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :$cap:tt $(, $($rest:tt)*)?]) => {
        $crate::__log_kv!([$level] [$msg] [$($acc)* [$key:$cap]] [$($($rest)*)?])
    };
    // Field: key (bare identifier)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident $(, $($rest:tt)*)?]) => {
        $crate::__log_kv!([$level] [$msg] [$($acc)* [$key]] [$($($rest)*)?])
    };
    // All fields processed: emit the log call, joining field groups with commas.
    ([$level:expr] [$msg:literal] [$([$($kv:tt)*])+] []) => {
        $crate::__private::log::log!(
            $crate::Level::to_log_level($level),
            $($($kv)*),+;
            $msg
        )
    };
}

/// Internal macro for span implementation with log backend.
///
/// Creates a [`SpanGuard`] and emits a `[SPAN ENTER]` log message. The guard
/// will emit `[SPAN EXIT]` when dropped. Key-value pairs are included in the
/// entry message using log's `kv` syntax, normalized by
/// [`__log_kv!`](crate::__log_kv) with the span name seeded as the first
/// field.
///
/// Not intended for direct use; called by the public span macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __span_impl {
    ($level:expr, $name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {{
        let __level = $level;
        $crate::__log_kv!(
            [__level] ["[SPAN ENTER]"]
            [[span = $name]]
            [$($key $(:$cap)? $(= $value)?),+]
        );
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
    ($level:expr, $name:expr) => {{
        let __level = $level;
        $crate::__private::log::log!($crate::Level::to_log_level(__level), span = $name; "[SPAN ENTER]");
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
}
