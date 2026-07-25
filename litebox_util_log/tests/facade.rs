// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for the litebox_util_log facade.
//!
//! These tests exercise the unified API and work with either backend.

use litebox_util_log::{
    Level, debug, debug_span, error, error_span, info, info_span, instrument, log, span, trace,
    trace_span, warn, warn_span,
};

#[test]
fn test_log_macro_simple() {
    log!(Level::Info, "simple log message");
    log!(Level::Error, "error level message");
    log!(Level::Warn, "warning level message");
    log!(Level::Debug, "debug level message");
    log!(Level::Trace, "trace level message");
}

#[test]
fn test_log_macro_with_kv() {
    let value = 42;
    log!(Level::Info, value:?; "message with debug capture");
    log!(Level::Info, value:debug; "message with explicit debug");

    let value = "hello";
    log!(Level::Info, value:%; "message with display capture");
    log!(Level::Info, value:display; "message with explicit display");

    log!(Level::Info, count:? = 100; "explicit value");
    log!(Level::Info, name:% = "test"; "explicit display value");

    let x = 1;
    let y = 2;
    log!(Level::Info, x, y:?; "multiple key-values");

    let debug_val = vec![1, 2, 3];
    let display_val = "hello";
    log!(Level::Info, debug_val:?, display_val:%; "mixed captures");

    let implicit = 42;
    log!(Level::Info, implicit:?, explicit:? = 100; "mixed implicit and explicit");
}

#[test]
fn test_log_macro_with_kv_hex() {
    struct NonCopy(u64);
    impl core::fmt::LowerHex for NonCopy {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::LowerHex::fmt(&self.0, f)
        }
    }

    let value = 0x2a_u32;
    log!(Level::Info, value:x; "hex capture shorthand");
    log!(Level::Info, addr:x = 0xdead_beef_u64; "hex capture with explicit value");
    log!(Level::Info, addr:x = value + 1; "hex capture with expression value");

    let flags = 0xff_u8;
    log!(Level::Info, flags:x, count:? = 100, name:% = "test"; "hex mixed with other captures");

    error!(value:x; "hex via error");
    warn!(value:x; "hex via warn");
    info!(value:x; "hex via info");
    debug!(value:x; "hex via debug");
    trace!(value:x; "hex via trace");

    // `:x` borrows its value like every other capture mode; a non-Copy value
    // must remain usable after being logged.
    let non_copy = NonCopy(0x1234);
    log!(Level::Info, non_copy:x; "hex shorthand borrows");
    log!(Level::Info, again:x = non_copy; "hex explicit value borrows");
    assert_eq!(non_copy.0, 0x1234);
}

#[test]
fn test_span_macros_with_hex() {
    let addr = 0x1000_usize;
    let _guard = span!(Level::Info, "hex_span", addr:x);
    let _guard = span!(Level::Info, "hex_span_explicit", addr:x = addr + 0x20, len:? = 4);
    let _i = info_span!("hex_info_span", addr:x);
}

/// End-to-end check that `:x` renders as `0x`-prefixed lowercase hex.
///
/// Only runs when the `log` backend is active (with `backend_tracing`
/// enabled the macros route to `tracing` and no `log` logger sees events).
#[test]
#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
fn test_hex_capture_renders_prefixed_lowercase() {
    use std::sync::Mutex;

    struct CaptureLogger(Mutex<String>);

    impl log::Log for CaptureLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            litebox_util_log::format_record(&mut *self.0.lock().unwrap(), record).unwrap();
        }
        fn flush(&self) {}
    }

    static LOGGER: CaptureLogger = CaptureLogger(Mutex::new(String::new()));
    log::set_logger(&LOGGER).expect("no other test installs a logger");
    log::set_max_level(log::LevelFilter::Info);

    let addr = 0xBEEF_usize;
    info!(addr:x, value:x = 0x2a_u32; "hex render");

    let output = LOGGER.0.lock().unwrap();
    assert!(
        output.contains("addr=0xbeef"),
        "unexpected output: {output}"
    );
    assert!(output.contains("value=0x2a"), "unexpected output: {output}");
}

#[test]
#[cfg(feature = "kv_std")]
fn test_log_macro_with_kv_err() {
    let error = "something went wrong";
    log!(Level::Error, error:err; "error capture");
}

#[test]
#[cfg(feature = "kv_sval")]
fn test_log_macro_with_kv_sval() {
    let data = vec![1, 2, 3];
    log!(Level::Debug, data:sval; "sval capture");
}

#[test]
#[cfg(feature = "kv_serde")]
fn test_log_macro_with_kv_serde() {
    let data = (1, "two", 3.0);
    log!(Level::Debug, data:serde; "serde capture");
}

#[test]
fn test_level_specific_macros() {
    error!("error message");
    warn!("warn message");
    info!("info message");
    debug!("debug message");
    trace!("trace message");

    let value = 42;
    error!(value:?; "error with kv");
    warn!(value:?; "warn with kv");
    info!(value:?; "info with kv");
    debug!(value:?; "debug with kv");
    trace!(value:?; "trace with kv");
}

#[test]
fn test_span_macros() {
    let _guard = span!(Level::Info, "test_span");

    let request_id = 12345;
    let _guard = span!(Level::Info, "request_handler", request_id:?);

    let _e = error_span!("error_span");
    let _w = warn_span!("warn_span");
    let _i = info_span!("info_span");
    let _d = debug_span!("debug_span");
    let _t = trace_span!("trace_span");

    let id = 1;
    let _e = error_span!("error_span", id:?);
    let _w = warn_span!("warn_span", id:?);
    let _i = info_span!("info_span", id:?);
    let _d = debug_span!("debug_span", id:?);
    let _t = trace_span!("trace_span", id:?);
}

#[test]
fn test_span_scoping() {
    {
        let _guard = info_span!("scoped_span");
        info!("inside span");
    }
    info!("after span dropped");

    let _outer = info_span!("outer");
    {
        let _inner = debug_span!("inner");
        debug!("in inner span");
    }
    info!("back in outer span");
}

#[instrument(level = info)]
fn instrumented_simple() {
    info!("inside instrumented function");
}

#[instrument(level = debug)]
fn instrumented_with_args(x: u32, y: &str) {
    debug!("processing");
    let _ = (x, y);
}

#[instrument(level = trace, fields(id:?, name:%))]
fn instrumented_with_specific_fields(id: u64, name: &str, _secret: &str) {
    trace!("handling request");
    let _ = (id, name);
}

#[instrument(level = info, skip(password))]
fn instrumented_with_skip(username: &str, password: &str) {
    info!("authenticating user");
    let _ = (username, password);
}

#[instrument(level = debug, skip_all)]
fn instrumented_skip_all(sensitive: &str, also_sensitive: u64) {
    debug!("doing something sensitive");
    let _ = (sensitive, also_sensitive);
}

#[instrument(level = warn, name = "custom_span_name")]
fn instrumented_with_custom_name() {
    warn!("inside custom named span");
}

#[instrument(level = info)]
fn instrumented_returning_value(x: i32) -> i32 {
    x * 2
}

#[instrument(level = debug, fields(a:debug, b:display))]
fn instrumented_with_explicit_capture_modes(a: i32, b: &str) {
    debug!("explicit modes");
    let _ = (a, b);
}

#[instrument(level = debug, fields(addr:x, len:?, base:x = 0x1000_usize))]
fn instrumented_with_hex_fields(addr: usize, len: usize) {
    debug!("hex capture mode");
    let _ = (addr, len);
}

#[derive(Debug)]
struct TestStruct {
    value: i32,
}

impl TestStruct {
    #[instrument(level = info, fields(self.value:?, self:?, test = 5, test2 = self))]
    fn instrumented_method(&self) {
        info!("in method");
    }
}

#[test]
fn test_instrument() {
    #[instrument(level = debug)]
    fn nested() {
        debug!("in nested");
    }

    instrumented_simple();
    instrumented_with_args(42, "hello");
    instrumented_with_specific_fields(123, "test", "secret_value");
    instrumented_with_skip("alice", "hunter2");
    instrumented_skip_all("secret", 42);
    instrumented_with_custom_name();
    assert_eq!(instrumented_returning_value(21), 42);
    instrumented_with_explicit_capture_modes(42, "hello");
    instrumented_with_hex_fields(0xdead_beef, 16);
    nested();
    TestStruct { value: 7 }.instrumented_method();
}

#[cfg(feature = "backend_log")]
#[test]
fn test_format_record_includes_key_values() {
    let key_values = [("count", 42), ("name", 7)];
    let record = log::Record::builder()
        .level(log::Level::Info)
        .args(format_args!("hello"))
        .key_values(&key_values)
        .build();
    let mut output = String::new();

    litebox_util_log::format_record(&mut output, &record).unwrap();

    assert_eq!(output, "[INFO] hello count=42 name=7\n");
}
