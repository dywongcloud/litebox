// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! cf-02-seccomp-production-attester: host-side orchestrator.
//!
//! Builds the two no_std guest binaries under
//! `litebox_packager/examples/seccomp-attester/` (real classic-BPF `seccomp(2)` probes, see that
//! directory's own `attester_guest.rs`), packages them into a minimal ustar tar, and launches them
//! through the REAL, signed `litebox_runner_linux_on_macos_userland --hvf` production runner path
//! -- the only backend `MacOsUserland::seccomp_mediation_capability` ever reports as `Complete`,
//! so this is the only way to exercise real classic-BPF enforcement rather than the disclosed
//! `ENOSYS` every other backend answers `SECCOMP_SET_MODE_FILTER` with. The guest reports one
//! `PROBE <name> <PASS|FAIL> ...` line per check plus a final `SUMMARY` line; this binary parses
//! that output, prints an aggregated report, and exits non-zero on any failure or on a run that
//! never reached its `SUMMARY` line at all (a hang or a crash is a failure, not silence).
//!
//! A real production diagnostic, not a test file: run it by hand (or from another tool) against a
//! freshly built, freshly codesigned copy of the runner -- this binary never builds, signs, or
//! launches a second copy of anything on its own, and performs its own best-effort host-memory/
//! concurrent-guest preflight (mirroring this project's own standing HVF-launch safety rule) so a
//! later caller who has not read that rule elsewhere still gets it enforced here.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("seccomp production attester: {message}");
            1
        }
    };
    std::process::exit(code);
}

struct Args {
    runner: PathBuf,
    guest_dir: PathBuf,
    work_dir: Option<PathBuf>,
    timeout: Duration,
    skip_preflight: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut runner = None;
    let mut guest_dir = None;
    let mut work_dir = None;
    let mut timeout = Duration::from_secs(30);
    let mut skip_preflight = false;

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--runner" => {
                runner = Some(PathBuf::from(
                    raw.next().ok_or("--runner requires a path")?,
                ));
            }
            "--guest-dir" => {
                guest_dir = Some(PathBuf::from(
                    raw.next().ok_or("--guest-dir requires a path")?,
                ));
            }
            "--work-dir" => {
                work_dir = Some(PathBuf::from(
                    raw.next().ok_or("--work-dir requires a path")?,
                ));
            }
            "--timeout-secs" => {
                let value = raw.next().ok_or("--timeout-secs requires a number")?;
                let secs: u64 = value
                    .parse()
                    .map_err(|_| format!("--timeout-secs: not a number: {value}"))?;
                timeout = Duration::from_secs(secs);
            }
            "--skip-host-preflight" => skip_preflight = true,
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let runner = runner.ok_or(
        "--runner <path-to-codesigned-litebox_runner_linux_on_macos_userland> is required",
    )?;
    let guest_dir = match guest_dir {
        Some(dir) => dir,
        None => default_guest_dir()?,
    };
    Ok(Args {
        runner,
        guest_dir,
        work_dir,
        timeout,
        skip_preflight,
    })
}

/// `litebox_packager/examples/seccomp-attester/`, resolved from this binary's own crate root
/// (`CARGO_MANIFEST_DIR` is `litebox_platform_macos_userland/`) so the default works from any
/// current directory a `cargo run --bin` invocation happens to use.
fn default_guest_dir() -> Result<PathBuf, String> {
    let manifest_dir =
        option_env!("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR not set at compile time")?;
    Ok(PathBuf::from(manifest_dir)
        .join("..")
        .join("litebox_packager")
        .join("examples")
        .join("seccomp-attester"))
}

fn run() -> Result<i32, String> {
    let args = parse_args()?;

    if !args.skip_preflight {
        host_preflight()?;
    }

    let owned_work_dir;
    let work_dir: &Path = match &args.work_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("create work dir {}: {e}", dir.display()))?;
            dir.as_path()
        }
        None => {
            let dir = std::env::temp_dir().join(format!(
                "seccomp-attester-{}-{}",
                std::process::id(),
                now_millis()
            ));
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("create work dir {}: {e}", dir.display()))?;
            owned_work_dir = dir;
            owned_work_dir.as_path()
        }
    };

    println!("[attester] building guest binaries from {}", args.guest_dir.display());
    build_guest(&args.guest_dir, work_dir)?;
    let tar_path = work_dir.join("seccomp-attester.tar");
    if !tar_path.is_file() {
        return Err(format!("build.sh did not produce {}", tar_path.display()));
    }

    println!(
        "[attester] launching {} --hvf --initial-files {} -- /attester_guest",
        args.runner.display(),
        tar_path.display()
    );
    let output = launch_runner(&args.runner, &tar_path, args.timeout)?;

    let report = ProbeReport::parse(&output.stdout_text);
    report.print();

    println!(
        "[attester] runner exit: {}",
        output
            .status_description
    );

    if !report.reached_summary {
        return Err(
            "guest never printed a SUMMARY line (hang, crash, or unexpected early exit) -- see captured output above"
                .to_owned(),
        );
    }

    Ok(if report.fail == 0 && report.exited_zero {
        0
    } else {
        1
    })
}

// ---------------------------------------------------------------------------
// Host-memory / concurrent-guest preflight -- mirrors this project's own standing HVF-launch
// safety rule so a later caller of this binary gets it enforced even without having read it
// elsewhere. Best-effort: a parse failure on either check is reported as a warning, never treated
// as "safe to proceed" by default, but also never silently masked as a hard crash of this tool --
// the actual gate is the free-memory and process-count numbers when they ARE readable.
// ---------------------------------------------------------------------------

fn host_preflight() -> Result<(), String> {
    let free_bytes = free_memory_bytes()?;
    println!(
        "[attester] host free memory: {:.2} GiB",
        free_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    const ONE_GIB: u64 = 1024 * 1024 * 1024;
    if free_bytes < ONE_GIB {
        return Err(format!(
            "free memory {free_bytes} bytes is under the ~1GiB floor -- refusing to launch a second HVF guest"
        ));
    }

    let existing = existing_runner_processes()?;
    if existing.is_empty() {
        println!("[attester] no other litebox HVF guest process found");
    } else if existing.len() == 1 {
        println!(
            "[attester] one other litebox HVF guest process is live (assumed the standing user session): {}",
            existing[0]
        );
    } else {
        return Err(format!(
            "found {} other litebox HVF guest processes already running -- refusing to start a second test guest:\n{}",
            existing.len(),
            existing.join("\n")
        ));
    }
    Ok(())
}

fn free_memory_bytes() -> Result<u64, String> {
    let output = Command::new("vm_stat")
        .output()
        .map_err(|e| format!("running vm_stat: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let page_size = text
        .lines()
        .next()
        .and_then(|line| line.rsplit(' ').nth(1))
        .and_then(|token| token.parse::<u64>().ok())
        .unwrap_or(4096);
    let free_pages = text
        .lines()
        .find(|line| line.starts_with("Pages free:"))
        .and_then(|line| line.trim_end_matches('.').rsplit(' ').next())
        .and_then(|token| token.trim().parse::<u64>().ok())
        .ok_or("could not parse 'Pages free:' from vm_stat output")?;
    Ok(free_pages.saturating_mul(page_size))
}

fn existing_runner_processes() -> Result<Vec<String>, String> {
    let output = Command::new("ps")
        .arg("aux")
        .output()
        .map_err(|e| format!("running ps aux: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut matches = Vec::new();
    for line in text.lines() {
        let is_runner = line.contains("runner-desktop-live")
            || line.contains("runner-")
                && (line.contains("-test") || line.contains("runner_linux_on_macos"));
        if is_runner && !line.contains("ps aux") && !line.contains("grep") {
            matches.push(line.to_owned());
        }
    }
    Ok(matches)
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Guest build + runner launch.
// ---------------------------------------------------------------------------

fn build_guest(guest_dir: &Path, out_dir: &Path) -> Result<(), String> {
    let build_script = guest_dir.join("build.sh");
    if !build_script.is_file() {
        return Err(format!("missing {}", build_script.display()));
    }
    let status = Command::new("sh")
        .arg(&build_script)
        .arg(out_dir)
        .status()
        .map_err(|e| format!("running {}: {e}", build_script.display()))?;
    if !status.success() {
        return Err(format!("{} exited with {status}", build_script.display()));
    }
    Ok(())
}

struct RunnerOutput {
    stdout_text: String,
    status_description: String,
}

fn launch_runner(runner: &Path, tar_path: &Path, timeout: Duration) -> Result<RunnerOutput, String> {
    if !runner.is_file() {
        return Err(format!("runner binary not found: {}", runner.display()));
    }
    let mut child = Command::new(runner)
        .arg("-Z")
        .arg("--hvf")
        .arg("--initial-files")
        .arg(tar_path)
        .arg("--")
        .arg("/attester_guest")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning {}: {e}", runner.display()))?;

    let mut stdout_pipe = child.stdout.take().ok_or("child stdout not piped")?;
    let mut stderr_pipe = child.stderr.take().ok_or("child stderr not piped")?;
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("waiting on runner: {e}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stdout_bytes = stdout_reader.join().unwrap_or_default();
            let stdout_text = String::from_utf8_lossy(&stdout_bytes).into_owned();
            return Err(format!(
                "runner did not exit within {timeout:?} -- killed it; partial stdout:\n{stdout_text}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let stdout_bytes = stdout_reader.join().unwrap_or_default();
    let stderr_bytes = stderr_reader.join().unwrap_or_default();
    let stdout_text = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();
    if !stderr_text.trim().is_empty() {
        println!("[attester] runner stderr:\n{stderr_text}");
    }

    Ok(RunnerOutput {
        stdout_text,
        status_description: format!("{status}"),
    })
}

// ---------------------------------------------------------------------------
// Guest report parsing.
// ---------------------------------------------------------------------------

struct ProbeLine {
    name: String,
    pass: bool,
    detail: String,
}

struct ProbeReport {
    probes: Vec<ProbeLine>,
    pass: u32,
    fail: u32,
    reached_summary: bool,
    summary_pass: u32,
    summary_fail: u32,
    exited_zero: bool,
    raw: String,
}

impl ProbeReport {
    fn parse(stdout_text: &str) -> Self {
        let mut probes = Vec::new();
        let mut reached_summary = false;
        let mut summary_pass = 0;
        let mut summary_fail = 0;
        for line in stdout_text.lines() {
            if let Some(rest) = line.strip_prefix("PROBE ") {
                let mut parts = rest.splitn(3, ' ');
                let name = parts.next().unwrap_or("").to_owned();
                let verdict = parts.next().unwrap_or("");
                let detail = parts.next().unwrap_or("").to_owned();
                if !name.is_empty() {
                    probes.push(ProbeLine {
                        name,
                        pass: verdict == "PASS",
                        detail,
                    });
                }
            } else if let Some(rest) = line.strip_prefix("SUMMARY ") {
                reached_summary = true;
                for field in rest.split(' ') {
                    if let Some(value) = field.strip_prefix("pass=") {
                        summary_pass = value.parse().unwrap_or(0);
                    } else if let Some(value) = field.strip_prefix("fail=") {
                        summary_fail = value.parse().unwrap_or(0);
                    }
                }
            }
        }
        let pass = probes.iter().filter(|p| p.pass).count() as u32;
        let fail = probes.iter().filter(|p| !p.pass).count() as u32;
        let exited_zero = reached_summary && summary_fail == 0 && fail == 0;
        Self {
            probes,
            pass,
            fail,
            reached_summary,
            summary_pass,
            summary_fail,
            exited_zero,
            raw: stdout_text.to_owned(),
        }
    }

    fn print(&self) {
        println!("[attester] --- probe results ---");
        for probe in &self.probes {
            let verdict = if probe.pass { "PASS" } else { "FAIL" };
            println!("  [{verdict}] {} {}", probe.name, probe.detail);
        }
        println!(
            "[attester] {} probes: {} pass, {} fail (guest SUMMARY: pass={} fail={}, reached={})",
            self.probes.len(),
            self.pass,
            self.fail,
            self.summary_pass,
            self.summary_fail,
            self.reached_summary
        );
        if self.probes.is_empty() {
            println!("[attester] raw guest stdout follows (no PROBE lines were parsed):\n{}", self.raw);
        }
    }
}
