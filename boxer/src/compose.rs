// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `boxer compose`: run several boxer instances together as one
//! composition, each its own host process/sandbox, wired together over TCP.
//!
//! LiteBox is single-process/thread-only per box (no `fork`), so a
//! multi-process workload (an X11 display server plus its clients, a
//! display server plus a VNC bridge, ...) cannot live inside one box. This
//! is the layer that makes that composable anyway: each role is its own
//! box on its own TUN device/subnet, addressed directly by IP (per
//! `--net-guest-ip`/`--net-host-ip`), with the host kernel routing between
//! subnets. See `examples/multibox-x11-composition/` for a worked example.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead as _, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, bail};
use serde::Deserialize;

/// A composition config: every instance to run together.
#[derive(Deserialize, Debug)]
struct ComposeConfig {
    instances: Vec<InstanceConfig>,
}

/// One instance in the composition.
#[derive(Deserialize, Debug, Clone)]
struct InstanceConfig {
    /// Unique name; also how other instances' `env` templates address this
    /// one's `guest_ip`/`host_ip` (`${name.guest_ip}`).
    name: String,
    /// Path to the `.box.wasm` artifact, resolved relative to the config
    /// file's own directory (matching how relative paths in a Dockerfile's
    /// build context work).
    #[serde(rename = "box")]
    box_path: PathBuf,
    /// Host-side TUN address. Auto-allocated (a distinct `10.90.<n>.1`) if
    /// omitted.
    net_host_ip: Option<Ipv4Addr>,
    /// Guest-side TUN address. Auto-allocated (`10.90.<n>.2`, paired with
    /// `net_host_ip`) if omitted.
    net_guest_ip: Option<Ipv4Addr>,
    /// TUN device name. Auto-derived (`utun9<n>`) if omitted.
    tun_device: Option<String>,
    /// Names of instances that must be started (and given
    /// `ready_delay_ms` to come up) before this one starts.
    #[serde(default)]
    depends_on: Vec<String>,
    /// Extra guest environment variables, layered over the box's own baked
    /// env. A value containing `${other.guest_ip}` or `${other.host_ip}` is
    /// substituted with that instance's resolved address before spawning --
    /// the mechanism that lets one box's launch config reference another's
    /// address without rebuilding either box.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// `-p` port-publish specs (`HOST:GUEST`, `PORT`, `IP:HOST:GUEST`),
    /// forwarded verbatim.
    #[serde(default)]
    publish: Vec<String>,
    /// How long to wait after spawning this instance before starting
    /// anything that `depends_on` it. A coarse readiness proxy: good enough
    /// for a process that binds a listening socket promptly, not a real
    /// health check. MVP scope -- a future revision could probe the
    /// published/guest port instead.
    #[serde(default = "default_ready_delay_ms")]
    ready_delay_ms: u64,
}

fn default_ready_delay_ms() -> u64 {
    1000
}

/// A resolved instance: every address fixed, every template substituted,
/// ready to spawn.
struct Resolved {
    config: InstanceConfig,
    host_ip: Ipv4Addr,
    guest_ip: Ipv4Addr,
    tun_device: String,
}

/// Run every instance in `config_path`'s composition, in dependency order,
/// until interrupted (Ctrl+C) or one instance exits unexpectedly.
pub fn up(config_path: &Path) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("cannot read compose config {}", config_path.display()))?;
    let config: ComposeConfig = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid compose config", config_path.display()))?;
    if config.instances.is_empty() {
        bail!("compose config lists no instances");
    }

    let base_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let order = topo_order(&config.instances)?;
    let resolved = resolve_addresses(&config.instances)?;

    ensure_ip_forwarding();

    let running = Arc::new(AtomicBool::new(true));
    install_sigint_handler(&running);

    let mut children: Vec<(String, Child)> = Vec::new();
    let mut result = spawn_in_order(&order, &resolved, base_dir, &running, &mut children);

    // Every instance is up (or startup was interrupted/failed, in which
    // case there is nothing to wait on) -- stay attached like `docker
    // compose up` without `-d`, streaming the already-running log-prefix
    // threads, until Ctrl+C or an instance exits on its own.
    if result.is_ok() {
        eprintln!("boxer compose: composition up, press Ctrl+C to stop");
        result = wait_until_interrupted_or_child_exit(&running, &mut children);
    }

    // Whatever happened -- clean success interrupted by Ctrl+C, or a
    // spawn/instance failure -- every child started so far gets torn down
    // before this returns; a composition that leaks sandboxed processes on
    // its own error path is worse than the error itself.
    eprintln!("boxer compose: shutting down {} instance(s)", children.len());
    for (name, mut child) in children {
        let _ = child.kill();
        let _ = child.wait();
        eprintln!("boxer compose: stopped {name}");
    }

    result
}

/// Block until Ctrl+C (`running` cleared) or any running instance exits on
/// its own -- the latter is reported as an error naming which instance and
/// its exit status, matching `docker compose up`'s behavior of tearing the
/// whole composition down when one service dies.
fn wait_until_interrupted_or_child_exit(
    running: &Arc<AtomicBool>,
    children: &mut [(String, Child)],
) -> anyhow::Result<()> {
    while running.load(Ordering::SeqCst) {
        for (name, child) in children.iter_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                bail!("instance '{name}' exited on its own ({status})");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}

/// Kahn's algorithm over `depends_on`, refusing an unknown dependency name
/// or a cycle by naming exactly what closes the loop.
fn topo_order(instances: &[InstanceConfig]) -> anyhow::Result<Vec<String>> {
    let names: HashSet<&str> = instances.iter().map(|i| i.name.as_str()).collect();
    if names.len() != instances.len() {
        bail!("compose config has duplicate instance names");
    }
    for inst in instances {
        for dep in &inst.depends_on {
            if !names.contains(dep.as_str()) {
                bail!(
                    "instance '{}' depends_on unknown instance '{dep}'",
                    inst.name
                );
            }
        }
    }

    let mut remaining: HashMap<&str, &InstanceConfig> =
        instances.iter().map(|i| (i.name.as_str(), i)).collect();
    let mut order = Vec::with_capacity(instances.len());
    while !remaining.is_empty() {
        let ready: Vec<&str> = remaining
            .values()
            .filter(|i| i.depends_on.iter().all(|d| !remaining.contains_key(d.as_str())))
            .map(|i| i.name.as_str())
            .collect();
        if ready.is_empty() {
            let stuck: Vec<&str> = remaining.keys().copied().collect();
            bail!(
                "compose config has a dependency cycle among: {}",
                stuck.join(", ")
            );
        }
        let mut ready = ready;
        ready.sort_unstable();
        for name in ready {
            order.push(name.to_string());
            remaining.remove(name);
        }
    }
    Ok(order)
}

/// Assign every instance a host/guest IP pair and TUN device, auto-filling
/// anything not given explicitly. Each auto-allocated pair gets its own
/// `/24` (`10.90.<n>.0/24`), so every instance can address every other
/// directly without an explicit `--net-guest-ip` collision.
fn resolve_addresses(instances: &[InstanceConfig]) -> anyhow::Result<HashMap<String, Resolved>> {
    let mut used_host_ips = HashSet::new();
    let mut used_guest_ips = HashSet::new();
    let mut used_devices = HashSet::new();
    for inst in instances {
        if let Some(ip) = inst.net_host_ip
            && !used_host_ips.insert(ip)
        {
            bail!("net_host_ip {ip} is assigned to more than one instance");
        }
        if let Some(ip) = inst.net_guest_ip
            && !used_guest_ips.insert(ip)
        {
            bail!("net_guest_ip {ip} is assigned to more than one instance");
        }
        if let Some(dev) = &inst.tun_device
            && !used_devices.insert(dev.clone())
        {
            bail!("tun_device '{dev}' is assigned to more than one instance");
        }
    }

    let mut resolved = HashMap::new();
    let mut next_subnet: u8 = 0;
    for (index, inst) in instances.iter().enumerate() {
        let (host_ip, guest_ip) = match (inst.net_host_ip, inst.net_guest_ip) {
            (Some(h), Some(g)) => (h, g),
            (None, None) => loop {
                let subnet = next_subnet;
                next_subnet = next_subnet
                    .checked_add(1)
                    .context("compose config has too many instances for the auto /24 pool")?;
                let host = Ipv4Addr::new(10, 90, subnet, 1);
                let guest = Ipv4Addr::new(10, 90, subnet, 2);
                if !used_host_ips.contains(&host) && !used_guest_ips.contains(&guest) {
                    break (host, guest);
                }
            },
            _ => bail!(
                "instance '{}' must set both net_host_ip and net_guest_ip, or neither",
                inst.name
            ),
        };
        // "utunNN" rather than an arbitrary name: Linux accepts any ASCII
        // name for `ip tuntap add`, but macOS's `utun` interfaces are only
        // ever named `utun<unit>` (see `litebox_platform_macos_userland::net`),
        // so an auto-derived name has to satisfy both to work on either
        // native runner without the compose config itself being
        // platform-specific. Offset by 90 to stay clear of the low utun
        // units macOS's own VPN/Wi-Fi/Handoff services commonly hold.
        let tun_device = inst
            .tun_device
            .clone()
            .unwrap_or_else(|| format!("utun{}", 90 + index));

        resolved.insert(
            inst.name.clone(),
            Resolved {
                config: inst.clone(),
                host_ip,
                guest_ip,
                tun_device,
            },
        );
    }
    Ok(resolved)
}

/// Substitute `${name.guest_ip}`/`${name.host_ip}` in `value` against
/// `resolved`. Any other `${...}` form, or a reference to an unknown
/// instance/field, is refused by name rather than passed through silently
/// wrong.
fn substitute_template(value: &str, resolved: &HashMap<String, Resolved>) -> anyhow::Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .with_context(|| format!("unterminated ${{...}} in '{value}'"))?;
        let expr = &after[..end];
        let (name, field) = expr
            .split_once('.')
            .with_context(|| format!("'${{{expr}}}' must be '${{name.guest_ip}}' or '${{name.host_ip}}'"))?;
        let target = resolved
            .get(name)
            .with_context(|| format!("'${{{expr}}}' references unknown instance '{name}'"))?;
        let substituted = match field {
            "guest_ip" => target.guest_ip.to_string(),
            "host_ip" => target.host_ip.to_string(),
            other => bail!("'${{{expr}}}': unknown field '{other}', expected guest_ip or host_ip"),
        };
        out.push_str(&substituted);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Best-effort: a composition needs the host to route between each
/// instance's own `/24`, which requires IP forwarding to be on. Not fatal
/// if this can't be set (already on, or not root) -- the actual `boxer run`
/// TUN/publish calls surface the real failure if routing genuinely doesn't
/// work.
#[cfg(target_os = "linux")]
fn ensure_ip_forwarding() {
    const PATH: &str = "/proc/sys/net/ipv4/ip_forward";
    match std::fs::read_to_string(PATH) {
        Ok(current) if current.trim() == "1" => {}
        _ => match std::fs::write(PATH, b"1\n") {
            Ok(()) => eprintln!("boxer compose: enabled IP forwarding ({PATH})"),
            Err(e) => eprintln!(
                "boxer compose: warning: could not enable IP forwarding ({e}); \
                 cross-instance routing may fail unless it is already on"
            ),
        },
    }
}

/// macOS has no `/proc`; the equivalent knob is the `net.inet.ip.forwarding`
/// sysctl, set via the `sysctl` binary rather than a raw syscall (no `libc`
/// wrapper for the BSD sysctl MIB by name is worth adding for one best-effort
/// call). Same not-fatal semantics as the Linux path.
#[cfg(target_os = "macos")]
fn ensure_ip_forwarding() {
    const NAME: &str = "net.inet.ip.forwarding";
    let current = std::process::Command::new("sysctl")
        .args(["-n", NAME])
        .output();
    if let Ok(out) = &current
        && out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "1"
    {
        return;
    }
    match std::process::Command::new("sysctl")
        .args(["-w", &format!("{NAME}=1")])
        .output()
    {
        Ok(out) if out.status.success() => {
            eprintln!("boxer compose: enabled IP forwarding ({NAME})");
        }
        Ok(out) => eprintln!(
            "boxer compose: warning: could not enable IP forwarding ({}); \
             cross-instance routing may fail unless it is already on",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!(
            "boxer compose: warning: could not enable IP forwarding ({e}); \
             cross-instance routing may fail unless it is already on"
        ),
    }
}

/// Set by [`install_sigint_handler`], read by [`sigint_handler`] -- a
/// signal handler can only reach process-global state, never a closure
/// capture.
static RUNNING_FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

extern "C" fn sigint_handler(_sig: libc::c_int) {
    if let Some(flag) = RUNNING_FLAG.get() {
        flag.store(false, Ordering::SeqCst);
    }
}

fn install_sigint_handler(running: &Arc<AtomicBool>) {
    let _ = RUNNING_FLAG.set(Arc::clone(running));
    // SAFETY: `sigint_handler` is async-signal-safe (only an atomic
    // store), and SIGINT/SIGTERM are the only signals this installs a
    // handler for.
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, sigint_handler as *const () as libc::sighandler_t);
    }
}

/// Spawn every instance in `order`, waiting each instance's own
/// `ready_delay_ms` after starting it before moving to the next (a
/// dependent is always later in `order` than its dependency, by
/// construction of [`topo_order`]). Stops early -- without error -- on
/// Ctrl+C; returns an error if a spawn itself fails or an already-running
/// instance exits before the composition finished starting.
fn spawn_in_order(
    order: &[String],
    resolved: &HashMap<String, Resolved>,
    base_dir: &Path,
    running: &Arc<AtomicBool>,
    children: &mut Vec<(String, Child)>,
) -> anyhow::Result<()> {
    let self_path = std::env::current_exe().context("cannot determine boxer's own path")?;

    for name in order {
        if !running.load(Ordering::SeqCst) {
            return Ok(());
        }
        let inst = &resolved[name];
        let child = spawn_instance(&self_path, inst, base_dir, resolved)
            .with_context(|| format!("failed to start instance '{name}'"))?;
        eprintln!("boxer compose: started '{name}' ({}/{})", inst.host_ip, inst.guest_ip);
        children.push((name.clone(), child));

        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(inst.config.ready_delay_ms);
        while std::time::Instant::now() < deadline {
            if !running.load(Ordering::SeqCst) {
                return Ok(());
            }
            // An instance exiting during its own ready-delay window, before
            // anything depends on it having come up, is already a failure
            // worth stopping the whole composition for -- waiting out the
            // rest of the deadline would only start dependents against a
            // dead peer.
            if let Some((failed_name, child)) = children.last_mut()
                && matches!(child.try_wait(), Ok(Some(_)))
            {
                let failed_name = failed_name.clone();
                bail!("instance '{failed_name}' exited during startup");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    Ok(())
}

fn spawn_instance(
    self_path: &Path,
    inst: &Resolved,
    base_dir: &Path,
    resolved: &HashMap<String, Resolved>,
) -> anyhow::Result<Child> {
    let box_path = if inst.config.box_path.is_absolute() {
        inst.config.box_path.clone()
    } else {
        base_dir.join(&inst.config.box_path)
    };

    let mut cmd = Command::new(self_path);
    cmd.arg("run")
        .arg(&box_path)
        .arg("--net")
        .arg(&inst.tun_device)
        .arg("--net-host-ip")
        .arg(inst.host_ip.to_string())
        .arg("--net-guest-ip")
        .arg(inst.guest_ip.to_string());

    for (key, value) in &inst.config.env {
        let substituted = substitute_template(value, resolved)
            .with_context(|| format!("instance '{}', env '{key}'", inst.config.name))?;
        cmd.arg("-e").arg(format!("{key}={substituted}"));
    }
    for spec in &inst.config.publish {
        cmd.arg("-p").arg(spec);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `boxer run` for '{}'", inst.config.name))?;

    prefix_stream(child.stdout.take(), &inst.config.name, false);
    prefix_stream(child.stderr.take(), &inst.config.name, true);

    Ok(child)
}

/// Read `stream` line by line on its own thread, printing each line
/// prefixed with `[name]` -- the composition's log aggregation, so several
/// concurrently-running instances stay distinguishable in one terminal.
fn prefix_stream(stream: Option<impl std::io::Read + Send + 'static>, name: &str, is_stderr: bool) {
    let Some(stream) = stream else { return };
    let name = name.to_string();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            if is_stderr {
                eprintln!("[{name}] {line}");
            } else {
                println!("[{name}] {line}");
            }
        }
    });
}
