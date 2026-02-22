#![allow(dead_code)]

//! Common utility functions for integration tests.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Once;

use tap_tunnel::TapConfig;

mod scripts;

#[allow(unused_imports)]
pub use scripts::*;

pub struct UserNetNamespace {
    child: Child,
    pid: u32,
}

impl UserNetNamespace {
    pub fn new(script: &str) -> std::io::Result<Self> {
        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--net", "--map-root-user", "sh", "-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Create a new process group so we can kill all children
            .process_group(0);
        let mut child = cmd.spawn()?;
        let pid = child.id();

        // Wait for "READY"
        let stdout = child.stdout.as_mut().unwrap();
        let mut buf = [0u8; 64];
        let mut total = 0;
        loop {
            let n = stdout.read(&mut buf[total..])?;
            if n == 0 {
                // Check stderr for error
                let mut stderr_buf = [0u8; 1024];
                let stderr = child.stderr.as_mut().unwrap();
                let n = stderr.read(&mut stderr_buf).unwrap_or(0);
                let stderr_msg = String::from_utf8_lossy(&stderr_buf[..n]);
                return Err(std::io::Error::other(format!(
                    "namespace exited before ready: {}",
                    stderr_msg
                )));
            }
            total += n;
            if String::from_utf8_lossy(&buf[..total]).contains("READY") {
                break;
            }
            if total >= buf.len() {
                return Err(std::io::Error::other(format!(
                    "unexpected output: {}",
                    String::from_utf8_lossy(&buf[..total])
                )));
            }
        }

        Ok(Self { child, pid })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for UserNetNamespace {
    fn drop(&mut self) {
        kill_process_tree(&mut self.child);
    }
}

/// Kill a process and all its children using process group.
pub fn kill_process_tree(child: &mut Child) {
    let pid = child.id() as i32;
    // Kill the entire process group (negative PID)
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    // Also kill the process directly in case it's not the group leader
    let _ = child.kill();
    let _ = child.wait();
}

/// Helper struct to manage the proxy process started with --socket-path
pub struct ProxyProcess {
    child: Child,
}

impl ProxyProcess {
    pub fn new(target_pid: u32, socket_path: &str) -> std::io::Result<Self> {
        // Find the proxy binary
        let proxy_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("tap-tunnel-proxy")))
            .filter(|p| p.exists())
            .unwrap_or_else(|| {
                std::path::PathBuf::from("target/debug/tap-tunnel-proxy")
            });

        let mut cmd = Command::new(&proxy_path);
        cmd.args([
            "--pid",
            &target_pid.to_string(),
            "--socket-path",
            socket_path,
            "--tap-addr",
            "10.0.0.1/24",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Create a new process group so we can kill all children
        .process_group(0);

        let child = cmd.spawn()?;
        Ok(Self { child })
    }
}

impl ProxyProcess {
    /// Kill the proxy process immediately.
    pub fn kill(&mut self) {
        kill_process_tree(&mut self.child);
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        kill_process_tree(&mut self.child);
    }
}

/// Default TAP interface IP (peer side, in namespace)
pub const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
/// Default smoltcp stack IP (local side, in test process)
pub const LOCAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
/// Subnet prefix length
pub const PREFIX_LEN: u8 = 24;

/// Create default TapConfig for tests
pub fn test_config() -> TapConfig {
    TapConfig::new()
        .interface_name("tap0")
        .peer_addr(PEER_IP, PREFIX_LEN)
        .local_addr(LOCAL_IP, PREFIX_LEN)
}

// Dual-tunnel addressing: Alice and Bob on different subnets
pub const ALICE_PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const ALICE_LOCAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
pub const BOB_PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
pub const BOB_LOCAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));

/// Create a network namespace with IP forwarding enabled.
/// This allows packets to be routed between two TAP interfaces.
pub fn forwarding_ns() -> std::io::Result<UserNetNamespace> {
    let script = r#"
echo 1 > /proc/sys/net/ipv4/ip_forward
echo READY
while true; do sleep 3600; done
"#;
    UserNetNamespace::new(script)
}

/// Create TapConfig for Alice (tap0, 10.0.0.x subnet)
pub fn alice_config() -> TapConfig {
    TapConfig::new()
        .interface_name("tap0")
        .peer_addr(ALICE_PEER_IP, PREFIX_LEN)
        .local_addr(ALICE_LOCAL_IP, PREFIX_LEN)
}

/// Create TapConfig for Bob (tap1, 10.0.1.x subnet)
pub fn bob_config() -> TapConfig {
    TapConfig::new()
        .interface_name("tap1")
        .peer_addr(BOB_PEER_IP, PREFIX_LEN)
        .local_addr(BOB_LOCAL_IP, PREFIX_LEN)
}

static INIT: Once = Once::new();

pub fn init_logging() {
    INIT.call_once(env_logger::init);
}
