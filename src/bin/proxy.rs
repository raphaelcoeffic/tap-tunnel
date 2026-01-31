//! TAP proxy binary for tap-tunnel.
//!
//! This binary is spawned by the main library to run inside a target namespace.
//! It joins the namespace BEFORE starting the tokio runtime, then relays
//! raw Ethernet frames between the TAP device and the parent process.
//!
//! Usage:
//!   tap-tunnel-proxy --pid <PID> --frame-fd <FD> [--tap-name <NAME>] [--tap-addr <IP/PREFIX>]

use clap::Parser;
use log::{debug, error};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd};

use tap_tunnel::TapConfig;
use tap_tunnel::namespace::join_namespace;
use tap_tunnel::proxy::run_proxy;

#[derive(Parser, Debug)]
#[command(name = "tap-tunnel-proxy")]
#[command(about = "TAP proxy process for tap-tunnel namespace operations")]
struct Args {
    /// Target PID to join namespace of
    #[arg(long)]
    pid: u32,

    /// File descriptor number for frame socket (Ethernet frame relay)
    #[arg(long)]
    frame_fd: i32,

    /// TAP interface name
    #[arg(long, default_value = "tap0")]
    tap_name: String,

    /// TAP interface address in IP/PREFIX format (optional)
    #[arg(long)]
    tap_addr: Option<String>,

    /// Packet loss percentage for testing (0-100)
    #[arg(long, default_value = "0")]
    packet_loss: u8,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    debug!(
        "proxy starting: ns_pid={}, frame_fd={}, tap_name={}",
        args.pid, args.frame_fd, args.tap_name,
    );

    // Join the target namespace BEFORE starting tokio
    if let Err(e) = join_namespace(args.pid) {
        error!("failed to join namespace: {}", e);
        std::process::exit(1);
    }
    debug!("joined namespace of pid {}", args.pid);

    // Take ownership of the inherited FD
    let frame_fd = unsafe { OwnedFd::from_raw_fd(args.frame_fd) };

    let config = build_tap_config(&args);

    let result = run(frame_fd, config);

    if let Err(e) = result {
        error!("proxy error: {}", e);
        std::process::exit(1);
    }
}

fn build_tap_config(args: &Args) -> TapConfig {
    let mut config = TapConfig::new()
        .interface_name(&args.tap_name)
        .packet_loss_percent(args.packet_loss);

    if let Some(addr_str) = &args.tap_addr {
        if let Some((ip, prefix)) = parse_ip_prefix(addr_str) {
            config = config.peer_addr(ip, prefix);
        } else {
            error!("invalid tap-addr format: {}", addr_str);
        }
    }

    config
}

fn parse_ip_prefix(s: &str) -> Option<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;

    if prefix > 32 {
        return None;
    }

    Some((ip, prefix))
}

fn run(frame_fd: OwnedFd, config: TapConfig) -> io::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_proxy(frame_fd, config))
}
