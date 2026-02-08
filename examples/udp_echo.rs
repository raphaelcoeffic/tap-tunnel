//! Example: UDP client via Tunnel API
//!
//! Usage:
//!   cargo run --example udp_echo <PID> [host:port]
//!
//! This connects to the network namespace of the given PID and sends/receives
//! UDP packets to/from the specified address (default: 10.0.0.1:5000).
//!
//! Test with:
//!   # Terminal 1: Create a namespace with a UDP server
//!   unshare --user --net --map-root-user bash
//!   echo $$  # Note the PID
//!   nc -u -l 5000
//!
//!   # Terminal 2: Run this example
//!   cargo run --example udp_echo <PID>
//!
//! Enable debug logging with:
//!   RUST_LOG=debug cargo run --example udp_echo <PID>

use log::{debug, info};
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use tap_tunnel::{TapConfig, Tunnel};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: {} <PID> [host:port]", args[0]);
        std::process::exit(1);
    }

    let pid: u32 = args[1].parse().map_err(|_| "Invalid PID")?;
    let target_addr: std::net::SocketAddr = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("10.0.0.1:5000")
        .parse()?;

    info!("Connecting to namespace of PID {}...", pid);

    // Configure the tunnel:
    // - TAP interface (peer) gets 10.0.0.1/24 (namespace side, where server listens)
    // - smoltcp stack (local) gets 10.0.0.2/24 (client side)
    let config = TapConfig::new()
        .interface_name("tap0")
        .peer_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24)
        .local_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24);

    let tunnel = Tunnel::connect_with_config(pid, config).await?;
    info!("Connected to tunnel");

    // Bind UDP socket on our local address
    let local_bind: std::net::SocketAddr = "10.0.0.2:0".parse()?;
    info!("Binding UDP socket to {}...", local_bind);
    let mut socket = tunnel.udp_bind(local_bind).await?;
    info!("Bound! Target: {}", target_addr);

    // Read from stdin and send to the target
    let stdin = tokio::io::stdin();
    let mut stdin = BufReader::new(stdin);
    let mut recv_buf = [0u8; 65535];

    info!("Type messages to send (Ctrl+D to quit):");

    loop {
        let mut line = String::new();

        tokio::select! {
            // Read from stdin
            result = stdin.read_line(&mut line) => {
                match result {
                    Ok(0) => {
                        info!("EOF on stdin, exiting");
                        break;
                    }
                    Ok(_) => {
                        let msg = line.trim_end();
                        debug!("Sending: {:?}", msg);
                        socket.send_to(msg.as_bytes(), target_addr).await?;
                    }
                    Err(e) => {
                        eprintln!("Error reading stdin: {}", e);
                        break;
                    }
                }
            }
            // Receive UDP packets
            result = socket.recv_from(&mut recv_buf) => {
                match result {
                    Ok((n, from)) => {
                        let msg = String::from_utf8_lossy(&recv_buf[..n]);
                        println!("Received from {}: {}", from, msg);
                    }
                    Err(e) => {
                        eprintln!("Error receiving: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
