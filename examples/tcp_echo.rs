//! Example: TCP client via Tunnel API
//!
//! Usage:
//!   cargo run --example tcp_echo <PID> [host:port]
//!
//! This connects to the network namespace of the given PID and establishes
//! a TCP connection to the specified address (default: 10.0.0.1:8080).
//!
//! Test with:
//!   # Terminal 1: Create a namespace with a TCP server
//!   unshare --user --net --map-root-user bash
//!   echo $$  # Note the PID
//!   nc -l 8080  # Listen on all interfaces
//!
//!   # Terminal 2: Run this example
//!   cargo run --example tcp_echo <PID>
//!
//! Enable debug logging with:
//!   RUST_LOG=debug cargo run --example tcp_echo <PID>

use log::{debug, info};
use std::env;
use std::net::Ipv4Addr;
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
        .unwrap_or("10.0.0.1:8080")
        .parse()?;

    info!("Connecting to namespace of PID {}...", pid);

    // Configure the tunnel:
    // - TAP interface (peer) gets 10.0.0.1/24 (namespace side, where server listens)
    // - smoltcp stack (local) gets 10.0.0.2/24 (client side)
    let config = TapConfig::new()
        .interface_name("tap0")
        .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24)
        .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24);

    let tunnel = Tunnel::connect_with_config(pid, config).await?;
    info!("Connected to tunnel");

    info!("Connecting to {}...", target_addr);
    let mut stream = tunnel.tcp_connect(target_addr).await?;
    info!("Connected!");

    // Read from stdin and send to the server
    let stdin = tokio::io::stdin();
    let mut stdin = BufReader::new(stdin);
    let mut recv_buf = [0u8; 4096];

    info!("Type messages to send (Ctrl+D to quit):");

    loop {
        let mut line = String::new();

        tokio::select! {
            // Read from stdin
            result = stdin.read_line(&mut line) => {
                match result {
                    Ok(0) => {
                        info!("EOF on stdin, closing connection");
                        break;
                    }
                    Ok(_) => {
                        debug!("Sending: {:?}", line.trim());
                        stream.write_all(line.as_bytes()).await?;
                    }
                    Err(e) => {
                        eprintln!("Error reading stdin: {}", e);
                        break;
                    }
                }
            }
            // Read from server
            result = stream.read(&mut recv_buf) => {
                match result {
                    Ok(0) => {
                        info!("Server closed connection");
                        break;
                    }
                    Ok(n) => {
                        let response = String::from_utf8_lossy(&recv_buf[..n]);
                        print!("Received: {}", response);
                    }
                    Err(e) => {
                        eprintln!("Error reading from server: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
