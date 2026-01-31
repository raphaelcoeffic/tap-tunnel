//! Example: ICMP echo responder via tap-tunnel
//!
//! Usage:
//!   cargo run --example echo_tunnel <PID>
//!
//! This connects to the network namespace of the given PID, configures the
//! TAP interface with 10.0.0.1/24, and responds to ICMP echo requests (pings)
//! sent to 10.0.0.2.
//!
//! Test with:
//!   # Terminal 1: Create a namespace
//!   unshare --user --net --map-root-user bash
//!   echo $$  # Note the PID
//!
//!   # Terminal 2: Run this example
//!   cargo run --example echo_tunnel <PID>
//!
//!   # Terminal 1: Ping the virtual host
//!   ping 10.0.0.2  # Should get replies

use std::env;
use std::net::Ipv4Addr;
use tap_tunnel::{TapConfig, TapTunnel};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <PID>", args[0]);
        std::process::exit(1);
    }

    let pid: u32 = args[1].parse().map_err(|_| "Invalid PID")?;

    println!("Connecting to namespace of PID {}...", pid);

    // Configure 10.0.0.1/24 on tap0 - this is the namespace's address.
    // The library "pretends" to be 10.0.0.2 by responding to ARP/ICMP.
    let config = TapConfig::new().address(Ipv4Addr::new(10, 0, 0, 1), 24);
    let tunnel = TapTunnel::connect_with_config(pid, config).await?;
    println!("Connected! TAP interface configured with 10.0.0.1/24");
    println!("In the namespace, run: ping 10.0.0.2");
    println!("Waiting for ICMP echo requests...");

    let debug = std::env::var("TAP_TUNNEL_DEBUG").is_ok();
    let mut buf = vec![0u8; 65535];

    loop {
        let n = tunnel.recv(&mut buf).await?;
        if n == 0 {
            break;
        }

        let packet = &buf[..n];

        if debug {
            eprintln!("[parent] received {} byte packet", n);
            if n >= 20 {
                let version = (packet[0] >> 4) & 0x0F;
                let protocol = packet[9];
                eprintln!("[parent] IP version={}, protocol={}", version, protocol);
            }
        }

        // Check if this is an IPv4 ICMP echo request
        if let Some(reply) = process_icmp_echo_request(packet) {
            println!(
                "Received ping from {}, sending reply",
                format_ipv4_src(packet)
            );
            if debug {
                eprintln!("[parent] sending {} byte reply", reply.len());
            }
            tunnel.send(&reply).await?;
            if debug {
                eprintln!("[parent] reply sent");
            }
        } else if debug {
            eprintln!("[parent] packet is not an ICMP echo request, ignoring");
        }
    }

    Ok(())
}

/// Process an IPv4 ICMP echo request and return the echo reply.
/// Returns None if the packet is not an ICMP echo request.
fn process_icmp_echo_request(packet: &[u8]) -> Option<Vec<u8>> {
    // Minimum IPv4 header (20 bytes) + ICMP header (8 bytes)
    if packet.len() < 28 {
        return None;
    }

    // Check IP version (should be 4)
    let version = (packet[0] >> 4) & 0x0F;
    if version != 4 {
        return None;
    }

    // Get IP header length (in 32-bit words)
    let ihl = (packet[0] & 0x0F) as usize;
    let ip_header_len = ihl * 4;
    if packet.len() < ip_header_len + 8 {
        return None;
    }

    // Check protocol (1 = ICMP)
    let protocol = packet[9];
    if protocol != 1 {
        return None;
    }

    // Get ICMP portion
    let icmp = &packet[ip_header_len..];

    // Check ICMP type (8 = echo request)
    let icmp_type = icmp[0];
    if icmp_type != 8 {
        return None;
    }

    // Build the reply packet
    let mut reply = packet.to_vec();

    // Swap source and destination IP addresses
    // Source IP is at offset 12-15, Dest IP is at offset 16-19
    for i in 0..4 {
        reply.swap(12 + i, 16 + i);
    }

    // Set ICMP type to 0 (echo reply)
    reply[ip_header_len] = 0;

    // Recalculate ICMP checksum
    // First, zero out the checksum field
    reply[ip_header_len + 2] = 0;
    reply[ip_header_len + 3] = 0;

    let icmp_data = &reply[ip_header_len..];
    let icmp_checksum = calculate_checksum(icmp_data);
    reply[ip_header_len + 2] = (icmp_checksum >> 8) as u8;
    reply[ip_header_len + 3] = (icmp_checksum & 0xFF) as u8;

    // Recalculate IP header checksum
    // First, zero out the checksum field (offset 10-11)
    reply[10] = 0;
    reply[11] = 0;

    let ip_header = &reply[..ip_header_len];
    let ip_checksum = calculate_checksum(ip_header);
    reply[10] = (ip_checksum >> 8) as u8;
    reply[11] = (ip_checksum & 0xFF) as u8;

    Some(reply)
}

/// Calculate the Internet checksum (RFC 1071).
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }

    // Add odd byte if present
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// Format the source IPv4 address from a packet for display.
fn format_ipv4_src(packet: &[u8]) -> String {
    if packet.len() >= 16 {
        format!(
            "{}.{}.{}.{}",
            packet[12], packet[13], packet[14], packet[15]
        )
    } else {
        "unknown".to_string()
    }
}
