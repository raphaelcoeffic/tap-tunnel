use crate::namespace::join_namespace;
use crate::tap::{bring_interface_up, configure_interface_ip, create_tap, get_interface_mac};
use crate::TapConfig;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

/// Ethernet header size in bytes
const ETH_HEADER_SIZE: usize = 14;

/// Maximum packet buffer size (larger than any MTU)
const MAX_PACKET_SIZE: usize = 65535;

/// EtherType for IPv4
const ETHERTYPE_IPV4: u16 = 0x0800;

/// EtherType for IPv6
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// EtherType for ARP
const ETHERTYPE_ARP: u16 = 0x0806;

/// ARP operation: request
const ARP_OP_REQUEST: u16 = 1;

/// ARP operation: reply
const ARP_OP_REPLY: u16 = 2;

/// Run the child process event loop.
///
/// This function joins the target namespace, creates a TAP interface,
/// and relays packets between the TAP device and the parent socket.
/// This function never returns normally - it either runs forever or
/// exits the process on error.
pub fn run_child(target_pid: u32, socket_fd: OwnedFd, config: TapConfig) -> ! {
    if let Err(e) = run_child_inner(target_pid, socket_fd, config) {
        eprintln!("tap-tunnel child error: {}", e);
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run_child_inner(target_pid: u32, socket_fd: OwnedFd, config: TapConfig) -> io::Result<()> {
    let debug = std::env::var("TAP_TUNNEL_DEBUG").is_ok();

    if debug {
        eprintln!("[child] starting, target_pid={}", target_pid);
    }

    // Join the target's namespaces
    join_namespace(target_pid)?;
    if debug {
        eprintln!("[child] joined namespaces");
    }

    // Create TAP interface
    let tap_fd = create_tap(&config.interface_name)?;
    if debug {
        eprintln!("[child] created TAP interface: {}", config.interface_name);
    }

    // Configure IP address if specified
    if let Some((ip, prefix_len)) = config.address {
        configure_interface_ip(&config.interface_name, ip, prefix_len)?;
        if debug {
            eprintln!("[child] configured IP: {}/{}", ip, prefix_len);
        }
    }

    // Bring the interface up so it can receive packets
    bring_interface_up(&config.interface_name)?;
    if debug {
        eprintln!("[child] interface {} is up", config.interface_name);
    }

    // Get the TAP's MAC address for constructing Ethernet headers
    let tap_mac =
        get_interface_mac(&config.interface_name).unwrap_or([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    // Run the packet relay loop
    relay_loop(tap_fd, socket_fd, tap_mac)
}

fn relay_loop(tap_fd: OwnedFd, socket_fd: OwnedFd, tap_mac: [u8; 6]) -> io::Result<()> {
    let tap_raw = tap_fd.as_raw_fd();
    let socket_raw = socket_fd.as_raw_fd();

    let debug = std::env::var("TAP_TUNNEL_DEBUG").is_ok();

    let mut buf = vec![0u8; MAX_PACKET_SIZE + ETH_HEADER_SIZE];

    if debug {
        eprintln!("[child] relay loop started, tap_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            tap_mac[0], tap_mac[1], tap_mac[2], tap_mac[3], tap_mac[4], tap_mac[5]);
    }

    loop {
        let mut poll_fds = [
            PollFd::new(tap_fd.as_fd(), PollFlags::POLLIN),
            PollFd::new(socket_fd.as_fd(), PollFlags::POLLIN),
        ];

        poll(&mut poll_fds, PollTimeout::NONE)?;

        // Check TAP for incoming frames
        if let Some(revents) = poll_fds[0].revents() {
            if revents.contains(PollFlags::POLLIN) {
                let n = unsafe {
                    libc::read(tap_raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };

                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                } else if n as usize > ETH_HEADER_SIZE {
                    let frame = &buf[..n as usize];
                    let ethertype = ((frame[12] as u16) << 8) | (frame[13] as u16);

                    if debug {
                        eprintln!("[child] TAP recv: {} bytes, ethertype=0x{:04x}", n, ethertype);
                    }

                    match ethertype {
                        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                            // Forward IP packet to parent (strip Ethernet header)
                            let ip_packet = &frame[ETH_HEADER_SIZE..];
                            if debug {
                                eprintln!("[child] forwarding IP packet to parent: {} bytes", ip_packet.len());
                            }
                            let sent = unsafe {
                                libc::send(
                                    socket_raw,
                                    ip_packet.as_ptr() as *const libc::c_void,
                                    ip_packet.len(),
                                    0,
                                )
                            };
                            if sent < 0 {
                                let err = io::Error::last_os_error();
                                if debug {
                                    eprintln!("[child] send to parent failed: {}", err);
                                }
                                if err.kind() != io::ErrorKind::WouldBlock {
                                    return Err(err);
                                }
                            } else if debug {
                                eprintln!("[child] sent {} bytes to parent", sent);
                            }
                        }
                        ETHERTYPE_ARP => {
                            if debug {
                                eprintln!("[child] received ARP frame");
                            }
                            // Handle ARP locally
                            if let Some(reply) = handle_arp_request(frame, &tap_mac) {
                                if debug {
                                    eprintln!("[child] sending ARP reply: {} bytes", reply.len());
                                }
                                let written = unsafe {
                                    libc::write(
                                        tap_raw,
                                        reply.as_ptr() as *const libc::c_void,
                                        reply.len(),
                                    )
                                };
                                if written < 0 {
                                    let err = io::Error::last_os_error();
                                    if debug {
                                        eprintln!("[child] ARP reply write failed: {}", err);
                                    }
                                    if err.kind() != io::ErrorKind::WouldBlock {
                                        return Err(err);
                                    }
                                } else if debug {
                                    eprintln!("[child] ARP reply written: {} bytes", written);
                                }
                            } else if debug {
                                eprintln!("[child] ARP frame ignored (not a request or invalid)");
                            }
                        }
                        _ => {
                            if debug {
                                eprintln!("[child] ignoring frame with ethertype 0x{:04x}", ethertype);
                            }
                        }
                    }
                }
            }

            if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TAP device closed",
                ));
            }
        }

        // Check socket for incoming IP packets from parent
        if let Some(revents) = poll_fds[1].revents() {
            if revents.contains(PollFlags::POLLIN) {
                // Receive into buffer after the Ethernet header space
                let n = unsafe {
                    libc::recv(
                        socket_raw,
                        buf[ETH_HEADER_SIZE..].as_mut_ptr() as *mut libc::c_void,
                        buf.len() - ETH_HEADER_SIZE,
                        0,
                    )
                };

                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                } else if n == 0 {
                    // Parent closed the socket, exit cleanly
                    if debug {
                        eprintln!("[child] parent closed socket, exiting");
                    }
                    return Ok(());
                } else {
                    if debug {
                        eprintln!("[child] received {} bytes from parent", n);
                    }

                    // Determine IP version from first byte
                    let ip_version = (buf[ETH_HEADER_SIZE] >> 4) & 0x0F;
                    let ethertype = if ip_version == 6 {
                        ETHERTYPE_IPV6
                    } else {
                        ETHERTYPE_IPV4
                    };

                    // Construct Ethernet header
                    // Destination: broadcast (works for most cases)
                    buf[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
                    // Source: TAP's MAC
                    buf[6..12].copy_from_slice(&tap_mac);
                    // EtherType (big-endian)
                    buf[12] = (ethertype >> 8) as u8;
                    buf[13] = (ethertype & 0xff) as u8;

                    // Write frame to TAP
                    let frame_len = ETH_HEADER_SIZE + n as usize;
                    if debug {
                        eprintln!("[child] writing {} byte frame to TAP (ethertype=0x{:04x})", frame_len, ethertype);
                    }
                    let written = unsafe {
                        libc::write(tap_raw, buf.as_ptr() as *const libc::c_void, frame_len)
                    };
                    if written < 0 {
                        let err = io::Error::last_os_error();
                        if debug {
                            eprintln!("[child] TAP write failed: {}", err);
                        }
                        if err.kind() != io::ErrorKind::WouldBlock {
                            return Err(err);
                        }
                    } else if debug {
                        eprintln!("[child] wrote {} bytes to TAP", written);
                    }
                }
            }

            if revents.contains(PollFlags::POLLHUP) {
                // Parent closed the socket, exit cleanly
                return Ok(());
            }

            if revents.contains(PollFlags::POLLERR) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket error"));
            }
        }
    }
}

/// Handle an ARP request and return an ARP reply if appropriate.
/// ARP packet structure (after Ethernet header):
///   - Hardware type (2 bytes): 0x0001 for Ethernet
///   - Protocol type (2 bytes): 0x0800 for IPv4
///   - Hardware addr len (1 byte): 6 for Ethernet
///   - Protocol addr len (1 byte): 4 for IPv4
///   - Operation (2 bytes): 1=request, 2=reply
///   - Sender hardware addr (6 bytes)
///   - Sender protocol addr (4 bytes)
///   - Target hardware addr (6 bytes)
///   - Target protocol addr (4 bytes)
fn handle_arp_request(frame: &[u8], tap_mac: &[u8; 6]) -> Option<Vec<u8>> {
    // Minimum ARP frame: 14 (eth) + 28 (arp) = 42 bytes
    if frame.len() < 42 {
        return None;
    }

    let arp = &frame[ETH_HEADER_SIZE..];

    // Check hardware type (Ethernet = 0x0001)
    if arp[0] != 0x00 || arp[1] != 0x01 {
        return None;
    }

    // Check protocol type (IPv4 = 0x0800)
    if arp[2] != 0x08 || arp[3] != 0x00 {
        return None;
    }

    // Check operation (request = 0x0001)
    let operation = ((arp[6] as u16) << 8) | (arp[7] as u16);
    if operation != ARP_OP_REQUEST {
        return None;
    }

    // Build ARP reply
    let mut reply = vec![0u8; 42];

    // Ethernet header
    // Destination: sender's MAC (from ARP sender hardware addr)
    reply[0..6].copy_from_slice(&arp[8..14]);
    // Source: our MAC
    reply[6..12].copy_from_slice(tap_mac);
    // EtherType: ARP
    reply[12] = (ETHERTYPE_ARP >> 8) as u8;
    reply[13] = (ETHERTYPE_ARP & 0xff) as u8;

    // ARP payload
    let arp_reply = &mut reply[ETH_HEADER_SIZE..];

    // Hardware type: Ethernet
    arp_reply[0] = 0x00;
    arp_reply[1] = 0x01;
    // Protocol type: IPv4
    arp_reply[2] = 0x08;
    arp_reply[3] = 0x00;
    // Hardware addr length: 6
    arp_reply[4] = 6;
    // Protocol addr length: 4
    arp_reply[5] = 4;
    // Operation: reply
    arp_reply[6] = (ARP_OP_REPLY >> 8) as u8;
    arp_reply[7] = (ARP_OP_REPLY & 0xff) as u8;

    // Sender hardware addr: our MAC
    arp_reply[8..14].copy_from_slice(tap_mac);
    // Sender protocol addr: target IP from request (we claim to be any IP)
    arp_reply[14..18].copy_from_slice(&arp[24..28]);

    // Target hardware addr: sender's MAC from request
    arp_reply[18..24].copy_from_slice(&arp[8..14]);
    // Target protocol addr: sender's IP from request
    arp_reply[24..28].copy_from_slice(&arp[14..18]);

    Some(reply)
}
