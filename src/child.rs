use crate::namespace::join_namespace;
use crate::tap::{bring_interface_up, create_tap, get_interface_mac};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

/// Ethernet header size in bytes
const ETH_HEADER_SIZE: usize = 14;

/// Maximum packet buffer size (larger than any MTU)
const MAX_PACKET_SIZE: usize = 65535;

/// EtherType for IPv4
const ETHERTYPE_IPV4: u16 = 0x0800;

/// EtherType for IPv6
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Run the child process event loop.
///
/// This function joins the target namespace, creates a TAP interface,
/// and relays packets between the TAP device and the parent socket.
/// This function never returns normally - it either runs forever or
/// exits the process on error.
pub fn run_child(target_pid: u32, socket_fd: OwnedFd) -> ! {
    if let Err(e) = run_child_inner(target_pid, socket_fd) {
        eprintln!("tap-tunnel child error: {}", e);
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run_child_inner(target_pid: u32, socket_fd: OwnedFd) -> io::Result<()> {
    // Join the target's namespaces
    join_namespace(target_pid)?;

    // Create TAP interface
    let tap_fd = create_tap("tap0")?;

    // Bring the interface up so it can receive packets
    bring_interface_up("tap0")?;

    // Get the TAP's MAC address for constructing Ethernet headers
    let tap_mac = get_interface_mac("tap0").unwrap_or([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    // Run the packet relay loop
    relay_loop(tap_fd, socket_fd, tap_mac)
}

fn relay_loop(tap_fd: OwnedFd, socket_fd: OwnedFd, tap_mac: [u8; 6]) -> io::Result<()> {
    let tap_raw = tap_fd.as_raw_fd();
    let socket_raw = socket_fd.as_raw_fd();

    let mut buf = vec![0u8; MAX_PACKET_SIZE + ETH_HEADER_SIZE];

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
                    // Strip Ethernet header and send IP packet to parent
                    let ip_packet = &buf[ETH_HEADER_SIZE..n as usize];
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
                        if err.kind() != io::ErrorKind::WouldBlock {
                            return Err(err);
                        }
                    }
                }
            }

            if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TAP device closed"));
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
                    return Ok(());
                } else {
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
                    let written = unsafe {
                        libc::write(tap_raw, buf.as_ptr() as *const libc::c_void, frame_len)
                    };
                    if written < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() != io::ErrorKind::WouldBlock {
                            return Err(err);
                        }
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

use std::os::fd::AsFd;
