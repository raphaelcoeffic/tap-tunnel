//! # tap-tunnel
//!
//! A Rust library providing an async tokio API to send/receive IP packets
//! to/from a network namespace via a TAP interface.
//!
//! This library requires no special capabilities - it leverages the target
//! process's user namespace to gain the necessary permissions.

mod child;
mod ipc;
mod namespace;
mod tap;

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// Configuration for the TAP interface.
#[derive(Clone, Debug)]
pub struct TapConfig {
    /// Name of the TAP interface (default: "tap0")
    pub interface_name: String,
    /// Optional IPv4 address and prefix length to configure on the interface
    pub address: Option<(Ipv4Addr, u8)>,
}

impl Default for TapConfig {
    fn default() -> Self {
        Self {
            interface_name: "tap0".to_string(),
            address: None,
        }
    }
}

impl TapConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface name.
    pub fn interface_name(mut self, name: impl Into<String>) -> Self {
        self.interface_name = name.into();
        self
    }

    /// Set the IPv4 address and prefix length for the interface.
    pub fn address(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.address = Some((addr, prefix_len));
        self
    }
}

/// A tunnel to a network namespace via a TAP interface.
///
/// The tunnel is established by forking a child process that joins the
/// target namespace, creates a TAP interface, and relays packets between
/// the TAP device and this process via a Unix socket.
pub struct TapTunnel {
    socket: AsyncFd<UnixStream>,
    #[allow(dead_code)]
    child_pid: u32,
}

impl TapTunnel {
    /// Connect to the network namespace of the given PID with default configuration.
    ///
    /// This is equivalent to `connect_with_config(pid, TapConfig::default())`.
    pub async fn connect(pid: u32) -> io::Result<Self> {
        Self::connect_with_config(pid, TapConfig::default()).await
    }

    /// Connect to the network namespace of the given PID with custom configuration.
    ///
    /// This forks a child process that:
    /// 1. Joins the target's user namespace (gaining capabilities)
    /// 2. Joins the target's network namespace
    /// 3. Creates a TAP interface with the configured name
    /// 4. Optionally configures an IP address on the interface
    /// 5. Brings the interface up
    /// 6. Relays packets between the TAP and this process
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target PID doesn't exist or its namespaces can't be accessed
    /// - The fork fails
    /// - The socketpair creation fails
    pub async fn connect_with_config(pid: u32, config: TapConfig) -> io::Result<Self> {
        // Create socketpair for parent-child communication
        let (parent_fd, child_fd) = ipc::create_socketpair()?;

        // Fork the child process
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Child) => {
                // Child process: close parent's end and run the relay loop
                drop(parent_fd);
                child::run_child(pid, child_fd, config);
                // run_child never returns
            }
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                // Parent process: close child's end
                drop(child_fd);

                // Convert OwnedFd to UnixStream for AsyncFd
                let stream = fd_to_unix_stream(parent_fd)?;

                // Set non-blocking for async operation
                stream.set_nonblocking(true)?;

                let socket = AsyncFd::new(stream)?;

                Ok(TapTunnel {
                    socket,
                    child_pid: child.as_raw() as u32,
                })
            }
            Err(e) => Err(io::Error::other(format!("fork failed: {}", e))),
        }
    }

    /// Send an IP packet into the namespace.
    ///
    /// The packet should be a raw IP packet (IPv4 or IPv6).
    /// The child process will add the appropriate Ethernet header
    /// before writing to the TAP device.
    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.socket.ready(Interest::WRITABLE).await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe {
                    libc::send(fd, packet.as_ptr() as *const libc::c_void, packet.len(), 0)
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive an IP packet from the namespace.
    ///
    /// Returns the number of bytes read into the buffer.
    /// The returned data is a raw IP packet (Ethernet headers stripped).
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.socket.ready(Interest::READABLE).await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe {
                    libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// Convert an OwnedFd to a UnixStream.
fn fd_to_unix_stream(fd: OwnedFd) -> io::Result<UnixStream> {
    use std::os::fd::FromRawFd;
    use std::os::fd::IntoRawFd;

    // Safety: we own the fd and are transferring ownership to UnixStream
    let raw_fd = fd.into_raw_fd();
    let stream = unsafe { UnixStream::from_raw_fd(raw_fd) };
    Ok(stream)
}

impl Drop for TapTunnel {
    fn drop(&mut self) {
        // Closing the socket will cause the child to detect EOF and exit.
        // We don't need to explicitly kill it.
    }
}
