//! TAP proxy - relays raw Ethernet frames between TAP device and IPC socket.
//!
//! This is a simplified frame relay with no protocol awareness.
//! All protocol handling (Ethernet, ARP, IP, TCP, UDP) is done by smoltcp
//! in the client library.

use crate::TapConfig;
use crate::tap::{bring_interface_up, configure_interface_ip, create_tap, get_interface_mac};
use log::{debug, trace};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use std::net::Ipv4Addr;

/// Maximum Ethernet frame size (MTU 1500 + Ethernet header + some margin)
const MAX_FRAME_SIZE: usize = 1522;

/// Build a gratuitous ARP reply frame.
///
/// This announces the IP/MAC mapping to pre-fill the peer's ARP cache
/// and signals that the proxy is ready.
fn build_gratuitous_arp(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_mac: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&target_mac); // Destination MAC
    frame.extend_from_slice(&sender_mac); // Source MAC
    frame.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP

    // ARP packet (28 bytes)
    frame.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    frame.push(6); // Hardware address length
    frame.push(4); // Protocol address length
    frame.extend_from_slice(&[0x00, 0x02]); // Operation: ARP Reply

    // Sender hardware address (MAC)
    frame.extend_from_slice(&sender_mac);
    // Sender protocol address (IP)
    frame.extend_from_slice(&sender_ip.octets());
    // Target hardware address (MAC)
    frame.extend_from_slice(&target_mac);
    // Target protocol address (IP) - same as sender for gratuitous ARP
    frame.extend_from_slice(&sender_ip.octets());

    frame
}

/// Async I/O wrapper for raw file descriptors.
///
/// Provides AsyncRead/AsyncWrite over any file descriptor (TAP devices,
/// SEQPACKET sockets, etc.) using tokio's AsyncFd for readiness notification.
struct AsyncFdIo {
    inner: AsyncFd<OwnedFd>,
}

impl AsyncFdIo {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        // Set non-blocking
        let raw_fd = fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }
}

impl AsyncRead for AsyncFdIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let fd = self.inner.get_ref().as_raw_fd();
            let unfilled = buf.initialize_unfilled();

            match guard.try_io(|_| {
                let ret = unsafe {
                    libc::read(
                        fd,
                        unfilled.as_mut_ptr() as *mut libc::c_void,
                        unfilled.len(),
                    )
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return std::task::Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncFdIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let fd = self.inner.get_ref().as_raw_fd();

            match guard.try_io(|_| {
                let ret =
                    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Run the TAP proxy - pure frame relay between TAP and IPC socket.
///
/// This creates a TAP interface and relays raw Ethernet frames unchanged
/// between the TAP device and the parent process. Before starting the relay,
/// it sends a gratuitous ARP to pre-fill the peer's ARP cache.
pub async fn run_proxy(frame_fd: OwnedFd, config: TapConfig) -> io::Result<()> {
    debug!("TAP proxy starting");

    // Create TAP interface
    let tap_fd = create_tap(&config.interface_name)?;
    debug!("created TAP interface: {}", config.interface_name);

    // Configure IP address if specified (peer_addr is the TAP interface address)
    if let Some((ip, prefix_len)) = config.peer_addr {
        configure_interface_ip(&config.interface_name, ip, prefix_len)?;
        debug!("configured IP: {}/{}", ip, prefix_len);
    }

    // Bring the interface up
    bring_interface_up(&config.interface_name)?;
    debug!("interface {} is up", config.interface_name);

    // Get TAP interface MAC address
    let tap_mac = get_interface_mac(&config.interface_name)?;
    debug!(
        "TAP MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        tap_mac[0], tap_mac[1], tap_mac[2], tap_mac[3], tap_mac[4], tap_mac[5]
    );

    // Wrap SEQPACKET socket in async wrapper
    let mut frame_socket = AsyncFdIo::new(frame_fd)?;

    // Send gratuitous ARP to pre-fill peer's ARP cache and signal readiness
    if let Some((ip, _)) = config.peer_addr {
        let broadcast_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let arp_frame = build_gratuitous_arp(tap_mac, ip, broadcast_mac);
        frame_socket.write_all(&arp_frame).await?;
        debug!("sent gratuitous ARP for {}", ip);
    }

    // Wrap TAP in async wrapper
    let tap = AsyncFdIo::new(tap_fd)?;

    // Run frame relay loop
    run_frame_relay(tap, frame_socket).await
}

/// Run the frame relay loop - bidirectional Ethernet frame forwarding.
async fn run_frame_relay(mut tap: AsyncFdIo, mut frame_socket: AsyncFdIo) -> io::Result<()> {
    let mut tap_buf = vec![0u8; MAX_FRAME_SIZE];
    let mut sock_buf = vec![0u8; MAX_FRAME_SIZE];

    debug!("[PROXY] frame relay starting");

    loop {
        tokio::select! {
            // TAP → IPC: Forward raw Ethernet frame unchanged
            result = tap.read(&mut tap_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("[PROXY] TAP closed");
                    return Ok(());
                }

                trace!("[PROXY] TAP → IPC: {} bytes", n);
                frame_socket.write_all(&tap_buf[..n]).await?;
            }

            // IPC → TAP: Forward raw Ethernet frame unchanged
            result = frame_socket.read(&mut sock_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("[PROXY] parent closed frame socket, exiting");
                    return Ok(());
                }

                trace!("[PROXY] IPC → TAP: {} bytes", n);
                tap.write_all(&sock_buf[..n]).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::create_socketpair;

    #[tokio::test]
    async fn test_async_fd_io() {
        let (parent_fd, child_fd) = create_socketpair().unwrap();
        let mut parent = AsyncFdIo::new(parent_fd).unwrap();

        let sample_pkt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let sample_pkt_len = sample_pkt.len();

        tokio::spawn(async move {
            for _ in 0..10 {
                parent.write_all(&sample_pkt[..]).await.unwrap();
                parent.write_all(&sample_pkt[..]).await.unwrap();
            }
        });

        let mut child = AsyncFdIo::new(child_fd).unwrap();
        let mut buf = [0u8; 64];

        for _ in 0..10 {
            let len = child.read(&mut buf[..]).await.unwrap();
            assert_eq!(len, sample_pkt_len);
        }
    }
}
