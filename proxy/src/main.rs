//! TAP proxy binary for tap-tunnel.
//!
//! This binary is spawned by the main library to run inside a target namespace.
//! It joins the namespace BEFORE starting the tokio runtime, then relays
//! raw Ethernet frames between the TAP device and the parent process.
//!
//! Usage:
//!   tap-tunnel-proxy --pid <PID> --frame-fd <FD> [--tap-name <NAME>] [--tap-addr <IP/PREFIX>]

use clap::Parser;
use log::{debug, error, trace};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

mod namespace;
mod tap;

use namespace::join_namespace;
use tap::{bring_interface_up, configure_interface_ip, create_tap, get_interface_mac};
use tap_tunnel::TapConfig;

/// Maximum Ethernet frame size (MTU 1500 + Ethernet header + some margin)
const MAX_FRAME_SIZE: usize = 1522;

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
async fn run_proxy(frame_fd: OwnedFd, config: TapConfig) -> io::Result<()> {
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
