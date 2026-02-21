//! TAP proxy binary for tap-tunnel.
//!
//! This binary is spawned by the main library to run inside a target namespace.
//! It joins the namespace BEFORE starting the tokio runtime, performs a protocol
//! handshake with the client, then relays Ethernet frames between the TAP device
//! and the parent process using the type-prefixed message protocol.
//!
//! ```
//! Usage:
//!   tap-tunnel-proxy --pid <PID> --frame-fd <FD> [--tap-name <NAME>] [--tap-addr <IP/PREFIX>]
//!   tap-tunnel-proxy --pid <PID> --socket-path <PATH> [--tap-name <NAME>] [--tap-addr <IP/PREFIX>]
//!   tap-tunnel-proxy --socket-path <PATH> [--tap-name <NAME>] [--tap-addr <IP/PREFIX>]
//! ```
//!
//! When `--pid` is omitted, the proxy assumes it's already running in the target namespace
//! (e.g., started directly inside a container).

use clap::Parser;
use log::{debug, error, trace};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

mod ipc;
mod namespace;
mod route;
mod tap;

use ipc::{accept_stream, create_stream_listener};
use namespace::join_namespace;
use tap::{configure_interface, create_tap};
use tap_tunnel::TapConfig;
use std::collections::HashMap;
use tap_tunnel::protocol::{
    ClientHello, InterfaceStats, Message, ProxyCommand, ProxyConfig, ProxyResponse,
    decode_control, decode_message, encode_control, encode_frame,
};

/// Ethernet header size in bytes.
const ETHERNET_HEADER_SIZE: usize = 14;

#[derive(Parser, Debug)]
#[command(name = "tap-tunnel-proxy")]
#[command(about = "TAP proxy process for tap-tunnel namespace operations")]
struct Args {
    /// Target PID to join namespace of.
    /// If omitted, assumes already running in the target namespace.
    #[arg(long)]
    pid: Option<u32>,

    /// File descriptor number for frame socket (Ethernet frame relay)
    /// Mutually exclusive with --socket-path
    #[arg(long, conflicts_with = "socket_path")]
    frame_fd: Option<i32>,

    /// Unix socket path to listen on for frame relay
    /// Mutually exclusive with --frame-fd
    #[arg(long, conflicts_with = "frame_fd")]
    socket_path: Option<PathBuf>,

    /// TAP interface name
    #[arg(long, default_value = "tap0")]
    tap_name: String,

    /// TAP interface address in IP/PREFIX format (optional)
    #[arg(long)]
    tap_addr: Option<String>,

    /// Packet loss percentage for testing (0-100)
    #[arg(long, default_value = "0")]
    packet_loss: u8,

    /// Routes to add on the TAP interface (repeatable, format: IP/PREFIX)
    #[arg(long)]
    tap_route: Vec<String>,

    /// IP-level MTU for the TAP interface (default: 1500)
    #[arg(long, default_value = "1500")]
    mtu: u16,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    // Validate that exactly one of frame_fd or socket_path is provided
    if args.frame_fd.is_none() && args.socket_path.is_none() {
        error!("either --frame-fd or --socket-path must be specified");
        std::process::exit(1);
    }

    debug!(
        "proxy starting: pid={:?}, frame_fd={:?}, socket_path={:?}, tap_name={}",
        args.pid, args.frame_fd, args.socket_path, args.tap_name,
    );

    // Join the target namespace BEFORE starting tokio (if PID provided)
    if let Some(pid) = args.pid {
        if let Err(e) = join_namespace(pid) {
            error!("failed to join namespace: {}", e);
            std::process::exit(1);
        }
        debug!("joined namespace of pid {}", pid);
    } else {
        debug!("no --pid specified, assuming already in target namespace");
    }

    let config = build_tap_config(&args);

    let result = if let Some(fd) = args.frame_fd {
        // Take ownership of the inherited FD
        let frame_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        run(frame_fd, config)
    } else if let Some(socket_path) = args.socket_path {
        // Socket-path mode: bind, listen, accept, then run
        run_socket_path_mode(&socket_path, config)
    } else {
        unreachable!()
    };

    if let Err(e) = result {
        error!("proxy error: {}", e);
        std::process::exit(1);
    }
}

fn build_tap_config(args: &Args) -> TapConfig {
    let mut config = TapConfig::new()
        .interface_name(&args.tap_name)
        .packet_loss_percent(args.packet_loss)
        .mtu(args.mtu);

    if let Some(addr_str) = &args.tap_addr {
        if let Some((ip, prefix)) = parse_ip_prefix(addr_str) {
            config = config.peer_addr(ip, prefix);
        } else {
            error!("invalid tap-addr format: {}", addr_str);
        }
    }

    for route_str in &args.tap_route {
        if let Some((ip, prefix)) = parse_ip_prefix(route_str) {
            config = config.peer_route(ip, prefix);
        } else {
            error!("invalid tap-route format: {}", route_str);
        }
    }

    config
}

fn parse_ip_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return None;
    }

    Some((ip, prefix))
}

fn run(frame_fd: OwnedFd, config: TapConfig) -> io::Result<()> {
    // 1. Create and configure TAP interface BEFORE handshake so we have MAC
    let tap_fd = create_tap(&config.interface_name)?;
    debug!("created TAP interface: {}", config.interface_name);

    // Configure IP (if specified), set MTU, bring up, and get MAC address
    let mtu_opt = if config.mtu != 1500 {
        Some(config.mtu)
    } else {
        None
    };
    let tap_mac = configure_interface(&config.interface_name, config.peer_addr, mtu_opt)?;
    if let Some((ip, prefix_len)) = config.peer_addr {
        debug!("configured IP: {}/{}", ip, prefix_len);
    }
    if config.mtu != 1500 {
        debug!("configured MTU: {}", config.mtu);
    }
    debug!("interface {} is up", config.interface_name);
    debug!(
        "TAP MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        tap_mac[0], tap_mac[1], tap_mac[2], tap_mac[3], tap_mac[4], tap_mac[5]
    );

    // 2. Perform protocol handshake - send proxy identity to client
    perform_handshake(&frame_fd, &config, tap_mac)?;
    debug!("handshake complete");

    // 3. Start async runtime for frame relay
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_proxy(frame_fd, tap_fd, tap_mac, config))
}

/// Run in socket-path mode: bind, listen, accept a connection, then run proxy with handshake.
fn run_socket_path_mode(socket_path: &std::path::Path, config: TapConfig) -> io::Result<()> {
    debug!("binding to socket path: {:?}", socket_path);
    let listener = create_stream_listener(socket_path)?;
    debug!("listening for connection on {:?}", socket_path);

    let frame_fd = accept_stream(&listener)?;
    debug!("accepted connection");

    // Close the listener, we only need one connection
    drop(listener);

    // run() handles handshake and protocol mode
    run(frame_fd, config)
}

/// Perform protocol handshake with client.
///
/// The handshake is simplified: client sends an empty ClientHello,
/// proxy responds with its identity (tap_ip, tap_mac, prefix_len).
/// The client is responsible for picking and managing its own IPs.
/// Blocking read_exact on a raw fd.
fn read_exact_fd(fd: i32, buf: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let ret = unsafe {
            libc::read(fd, buf[offset..].as_mut_ptr() as *mut libc::c_void, buf.len() - offset)
        };
        if ret < 0 { return Err(io::Error::last_os_error()); }
        if ret == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")); }
        offset += ret as usize;
    }
    Ok(())
}

/// Blocking write_all on a raw fd.
fn write_all_fd(fd: i32, buf: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let ret = unsafe {
            libc::write(fd, buf[offset..].as_ptr() as *const libc::c_void, buf.len() - offset)
        };
        if ret < 0 { return Err(io::Error::last_os_error()); }
        offset += ret as usize;
    }
    Ok(())
}

fn perform_handshake(fd: &OwnedFd, config: &TapConfig, tap_mac: [u8; 6]) -> io::Result<()> {
    let raw_fd = fd.as_raw_fd();

    // Receive ClientHello with length-prefix framing
    let mut len_buf = [0u8; 4];
    read_exact_fd(raw_fd, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    read_exact_fd(raw_fd, &mut buf)?;

    let msg = decode_message(&buf)?;
    let hello: ClientHello = match msg {
        Message::Control(payload) => decode_control(&payload)?,
        Message::Frame(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected ClientHello, got frame",
            ));
        }
    };
    debug!("received ClientHello: {:?}", hello);

    // Get TAP config
    let (tap_ip, prefix_len) = config.peer_addr.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "tap_addr must be configured")
    })?;

    // Send ProxyConfig with proxy identity (length-prefix framed)
    let proxy_config = ProxyConfig {
        tap_ip,
        tap_mac,
        prefix_len,
        mtu: config.mtu,
    };
    let config_msg = encode_control(&proxy_config)?;
    let len = (config_msg.len() as u32).to_be_bytes();
    write_all_fd(raw_fd, &len)?;
    write_all_fd(raw_fd, &config_msg)?;
    debug!("sent ProxyConfig: {}", proxy_config);

    Ok(())
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

/// Run the TAP proxy with type-prefixed message protocol.
///
/// The TAP device is pre-created so the MAC is available for the handshake.
async fn run_proxy(
    frame_fd: OwnedFd,
    tap_fd: OwnedFd,
    tap_mac: [u8; 6],
    config: TapConfig,
) -> io::Result<()> {
    debug!("TAP proxy starting");

    // Wrap STREAM socket as tokio UnixStream for efficient async I/O
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(frame_fd.into_raw_fd()) };
    std_stream.set_nonblocking(true)?;
    let ipc_stream = tokio::net::UnixStream::from_std(std_stream)?;
    let (ipc_read, mut ipc_write) = ipc_stream.into_split();

    // Send gratuitous ARP to pre-fill peer's ARP cache (IPv4 only)
    // IPv6 uses NDP (Neighbor Discovery Protocol) instead of ARP
    if let Some((IpAddr::V4(ipv4), _)) = config.peer_addr {
        use tokio::io::AsyncWriteExt;

        let broadcast_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let arp_frame = build_gratuitous_arp(tap_mac, ipv4, broadcast_mac);
        let msg = encode_frame(&arp_frame);
        let len = (msg.len() as u32).to_be_bytes();
        ipc_write.write_all(&len).await?;
        ipc_write.write_all(&msg).await?;
        debug!("sent gratuitous ARP for {}", ipv4);
    }

    // Set up rtnetlink connection for route management
    let (rt_conn, rt_handle, _) = rtnetlink::new_connection()
        .map_err(|e| io::Error::other(format!("failed to create rtnetlink connection: {}", e)))?;
    tokio::spawn(rt_conn);

    // Add initial routes from CLI args
    for (dest, prefix_len) in &config.peer_routes {
        match route::add_route(&rt_handle, &config.interface_name, *dest, *prefix_len).await {
            Ok(()) => debug!("added initial route {}/{} dev {}", dest, prefix_len, config.interface_name),
            Err(e) => error!("failed to add initial route {}/{}: {}", dest, prefix_len, e),
        }
    }

    // Wrap TAP in async wrapper (still uses AsyncFdIo - it's a character device, not a socket)
    let tap = AsyncFdIo::new(tap_fd)?;

    // Compute max frame size from configured MTU
    let max_frame_size = config.mtu as usize + ETHERNET_HEADER_SIZE;

    // Run frame relay loop with protocol support
    run_frame_relay(tap, ipc_read, ipc_write, &rt_handle, &config.interface_name, max_frame_size).await
}

/// Handle a proxy command and return a response.
async fn handle_proxy_command(
    cmd: ProxyCommand,
    rt_handle: &rtnetlink::Handle,
    iface_name: &str,
) -> ProxyResponse {
    match cmd {
        ProxyCommand::AddRoute {
            id,
            destination,
            prefix_len,
        } => match route::add_route(rt_handle, iface_name, destination, prefix_len).await {
            Ok(()) => {
                debug!(
                    "[PROXY] added route {}/{} dev {}",
                    destination, prefix_len, iface_name
                );
                ProxyResponse::ok(id)
            }
            Err(e) => {
                error!(
                    "[PROXY] failed to add route {}/{}: {}",
                    destination, prefix_len, e
                );
                ProxyResponse::error(id, e.to_string())
            }
        },
        ProxyCommand::RemoveRoute {
            id,
            destination,
            prefix_len,
        } => match route::remove_route(rt_handle, iface_name, destination, prefix_len).await {
            Ok(()) => {
                debug!(
                    "[PROXY] removed route {}/{} dev {}",
                    destination, prefix_len, iface_name
                );
                ProxyResponse::ok(id)
            }
            Err(e) => {
                error!(
                    "[PROXY] failed to remove route {}/{}: {}",
                    destination, prefix_len, e
                );
                ProxyResponse::error(id, e.to_string())
            }
        },
        ProxyCommand::GetIfaceStats { id } => match read_proc_net_dev() {
            Ok(interfaces) => {
                debug!("[PROXY] returning interface stats ({} interfaces)", interfaces.len());
                ProxyResponse::IfaceStats { id, interfaces }
            }
            Err(e) => {
                error!("[PROXY] failed to read /proc/net/dev: {}", e);
                ProxyResponse::error(id, e.to_string())
            }
        },
    }
}

/// Parse /proc/net/dev and return per-interface statistics.
fn read_proc_net_dev() -> io::Result<HashMap<String, InterfaceStats>> {
    let content = std::fs::read_to_string("/proc/net/dev")?;
    let mut stats = HashMap::new();
    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 13 {
            let iface = parts[0].trim_end_matches(':').to_string();
            stats.insert(
                iface,
                InterfaceStats {
                    rx_bytes: parts[1].parse().unwrap_or(0),
                    rx_packets: parts[2].parse().unwrap_or(0),
                    rx_errors: parts[3].parse().unwrap_or(0),
                    rx_dropped: parts[4].parse().unwrap_or(0),
                    tx_bytes: parts[9].parse().unwrap_or(0),
                    tx_packets: parts[10].parse().unwrap_or(0),
                    tx_errors: parts[11].parse().unwrap_or(0),
                    tx_dropped: parts[12].parse().unwrap_or(0),
                },
            );
        }
    }
    Ok(stats)
}

/// Duplicate an OwnedFd via dup().
fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let new_fd = unsafe { libc::dup(fd.as_raw_fd()) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Capacity of the internal channel between TAP reader and IPC writer in the proxy.
///
/// This decouples TAP reads from IPC writes so the kernel never sees the proxy
/// stalling on TAP reads (which would cause kernel TX drops on the TAP device).
const PROXY_FRAME_CHANNEL_CAPACITY: usize = 4096;

/// Size of the IPC BufReader/BufWriter buffers in the proxy.
///
/// Large buffers allow batching many Ethernet frames per syscall.
/// 256KB accommodates ~1200 frames at 200 bytes each.
const PROXY_IPC_BUFFER_SIZE: usize = 256 * 1024;

/// Run the frame relay loop - bidirectional Ethernet frame forwarding with protocol.
///
/// Uses length-prefix framed STREAM socket with BufReader/BufWriter for batched I/O.
/// The TAP→IPC direction is decoupled via a channel so TAP reads never block on IPC.
async fn run_frame_relay(
    tap: AsyncFdIo,
    ipc_read: tokio::net::unix::OwnedReadHalf,
    ipc_write: tokio::net::unix::OwnedWriteHalf,
    rt_handle: &rtnetlink::Handle,
    iface_name: &str,
    max_frame_size: usize,
) -> io::Result<()> {
    // Dup the TAP fd so we can read and write independently
    let tap_write_fd = dup_fd(tap.inner.get_ref())?;
    let mut tap_reader = tap;
    let mut tap_writer = AsyncFdIo::new(tap_write_fd)?;

    // Wrap IPC socket halves in buffered I/O for batched reads/writes
    let mut ipc_reader = tokio::io::BufReader::with_capacity(PROXY_IPC_BUFFER_SIZE, ipc_read);
    let ipc_writer = tokio::io::BufWriter::with_capacity(PROXY_IPC_BUFFER_SIZE, ipc_write);

    // Channel between TAP reader and IPC writer — decouples TAP reads from IPC writes
    let (tap_frame_tx, mut tap_frame_rx) =
        tokio::sync::mpsc::channel::<Vec<u8>>(PROXY_FRAME_CHANNEL_CAPACITY);

    // Channel for control responses from ipc_to_tap back to the socket writer
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

    debug!("[PROXY] frame relay starting (stream mode)");

    // Clone rt_handle and own iface_name so spawned tasks are 'static
    let rt_handle = rt_handle.clone();
    let iface_name = iface_name.to_string();

    // Task 1: TAP reader — drains TAP device into channel, never blocks on IPC
    let h1 = tokio::spawn(async move {
        let mut buf = vec![0u8; max_frame_size];
        let mut dropped: u64 = 0;
        loop {
            let n = match tap_reader.read(&mut buf).await {
                Ok(0) => {
                    debug!("[PROXY] TAP closed");
                    return Ok::<_, io::Error>(());
                }
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            // Encode frame with type prefix (will be length-prefixed when written to IPC)
            let msg = encode_frame(&buf[..n]);
            trace!("[PROXY] TAP → chan: {} bytes (frame: {})", msg.len(), n);
            if let Err(e) = tap_frame_tx.try_send(msg) {
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        dropped += 1;
                        if dropped % 1000 == 1 {
                            debug!("[PROXY] TAP→IPC channel full, dropped {} frames", dropped);
                        }
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        return Ok(());
                    }
                }
            }
        }
    });

    // Task 2: IPC writer — batches frames from channel + responses, flushes to socket
    let h2 = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        let mut writer = ipc_writer;
        loop {
            // Wait for the first frame or response
            tokio::select! {
                frame = tap_frame_rx.recv() => {
                    match frame {
                        Some(msg) => {
                            let len = (msg.len() as u32).to_be_bytes();
                            writer.write_all(&len).await?;
                            writer.write_all(&msg).await?;
                        }
                        None => {
                            debug!("[PROXY] TAP reader closed");
                            writer.flush().await?;
                            return Ok::<_, io::Error>(());
                        }
                    }
                }
                Some(response) = response_rx.recv() => {
                    let len = (response.len() as u32).to_be_bytes();
                    writer.write_all(&len).await?;
                    writer.write_all(&response).await?;
                }
            }

            // Drain any additional buffered frames/responses (non-blocking) for batching
            while let Ok(msg) = tap_frame_rx.try_recv() {
                let len = (msg.len() as u32).to_be_bytes();
                writer.write_all(&len).await?;
                writer.write_all(&msg).await?;
            }
            while let Ok(response) = response_rx.try_recv() {
                let len = (response.len() as u32).to_be_bytes();
                writer.write_all(&len).await?;
                writer.write_all(&response).await?;
            }

            // Flush all accumulated writes as a single syscall
            writer.flush().await?;
        }
    });

    // Task 3: IPC reader → TAP writer (reads length-prefixed messages)
    let h3 = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;

        let mut len_buf = [0u8; 4];
        let mut msg_buf = vec![0u8; max_frame_size + 16];
        loop {
            // Read length prefix
            if ipc_reader.read_exact(&mut len_buf).await.is_err() {
                debug!("[PROXY] parent closed frame socket, exiting");
                return Ok::<_, io::Error>(());
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len == 0 || msg_len > msg_buf.len() {
                debug!("[PROXY] invalid message length: {}", msg_len);
                continue;
            }

            // Read message body
            if ipc_reader.read_exact(&mut msg_buf[..msg_len]).await.is_err() {
                debug!("[PROXY] parent closed during message read");
                return Ok(());
            }

            match decode_message(&msg_buf[..msg_len]) {
                Ok(Message::Frame(frame)) => {
                    trace!("[PROXY] IPC → TAP: {} bytes", frame.len());
                    tap_writer.write_all(&frame).await?;
                }
                Ok(Message::Control(payload)) => {
                    match decode_control::<ProxyCommand>(&payload) {
                        Ok(cmd) => {
                            let response = handle_proxy_command(cmd, &rt_handle, &iface_name).await;
                            let response_msg = encode_control(&response)
                                .expect("failed to encode ProxyResponse");
                            // Send response via channel to socket writer task
                            let _ = response_tx.send(response_msg).await;
                        }
                        Err(e) => {
                            debug!("[PROXY] failed to decode control message: {}", e);
                        }
                    }
                }
                Err(e) => {
                    debug!("[PROXY] decode error: {}", e);
                }
            }
        }
    });

    // Wait for any task to complete, then return its result
    tokio::select! {
        r = h1 => r.map_err(|e| io::Error::other(e.to_string()))?,
        r = h2 => r.map_err(|e| io::Error::other(e.to_string()))?,
        r = h3 => r.map_err(|e| io::Error::other(e.to_string()))?,
    }
}
