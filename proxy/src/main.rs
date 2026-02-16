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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

mod ipc;
mod namespace;
mod route;
mod tap;

use ipc::{accept_seqpacket, create_seqpacket_listener};
use namespace::join_namespace;
use tap::{configure_interface, create_tap};
use tap_tunnel::TapConfig;
use tap_tunnel::protocol::{
    ClientHello, Message, ProxyCommand, ProxyConfig, ProxyResponse, decode_control, decode_message,
    encode_control, encode_frame,
};

/// Maximum Ethernet frame size (MTU 1500 + Ethernet header + some margin)
const MAX_FRAME_SIZE: usize = 1522;

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
        .packet_loss_percent(args.packet_loss);

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

    // Configure IP (if specified), bring up, and get MAC address
    let tap_mac = configure_interface(&config.interface_name, config.peer_addr)?;
    if let Some((ip, prefix_len)) = config.peer_addr {
        debug!("configured IP: {}/{}", ip, prefix_len);
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
    let listener = create_seqpacket_listener(socket_path)?;
    debug!("listening for connection on {:?}", socket_path);

    let frame_fd = accept_seqpacket(&listener)?;
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
fn perform_handshake(fd: &OwnedFd, config: &TapConfig, tap_mac: [u8; 6]) -> io::Result<()> {
    let raw_fd = fd.as_raw_fd();

    // Receive ClientHello (may be empty)
    let mut buf = [0u8; 1024];
    let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "client closed connection during handshake",
        ));
    }

    let msg = decode_message(&buf[..n as usize])?;
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

    // Send ProxyConfig with proxy identity
    let proxy_config = ProxyConfig {
        tap_ip,
        tap_mac,
        prefix_len,
    };
    let config_msg = encode_control(&proxy_config)?;
    let written = unsafe {
        libc::write(
            raw_fd,
            config_msg.as_ptr() as *const libc::c_void,
            config_msg.len(),
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
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

    // Wrap SEQPACKET socket in async wrapper
    let mut frame_socket = AsyncFdIo::new(frame_fd)?;

    // Send gratuitous ARP to pre-fill peer's ARP cache (IPv4 only)
    // IPv6 uses NDP (Neighbor Discovery Protocol) instead of ARP
    if let Some((IpAddr::V4(ipv4), _)) = config.peer_addr {
        let broadcast_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let arp_frame = build_gratuitous_arp(tap_mac, ipv4, broadcast_mac);
        let msg = encode_frame(&arp_frame);
        frame_socket.write_all(&msg).await?;
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

    // Wrap TAP in async wrapper
    let tap = AsyncFdIo::new(tap_fd)?;

    // Run frame relay loop with protocol support
    run_frame_relay(tap, frame_socket, &rt_handle, &config.interface_name).await
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
                ProxyResponse { id, error: None }
            }
            Err(e) => {
                error!(
                    "[PROXY] failed to add route {}/{}: {}",
                    destination, prefix_len, e
                );
                ProxyResponse {
                    id,
                    error: Some(e.to_string()),
                }
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
                ProxyResponse { id, error: None }
            }
            Err(e) => {
                error!(
                    "[PROXY] failed to remove route {}/{}: {}",
                    destination, prefix_len, e
                );
                ProxyResponse {
                    id,
                    error: Some(e.to_string()),
                }
            }
        },
    }
}

/// Run the frame relay loop - bidirectional Ethernet frame forwarding with protocol.
async fn run_frame_relay(
    mut tap: AsyncFdIo,
    mut frame_socket: AsyncFdIo,
    rt_handle: &rtnetlink::Handle,
    iface_name: &str,
) -> io::Result<()> {
    let mut tap_buf = vec![0u8; MAX_FRAME_SIZE];
    let mut sock_buf = vec![0u8; MAX_FRAME_SIZE + 1]; // Extra byte for type prefix

    debug!("[PROXY] frame relay starting");

    loop {
        tokio::select! {
            // TAP → IPC: Forward Ethernet frame with type prefix
            result = tap.read(&mut tap_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("[PROXY] TAP closed");
                    return Ok(());
                }

                // Encode frame with type prefix
                let msg = encode_frame(&tap_buf[..n]);
                trace!("[PROXY] TAP → IPC: {} bytes (frame: {})", msg.len(), n);
                frame_socket.write_all(&msg).await?;
            }

            // IPC → TAP: Decode message and forward frame
            result = frame_socket.read(&mut sock_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("[PROXY] parent closed frame socket, exiting");
                    return Ok(());
                }

                // Decode message
                match decode_message(&sock_buf[..n]) {
                    Ok(Message::Frame(frame)) => {
                        trace!("[PROXY] IPC → TAP: {} bytes", frame.len());
                        tap.write_all(&frame).await?;
                    }
                    Ok(Message::Control(payload)) => {
                        // Decode as ProxyCommand and handle it
                        match decode_control::<ProxyCommand>(&payload) {
                            Ok(cmd) => {
                                let response = handle_proxy_command(cmd, rt_handle, iface_name).await;
                                let response_msg = encode_control(&response)
                                    .expect("failed to encode ProxyResponse");
                                frame_socket.write_all(&response_msg).await?;
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
        }
    }
}
