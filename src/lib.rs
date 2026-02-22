//! # tap-tunnel
//!
//! A Rust library providing an async tokio API to create TCP/UDP sockets
//! within a network namespace via a userspace TCP/IP stack (smoltcp).
//!
//! This library requires no special capabilities - it leverages the target
//! process's user namespace to gain the necessary permissions.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Client Process                       │
//! │  ┌──────────────────────────────────────────────────┐   │
//! │  │              User Code (async)                   │   │
//! │  │   TcpStream::connect(), stream.read/write()      │   │
//! │  └──────────────────┬───────────────────────────────┘   │
//! │                     │ channels                          │
//! │  ┌──────────────────▼───────────────────────────────┐   │
//! │  │           smoltcp Stack Task (async)             │   │
//! │  │   Interface + Sockets + poll() loop              │   │
//! │  └──────────────────┬───────────────────────────────┘   │
//! │                     │ ProxyDevice (impl Device)         │
//! │  ┌──────────────────▼───────────────────────────────┐   │
//! │  │              IPC (Unix socket)                   │   │
//! │  └──────────────────┬───────────────────────────────┘   │
//! └─────────────────────┼───────────────────────────────────┘
//!                       │ Ethernet frames
//! ┌─────────────────────▼───────────────────────────────────┐
//! │                  TAP Proxy Process                      │
//! │          TAP device ←→ Frame relay ←→ IPC               │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use tap_tunnel::{TapConfig, Tunnel};
//! use std::net::IpAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to the network namespace of PID 1234
//! // - peer_addr: IP for the TAP interface in the namespace (server side)
//! // - local_addr: IP for the smoltcp stack (client side)
//! let config = TapConfig::new()
//!     .peer_addr("10.0.0.1".parse().unwrap(), 24)
//!     .local_addr("10.0.0.2".parse().unwrap(), 24);
//! let tunnel = Tunnel::connect_with_config(1234, config).await?;
//!
//! // Create a TCP connection to a server in the namespace
//! let mut stream = tunnel.tcp_connect("10.0.0.1:8080".parse()?).await?;
//! stream.write_all(b"Hello!").await?;
//!
//! let mut buf = [0u8; 1024];
//! let n = stream.read(&mut buf).await?;
//! # Ok(())
//! # }
//! ```

pub(crate) mod ipc;
pub mod protocol;
pub mod socket;
mod stack;

use log::debug;
use smoltcp::phy::FaultInjector;
use socket::{TcpListener, TcpStream, UdpSocket};
use stack::{ProxyDevice, StackCommand, StackConfig};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, Sender};

/// Counters for diagnosing data path bottlenecks.
///
/// Tracks frames/packets at every point where data can be dropped.
#[derive(Debug, Default)]
pub struct TunnelStats {
    // IPC reader: proxy → stack
    /// Frames received from proxy via IPC
    pub ipc_rx_frames: AtomicU64,
    /// Frames dropped by IPC reader (channel full)
    pub ipc_rx_dropped: AtomicU64,

    // IPC writer: stack → proxy
    /// Frames sent to proxy via IPC
    pub ipc_tx_frames: AtomicU64,
    /// Frames dropped by IPC writer (write error)
    pub ipc_tx_errors: AtomicU64,

    // ProxyDevice (smoltcp device)
    /// Frames received from channel by smoltcp device
    pub device_rx_frames: AtomicU64,
    /// Frames transmitted by smoltcp device
    pub device_tx_frames: AtomicU64,
    /// Frames dropped by smoltcp device (channel full)
    pub device_tx_dropped: AtomicU64,

    // Stack UDP path
    /// UDP packets sent from app to smoltcp (send_slice calls)
    pub udp_tx_packets: AtomicU64,
    /// UDP packets that smoltcp rejected (send_slice error)
    pub udp_tx_failed: AtomicU64,
    /// UDP packets delivered from smoltcp to app (recv_slice calls)
    pub udp_rx_packets: AtomicU64,
    /// UDP packets dropped (app channel full)
    pub udp_rx_dropped: AtomicU64,
}

impl TunnelStats {
    /// Create a new stats instance wrapped in Arc for sharing.
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Get a snapshot of all counters.
    pub fn snapshot(&self) -> TunnelStatsSnapshot {
        TunnelStatsSnapshot {
            ipc_rx_frames: self.ipc_rx_frames.load(Ordering::Relaxed),
            ipc_rx_dropped: self.ipc_rx_dropped.load(Ordering::Relaxed),
            ipc_tx_frames: self.ipc_tx_frames.load(Ordering::Relaxed),
            ipc_tx_errors: self.ipc_tx_errors.load(Ordering::Relaxed),
            device_rx_frames: self.device_rx_frames.load(Ordering::Relaxed),
            device_tx_frames: self.device_tx_frames.load(Ordering::Relaxed),
            device_tx_dropped: self.device_tx_dropped.load(Ordering::Relaxed),
            udp_tx_packets: self.udp_tx_packets.load(Ordering::Relaxed),
            udp_tx_failed: self.udp_tx_failed.load(Ordering::Relaxed),
            udp_rx_packets: self.udp_rx_packets.load(Ordering::Relaxed),
            udp_rx_dropped: self.udp_rx_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of tunnel statistics.
#[derive(Debug, Clone)]
pub struct TunnelStatsSnapshot {
    pub ipc_rx_frames: u64,
    pub ipc_rx_dropped: u64,
    pub ipc_tx_frames: u64,
    pub ipc_tx_errors: u64,
    pub device_rx_frames: u64,
    pub device_tx_frames: u64,
    pub device_tx_dropped: u64,
    pub udp_tx_packets: u64,
    pub udp_tx_failed: u64,
    pub udp_rx_packets: u64,
    pub udp_rx_dropped: u64,
}

impl fmt::Display for TunnelStatsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "IPC:    rx={} rx_drop={} tx={} tx_err={}",
            self.ipc_rx_frames,
            self.ipc_rx_dropped,
            self.ipc_tx_frames,
            self.ipc_tx_errors
        )?;
        writeln!(
            f,
            "Device: rx={} tx={} tx_drop={}",
            self.device_rx_frames,
            self.device_tx_frames,
            self.device_tx_dropped
        )?;
        write!(
            f,
            "UDP:    tx={} tx_fail={} rx={} rx_drop={}",
            self.udp_tx_packets,
            self.udp_tx_failed,
            self.udp_rx_packets,
            self.udp_rx_dropped
        )
    }
}

pub use socket::{
    OwnedReadHalf, OwnedWriteHalf, TcpListener as TunnelTcpListener,
    TcpStream as TunnelTcpStream, UdpSocket as TunnelUdpSocket,
};

/// Capacity of the command channel between async API and stack task.
///
/// This limits how many pending socket operations can be queued.
const COMMAND_CHANNEL_CAPACITY: usize = 256;

/// Capacity of the frame channels between IPC tasks and stack task.
///
/// This limits how many Ethernet frames can be buffered in each direction.
const FRAME_CHANNEL_CAPACITY: usize = 2048;

/// Default IP-level MTU (Maximum Transmission Unit).
const DEFAULT_MTU: u16 = 1500;

/// Ethernet header size in bytes.
const ETHERNET_HEADER_SIZE: usize = 14;

/// Default backlog for TCP listeners.
///
/// This is the number of pending connections that can be queued before
/// new connections are refused.
const DEFAULT_TCP_BACKLOG: usize = 8;

/// Channel sender for stack commands.
pub(crate) type CommandSender = Sender<StackCommand>;

/// IP address with prefix length (e.g., 10.0.0.1/24 or fd00::1/64).
pub type IpWithPrefix = (IpAddr, u8);

/// Configuration for the TAP tunnel.
///
/// The tunnel creates a point-to-point link between the smoltcp stack (client side)
/// and the TAP interface (namespace side):
///
/// ```text
/// Client Process              │  Target Namespace
/// ────────────────────────────┼───────────────────────
/// smoltcp stack               │  TAP interface
/// local_addr (e.g. 10.0.0.2)  │  peer_addr (e.g. 10.0.0.1)
/// ```
#[derive(Clone, Debug)]
pub struct TapConfig {
    /// Name of the TAP interface (default: "tap0")
    pub interface_name: String,
    /// IP address for the TAP interface in the namespace (peer side)
    pub peer_addr: Option<IpWithPrefix>,
    /// IP address for the smoltcp stack (local/client side)
    pub local_addr: Option<IpWithPrefix>,
    /// MAC address for the smoltcp stack (default: auto-generated)
    pub mac: Option<[u8; 6]>,
    /// Packet loss percentage for testing (0-100, default: 0)
    pub packet_loss_percent: u8,
    /// Routes to add on the TAP interface in the namespace.
    ///
    /// Each entry is (destination, prefix_len), e.g. `(10.99.0.0, 24)`.
    /// These are device routes (`ip route add <dest>/<prefix> dev <tap>`)
    /// that allow the namespace kernel to route traffic for cross-subnet
    /// IPs back through the TAP interface.
    pub peer_routes: Vec<(IpAddr, u8)>,
    /// IP-level MTU (Maximum Transmission Unit) in bytes.
    ///
    /// This controls the maximum size of IP packets on the tunnel link.
    /// Standard Ethernet is 1500; set higher for jumbo frames or lower
    /// for constrained environments. Default: 1500.
    pub mtu: u16,
}

impl Default for TapConfig {
    fn default() -> Self {
        Self {
            interface_name: "tap0".to_string(),
            peer_addr: None,
            local_addr: None,
            mac: None,
            packet_loss_percent: 0,
            peer_routes: Vec::new(),
            mtu: DEFAULT_MTU,
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

    /// Set the IP address for the TAP interface in the namespace.
    /// This is the address that servers in the namespace should listen on.
    pub fn peer_addr(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.peer_addr = Some((addr, prefix_len));
        self
    }

    /// Set the IP address for the smoltcp stack (client side).
    /// This is the source address used when connecting to servers.
    pub fn local_addr(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.local_addr = Some((addr, prefix_len));
        self
    }

    /// Set the MAC address for the smoltcp stack.
    pub fn mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Set the packet loss percentage for testing (0-100).
    /// Uses smoltcp's FaultInjector to simulate lossy networks.
    pub fn packet_loss_percent(mut self, percent: u8) -> Self {
        self.packet_loss_percent = percent;
        self
    }

    /// Add a route on the TAP interface in the namespace.
    ///
    /// This creates a device route (`ip route add <dest>/<prefix> dev <tap>`)
    /// so the namespace kernel routes traffic for these IPs through the TAP.
    /// Needed when using `add_local_ip` with IPs outside the TAP subnet.
    pub fn peer_route(mut self, dest: IpAddr, prefix_len: u8) -> Self {
        self.peer_routes.push((dest, prefix_len));
        self
    }

    /// Set the IP-level MTU (Maximum Transmission Unit) in bytes.
    ///
    /// Controls the maximum IP packet size on the tunnel link.
    /// Default is 1500 (standard Ethernet). Use larger values for
    /// jumbo frames or smaller values for constrained environments.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }
}

/// A tunnel to a network namespace providing socket access via smoltcp.
///
/// The tunnel is established by:
/// 1. Spawning a TAP proxy process that joins the target namespace
/// 2. Running a smoltcp stack task that handles protocol processing
///
/// This type is cloneable and can be shared between tasks.
pub struct Tunnel {
    inner: Arc<TunnelInner>,
}

/// Pending proxy response senders, keyed by request ID.
type PendingProxyResponses = Arc<
    Mutex<HashMap<u64, tokio::sync::oneshot::Sender<protocol::ProxyResponse>>>,
>;

struct TunnelInner {
    /// Channel to send commands to the stack task
    commands: CommandSender,
    /// Channel to send control messages to the proxy via IPC
    control_tx: Sender<Vec<u8>>,
    /// TAP proxy child process (None when using socket-path mode)
    proxy_child: Mutex<Option<Child>>,
    /// Gateway info from proxy: (tap_ip, tap_mac)
    gateway: (IpAddr, [u8; 6]),
    /// Local IP (first IP added to the interface)
    local_addr: IpWithPrefix,
    /// Whether close() has been called
    closed: Arc<AtomicBool>,
    /// Atomic counter for proxy command request IDs
    next_request_id: AtomicU64,
    /// Map of pending proxy command responses
    pending_proxy_responses: PendingProxyResponses,
    /// Data path statistics
    stats: Arc<TunnelStats>,
    /// JoinHandles for IPC reader, IPC writer, and stack tasks (aborted on close)
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl TunnelInner {
    /// Kill the proxy child process and abort IPC/stack tasks.
    ///
    /// Idempotent — the `closed` flag ensures cleanup happens at most once.
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut guard) = self.proxy_child.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
            *guard = None;
        }
        // Abort IPC reader, IPC writer, and stack tasks to release socket FDs
        if let Ok(mut handles) = self.task_handles.lock() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
    }
}

impl Drop for TunnelInner {
    fn drop(&mut self) {
        self.close();
    }
}

/// Find the proxy binary path.
fn find_proxy_binary() -> io::Result<std::path::PathBuf> {
    const PROXY_NAME: &str = "tap-tunnel-proxy";

    // 1. Check same directory as current executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        let proxy_path = exe_dir.join(PROXY_NAME);
        if proxy_path.try_exists()? {
            return Ok(proxy_path);
        }

        // Also check parent directories for cargo target structure
        if let Some(parent) = exe_dir.parent() {
            let proxy_path = parent.join(PROXY_NAME);
            if proxy_path.try_exists()? {
                return Ok(proxy_path);
            }
        }
    }

    // 2. Check TAP_TUNNEL_PROXY environment variable
    if let Ok(proxy_path) = std::env::var("TAP_TUNNEL_PROXY") {
        let path = std::path::PathBuf::from(&proxy_path);
        if path.try_exists()? {
            return Ok(path);
        }
    }

    // 3. Check CARGO_MANIFEST_DIR for development builds
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let target_debug = std::path::PathBuf::from(&manifest_dir)
            .join("target")
            .join("debug")
            .join(PROXY_NAME);
        if target_debug.try_exists()? {
            return Ok(target_debug);
        }

        let target_release = std::path::PathBuf::from(&manifest_dir)
            .join("target")
            .join("release")
            .join(PROXY_NAME);
        if target_release.try_exists()? {
            return Ok(target_release);
        }
    }

    // 4. Check system PATH using `which`
    let output = std::process::Command::new("which").arg(PROXY_NAME).output();

    if let Ok(output) = output
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout);
        let path = std::path::PathBuf::from(path_str.trim());
        if path.try_exists()? {
            return Ok(path);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "proxy binary '{}' not found. Ensure it's in the same directory as the executable, \
             set TAP_TUNNEL_PROXY environment variable, or install it in PATH",
            PROXY_NAME
        ),
    ))
}

/// Remove the CLOEXEC flag from a file descriptor so it's inherited across exec.
fn remove_cloexec(fd: &OwnedFd) -> io::Result<()> {
    let raw_fd = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let new_flags = flags & !libc::FD_CLOEXEC;
    let ret = unsafe { libc::fcntl(raw_fd, libc::F_SETFD, new_flags) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Spawn the proxy binary.
fn spawn_proxy(
    pid: u32,
    frame_fd: OwnedFd,
    config: &TapConfig,
) -> io::Result<Child> {
    remove_cloexec(&frame_fd)?;

    let proxy_path = find_proxy_binary()?;
    let frame_fd_num = frame_fd.as_raw_fd();

    let mut cmd = Command::new(&proxy_path);
    cmd.arg("--pid").arg(pid.to_string());
    cmd.arg("--frame-fd").arg(frame_fd_num.to_string());
    cmd.arg("--tap-name").arg(&config.interface_name);

    // Configure the TAP interface with the peer address
    if let Some((ip, prefix)) = config.peer_addr {
        cmd.arg("--tap-addr").arg(format!("{}/{}", ip, prefix));
    }

    cmd.arg("--mtu").arg(config.mtu.to_string());

    // Pass initial routes for the TAP interface
    for (dest, prefix) in &config.peer_routes {
        cmd.arg("--tap-route").arg(format!("{}/{}", dest, prefix));
    }

    let child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "failed to spawn proxy binary '{}': {}",
                proxy_path.display(),
                e
            ),
        )
    })?;

    // Close the child's end of the socketpair in the parent process.
    // The proxy process has inherited its own copy of this FD.
    drop(frame_fd);

    Ok(child)
}

/// Convert an OwnedFd to a UnixStream.
fn fd_to_unix_stream(fd: OwnedFd) -> io::Result<UnixStream> {
    let raw_fd = fd.into_raw_fd();
    let stream = unsafe { UnixStream::from_raw_fd(raw_fd) };
    Ok(stream)
}

/// Read stderr from a child process (best-effort, for error reporting).
fn read_child_stderr(child: &mut Child) -> String {
    use std::io::Read;
    child
        .stderr
        .take()
        .and_then(|mut stderr| {
            let mut s = String::new();
            stderr.read_to_string(&mut s).ok().map(|_| s)
        })
        .unwrap_or_default()
        .trim()
        .to_string()
}

impl Tunnel {
    /// Connect to the network namespace of the given PID with default configuration.
    pub async fn connect(pid: u32) -> io::Result<Self> {
        Self::connect_with_config(pid, TapConfig::default()).await
    }

    /// Connect to the network namespace of the given PID with custom configuration.
    ///
    /// This spawns a TAP proxy process and starts a smoltcp stack task.
    pub async fn connect_with_config(
        pid: u32,
        config: TapConfig,
    ) -> io::Result<Self> {
        Self::connect_with_config_blocking(pid, config)
    }

    /// Synchronous version of connect_with_config.
    pub fn connect_with_config_blocking(
        pid: u32,
        mut config: TapConfig,
    ) -> io::Result<Self> {
        use protocol::{
            ClientHello, Message, ProxyConfig, decode_control, decode_message,
            default_client_ip, encode_control, write_framed_sync,
        };
        use std::io::Read;

        // Create socketpair for frame relay (STREAM with length-prefix framing)
        let (parent_fd, child_fd) = ipc::create_socketpair()?;

        // Spawn the proxy process
        let mut proxy_child = spawn_proxy(pid, child_fd, &config)?;

        // Convert to UnixStream for handshake
        let mut stream = fd_to_unix_stream(parent_fd)?;

        // Send ClientHello with length-prefix framing
        let hello = ClientHello::default();
        let hello_msg = encode_control(&hello)?;
        write_framed_sync(&mut stream, &hello_msg)?;
        debug!("sent ClientHello: {:?}", hello);

        // Receive ProxyConfig with timeout and child-exit monitoring (length-prefix framed)
        stream.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(5);

        // Read the 4-byte length prefix with timeout/retry
        let mut len_buf = [0u8; 4];
        let mut len_offset = 0;
        loop {
            match stream.read(&mut len_buf[len_offset..]) {
                Ok(0) => {
                    let stderr = read_child_stderr(&mut proxy_child);
                    let msg = if stderr.is_empty() {
                        "proxy closed connection during handshake".to_string()
                    } else {
                        format!(
                            "proxy closed connection during handshake: {}",
                            stderr
                        )
                    };
                    return Err(unexpected_eof(&msg));
                }
                Ok(n) => {
                    len_offset += n;
                    if len_offset >= 4 {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if std::time::Instant::now() > deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "timed out waiting for proxy handshake",
                        ));
                    }
                    if let Some(status) = proxy_child.try_wait()? {
                        let stderr = read_child_stderr(&mut proxy_child);
                        let msg = if stderr.is_empty() {
                            format!("proxy exited with {status}")
                        } else {
                            format!("proxy exited with {status}: {stderr}")
                        };
                        return Err(io::Error::other(msg));
                    }
                }
                Err(e) => return Err(e),
            }
        }

        // Read the message body (blocking is fine now, we know data is coming)
        stream.set_read_timeout(None)?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        std::io::Read::read_exact(&mut stream, &mut buf)?;

        let msg = decode_message(&buf)?;
        let proxy_config: ProxyConfig = match msg {
            Message::Control(payload) => decode_control(&payload)?,
            Message::Frame(_) => {
                return Err(invalid_data("expected ProxyConfig, got frame"));
            }
        };
        debug!("received ProxyConfig: {}", proxy_config);

        // Store gateway info
        let gateway = (proxy_config.tap_ip, proxy_config.tap_mac);

        // Client picks its own IP: use configured local_addr or default (tap_ip + 1)
        let client_ip = config
            .local_addr
            .map(|(ip, _)| ip)
            .unwrap_or_else(|| default_client_ip(proxy_config.tap_ip));

        // Update config with proxy info and client-picked IP.
        // Use the MTU reported by the proxy (the TAP device's actual MTU).
        config = config
            .peer_addr(proxy_config.tap_ip, proxy_config.prefix_len)
            .local_addr(client_ip, proxy_config.prefix_len)
            .mtu(proxy_config.mtu);

        // Use PID-based MAC if not explicitly set
        if config.mac.is_none() {
            let mut mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            mac[5] = (pid & 0xff) as u8;
            config.mac = Some(mac);
        }

        Self::setup_stack_from_fd(stream, config, Some(proxy_child), gateway)
    }

    /// Connect to a proxy already listening on the given Unix socket path.
    ///
    /// This performs a handshake with the proxy to receive its identity
    /// (TAP IP, MAC, prefix). The client then picks its own IP from the subnet.
    /// If `local_ip` is provided, that IP will be used; otherwise a default
    /// (tap_ip + 1) is used.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tap_tunnel::Tunnel;
    /// use std::net::IpAddr;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// // Use default IP (tap_ip + 1)
    /// let tunnel = Tunnel::connect_to("/tmp/tunnel.sock", None).await?;
    ///
    /// // Use specific IP
    /// let tunnel = Tunnel::connect_to(
    ///     "/tmp/tunnel.sock",
    ///     Some("10.0.0.5".parse().unwrap()),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_to(
        socket_path: impl AsRef<Path>,
        local_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        Self::connect_to_blocking(socket_path, local_ip)
    }

    /// Synchronous version of `connect_to`.
    pub fn connect_to_blocking(
        socket_path: impl AsRef<Path>,
        local_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        use protocol::{
            ClientHello, Message, ProxyConfig, decode_control, decode_message,
            default_client_ip, encode_control, read_framed_sync,
            write_framed_sync,
        };

        let socket_path = socket_path.as_ref();

        // Connect to the proxy's listening socket
        let frame_fd = ipc::connect_stream(socket_path)?;
        debug!("connected to proxy at {:?}", socket_path);

        // Convert to UnixStream for handshake
        let mut stream = fd_to_unix_stream(frame_fd)?;

        // Send ClientHello with length-prefix framing
        let hello = ClientHello::default();
        let hello_msg = encode_control(&hello)?;
        write_framed_sync(&mut stream, &hello_msg)?;
        debug!("sent ClientHello: {:?}", hello);

        // Receive ProxyConfig with length-prefix framing
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut buf = vec![0u8; 1024];
        let n = read_framed_sync(&mut stream, &mut buf)?;
        stream.set_read_timeout(None)?;

        let msg = decode_message(&buf[..n])?;
        let proxy_config: ProxyConfig = match msg {
            Message::Control(payload) => decode_control(&payload)?,
            Message::Frame(_) => {
                return Err(invalid_data("expected ProxyConfig, got frame"));
            }
        };
        debug!("received ProxyConfig: {:?}", proxy_config);

        // Store gateway info
        let gateway = (proxy_config.tap_ip, proxy_config.tap_mac);

        // Client picks its own IP: use provided local_ip or default (tap_ip + 1)
        let client_ip =
            local_ip.unwrap_or_else(|| default_client_ip(proxy_config.tap_ip));

        // Build TapConfig from received config, using the proxy's reported MTU
        let config = TapConfig::new()
            .peer_addr(proxy_config.tap_ip, proxy_config.prefix_len)
            .local_addr(client_ip, proxy_config.prefix_len)
            .mtu(proxy_config.mtu);

        // Set up the stack with protocol-aware IPC
        Self::setup_stack_from_fd(stream, config, None, gateway)
    }

    /// Common setup code: given a connected frame FD, set up channels, IPC tasks, and stack.
    ///
    /// Messages are prefixed with a type byte (0x00=control, 0x01=frame).
    fn setup_stack_from_fd(
        frame_stream: UnixStream,
        config: TapConfig,
        proxy_child: Option<Child>,
        gateway: (IpAddr, [u8; 6]),
    ) -> io::Result<Self> {
        // Set up channels for stack communication
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_CHANNEL_CAPACITY);
        let (frame_to_proxy_tx, mut frame_to_proxy_rx) =
            mpsc::channel::<Vec<u8>>(FRAME_CHANNEL_CAPACITY);

        // Control channel for sending proxy commands (route add/remove)
        let (control_tx, mut control_rx) = mpsc::channel::<Vec<u8>>(32);

        // Data path statistics
        let stats = TunnelStats::new_shared();
        let stats_ipc_reader = Arc::clone(&stats);
        let stats_ipc_writer = Arc::clone(&stats);
        let stats_stack = Arc::clone(&stats);

        // Pending proxy responses (shared between API methods and IPC reader)
        let pending_proxy_responses: PendingProxyResponses =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_for_reader = Arc::clone(&pending_proxy_responses);

        // Generate MAC address
        let mac = config.mac.unwrap_or_else(|| {
            let mut mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            mac[5] = (std::process::id() & 0xff) as u8;
            mac
        });

        // Get IP configuration for smoltcp stack (local/client side)
        let (local_ip, local_prefix) = config
            .local_addr
            .ok_or_else(|| invalid_input("local_addr must be configured"))?;

        // Gateway IP is the peer address (TAP interface in namespace)
        let (gateway_ip, _) = config
            .peer_addr
            .ok_or_else(|| invalid_input("peer_addr missing"))?;

        let stack_config = StackConfig {
            mac,
            ip: local_ip,
            prefix_len: local_prefix,
            gateway: gateway_ip,
        };

        // Use STREAM socket with into_split() for truly concurrent read/write.
        frame_stream.set_nonblocking(true)?;
        let ipc_stream = tokio::net::UnixStream::from_std(frame_stream)?;
        let (ipc_read_half, ipc_write_half) = ipc_stream.into_split();

        // Wrap in BufReader/BufWriter for batched I/O (reduces syscalls dramatically)
        const LIB_IPC_BUFFER_SIZE: usize = 256 * 1024;

        // Shared flag: set by IPC tasks when proxy connection is lost
        let ipc_dead = Arc::new(AtomicBool::new(false));
        let ipc_dead_reader = Arc::clone(&ipc_dead);
        let ipc_dead_writer = Arc::clone(&ipc_dead);

        // Closed flag
        let closed = Arc::new(AtomicBool::new(false));
        // let closed_reader = Arc::clone(&closed);
        // let closed_writer = Arc::clone(&closed);

        // Spawn IPC reader task (proxy -> stack) with length-prefix framing
        let ipc_reader_handle = tokio::spawn(async move {
            use protocol::{
                Message, ProxyResponse, decode_control, decode_message,
            };
            use tokio::io::AsyncReadExt;

            debug!("[IPC-RX] reader task starting (stream mode)");
            let mut reader = tokio::io::BufReader::with_capacity(
                LIB_IPC_BUFFER_SIZE,
                ipc_read_half,
            );
            let mut len_buf = [0u8; 4];
            let mut msg_buf = vec![0u8; 2048];

            // while !closed_reader.load(Ordering::Relaxed) {
            loop {
                // Read length prefix
                match reader.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        debug!("[IPC-RX] proxy closed connection");
                        ipc_dead_reader.store(true, Ordering::Relaxed);
                        break;
                    }
                    Err(e) => {
                        debug!("[IPC-RX] read error: {}", e);
                        ipc_dead_reader.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                if msg_len > msg_buf.len() {
                    msg_buf.resize(msg_len, 0);
                }

                // Read message body
                if let Err(e) = reader.read_exact(&mut msg_buf[..msg_len]).await
                {
                    debug!("[IPC-RX] read error during body: {}", e);
                    ipc_dead_reader.store(true, Ordering::Relaxed);
                    break;
                }

                match decode_message(&msg_buf[..msg_len]) {
                    Ok(Message::Frame(frame)) => {
                        stats_ipc_reader
                            .ipc_rx_frames
                            .fetch_add(1, Ordering::Relaxed);
                        match frame_tx.try_send(frame) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                stats_ipc_reader
                                    .ipc_rx_dropped
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                break;
                            }
                        }
                    }
                    Ok(Message::Control(payload)) => {
                        if let Ok(resp) =
                            decode_control::<ProxyResponse>(&payload)
                        {
                            let sender = {
                                pending_for_reader
                                    .lock()
                                    .ok()
                                    .and_then(|mut map| map.remove(&resp.id()))
                            };
                            if let Some(tx) = sender {
                                let _ = tx.send(resp);
                            }
                        }
                    }
                    Err(_) => {} // Ignore decode errors
                }
            }
            debug!("[IPC-RX] reader task exit");
        });

        // Spawn IPC writer task (stack -> proxy) with batched length-prefix framing
        let ipc_writer_handle = tokio::spawn(async move {
            use protocol::encode_frame;
            use tokio::io::AsyncWriteExt;

            debug!("[IPC-TX] writer task starting (stream mode)");
            let mut writer = tokio::io::BufWriter::with_capacity(
                LIB_IPC_BUFFER_SIZE,
                ipc_write_half,
            );
            loop {
                // Wait for the first frame or control message
                tokio::select! {
                    frame = frame_to_proxy_rx.recv() => {
                        match frame {
                            Some(frame) => {
                                let msg = encode_frame(&frame);
                                let len = (msg.len() as u32).to_be_bytes();
                                if writer.write_all(&len).await.is_err()
                                    || writer.write_all(&msg).await.is_err()
                                {
                                    debug!("[IPC-TX] write error, proxy connection lost");
                                    stats_ipc_writer.ipc_tx_errors.fetch_add(1, Ordering::Relaxed);
                                    ipc_dead_writer.store(true, Ordering::Relaxed);
                                    break;
                                }
                                stats_ipc_writer.ipc_tx_frames.fetch_add(1, Ordering::Relaxed);
                            }
                            None => break,
                        }
                    }
                    ctrl = control_rx.recv() => {
                        match ctrl {
                            Some(msg) => {
                                let len = (msg.len() as u32).to_be_bytes();
                                if writer.write_all(&len).await.is_err()
                                    || writer.write_all(&msg).await.is_err()
                                {
                                    debug!("[IPC-TX] write error on control, proxy connection lost");
                                    ipc_dead_writer.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }

                // Drain additional buffered frames (non-blocking) for batching
                while let Ok(frame) = frame_to_proxy_rx.try_recv() {
                    let msg = encode_frame(&frame);
                    let len = (msg.len() as u32).to_be_bytes();
                    if writer.write_all(&len).await.is_err()
                        || writer.write_all(&msg).await.is_err()
                    {
                        stats_ipc_writer
                            .ipc_tx_errors
                            .fetch_add(1, Ordering::Relaxed);
                        ipc_dead_writer.store(true, Ordering::Relaxed);
                        break;
                    }
                    stats_ipc_writer
                        .ipc_tx_frames
                        .fetch_add(1, Ordering::Relaxed);
                }
                while let Ok(msg) = control_rx.try_recv() {
                    let len = (msg.len() as u32).to_be_bytes();
                    if writer.write_all(&len).await.is_err()
                        || writer.write_all(&msg).await.is_err()
                    {
                        ipc_dead_writer.store(true, Ordering::Relaxed);
                        break;
                    }
                }

                // Flush all accumulated writes as a batch
                if writer.flush().await.is_err() {
                    debug!("[IPC-TX] flush error, proxy connection lost");
                    ipc_dead_writer.store(true, Ordering::Relaxed);
                    break;
                }
            }
            debug!("[IPC-TX] writer task exit");
        });

        // Create device for smoltcp
        let ethernet_frame_size = config.mtu as usize + ETHERNET_HEADER_SIZE;
        let stats_device = Arc::clone(&stats);
        let device = ProxyDevice::new(
            frame_rx,
            frame_to_proxy_tx,
            ethernet_frame_size,
            stats_device,
        );

        // Spawn stack task (will exit when command channel disconnects or IPC dies).
        // Only wrap with FaultInjector when packet loss is configured, because
        // FaultInjector caps MTU at 1536 (smoltcp internal limit).
        let packet_loss = config.packet_loss_percent;
        let stack_handle = if packet_loss > 0 {
            let mut device = FaultInjector::new(device, random_seed());
            device.set_drop_chance(packet_loss);
            tokio::spawn(async move {
                stack::run_stack(
                    &mut device,
                    stack_config,
                    cmd_rx,
                    ipc_dead,
                    stats_stack,
                )
                .await;
            })
        } else {
            let mut device = device;
            tokio::spawn(async move {
                stack::run_stack(
                    &mut device,
                    stack_config,
                    cmd_rx,
                    ipc_dead,
                    stats_stack,
                )
                .await;
            })
        };

        Ok(Tunnel {
            inner: Arc::new(TunnelInner {
                commands: cmd_tx,
                control_tx,
                proxy_child: Mutex::new(proxy_child),
                gateway,
                local_addr: (local_ip, local_prefix),
                closed,
                next_request_id: AtomicU64::new(1),
                pending_proxy_responses,
                stats,
                task_handles: Mutex::new(vec![
                    ipc_reader_handle,
                    ipc_writer_handle,
                    stack_handle,
                ]),
            }),
        })
    }

    /// Create a TCP connection to the given address.
    ///
    /// Uses the default local IP (the first IP configured on the stack).
    pub async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::TcpConnect {
                local_ip: None,
                addr,
                response: tx,
            })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        let (handle, local_addr, peer_addr, channels) =
            rx.await.map_err(|_| broken_pipe("stack task gone"))??;

        Ok(TcpStream::from_channels(
            handle,
            self.inner.commands.clone(),
            local_addr,
            peer_addr,
            channels,
        ))
    }

    /// Create a TCP listener bound to the given address.
    ///
    /// The listener will accept incoming connections from the network namespace.
    /// Use `accept()` to accept connections.
    pub async fn tcp_listen(
        &self,
        addr: SocketAddr,
    ) -> io::Result<TcpListener> {
        self.tcp_listen_with_backlog(addr, DEFAULT_TCP_BACKLOG)
            .await
    }

    /// Create a TCP listener with a specified backlog.
    ///
    /// The backlog determines how many pending connections can be queued
    /// before new connections are refused.
    pub async fn tcp_listen_with_backlog(
        &self,
        addr: SocketAddr,
        backlog: usize,
    ) -> io::Result<TcpListener> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::TcpListen {
                addr,
                backlog,
                response: tx,
            })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        let (handle, local_addr) =
            rx.await.map_err(|_| broken_pipe("stack task gone"))??;

        Ok(TcpListener::from_handle(
            handle,
            local_addr,
            self.inner.commands.clone(),
        ))
    }

    /// Bind a UDP socket to the given address.
    pub async fn udp_bind(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::UdpBind { addr, response: tx })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        let (handle, local_addr, channels) =
            rx.await.map_err(|_| broken_pipe("stack task gone"))??;

        Ok(UdpSocket::from_channels(
            handle,
            self.inner.commands.clone(),
            local_addr,
            channels,
        ))
    }

    /// Create a TCP connection from a specific local IP address.
    ///
    /// Use this when you have multiple IPs configured on the tunnel
    /// and want to bind to a specific one for the outgoing connection.
    pub async fn tcp_connect_from(
        &self,
        local_ip: IpAddr,
        remote_addr: SocketAddr,
    ) -> io::Result<TcpStream> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::TcpConnect {
                local_ip: Some(local_ip),
                addr: remote_addr,
                response: tx,
            })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        let (handle, local_addr, peer_addr, channels) =
            rx.await.map_err(|_| broken_pipe("stack task gone"))??;

        Ok(TcpStream::from_channels(
            handle,
            self.inner.commands.clone(),
            local_addr,
            peer_addr,
            channels,
        ))
    }

    /// Add a local IP address to the smoltcp interface.
    ///
    /// This allows the tunnel to send/receive traffic using this IP.
    /// The prefix length determines the subnet mask for routing.
    pub async fn add_local_ip(
        &self,
        ip: IpAddr,
        prefix_len: u8,
    ) -> io::Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::AddIp {
                ip,
                prefix_len,
                response: tx,
            })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        rx.await.map_err(|_| broken_pipe("stack task gone"))?
    }

    /// Remove a local IP address from the smoltcp interface.
    pub async fn remove_local_ip(&self, ip: IpAddr) -> io::Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::RemoveIp { ip, response: tx })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        rx.await.map_err(|_| broken_pipe("stack task gone"))?
    }

    /// Get current local IP addresses on the smoltcp interface.
    ///
    /// Returns a list of (IP, prefix_len) pairs.
    pub async fn local_ips(&self) -> io::Result<Vec<IpWithPrefix>> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::GetIps { response: tx })
            .await
            .map_err(|_| broken_pipe("stack task gone"))?;

        rx.await.map_err(|_| broken_pipe("stack task gone"))
    }

    /// Add a route on the TAP interface in the namespace.
    ///
    /// This tells the namespace kernel to route traffic for the given
    /// destination through the TAP device, enabling cross-subnet communication.
    /// Use this together with `add_local_ip` when the local IP is outside
    /// the TAP interface's subnet.
    pub async fn add_peer_route(
        &self,
        dest: IpAddr,
        prefix_len: u8,
    ) -> io::Result<()> {
        let resp = self
            .send_proxy_command(protocol::ProxyCommand::AddRoute {
                id: 0,
                destination: dest,
                prefix_len,
            })
            .await?;
        match resp {
            protocol::ProxyResponse::Ok { .. } => Ok(()),
            protocol::ProxyResponse::Error { error, .. } => {
                Err(io::Error::other(error))
            }
            _ => Err(io::Error::other("unexpected response")),
        }
    }

    /// Remove a route from the TAP interface in the namespace.
    pub async fn remove_peer_route(
        &self,
        dest: IpAddr,
        prefix_len: u8,
    ) -> io::Result<()> {
        let resp = self
            .send_proxy_command(protocol::ProxyCommand::RemoveRoute {
                id: 0,
                destination: dest,
                prefix_len,
            })
            .await?;
        match resp {
            protocol::ProxyResponse::Ok { .. } => Ok(()),
            protocol::ProxyResponse::Error { error, .. } => {
                Err(io::Error::other(error))
            }
            _ => Err(io::Error::other("unexpected response")),
        }
    }

    /// Get kernel interface statistics from inside the namespace.
    ///
    /// Returns a map of interface name to statistics from /proc/net/dev.
    pub async fn get_iface_stats(
        &self,
    ) -> io::Result<HashMap<String, protocol::InterfaceStats>> {
        let resp = self
            .send_proxy_command(protocol::ProxyCommand::GetIfaceStats { id: 0 })
            .await?;
        match resp {
            protocol::ProxyResponse::IfaceStats { interfaces, .. } => {
                Ok(interfaces)
            }
            protocol::ProxyResponse::Error { error, .. } => {
                Err(io::Error::other(error))
            }
            _ => Err(io::Error::other("unexpected response")),
        }
    }

    /// Send a command to the proxy and wait for the response.
    async fn send_proxy_command(
        &self,
        mut cmd: protocol::ProxyCommand,
    ) -> io::Result<protocol::ProxyResponse> {
        let id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Set the ID on the command
        match &mut cmd {
            protocol::ProxyCommand::AddRoute { id: cid, .. } => *cid = id,
            protocol::ProxyCommand::RemoveRoute { id: cid, .. } => *cid = id,
            protocol::ProxyCommand::GetIfaceStats { id: cid } => *cid = id,
        }

        // Register a oneshot for the response
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut map = self
                .inner
                .pending_proxy_responses
                .lock()
                .map_err(|_| broken_pipe("response map poisoned"))?;
            map.insert(id, tx);
        }

        // Encode and send the control message
        let msg = protocol::encode_control(&cmd)?;
        self.inner
            .control_tx
            .send(msg)
            .await
            .map_err(|_| broken_pipe("IPC writer gone"))?;

        // Wait for response
        rx.await.map_err(|_| broken_pipe("proxy response lost"))
    }

    /// Explicitly close the tunnel, killing the proxy child process.
    ///
    /// This is idempotent — calling it multiple times is safe.
    /// After closing, tunnel sockets will fail as the proxy is gone.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Local IP (first IP added to the interface)
    pub fn local_addr(&self) -> IpWithPrefix {
        self.inner.local_addr
    }

    /// Get the proxy's gateway info (TAP IP and MAC address).
    pub fn gateway(&self) -> (IpAddr, [u8; 6]) {
        self.inner.gateway
    }

    /// Get a snapshot of data path statistics.
    pub fn stats(&self) -> TunnelStatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// Get a reference to the shared stats for direct access.
    pub fn stats_shared(&self) -> &Arc<TunnelStats> {
        &self.inner.stats
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Tunnel {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn random_seed() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

fn broken_pipe(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, msg)
}

fn invalid_input(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn unexpected_eof(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}
