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
//! │  │         smoltcp Stack Thread (blocking)          │   │
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
//! use std::net::Ipv4Addr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to the network namespace of PID 1234
//! // - peer_addr: IP for the TAP interface in the namespace (server side)
//! // - local_addr: IP for the smoltcp stack (client side)
//! let config = TapConfig::new()
//!     .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24)
//!     .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24);
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
pub mod socket;
mod stack;

use crossbeam_channel::{Sender, bounded};
use log::debug;
use smoltcp::phy::FaultInjector;
use socket::{TcpListener, TcpStream, UdpSocket};
use stack::{ProxyDevice, StackCommand, StackConfig};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub use socket::{TcpListener as TunnelTcpListener, TcpStream as TunnelTcpStream, UdpSocket as TunnelUdpSocket};

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
    /// IPv4 address for the TAP interface in the namespace (peer side)
    pub peer_addr: Option<(Ipv4Addr, u8)>,
    /// IPv4 address for the smoltcp stack (local/client side)
    pub local_addr: Option<(Ipv4Addr, u8)>,
    /// MAC address for the smoltcp stack (default: auto-generated)
    pub mac: Option<[u8; 6]>,
    /// Packet loss percentage for testing (0-100, default: 0)
    pub packet_loss_percent: u8,
}

impl Default for TapConfig {
    fn default() -> Self {
        Self {
            interface_name: "tap0".to_string(),
            peer_addr: None,
            local_addr: None,
            mac: None,
            packet_loss_percent: 0,
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

    /// Set the IPv4 address for the TAP interface in the namespace.
    /// This is the address that servers in the namespace should listen on.
    pub fn peer_addr(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.peer_addr = Some((addr, prefix_len));
        self
    }

    /// Set the IPv4 address for the smoltcp stack (client side).
    /// This is the source address used when connecting to servers.
    pub fn local_addr(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
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
}

/// A tunnel to a network namespace providing socket access via smoltcp.
///
/// The tunnel is established by:
/// 1. Spawning a TAP proxy process that joins the target namespace
/// 2. Running a smoltcp stack thread that handles protocol processing
///
/// This type is cloneable and can be shared between tasks.
pub struct Tunnel {
    inner: Arc<TunnelInner>,
}

struct TunnelInner {
    /// Channel to send commands to the stack thread
    commands: Sender<StackCommand>,
    /// TAP proxy child process (None when using socket-path mode)
    proxy_child: Mutex<Option<Child>>,
    /// Stack thread handle
    stack_thread: Mutex<Option<JoinHandle<()>>>,
    /// IPC reader thread handle
    ipc_reader_thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for TunnelInner {
    fn drop(&mut self) {
        // Signal stack to shutdown
        let _ = self.commands.send(StackCommand::Shutdown);

        // Wait for stack thread
        if let Ok(mut handle) = self.stack_thread.lock()
            && let Some(h) = handle.take()
        {
            let _ = h.join();
        }

        // Wait for IPC reader thread
        if let Ok(mut handle) = self.ipc_reader_thread.lock()
            && let Some(h) = handle.take()
        {
            let _ = h.join();
        }

        // Clean up proxy process (if we spawned one)
        if let Ok(mut guard) = self.proxy_child.lock()
            && let Some(ref mut child) = *guard
        {
            let _ = child.kill();
            let _ = child.wait();
        }
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
        if proxy_path.exists() {
            return Ok(proxy_path);
        }

        // Also check parent directories for cargo target structure
        if let Some(parent) = exe_dir.parent() {
            let proxy_path = parent.join(PROXY_NAME);
            if proxy_path.exists() {
                return Ok(proxy_path);
            }
        }
    }

    // 2. Check TAP_TUNNEL_PROXY environment variable
    if let Ok(proxy_path) = std::env::var("TAP_TUNNEL_PROXY") {
        let path = std::path::PathBuf::from(&proxy_path);
        if path.exists() {
            return Ok(path);
        }
    }

    // 3. Check CARGO_MANIFEST_DIR for development builds
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let target_debug = std::path::PathBuf::from(&manifest_dir)
            .join("target")
            .join("debug")
            .join(PROXY_NAME);
        if target_debug.exists() {
            return Ok(target_debug);
        }

        let target_release = std::path::PathBuf::from(&manifest_dir)
            .join("target")
            .join("release")
            .join(PROXY_NAME);
        if target_release.exists() {
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
        if path.exists() {
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
fn spawn_proxy(pid: u32, frame_fd: OwnedFd, config: &TapConfig) -> io::Result<Child> {
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

    // Prevent the FD from being closed - proxy now owns it
    std::mem::forget(frame_fd);

    Ok(child)
}

/// Convert an OwnedFd to a UnixStream.
fn fd_to_unix_stream(fd: OwnedFd) -> io::Result<UnixStream> {
    let raw_fd = fd.into_raw_fd();
    let stream = unsafe { UnixStream::from_raw_fd(raw_fd) };
    Ok(stream)
}

impl Tunnel {
    /// Connect to the network namespace of the given PID with default configuration.
    pub async fn connect(pid: u32) -> io::Result<Self> {
        Self::connect_with_config(pid, TapConfig::default()).await
    }

    /// Connect to the network namespace of the given PID with custom configuration.
    ///
    /// This spawns a TAP proxy process and starts a smoltcp stack thread.
    pub async fn connect_with_config(pid: u32, config: TapConfig) -> io::Result<Self> {
        Self::connect_with_config_blocking(pid, config)
    }

    /// Synchronous version of connect_with_config.
    pub fn connect_with_config_blocking(pid: u32, mut config: TapConfig) -> io::Result<Self> {
        // Create socketpair for frame relay (SEQPACKET for message boundaries)
        let (parent_fd, child_fd) = ipc::create_socketpair()?;

        // Spawn the proxy process
        let proxy_child = spawn_proxy(pid, child_fd, &config)?;

        // Use PID-based MAC if not explicitly set
        if config.mac.is_none() {
            let mut mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            mac[5] = (pid & 0xff) as u8;
            config.mac = Some(mac);
        }

        Self::setup_stack_from_fd(parent_fd, config, Some(proxy_child))
    }

    /// Connect to a proxy already listening on the given Unix socket path.
    ///
    /// This is useful when the proxy is running inside a container and the
    /// socket is mounted into the host filesystem. The proxy should be started
    /// with `--socket-path` before calling this method.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tap_tunnel::{TapConfig, Tunnel};
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let config = TapConfig::new()
    ///     .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24)
    ///     .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24);
    /// let tunnel = Tunnel::connect_to("/tmp/tunnel/frame.sock", config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_to(
        socket_path: impl AsRef<Path>,
        config: TapConfig,
    ) -> io::Result<Self> {
        Self::connect_to_blocking(socket_path, config)
    }

    /// Synchronous version of `connect_to`.
    pub fn connect_to_blocking(
        socket_path: impl AsRef<Path>,
        config: TapConfig,
    ) -> io::Result<Self> {
        let socket_path = socket_path.as_ref();

        // Connect to the proxy's listening socket
        let frame_fd = ipc::connect_seqpacket(socket_path)?;
        debug!("connected to proxy at {:?}", socket_path);

        // Set up the stack (shared code with connect_with_config_blocking)
        Self::setup_stack_from_fd(frame_fd, config, None)
    }

    /// Common setup code: given a connected frame FD, set up channels, IPC threads, and stack.
    fn setup_stack_from_fd(
        frame_fd: OwnedFd,
        config: TapConfig,
        proxy_child: Option<Child>,
    ) -> io::Result<Self> {
        // Set up channels for stack communication
        let (cmd_tx, cmd_rx) = bounded::<StackCommand>(256);
        let (frame_tx, frame_rx) = bounded::<Vec<u8>>(256);
        let (frame_to_proxy_tx, frame_to_proxy_rx) = bounded::<Vec<u8>>(256);

        // Convert FD to blocking UnixStream for IPC
        let ipc_stream = fd_to_unix_stream(frame_fd)?;
        ipc_stream.set_nonblocking(false)?;

        // Generate MAC address
        let mac = config.mac.unwrap_or_else(|| {
            // Generate a locally administered unicast MAC
            let mut mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            // Use random byte for uniqueness when no PID available
            mac[5] = (std::process::id() & 0xff) as u8;
            mac
        });

        // Get IP configuration for smoltcp stack (local/client side)
        let (local_ip, local_prefix) = config.local_addr.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "local_addr must be configured")
        })?;

        // Gateway is the peer address (TAP interface in namespace)
        let gateway = config.peer_addr.map(|(ip, _)| ip);

        let stack_config = StackConfig {
            mac,
            ip: local_ip,
            prefix_len: local_prefix,
            gateway,
        };

        // Clone for IPC threads
        let ipc_read_stream = ipc_stream.try_clone()?;
        let ipc_write_stream = ipc_stream;

        // Spawn IPC reader thread (proxy -> stack)
        let ipc_reader_thread = std::thread::spawn(move || {
            debug!("[IPC-RX] reader thread starting");
            let mut buf = [0u8; 1522];
            loop {
                use std::io::Read;
                match (&ipc_read_stream).read(&mut buf) {
                    Ok(0) => {
                        debug!("[IPC-RX] proxy closed connection");
                        break;
                    }
                    Ok(n) => {
                        debug!("[IPC-RX] read {} bytes, sending to stack", n);
                        if frame_tx.send(buf[..n].to_vec()).is_err() {
                            debug!("[IPC-RX] stack channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("[IPC-RX] error: {}", e);
                        break;
                    }
                }
            }
            debug!("[IPC-RX] reader thread exiting");
        });

        // Spawn IPC writer thread (stack -> proxy)
        std::thread::spawn(move || {
            use std::io::Write;
            debug!("[IPC-TX] writer thread starting");
            loop {
                match frame_to_proxy_rx.recv() {
                    Ok(frame) => {
                        debug!("[IPC-TX] sending {} bytes to proxy", frame.len());
                        if let Err(e) = (&ipc_write_stream).write_all(&frame) {
                            debug!("[IPC-TX] write error: {}", e);
                            break;
                        }
                        debug!("[IPC-TX] sent successfully");
                    }
                    Err(_) => {
                        debug!("[IPC-TX] stack channel closed");
                        break;
                    }
                }
            }
            debug!("[IPC-TX] writer thread exiting");
        });

        // Create device for smoltcp (wrap in FaultInjector for packet loss simulation)
        let device = ProxyDevice::new(frame_rx, frame_to_proxy_tx, 1514);
        let mut device = FaultInjector::new(device, random_seed());
        device.set_drop_chance(config.packet_loss_percent);

        // Spawn stack thread
        let stack_thread = std::thread::spawn(move || {
            stack::run_stack(&mut device, stack_config, cmd_rx);
        });

        Ok(Tunnel {
            inner: Arc::new(TunnelInner {
                commands: cmd_tx,
                proxy_child: Mutex::new(proxy_child),
                stack_thread: Mutex::new(Some(stack_thread)),
                ipc_reader_thread: Mutex::new(Some(ipc_reader_thread)),
            }),
        })
    }

    /// Create a TCP connection to the given address.
    pub async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::TcpConnect { addr, response: tx })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let handle = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        Ok(TcpStream::from_handle(handle, self.inner.commands.clone()))
    }

    /// Create a TCP listener bound to the given address.
    ///
    /// The listener will accept incoming connections from the network namespace.
    /// Use `accept()` to accept connections.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tap_tunnel::{TapConfig, Tunnel};
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = TapConfig::new()
    ///     .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24)
    ///     .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24);
    /// let tunnel = Tunnel::connect_with_config(1234, config).await?;
    ///
    /// // Listen on the smoltcp stack's address
    /// let listener = tunnel.tcp_listen("10.0.0.2:8080".parse()?).await?;
    ///
    /// // Accept connections from the namespace
    /// let (stream, peer_addr) = listener.accept().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn tcp_listen(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        self.tcp_listen_with_backlog(addr, 16).await
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
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let (handle, local_addr) = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

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
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let handle = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        Ok(UdpSocket::from_handle(handle, self.inner.commands.clone()))
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
