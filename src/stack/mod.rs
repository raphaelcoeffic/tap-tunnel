//! smoltcp network stack running as a tokio task.
//!
//! This module provides a TCP/UDP socket API backed by smoltcp, which handles
//! all protocol processing (Ethernet, ARP, NDP, IP, TCP, UDP) in userspace.

mod device;

pub use device::ProxyDevice;

use crate::IpWithPrefix;
use log::{debug, trace, warn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::Device;
use smoltcp::socket::tcp::{self, State as TcpState};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::oneshot;

/// Maximum number of ingress packets to process per poll iteration.
///
/// This bounds the work done in each async task iteration to avoid blocking
/// the tokio runtime when many packets are queued. After processing this many
/// packets, the task yields to allow other tasks to run.
const INGRESS_BATCH_SIZE: usize = 16;

/// Size of TCP socket send and receive buffers in bytes.
///
/// This is the maximum amount of data that can be buffered for a single TCP
/// connection in each direction. 64KB matches the maximum TCP window size
/// without window scaling.
const TCP_SOCKET_BUFFER_SIZE: usize = 65535;

/// Size of UDP socket packet buffer in bytes.
///
/// This is the total buffer space for UDP packets. With standard MTU, this
/// allows buffering many packets.
const UDP_PACKET_BUFFER_SIZE: usize = 65535;

/// Number of UDP packet metadata slots.
///
/// This limits how many UDP packets can be queued at once. Each slot holds
/// metadata (source/dest addresses) for one packet.
const UDP_PACKET_METADATA_SLOTS: usize = 128;

/// Starting port number for ephemeral port allocation.
///
/// Per IANA, the dynamic/ephemeral port range is 49152-65535.
const EPHEMERAL_PORT_START: u16 = 49152;

/// Maximum poll interval in milliseconds.
///
/// The stack will poll at least this often, even if smoltcp doesn't request
/// earlier polling. This ensures responsiveness to incoming frames.
const MAX_POLL_INTERVAL_MS: u64 = 1;

/// Capacity of per-TCP-socket data channels.
///
/// This limits how many data chunks can be buffered between the socket API
/// and the stack task. Each chunk is typically up to TCP_SOCKET_BUFFER_SIZE.
const TCP_CHANNEL_CAPACITY: usize = 8;

/// Capacity of per-UDP-socket data channels.
///
/// This limits how many packets can be buffered between the socket API
/// and the stack task.
const UDP_CHANNEL_CAPACITY: usize = 32;

type ResponseSender<R> = oneshot::Sender<io::Result<R>>;

/// Channels for TCP socket data flow.
///
/// These channels provide a dedicated path for data between the async socket
/// API and the stack task, avoiding per-operation commands.
pub struct TcpChannels {
    /// Write path: socket → stack (data to send)
    pub write_tx: mpsc::Sender<Vec<u8>>,
    /// Read path: stack → socket (received data)
    pub read_rx: mpsc::Receiver<Vec<u8>>,
    /// Notify stack when data is written
    pub write_notify: Arc<Notify>,
}

/// Internal state held by stack task for each TCP socket.
struct TcpSocketState {
    write_rx: mpsc::Receiver<Vec<u8>>,
    read_tx: mpsc::Sender<Vec<u8>>,
    pending_write: Option<Vec<u8>>,
}

/// Channels for UDP socket data flow.
///
/// Similar to TcpChannels but includes destination/source address with each packet.
pub struct UdpChannels {
    /// Write path: socket → stack (data + destination)
    pub write_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// Read path: stack → socket (data + source)
    pub read_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    /// Notify stack when data is written
    pub write_notify: Arc<Notify>,
}

/// Internal state held by stack task for each UDP socket.
struct UdpSocketState {
    write_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    read_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

/// Create TCP channels for a new socket.
fn create_tcp_channels(write_notify: Arc<Notify>) -> (TcpChannels, TcpSocketState) {
    let (write_tx, write_rx) = mpsc::channel(TCP_CHANNEL_CAPACITY);
    let (read_tx, read_rx) = mpsc::channel(TCP_CHANNEL_CAPACITY);

    let channels = TcpChannels {
        write_tx,
        read_rx,
        write_notify,
    };

    let state = TcpSocketState {
        write_rx,
        read_tx,
        pending_write: None,
    };

    (channels, state)
}

/// Create UDP channels for a new socket.
fn create_udp_channels(write_notify: Arc<Notify>) -> (UdpChannels, UdpSocketState) {
    let (write_tx, write_rx) = mpsc::channel(UDP_CHANNEL_CAPACITY);
    let (read_tx, read_rx) = mpsc::channel(UDP_CHANNEL_CAPACITY);

    let channels = UdpChannels {
        write_tx,
        read_rx,
        write_notify,
    };

    let state = UdpSocketState { write_rx, read_tx };

    (channels, state)
}

/// Map of socket handles to their pending operations.
type PendingOps = HashMap<SocketHandle, PendingOp>;

/// Map of listener handles to their state.
type Listeners = HashMap<SocketHandle, ListenerState>;

/// Commands sent from async socket handles to the stack task.
pub enum StackCommand {
    /// Create a TCP socket and initiate connection.
    /// Returns (handle, local_addr, peer_addr, channels) on success.
    TcpConnect {
        /// Optional local IP to bind the socket to. If None, uses the default (config.ip).
        local_ip: Option<IpAddr>,
        addr: SocketAddr,
        response: ResponseSender<(SocketHandle, SocketAddr, SocketAddr, TcpChannels)>,
    },
    /// Create a TCP listener and bind to the given address.
    TcpListen {
        addr: SocketAddr,
        backlog: usize,
        response: ResponseSender<(SocketHandle, SocketAddr)>,
    },
    /// Accept an incoming connection on a TCP listener.
    /// Returns (handle, local_addr, peer_addr, channels) on success.
    TcpAccept {
        handle: SocketHandle,
        response: ResponseSender<(SocketHandle, SocketAddr, SocketAddr, TcpChannels)>,
    },
    /// Close a TCP listener and all its pending sockets.
    TcpListenerClose { handle: SocketHandle },
    /// Close a TCP socket.
    TcpClose { handle: SocketHandle },
    /// Bind a UDP socket.
    /// Returns (handle, actual_bound_addr, channels) on success.
    UdpBind {
        addr: SocketAddr,
        response: ResponseSender<(SocketHandle, SocketAddr, UdpChannels)>,
    },
    /// Close a UDP socket.
    UdpClose { handle: SocketHandle },
    /// Add an IP address to the smoltcp interface.
    AddIp {
        ip: IpAddr,
        prefix_len: u8,
        response: oneshot::Sender<io::Result<()>>,
    },
    /// Remove an IP address from the smoltcp interface.
    RemoveIp {
        ip: IpAddr,
        response: oneshot::Sender<io::Result<()>>,
    },
    /// Get all IP addresses on the smoltcp interface.
    GetIps {
        response: oneshot::Sender<Vec<IpWithPrefix>>,
    },
}

/// Pending operations waiting for socket state changes.
enum PendingOp {
    TcpConnect {
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        channels: TcpChannels,
        response: ResponseSender<(SocketHandle, SocketAddr, SocketAddr, TcpChannels)>,
    },
    TcpAccept {
        response: ResponseSender<(SocketHandle, SocketAddr, SocketAddr, TcpChannels)>,
    },
}

/// State for a TCP listener managing multiple listening sockets for backlog.
struct ListenerState {
    /// The address this listener is bound to.
    addr: SocketAddr,
    /// Socket handles currently in Listen state.
    listening_handles: Vec<SocketHandle>,
}

/// Configuration for the network stack.
pub struct StackConfig {
    pub mac: [u8; 6],
    pub ip: IpAddr,
    pub prefix_len: u8,
    pub gateway: IpAddr,
}

/// Run the smoltcp stack as an async task.
///
/// This function runs the smoltcp poll loop, processing:
/// - Incoming frames from the proxy (via device)
/// - Socket commands from async handles
/// - Protocol state machines (TCP, ARP, NDP, etc.)
pub async fn run_stack(
    device: &mut impl Device,
    config: StackConfig,
    mut commands: Receiver<StackCommand>,
    ipc_dead: Arc<AtomicBool>,
) {
    debug!("run_stack starting");

    // Create smoltcp interface
    let mac = EthernetAddress(config.mac);
    let iface_config = Config::new(mac.into());

    let start_timestamp = StdInstant::now();
    let mut iface = Interface::new(iface_config, device, instant_since(start_timestamp));

    // Configure IP address
    let ip_cidr = IpCidr::new(ip_addr_to_smoltcp(config.ip), config.prefix_len);
    iface.update_ip_addrs(|addrs| {
        addrs.push(ip_cidr).expect("failed to add IP address");
    });

    // Configure default route based on address family
    match config.gateway {
        IpAddr::V4(v4) => {
            iface
                .routes_mut()
                .add_default_ipv4_route(v4.octets().into())
                .expect("failed to add default IPv4 route");
        }
        IpAddr::V6(v6) => {
            iface
                .routes_mut()
                .add_default_ipv6_route(v6.octets().into())
                .expect("failed to add default IPv6 route");
        }
    }

    // Enable Any-IP
    iface.set_any_ip(true);

    debug!("stack started: mac={}, ip={}", mac, ip_cidr);

    // Socket storage
    let mut sockets = SocketSet::new(vec![]);
    let mut pending: PendingOps = HashMap::new();
    let mut listeners: Listeners = HashMap::new();

    // Per-socket data channel state
    let mut tcp_states: HashMap<SocketHandle, TcpSocketState> = HashMap::new();
    let mut udp_states: HashMap<SocketHandle, UdpSocketState> = HashMap::new();

    // Notify used to signal when data is written to any socket's channel
    let write_notify = Arc::new(Notify::new());

    loop {
        // Calculate poll interval based on smoltcp's needs
        let timestamp = instant_since(start_timestamp);
        let poll_delay = iface.poll_delay(timestamp, &sockets);
        let poll_interval = if let Some(delay) = poll_delay {
            StdDuration::from_micros(delay.total_micros())
                .min(StdDuration::from_millis(MAX_POLL_INTERVAL_MS))
        } else {
            StdDuration::from_millis(MAX_POLL_INTERVAL_MS)
        };

        // Wait for either a command, write notification, or timeout
        tokio::select! {
            biased;

            cmd = commands.recv() => {
                match cmd {
                    Some(cmd) => {
                        trace!("received command");
                        if !handle_command(
                            cmd,
                            &mut iface,
                            &mut sockets,
                            &mut pending,
                            &mut listeners,
                            &config,
                            &mut tcp_states,
                            &mut udp_states,
                            &write_notify,
                        ) {
                            debug!("stack shutting down");
                            return;
                        }
                    }
                    None => {
                        debug!("command channel disconnected");
                        return;
                    }
                }
            }

            // TODO: poll UnorderedFutures instead
            //
            // Application wrote data - need to poll write channels
            _ = write_notify.notified() => {}

            _ = tokio::time::sleep(poll_interval) => {
                // Timeout - continue to poll interface
            }
        }

        // Poll write channels for all sockets (app -> smoltcp)
        poll_write_channels(&mut sockets, &mut tcp_states, &mut udp_states);

        // Poll the interface in batches to avoid blocking the runtime
        let timestamp = instant_since(start_timestamp);
        let mut socket_state_changed = false;

        for _ in 0..INGRESS_BATCH_SIZE {
            match iface.poll_ingress_single(timestamp, device, &mut sockets) {
                smoltcp::iface::PollIngressSingleResult::None => break,
                smoltcp::iface::PollIngressSingleResult::PacketProcessed => {}
                smoltcp::iface::PollIngressSingleResult::SocketStateChanged => {
                    socket_state_changed = true;
                }
            }
        }

        // Process egress (responses, retransmits, etc.)
        let egress_result = iface.poll_egress(timestamp, device, &mut sockets);
        if matches!(
            egress_result,
            smoltcp::iface::PollResult::SocketStateChanged
        ) {
            socket_state_changed = true;
        }

        // Process read channels for all sockets (smoltcp -> app)
        poll_read_channels(&mut sockets, &mut tcp_states, &mut udp_states);

        // Process pending operations that may now be completable
        if socket_state_changed {
            trace!("socket state changed");
            process_pending(
                &mut sockets,
                &mut pending,
                &mut listeners,
                &mut tcp_states,
                &write_notify,
            );
        }

        // Check if IPC connection to proxy was lost
        if ipc_dead.load(atomic::Ordering::Relaxed) {
            warn!("IPC connection lost, shutting down stack");
            // Fail all pending operations
            for (_handle, op) in pending.drain() {
                match op {
                    PendingOp::TcpConnect { response, .. } => {
                        let _ = response.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "proxy connection lost",
                        )));
                    }
                    PendingOp::TcpAccept { response } => {
                        let _ = response.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "proxy connection lost",
                        )));
                    }
                }
            }
            return;
        }
    }
}

/// Handle a command from an async socket handle.
/// Returns false if the stack should shut down.
#[allow(clippy::too_many_arguments)]
fn handle_command(
    cmd: StackCommand,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    pending: &mut PendingOps,
    listeners: &mut Listeners,
    config: &StackConfig,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
    udp_states: &mut HashMap<SocketHandle, UdpSocketState>,
    write_notify: &Arc<Notify>,
) -> bool {
    match cmd {
        StackCommand::TcpConnect {
            local_ip,
            addr,
            response,
        } => {
            handle_tcp_connect(
                local_ip,
                addr,
                iface,
                sockets,
                pending,
                config,
                tcp_states,
                write_notify,
                response,
            );
        }
        StackCommand::TcpListen {
            addr,
            backlog,
            response,
        } => {
            handle_tcp_listen(addr, backlog, sockets, listeners, response);
        }
        StackCommand::TcpAccept { handle, response } => {
            handle_tcp_accept(
                handle,
                sockets,
                listeners,
                pending,
                tcp_states,
                write_notify,
                response,
            );
        }
        StackCommand::TcpListenerClose { handle } => {
            handle_tcp_listener_close(handle, sockets, listeners, pending);
        }
        StackCommand::TcpClose { handle } => {
            handle_tcp_close(handle, sockets, tcp_states);
        }
        StackCommand::UdpBind { addr, response } => {
            handle_udp_bind(addr, sockets, udp_states, write_notify, response);
        }
        StackCommand::UdpClose { handle } => {
            handle_udp_close(handle, sockets, udp_states);
        }
        StackCommand::AddIp {
            ip,
            prefix_len,
            response,
        } => {
            handle_add_ip(ip, prefix_len, iface, response);
        }
        StackCommand::RemoveIp { ip, response } => {
            handle_remove_ip(ip, iface, response);
        }
        StackCommand::GetIps { response } => {
            handle_get_ips(iface, response);
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn handle_tcp_connect(
    local_ip: Option<IpAddr>,
    addr: SocketAddr,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    pending: &mut PendingOps,
    config: &StackConfig,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
    write_notify: &Arc<Notify>,
    response: ResponseSender<(SocketHandle, SocketAddr, SocketAddr, TcpChannels)>,
) {
    debug!("tcp_connect to {} from {:?}", addr, local_ip);

    // Create TCP socket with buffers
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER_SIZE]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER_SIZE]);
    let socket = tcp::Socket::new(rx_buf, tx_buf);

    // Add socket first, then connect
    let handle = sockets.add(socket);

    // Convert address
    let remote = socket_addr_to_endpoint(addr);

    // Use provided local_ip or fall back to config.ip
    let source_ip = local_ip.unwrap_or(config.ip);

    // Use ephemeral local port
    let local_port = allocate_ephemeral_port();
    let local = IpListenEndpoint {
        addr: Some(ip_addr_to_smoltcp(source_ip)),
        port: local_port,
    };

    trace!("tcp_connect: local {}:{}", source_ip, local_port);

    // Initiate connection
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if let Err(e) = socket.connect(iface.context(), remote, local) {
        warn!("tcp_connect failed: {}", e);
        sockets.remove(handle);
        let _ = response.send(Err(io::Error::other(format!("connect failed: {}", e))));
        return;
    }

    trace!("tcp_connect initiated: handle={:?}", handle);

    // Create channels for this socket (will be returned when connection completes)
    let (channels, state) = create_tcp_channels(Arc::clone(write_notify));
    tcp_states.insert(handle, state);

    // Construct local and peer addresses for later
    let local_addr = make_socket_addr(source_ip, local_port);
    let peer_addr = addr;

    // Store pending connect with address info and channels
    pending.insert(
        handle,
        PendingOp::TcpConnect {
            local_addr,
            peer_addr,
            channels,
            response,
        },
    );
}

fn handle_tcp_listen(
    addr: SocketAddr,
    backlog: usize,
    sockets: &mut SocketSet<'_>,
    listeners: &mut Listeners,
    response: oneshot::Sender<io::Result<(SocketHandle, SocketAddr)>>,
) {
    debug!("tcp_listen on {} with backlog {}", addr, backlog);

    let listen_endpoint = socket_addr_to_listen_endpoint(addr);

    // Check for port 0 (not supported for listen)
    if addr.port() == 0 {
        let _ = response.send(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot listen on port 0",
        )));
        return;
    }

    // Check if address is already bound by another listener
    for state in listeners.values() {
        if state.addr.port() == addr.port() {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already in use",
            )));
            return;
        }
    }

    // Create `backlog` listening sockets
    let backlog = backlog.max(1); // At least 1 socket
    let mut listening_handles = Vec::with_capacity(backlog);

    for _ in 0..backlog {
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER_SIZE]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);

        if let Err(e) = socket.listen(listen_endpoint) {
            warn!("tcp_listen failed: {}", e);
            // Clean up already-created sockets
            for h in listening_handles {
                sockets.remove(h);
            }
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("listen failed: {}", e),
            )));
            return;
        }

        let handle = sockets.add(socket);
        listening_handles.push(handle);
    }

    // Use first handle as the "primary" handle for the listener
    let primary_handle = listening_handles[0];

    // Store listener state
    listeners.insert(
        primary_handle,
        ListenerState {
            addr,
            listening_handles,
        },
    );

    debug!(
        "TCP listener created: handle={:?}, addr={}, backlog={}",
        primary_handle, addr, backlog
    );
    let _ = response.send(Ok((primary_handle, addr)));
}

fn handle_tcp_accept(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    listeners: &mut Listeners,
    pending: &mut PendingOps,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
    write_notify: &Arc<Notify>,
    response: ResponseSender<(SocketHandle, SocketAddr, SocketAddr, TcpChannels)>,
) {
    trace!("tcp_accept on handle={:?}", handle);

    // Check if we have a listener for this handle
    let state = match listeners.get_mut(&handle) {
        Some(s) => s,
        None => {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a listener handle",
            )));
            return;
        }
    };

    // Check if any listening socket has become established
    if let Some((accepted_handle, local, peer)) = try_accept_socket(sockets, state) {
        // Create channels for the accepted socket
        let (channels, socket_state) = create_tcp_channels(Arc::clone(write_notify));
        tcp_states.insert(accepted_handle, socket_state);
        let _ = response.send(Ok((accepted_handle, local, peer, channels)));
        return;
    }

    // No connection ready yet - store as pending
    trace!("tcp_accept: no connection ready, queuing");
    pending.insert(handle, PendingOp::TcpAccept { response });
}

/// Try to accept a connection from one of the listener's sockets.
/// If successful, returns the accepted socket handle, local address, and peer address,
/// and spawns a replacement listening socket.
fn try_accept_socket(
    sockets: &mut SocketSet<'_>,
    state: &mut ListenerState,
) -> Option<(SocketHandle, SocketAddr, SocketAddr)> {
    // Find a socket that has transitioned to Established
    let mut accepted_idx = None;
    let mut peer_addr = None;
    let mut local_addr = None;

    for (idx, &socket_handle) in state.listening_handles.iter().enumerate() {
        let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
        if socket.state() == TcpState::Established {
            // Get peer and local addresses before we remove from the list
            if let Some(remote) = socket.remote_endpoint() {
                peer_addr = Some(endpoint_to_socket_addr(remote));
                // Get the actual local endpoint from the socket
                if let Some(local) = socket.local_endpoint() {
                    local_addr = Some(endpoint_to_socket_addr(local));
                } else {
                    // Fallback to listener's address
                    local_addr = Some(state.addr);
                }
                accepted_idx = Some(idx);
                break;
            }
        }
    }

    let idx = accepted_idx?;
    let peer = peer_addr?;
    let local = local_addr?;

    // Remove the accepted socket from listening_handles
    let accepted_handle = state.listening_handles.remove(idx);

    debug!(
        "TCP accept: handle={:?}, local={}, peer={}, remaining_listeners={}",
        accepted_handle,
        local,
        peer,
        state.listening_handles.len()
    );

    // Create a replacement listening socket to maintain backlog
    let listen_endpoint = socket_addr_to_listen_endpoint(state.addr);

    let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER_SIZE]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER_SIZE]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);

    if socket.listen(listen_endpoint).is_ok() {
        let new_handle = sockets.add(socket);
        state.listening_handles.push(new_handle);
        trace!(
            "Created replacement listener socket: handle={:?}",
            new_handle
        );
    } else {
        warn!("Failed to create replacement listener socket");
    }

    Some((accepted_handle, local, peer))
}

fn handle_tcp_listener_close(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    listeners: &mut Listeners,
    pending: &mut PendingOps,
) {
    debug!("tcp_listener_close: handle={:?}", handle);

    // Remove any pending accept
    pending.remove(&handle);

    // Get and remove the listener state
    if let Some(state) = listeners.remove(&handle) {
        // Close all listening sockets that are still in Listen state
        for socket_handle in state.listening_handles {
            let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
            // Only close if still in Listen state (not yet accepted)
            if socket.state() == TcpState::Listen {
                socket.close();
                trace!("Closed listener socket: handle={:?}", socket_handle);
            }
        }
    }
}

fn handle_tcp_close(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    socket.close();
    tcp_states.remove(&handle);
    debug!("TCP closing: handle={:?}", handle);
}

fn handle_udp_bind(
    addr: SocketAddr,
    sockets: &mut SocketSet<'_>,
    udp_states: &mut HashMap<SocketHandle, UdpSocketState>,
    write_notify: &Arc<Notify>,
    response: ResponseSender<(SocketHandle, SocketAddr, UdpChannels)>,
) {
    debug!("udp_bind: addr={}", addr);

    let rx_buf = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_METADATA_SLOTS],
        vec![0u8; UDP_PACKET_BUFFER_SIZE],
    );
    let tx_buf = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_METADATA_SLOTS],
        vec![0u8; UDP_PACKET_BUFFER_SIZE],
    );
    let mut socket = udp::Socket::new(rx_buf, tx_buf);

    // For port 0, allocate an ephemeral port
    let port = if addr.port() == 0 {
        allocate_ephemeral_port()
    } else {
        addr.port()
    };

    // Construct the actual bound address (with allocated port if ephemeral)
    let bound_addr = match addr {
        SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), port)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(*v6.ip(), port, 0, 0)),
    };

    let endpoint = socket_addr_to_listen_endpoint_with_port(addr, port);

    trace!("udp_bind: endpoint={:?}", endpoint);

    if let Err(e) = socket.bind(endpoint) {
        warn!("udp_bind failed: {:?}", e);
        let _ = response.send(Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("bind failed: {}", e),
        )));
        return;
    }

    let handle = sockets.add(socket);

    // Create channels for this socket
    let (channels, state) = create_udp_channels(Arc::clone(write_notify));
    udp_states.insert(handle, state);

    debug!("UDP bound: handle={:?}, addr={}", handle, bound_addr);
    let _ = response.send(Ok((handle, bound_addr, channels)));
}

fn handle_udp_close(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    udp_states: &mut HashMap<SocketHandle, UdpSocketState>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket.close();
    udp_states.remove(&handle);
    debug!("UDP closed: handle={:?}", handle);
}

fn handle_add_ip(
    ip: IpAddr,
    prefix_len: u8,
    iface: &mut Interface,
    response: oneshot::Sender<io::Result<()>>,
) {
    debug!("add_ip: {}/{}", ip, prefix_len);
    let cidr = IpCidr::new(ip_addr_to_smoltcp(ip), prefix_len);

    // Check if already present
    let already_present = iface.ip_addrs().iter().any(|a| a == &cidr);
    if already_present {
        let _ = response.send(Ok(()));
        return;
    }

    // Try to add the IP
    let mut add_result = Ok(());
    iface.update_ip_addrs(|addrs| {
        if addrs.push(cidr).is_err() {
            add_result = Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "address list full",
            ));
        }
    });

    let _ = response.send(add_result);
}

fn handle_remove_ip(ip: IpAddr, iface: &mut Interface, response: oneshot::Sender<io::Result<()>>) {
    debug!("remove_ip: {}", ip);
    let target = ip_addr_to_smoltcp(ip);

    iface.update_ip_addrs(|addrs| {
        addrs.retain(|a| a.address() != target);
    });

    let _ = response.send(Ok(()));
}

fn handle_get_ips(iface: &Interface, response: oneshot::Sender<Vec<IpWithPrefix>>) {
    let ips: Vec<_> = iface
        .ip_addrs()
        .iter()
        .map(|cidr| {
            let ip = smoltcp_to_ip_addr(cidr.address());
            (ip, cidr.prefix_len())
        })
        .collect();

    debug!("get_ips: {:?}", ips);
    let _ = response.send(ips);
}

/// Poll all write channels and send data to smoltcp.
/// Uses try_recv which is cheap if channel is empty.
fn poll_write_channels(
    sockets: &mut SocketSet<'_>,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
    udp_states: &mut HashMap<SocketHandle, UdpSocketState>,
) {
    // Process TCP write channels
    for (&handle, state) in tcp_states.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        process_tcp_write(socket, state);
    }

    // Process UDP write channels
    for (&handle, state) in udp_states.iter_mut() {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        process_udp_write(socket, state);
    }
}

/// Poll all read channels and receive data from smoltcp.
fn poll_read_channels(
    sockets: &mut SocketSet<'_>,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
    udp_states: &mut HashMap<SocketHandle, UdpSocketState>,
) {
    // Process TCP read channels
    for (&handle, state) in tcp_states.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        process_tcp_read(socket, state);
    }

    // Process UDP read channels
    for (&handle, state) in udp_states.iter_mut() {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        process_udp_read(socket, state);
    }
}

/// Process TCP write path: pull data from channel and send to smoltcp.
fn process_tcp_write(socket: &mut tcp::Socket, state: &mut TcpSocketState) {
    // First, try to send any pending partial write
    if let Some(pending) = state.pending_write.take() {
        if socket.may_send() {
            match socket.send_slice(&pending) {
                Ok(n) if n < pending.len() => {
                    state.pending_write = Some(pending[n..].to_vec());
                    return; // Buffer full, wait for waker
                }
                Ok(_) => {}       // Fully sent, continue
                Err(_) => return, // Error, will be detected on read
            }
        } else {
            state.pending_write = Some(pending);
            return;
        }
    }

    // Pull new data from channel
    while socket.can_send() {
        match state.write_rx.try_recv() {
            Ok(data) => match socket.send_slice(&data) {
                Ok(n) if n < data.len() => {
                    state.pending_write = Some(data[n..].to_vec());
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            },
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                // Socket dropped, initiate close
                socket.close();
                break;
            }
        }
    }
}

/// Process TCP read path: receive data from smoltcp and push to channel.
fn process_tcp_read(socket: &mut tcp::Socket, state: &mut TcpSocketState) {
    while socket.can_recv() {
        // Check if channel has capacity
        match state.read_tx.try_reserve() {
            Ok(permit) => {
                let mut buf = vec![0u8; TCP_SOCKET_BUFFER_SIZE];
                match socket.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        permit.send(buf);
                    }
                    _ => break,
                }
            }
            Err(_) => break, // Channel full, backpressure
        }
    }
}

/// Process UDP write path: pull data from channel and send to smoltcp.
fn process_udp_write(socket: &mut udp::Socket, state: &mut UdpSocketState) {
    while socket.can_send() {
        match state.write_rx.try_recv() {
            Ok((data, dest)) => {
                let endpoint = socket_addr_to_endpoint(dest);
                let _ = socket.send_slice(&data, endpoint);
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                socket.close();
                break;
            }
        }
    }
}

/// Process UDP read path: receive data from smoltcp and push to channel.
fn process_udp_read(socket: &mut udp::Socket, state: &mut UdpSocketState) {
    while socket.can_recv() {
        match state.read_tx.try_reserve() {
            Ok(permit) => {
                let mut buf = vec![0u8; UDP_PACKET_BUFFER_SIZE];
                match socket.recv_slice(&mut buf) {
                    Ok((n, meta)) => {
                        buf.truncate(n);
                        let addr = endpoint_to_socket_addr(meta.endpoint);
                        permit.send((buf, addr));
                    }
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
    }
}

/// Process pending operations that may now be completable.
fn process_pending(
    sockets: &mut SocketSet<'_>,
    pending: &mut PendingOps,
    listeners: &mut Listeners,
    tcp_states: &mut HashMap<SocketHandle, TcpSocketState>,
    write_notify: &Arc<Notify>,
) {
    let handles: Vec<_> = pending.keys().cloned().collect();

    for handle in handles {
        let completed = match pending.get(&handle) {
            Some(PendingOp::TcpConnect { .. }) => {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                let state = socket.state();
                match state {
                    TcpState::Established => {
                        debug!("TCP connected: handle={:?}", handle);
                        if let Some(PendingOp::TcpConnect {
                            local_addr,
                            peer_addr,
                            channels,
                            response,
                        }) = pending.remove(&handle)
                        {
                            let _ = response.send(Ok((handle, local_addr, peer_addr, channels)));
                        }
                        true
                    }
                    TcpState::Closed | TcpState::TimeWait => {
                        debug!(
                            "TCP connection failed: handle={:?}, state={:?}",
                            handle, state
                        );
                        if let Some(PendingOp::TcpConnect { response, .. }) =
                            pending.remove(&handle)
                        {
                            // Remove the socket state since connection failed
                            tcp_states.remove(&handle);
                            let _ = response.send(Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "connection failed",
                            )));
                        }
                        true
                    }
                    _ => false,
                }
            }
            Some(PendingOp::TcpAccept { .. }) => {
                // Check if we have a listener for this handle and try to accept
                if let Some(state) = listeners.get_mut(&handle) {
                    if let Some((accepted_handle, local, peer)) = try_accept_socket(sockets, state)
                    {
                        if let Some(PendingOp::TcpAccept { response }) = pending.remove(&handle) {
                            // Create channels for the accepted socket
                            let (channels, socket_state) =
                                create_tcp_channels(Arc::clone(write_notify));
                            tcp_states.insert(accepted_handle, socket_state);
                            let _ = response.send(Ok((accepted_handle, local, peer, channels)));
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    // Listener was closed, fail the pending accept
                    if let Some(PendingOp::TcpAccept { response }) = pending.remove(&handle) {
                        let _ = response.send(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "listener closed",
                        )));
                    }
                    true
                }
            }
            None => true,
        };

        if completed {
            continue;
        }
    }
}

// Helper functions

fn instant_since(start: StdInstant) -> Instant {
    Instant::from_micros((StdInstant::now() - start).as_micros() as i64)
}

/// Convert a std IpAddr to a smoltcp IpAddress.
fn ip_addr_to_smoltcp(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4.octets().into()),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6.octets().into()),
    }
}

/// Convert a smoltcp IpAddress to a std IpAddr.
fn smoltcp_to_ip_addr(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(Ipv4Addr::from(v4.octets())),
        IpAddress::Ipv6(v6) => IpAddr::V6(Ipv6Addr::from(v6.octets())),
    }
}

/// Convert a SocketAddr to a smoltcp IpEndpoint.
fn socket_addr_to_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(ip_addr_to_smoltcp(addr.ip()), addr.port())
}

/// Convert a smoltcp IpEndpoint to a SocketAddr.
fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    make_socket_addr(smoltcp_to_ip_addr(endpoint.addr), endpoint.port)
}

/// Convert a SocketAddr to a smoltcp IpListenEndpoint.
fn socket_addr_to_listen_endpoint(addr: SocketAddr) -> IpListenEndpoint {
    let smoltcp_addr = ip_addr_to_smoltcp(addr.ip());
    IpListenEndpoint {
        addr: if addr.ip().is_unspecified() {
            None
        } else {
            Some(smoltcp_addr)
        },
        port: addr.port(),
    }
}

/// Convert a SocketAddr to a smoltcp IpListenEndpoint with a specific port.
fn socket_addr_to_listen_endpoint_with_port(addr: SocketAddr, port: u16) -> IpListenEndpoint {
    let smoltcp_addr = ip_addr_to_smoltcp(addr.ip());
    IpListenEndpoint {
        addr: if addr.ip().is_unspecified() {
            None
        } else {
            Some(smoltcp_addr)
        },
        port,
    }
}

/// Create a SocketAddr from an IpAddr and port.
fn make_socket_addr(ip: IpAddr, port: u16) -> SocketAddr {
    match ip {
        IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
    }
}

static EPHEMERAL_PORT: atomic::AtomicU16 = atomic::AtomicU16::new(EPHEMERAL_PORT_START);

fn allocate_ephemeral_port() -> u16 {
    EPHEMERAL_PORT.fetch_add(1, atomic::Ordering::Relaxed)
}
