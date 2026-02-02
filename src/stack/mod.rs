//! smoltcp network stack running on a dedicated thread.
//!
//! This module provides a TCP/UDP socket API backed by smoltcp, which handles
//! all protocol processing (Ethernet, ARP, IP, TCP, UDP) in userspace.

mod device;

pub use device::ProxyDevice;

use crossbeam_channel::{Receiver, TryRecvError};
use log::{debug, trace, warn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::Device;
use smoltcp::socket::tcp::{self, State as TcpState};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration as StdDuration, Instant as StdInstant};

/// Commands sent from async socket handles to the stack thread.
pub enum StackCommand {
    /// Create a TCP socket and initiate connection.
    TcpConnect {
        addr: SocketAddr,
        response: tokio::sync::oneshot::Sender<io::Result<SocketHandle>>,
    },
    /// Create a TCP listener and bind to the given address.
    TcpListen {
        addr: SocketAddr,
        backlog: usize,
        response: tokio::sync::oneshot::Sender<io::Result<(SocketHandle, SocketAddr)>>,
    },
    /// Accept an incoming connection on a TCP listener.
    TcpAccept {
        handle: SocketHandle,
        response: tokio::sync::oneshot::Sender<io::Result<(SocketHandle, SocketAddr)>>,
    },
    /// Close a TCP listener and all its pending sockets.
    TcpListenerClose { handle: SocketHandle },
    /// Send data on a TCP socket.
    TcpSend {
        handle: SocketHandle,
        data: Vec<u8>,
        response: tokio::sync::oneshot::Sender<io::Result<usize>>,
    },
    /// Receive data from a TCP socket.
    TcpRecv {
        handle: SocketHandle,
        max_len: usize,
        response: tokio::sync::oneshot::Sender<io::Result<Vec<u8>>>,
    },
    /// Close a TCP socket.
    TcpClose { handle: SocketHandle },
    /// Bind a UDP socket.
    UdpBind {
        addr: SocketAddr,
        response: tokio::sync::oneshot::Sender<io::Result<SocketHandle>>,
    },
    /// Send data on a UDP socket.
    UdpSend {
        handle: SocketHandle,
        dest: SocketAddr,
        data: Vec<u8>,
        response: tokio::sync::oneshot::Sender<io::Result<usize>>,
    },
    /// Receive data from a UDP socket.
    UdpRecv {
        handle: SocketHandle,
        response: tokio::sync::oneshot::Sender<io::Result<(Vec<u8>, SocketAddr)>>,
    },
    /// Close a UDP socket.
    UdpClose { handle: SocketHandle },
    /// Shutdown the stack thread.
    Shutdown,
}

/// Pending operations waiting for socket state changes.
enum PendingOp {
    TcpConnect(tokio::sync::oneshot::Sender<io::Result<SocketHandle>>),
    TcpAccept(tokio::sync::oneshot::Sender<io::Result<(SocketHandle, SocketAddr)>>),
    TcpSend {
        data: Vec<u8>,
        offset: usize,
        response: tokio::sync::oneshot::Sender<io::Result<usize>>,
    },
    TcpRecv {
        max_len: usize,
        response: tokio::sync::oneshot::Sender<io::Result<Vec<u8>>>,
    },
    UdpRecv(tokio::sync::oneshot::Sender<io::Result<(Vec<u8>, SocketAddr)>>),
}

/// State for a TCP listener managing multiple listening sockets for backlog.
struct ListenerState {
    /// The address this listener is bound to.
    addr: SocketAddr,
    /// Desired number of listening sockets (backlog).
    /// Currently stored for potential future use (e.g., dynamic backlog adjustment).
    #[allow(dead_code)]
    backlog: usize,
    /// Socket handles currently in Listen state.
    listening_handles: Vec<SocketHandle>,
}

/// Configuration for the network stack.
pub struct StackConfig {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
}

/// Run the smoltcp stack on the current thread (blocking).
///
/// This function runs the smoltcp poll loop, processing:
/// - Incoming frames from the proxy (via device)
/// - Socket commands from async handles
/// - Protocol state machines (TCP, ARP, etc.)
pub fn run_stack(device: &mut impl Device, config: StackConfig, commands: Receiver<StackCommand>) {
    debug!("run_stack starting");

    // Create smoltcp interface
    let mac = EthernetAddress(config.mac);
    let iface_config = Config::new(mac.into());

    let start_timestamp = StdInstant::now();
    let mut iface = Interface::new(iface_config, device, instant_since(start_timestamp));

    // Configure IP address
    let ip_cidr = IpCidr::new(IpAddress::Ipv4(config.ip), config.prefix_len);
    iface.update_ip_addrs(|addrs| {
        addrs.push(ip_cidr).expect("failed to add IP address");
    });

    // Configure gateway if provided
    if let Some(gw) = config.gateway {
        iface
            .routes_mut()
            .add_default_ipv4_route(gw.octets().into())
            .expect("failed to add default route");
    }

    debug!("stack started: mac={}, ip={}", mac, ip_cidr);

    // Socket storage
    let mut sockets = SocketSet::new(vec![]);
    let mut pending: HashMap<SocketHandle, PendingOp> = HashMap::new();
    let mut listeners: HashMap<SocketHandle, ListenerState> = HashMap::new();

    loop {
        // 1. Process commands (non-blocking)
        match commands.try_recv() {
            Ok(cmd) => {
                trace!("received command");
                if !handle_command(
                    cmd,
                    &mut iface,
                    &mut sockets,
                    &mut pending,
                    &mut listeners,
                    &config,
                ) {
                    debug!("stack shutting down");
                    return;
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                debug!("command channel disconnected");
                return;
            }
        }

        // 2. Poll the interface
        let timestamp = instant_since(start_timestamp);
        let poll_result = iface.poll(timestamp, device, &mut sockets);

        // 3. Process pending operations that may now be completable
        if matches!(poll_result, smoltcp::iface::PollResult::SocketStateChanged) {
            trace!("socket state changed");
            process_pending(&mut sockets, &mut pending, &mut listeners);
        }

        // 4. Calculate sleep duration
        // Use a short timeout to be responsive to incoming frames
        let poll_delay = iface.poll_delay(timestamp, &sockets);

        let sleep_duration = if let Some(delay) = poll_delay {
            StdDuration::from_micros(delay.total_micros()).min(StdDuration::from_millis(1))
        } else {
            StdDuration::from_millis(1)
        };

        std::thread::sleep(sleep_duration);
    }
}

/// Handle a command from an async socket handle.
/// Returns false if the stack should shut down.
fn handle_command(
    cmd: StackCommand,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    listeners: &mut HashMap<SocketHandle, ListenerState>,
    config: &StackConfig,
) -> bool {
    match cmd {
        StackCommand::TcpConnect { addr, response } => {
            handle_tcp_connect(addr, iface, sockets, pending, config, response);
        }
        StackCommand::TcpListen {
            addr,
            backlog,
            response,
        } => {
            handle_tcp_listen(addr, backlog, sockets, listeners, response);
        }
        StackCommand::TcpAccept { handle, response } => {
            handle_tcp_accept(handle, sockets, listeners, pending, response);
        }
        StackCommand::TcpListenerClose { handle } => {
            handle_tcp_listener_close(handle, sockets, listeners, pending);
        }
        StackCommand::TcpSend {
            handle,
            data,
            response,
        } => {
            handle_tcp_send(handle, data, sockets, pending, response);
        }
        StackCommand::TcpRecv {
            handle,
            max_len,
            response,
        } => {
            handle_tcp_recv(handle, max_len, sockets, pending, response);
        }
        StackCommand::TcpClose { handle } => {
            handle_tcp_close(handle, sockets, pending);
        }
        StackCommand::UdpBind { addr, response } => {
            handle_udp_bind(addr, sockets, response);
        }
        StackCommand::UdpSend {
            handle,
            dest,
            data,
            response,
        } => {
            handle_udp_send(handle, dest, data, sockets, response);
        }
        StackCommand::UdpRecv { handle, response } => {
            handle_udp_recv(handle, sockets, pending, response);
        }
        StackCommand::UdpClose { handle } => {
            handle_udp_close(handle, sockets, pending);
        }
        StackCommand::Shutdown => {
            return false;
        }
    }
    true
}

fn handle_tcp_connect(
    addr: SocketAddr,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    config: &StackConfig,
    response: tokio::sync::oneshot::Sender<io::Result<SocketHandle>>,
) {
    debug!("tcp_connect to {}", addr);

    // Create TCP socket with buffers
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
    let socket = tcp::Socket::new(rx_buf, tx_buf);

    // Add socket first, then connect
    let handle = sockets.add(socket);

    // Convert address
    let remote = socket_addr_to_endpoint(addr);

    // Use ephemeral local port
    let local_port = allocate_ephemeral_port();
    let local = IpListenEndpoint {
        addr: Some(IpAddress::Ipv4(config.ip)),
        port: local_port,
    };

    trace!("tcp_connect: local port {}", local_port);

    // Initiate connection
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if let Err(e) = socket.connect(iface.context(), remote, local) {
        warn!("tcp_connect failed: {}", e);
        sockets.remove(handle);
        let _ = response.send(Err(io::Error::other(format!("connect failed: {}", e))));
        return;
    }

    trace!("tcp_connect initiated: handle={:?}", handle);

    // Store pending connect
    pending.insert(handle, PendingOp::TcpConnect(response));
}

fn handle_tcp_listen(
    addr: SocketAddr,
    backlog: usize,
    sockets: &mut SocketSet<'_>,
    listeners: &mut HashMap<SocketHandle, ListenerState>,
    response: tokio::sync::oneshot::Sender<io::Result<(SocketHandle, SocketAddr)>>,
) {
    debug!("tcp_listen on {} with backlog {}", addr, backlog);

    // Validate address
    let listen_endpoint = match addr {
        SocketAddr::V4(v4) => IpListenEndpoint {
            addr: if v4.ip().is_unspecified() {
                None
            } else {
                Some(IpAddress::Ipv4(*v4.ip()))
            },
            port: v4.port(),
        },
        SocketAddr::V6(_) => {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 not supported",
            )));
            return;
        }
    };

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
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
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
            backlog,
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
    listeners: &mut HashMap<SocketHandle, ListenerState>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    response: tokio::sync::oneshot::Sender<io::Result<(SocketHandle, SocketAddr)>>,
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
    if let Some(result) = try_accept(sockets, state) {
        let _ = response.send(Ok(result));
        return;
    }

    // No connection ready yet - store as pending
    trace!("tcp_accept: no connection ready, queuing");
    pending.insert(handle, PendingOp::TcpAccept(response));
}

/// Try to accept a connection from one of the listener's sockets.
/// If successful, returns the accepted socket handle and peer address,
/// and spawns a replacement listening socket.
fn try_accept(
    sockets: &mut SocketSet<'_>,
    state: &mut ListenerState,
) -> Option<(SocketHandle, SocketAddr)> {
    // Find a socket that has transitioned to Established
    let mut accepted_idx = None;
    let mut peer_addr = None;

    for (idx, &socket_handle) in state.listening_handles.iter().enumerate() {
        let socket = sockets.get_mut::<tcp::Socket>(socket_handle);
        if socket.state() == TcpState::Established {
            // Get peer address before we remove from the list
            if let Some(remote) = socket.remote_endpoint() {
                peer_addr = Some(endpoint_to_socket_addr(remote));
                accepted_idx = Some(idx);
                break;
            }
        }
    }

    let idx = accepted_idx?;
    let peer = peer_addr?;

    // Remove the accepted socket from listening_handles
    let accepted_handle = state.listening_handles.remove(idx);

    debug!(
        "TCP accept: handle={:?}, peer={}, remaining_listeners={}",
        accepted_handle,
        peer,
        state.listening_handles.len()
    );

    // Create a replacement listening socket to maintain backlog
    let listen_endpoint = match state.addr {
        SocketAddr::V4(v4) => IpListenEndpoint {
            addr: if v4.ip().is_unspecified() {
                None
            } else {
                Some(IpAddress::Ipv4(*v4.ip()))
            },
            port: v4.port(),
        },
        SocketAddr::V6(_) => {
            // Shouldn't happen, but handle gracefully
            return Some((accepted_handle, peer));
        }
    };

    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
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

    Some((accepted_handle, peer))
}

fn handle_tcp_listener_close(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    listeners: &mut HashMap<SocketHandle, ListenerState>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
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

fn handle_tcp_send(
    handle: SocketHandle,
    data: Vec<u8>,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    response: tokio::sync::oneshot::Sender<io::Result<usize>>,
) {
    trace!("tcp_send: {} bytes", data.len());
    let socket = sockets.get_mut::<tcp::Socket>(handle);

    if !socket.may_send() {
        trace!("tcp_send: socket not connected");
        let _ = response.send(Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "socket not connected",
        )));
        return;
    }

    // Try to send immediately
    match socket.send_slice(&data) {
        Ok(n) if n == data.len() => {
            trace!("tcp_send: sent {} bytes", n);
            let _ = response.send(Ok(n));
        }
        Ok(n) => {
            trace!("tcp_send: partial send {}/{}, queuing", n, data.len());
            // Partial send - queue remainder
            pending.insert(
                handle,
                PendingOp::TcpSend {
                    data,
                    offset: n,
                    response,
                },
            );
        }
        Err(e) => {
            trace!("tcp_send: failed {:?}, queuing", e);
            // Queue for later
            pending.insert(
                handle,
                PendingOp::TcpSend {
                    data,
                    offset: 0,
                    response,
                },
            );
        }
    }
}

fn handle_tcp_recv(
    handle: SocketHandle,
    max_len: usize,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    response: tokio::sync::oneshot::Sender<io::Result<Vec<u8>>>,
) {
    trace!("tcp_recv: max_len={}", max_len);
    let socket = sockets.get_mut::<tcp::Socket>(handle);

    // Try to receive immediately
    if socket.can_recv() {
        let mut buf = vec![0u8; max_len];
        match socket.recv_slice(&mut buf) {
            Ok(n) => {
                trace!("tcp_recv: got {} bytes", n);
                buf.truncate(n);
                let _ = response.send(Ok(buf));
                return;
            }
            Err(e) => {
                trace!("tcp_recv: immediate recv failed {:?}", e);
            }
        }
    }

    // Check for closed connection
    if !socket.may_recv() {
        trace!("tcp_recv: socket closed, sending EOF");
        let _ = response.send(Ok(vec![])); // EOF
        return;
    }

    trace!("tcp_recv: queuing for later");
    // Queue for later
    pending.insert(handle, PendingOp::TcpRecv { max_len, response });
}

fn handle_tcp_close(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    socket.close();
    pending.remove(&handle);
    debug!("TCP closing: handle={:?}", handle);
}

fn handle_udp_bind(
    addr: SocketAddr,
    sockets: &mut SocketSet<'_>,
    response: tokio::sync::oneshot::Sender<io::Result<SocketHandle>>,
) {
    debug!("udp_bind: addr={}", addr);

    let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65535]);
    let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65535]);
    let mut socket = udp::Socket::new(rx_buf, tx_buf);

    // For port 0, allocate an ephemeral port
    let port = if addr.port() == 0 {
        allocate_ephemeral_port()
    } else {
        addr.port()
    };

    let endpoint = IpListenEndpoint {
        addr: match addr {
            SocketAddr::V4(v4) => {
                if v4.ip().is_unspecified() {
                    None
                } else {
                    Some(IpAddress::Ipv4(*v4.ip()))
                }
            }
            SocketAddr::V6(_) => {
                let _ = response.send(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv6 not supported",
                )));
                return;
            }
        },
        port,
    };

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
    debug!("UDP bound: handle={:?}, addr={}", handle, addr);
    let _ = response.send(Ok(handle));
}

fn handle_udp_send(
    handle: SocketHandle,
    dest: SocketAddr,
    data: Vec<u8>,
    sockets: &mut SocketSet<'_>,
    response: tokio::sync::oneshot::Sender<io::Result<usize>>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);
    let endpoint = socket_addr_to_endpoint(dest);

    match socket.send_slice(&data, endpoint) {
        Ok(()) => {
            let _ = response.send(Ok(data.len()));
        }
        Err(e) => {
            let _ = response.send(Err(io::Error::other(format!("send failed: {}", e))));
        }
    }
}

fn handle_udp_recv(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    response: tokio::sync::oneshot::Sender<io::Result<(Vec<u8>, SocketAddr)>>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);

    // Try to receive immediately
    if socket.can_recv() {
        let mut buf = vec![0u8; 65535];
        if let Ok((n, meta)) = socket.recv_slice(&mut buf) {
            buf.truncate(n);
            let addr = endpoint_to_socket_addr(meta.endpoint);
            let _ = response.send(Ok((buf, addr)));
            return;
        }
    }

    // Queue for later
    pending.insert(handle, PendingOp::UdpRecv(response));
}

fn handle_udp_close(
    handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket.close();
    pending.remove(&handle);
    debug!("UDP closed: handle={:?}", handle);
}

/// Process pending operations that may now be completable.
fn process_pending(
    sockets: &mut SocketSet<'_>,
    pending: &mut HashMap<SocketHandle, PendingOp>,
    listeners: &mut HashMap<SocketHandle, ListenerState>,
) {
    let handles: Vec<_> = pending.keys().cloned().collect();

    for handle in handles {
        let completed = match pending.get(&handle) {
            Some(PendingOp::TcpConnect(_)) => {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                let state = socket.state();
                match state {
                    TcpState::Established => {
                        debug!("TCP connected: handle={:?}", handle);
                        if let Some(PendingOp::TcpConnect(response)) = pending.remove(&handle) {
                            let _ = response.send(Ok(handle));
                        }
                        true
                    }
                    TcpState::Closed | TcpState::TimeWait => {
                        debug!(
                            "TCP connection failed: handle={:?}, state={:?}",
                            handle, state
                        );
                        if let Some(PendingOp::TcpConnect(response)) = pending.remove(&handle) {
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
            Some(PendingOp::TcpAccept(_)) => {
                // Check if we have a listener for this handle and try to accept
                if let Some(state) = listeners.get_mut(&handle) {
                    if let Some(result) = try_accept(sockets, state) {
                        if let Some(PendingOp::TcpAccept(response)) = pending.remove(&handle) {
                            let _ = response.send(Ok(result));
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    // Listener was closed, fail the pending accept
                    if let Some(PendingOp::TcpAccept(response)) = pending.remove(&handle) {
                        let _ = response.send(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "listener closed",
                        )));
                    }
                    true
                }
            }
            Some(PendingOp::TcpSend { .. }) => {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                if socket.may_send() {
                    if let Some(PendingOp::TcpSend {
                        data,
                        offset,
                        response,
                    }) = pending.remove(&handle)
                    {
                        match socket.send_slice(&data[offset..]) {
                            Ok(n) => {
                                let total = offset + n;
                                if total < data.len() {
                                    // Still more to send
                                    pending.insert(
                                        handle,
                                        PendingOp::TcpSend {
                                            data,
                                            offset: total,
                                            response,
                                        },
                                    );
                                } else {
                                    let _ = response.send(Ok(data.len()));
                                }
                            }
                            Err(_) => {
                                let _ = response.send(Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "send failed",
                                )));
                            }
                        }
                    }
                    true
                } else {
                    false
                }
            }
            Some(PendingOp::TcpRecv { .. }) => {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    if let Some(PendingOp::TcpRecv { max_len, response }) = pending.remove(&handle)
                    {
                        let mut buf = vec![0u8; max_len];
                        match socket.recv_slice(&mut buf) {
                            Ok(n) => {
                                trace!("TCP recv: {} bytes", n);
                                buf.truncate(n);
                                let _ = response.send(Ok(buf));
                            }
                            Err(e) => {
                                warn!("TCP recv error: {:?}", e);
                                let _ = response.send(Err(io::Error::other("recv failed")));
                            }
                        }
                    }
                    true
                } else if !socket.may_recv() {
                    // Socket closed
                    trace!("TCP recv: EOF");
                    if let Some(PendingOp::TcpRecv { response, .. }) = pending.remove(&handle) {
                        let _ = response.send(Ok(vec![])); // EOF
                    }
                    true
                } else {
                    false
                }
            }
            Some(PendingOp::UdpRecv(_)) => {
                let socket = sockets.get_mut::<udp::Socket>(handle);
                if socket.can_recv() {
                    if let Some(PendingOp::UdpRecv(response)) = pending.remove(&handle) {
                        let mut buf = vec![0u8; 65535];
                        match socket.recv_slice(&mut buf) {
                            Ok((n, meta)) => {
                                buf.truncate(n);
                                let addr = endpoint_to_socket_addr(meta.endpoint);
                                let _ = response.send(Ok((buf, addr)));
                            }
                            Err(_) => {
                                let _ = response.send(Err(io::Error::other("recv failed")));
                            }
                        }
                    }
                    true
                } else {
                    false
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

fn socket_addr_to_endpoint(addr: SocketAddr) -> IpEndpoint {
    match addr {
        SocketAddr::V4(v4) => IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port()),
        SocketAddr::V6(_) => panic!("IPv6 not supported"),
    }
}

fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(v4) => {
            let octets = v4.octets();
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
                endpoint.port,
            ))
        }
    }
}

static EPHEMERAL_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(49152);

fn allocate_ephemeral_port() -> u16 {
    EPHEMERAL_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
