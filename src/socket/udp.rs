//! UDP socket type for the Namespace API.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// A UDP socket bound to an address in a network namespace.
///
/// Supports both connected and unconnected modes.
pub struct UdpSocket {
    socket: AsyncFd<UnixStream>,
    local_addr: SocketAddr,
    peer_addr: Mutex<Option<SocketAddr>>,
}

impl UdpSocket {
    /// Create a new UdpSocket from a Unix socket.
    pub(crate) fn new(socket: UnixStream, local_addr: SocketAddr) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
            local_addr,
            peer_addr: Mutex::new(None),
        })
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Returns the peer address if the socket is connected.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr
            .lock()
            .unwrap()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "socket not connected"))
    }

    /// Connect the socket to a remote address.
    ///
    /// After connecting, you can use `send()` and `recv()` instead of
    /// `send_to()` and `recv_from()`.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        // For UDP, "connecting" just means setting the default peer address.
        // The actual socket in the child is not connected; we just filter
        // in the parent and always include the peer address in messages.
        *self.peer_addr.lock().unwrap() = Some(addr);
        Ok(())
    }

    /// Send data to the specified address.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // Encode: address + data
        let msg = encode_udp_message(addr, buf);
        self.send_raw(&msg).await?;
        Ok(buf.len())
    }

    /// Receive data and the source address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // We need enough buffer for address header + data
        let mut recv_buf = vec![0u8; buf.len() + 32];
        let n = self.recv_raw(&mut recv_buf).await?;
        let (addr, data) = decode_udp_message(&recv_buf[..n])?;
        let copy_len = data.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);
        Ok((copy_len, addr))
    }

    /// Send data to the connected peer.
    ///
    /// The socket must be connected with `connect()` first.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let peer = self.peer_addr()?;
        self.send_to(buf, peer).await
    }

    /// Receive data from the connected peer.
    ///
    /// The socket must be connected with `connect()` first.
    /// Data from other addresses is silently discarded.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let peer = self.peer_addr()?;
        loop {
            let (n, from) = self.recv_from(buf).await?;
            if from == peer {
                return Ok(n);
            }
            // Discard packets from other addresses
        }
    }

    async fn send_raw(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.socket.ready(Interest::WRITABLE).await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe {
                    libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
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

    async fn recv_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.socket.ready(Interest::READABLE).await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe {
                    libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else if ret == 0 {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"))
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

/// Encode a UDP message with address header.
/// Format: 1 byte tag (4=v4, 6=v6) + address bytes + 2 byte port + data
pub(crate) fn encode_udp_message(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + data.len());
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_le_bytes());
        }
    }
    buf.extend_from_slice(data);
    buf
}

/// Decode a UDP message with address header.
pub(crate) fn decode_udp_message(buf: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty message"));
    }

    let tag = buf[0];
    match tag {
        4 => {
            if buf.len() < 7 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message too short"));
            }
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_le_bytes([buf[5], buf[6]]);
            let addr = SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
            Ok((addr, &buf[7..]))
        }
        6 => {
            if buf.len() < 19 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_le_bytes([buf[17], buf[18]]);
            let addr = SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0));
            Ok((addr, &buf[19..]))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid address tag: {}", tag),
        )),
    }
}
