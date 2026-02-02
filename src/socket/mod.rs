//! Async socket types backed by smoltcp.
//!
//! These types provide a familiar async socket API (similar to tokio::net)
//! but backed by the smoltcp userspace TCP/IP stack.

use crate::stack::StackCommand;
use crossbeam_channel::Sender;
use smoltcp::iface::SocketHandle;
use std::io;
use std::net::SocketAddr;

/// A TCP stream connected to a remote endpoint.
///
/// This provides an async read/write interface similar to `tokio::net::TcpStream`,
/// but backed by smoltcp running in a dedicated thread.
pub struct TcpStream {
    handle: SocketHandle,
    commands: Sender<StackCommand>,
}

impl TcpStream {
    /// Create a TcpStream from an existing socket handle.
    pub(crate) fn from_handle(handle: SocketHandle, commands: Sender<StackCommand>) -> Self {
        Self { handle, commands }
    }

    /// Read data from the stream.
    ///
    /// Returns the number of bytes read, or 0 if the connection is closed.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.commands
            .send(StackCommand::TcpRecv {
                handle: self.handle,
                max_len: buf.len(),
                response: tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let data = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.commands
            .send(StackCommand::TcpSend {
                handle: self.handle,
                data: buf.to_vec(),
                response: tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?
    }

    /// Write all data to the stream.
    pub async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            let n = self.write(&buf[written..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            written += n;
        }
        Ok(())
    }

    /// Close the stream.
    pub fn close(&self) {
        let _ = self.commands.send(StackCommand::TcpClose {
            handle: self.handle,
        });
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close();
    }
}

/// A UDP socket.
///
/// This provides an async send/recv interface similar to `tokio::net::UdpSocket`,
/// but backed by smoltcp running in a dedicated thread.
pub struct UdpSocket {
    handle: SocketHandle,
    commands: Sender<StackCommand>,
}

impl UdpSocket {
    /// Create a UdpSocket from an existing socket handle.
    pub(crate) fn from_handle(handle: SocketHandle, commands: Sender<StackCommand>) -> Self {
        Self { handle, commands }
    }

    /// Send data to the specified address.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.commands
            .send(StackCommand::UdpSend {
                handle: self.handle,
                dest: addr,
                data: buf.to_vec(),
                response: tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?
    }

    /// Receive data and the source address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.commands
            .send(StackCommand::UdpRecv {
                handle: self.handle,
                response: tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let (data, addr) = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok((len, addr))
    }

    /// Close the socket.
    pub fn close(&self) {
        let _ = self.commands.send(StackCommand::UdpClose {
            handle: self.handle,
        });
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.close();
    }
}

/// A TCP listener that accepts incoming connections.
///
/// This provides an async accept interface similar to `tokio::net::TcpListener`,
/// but backed by smoltcp running in a dedicated thread.
pub struct TcpListener {
    handle: SocketHandle,
    local_addr: SocketAddr,
    commands: Sender<StackCommand>,
}

impl TcpListener {
    /// Create a TcpListener from an existing socket handle.
    pub(crate) fn from_handle(
        handle: SocketHandle,
        local_addr: SocketAddr,
        commands: Sender<StackCommand>,
    ) -> Self {
        Self {
            handle,
            local_addr,
            commands,
        }
    }

    /// Accept an incoming connection.
    ///
    /// Returns the connected stream and the peer's address.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.commands
            .send(StackCommand::TcpAccept {
                handle: self.handle,
                response: tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let (stream_handle, peer_addr) = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        Ok((
            TcpStream::from_handle(stream_handle, self.commands.clone()),
            peer_addr,
        ))
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the listener.
    pub fn close(&self) {
        let _ = self.commands.send(StackCommand::TcpListenerClose {
            handle: self.handle,
        });
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.close();
    }
}
