//! TCP socket types for the Tunnel API.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Tunnel;

/// A TCP stream connected to an address in a network namespace.
///
/// This type implements `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`,
/// allowing it to be used with standard async I/O patterns.
pub struct TcpStream {
    socket: AsyncFd<UnixStream>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl TcpStream {
    /// Create a new TcpStream from a Unix socket and addresses.
    pub(crate) fn new(socket: UnixStream, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
            local_addr,
            peer_addr,
        })
    }

    /// Returns the local address of this TCP stream.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Returns the remote address of this TCP stream.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.socket.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let fd = self.socket.get_ref().as_raw_fd();
            let unfilled = buf.initialize_unfilled();

            match guard.try_io(|_| {
                let ret = unsafe {
                    libc::recv(
                        fd,
                        unfilled.as_mut_ptr() as *mut libc::c_void,
                        unfilled.len(),
                        0,
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
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.socket.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let fd = self.socket.get_ref().as_raw_fd();

            match guard.try_io(|_| {
                let ret = unsafe {
                    libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Unix sockets don't need flushing
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutdown the write half of the Unix socket
        self.socket.get_ref().shutdown(std::net::Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

/// A TCP listener bound to an address in a network namespace.
///
/// Use `accept()` to wait for incoming connections.
pub struct TcpListener {
    tunnel: Arc<Tunnel>,
    id: u64,
    local_addr: SocketAddr,
}

impl TcpListener {
    /// Create a new TcpListener.
    pub(crate) fn new(tunnel: Arc<Tunnel>, id: u64, local_addr: SocketAddr) -> Self {
        Self { tunnel, id, local_addr }
    }

    /// Accept a new incoming connection.
    ///
    /// Returns the connected stream and the remote address.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.tunnel.accept_tcp(self.id).await
    }

    /// Returns the local address of this listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        // Send close command to clean up the listener in the child
        let _ = self.tunnel.close_socket(self.id);
    }
}
