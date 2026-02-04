//! Async socket types backed by smoltcp.
//!
//! These types provide a familiar async socket API (similar to tokio::net)
//! but backed by the smoltcp userspace TCP/IP stack.

use crate::CommandSender;
use crate::stack::StackCommand;
use smoltcp::iface::SocketHandle;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A TCP stream connected to a remote endpoint.
///
/// This provides an async read/write interface similar to `tokio::net::TcpStream`,
/// but backed by smoltcp running in a dedicated thread.
pub struct TcpStream {
    handle: SocketHandle,
    commands: CommandSender,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl TcpStream {
    /// Create a TcpStream from an existing socket handle.
    pub(crate) fn from_handle(
        handle: SocketHandle,
        commands: CommandSender,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            handle,
            commands,
            local_addr,
            peer_addr,
        }
    }

    /// Returns the local address this socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the remote address this socket is connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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
            .await
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
            .await
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
        // Use try_send for non-blocking close (fire-and-forget)
        let _ = self.commands.try_send(StackCommand::TcpClose {
            handle: self.handle,
        });
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Create a future for this read operation
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Try to send the command
        match self.commands.try_send(StackCommand::TcpRecv {
            handle: self.handle,
            max_len: buf.remaining(),
            response: tx,
        }) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register waker and return pending
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stack thread gone",
                )));
            }
        }

        // Poll the receiver
        let mut rx = Box::pin(rx);
        match rx.as_mut().poll(cx) {
            Poll::Ready(Ok(Ok(data))) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stack thread gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Create a future for this write operation
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Try to send the command
        match self.commands.try_send(StackCommand::TcpSend {
            handle: self.handle,
            data: buf.to_vec(),
            response: tx,
        }) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register waker and return pending
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stack thread gone",
                )));
            }
        }

        // Poll the receiver
        let mut rx = Box::pin(rx);
        match rx.as_mut().poll(cx) {
            Poll::Ready(Ok(Ok(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stack thread gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data is sent immediately to the stack, no buffering
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

/// Splits a `TcpStream` into a read half and a write half, which can be used
/// to read and write the stream concurrently.
impl TcpStream {
    /// Splits this `TcpStream` into a read half and a write half.
    ///
    /// This is useful for when you need to read and write concurrently from
    /// separate tasks. The socket will be closed when both halves are dropped.
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        let inner = Arc::new(TcpStreamInner {
            handle: self.handle,
            commands: self.commands.clone(),
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        });

        // Prevent TcpStream::drop from closing the socket
        std::mem::forget(self);

        (
            OwnedReadHalf {
                inner: Arc::clone(&inner),
            },
            OwnedWriteHalf { inner },
        )
    }
}

/// Shared inner state for split TCP stream halves.
struct TcpStreamInner {
    handle: SocketHandle,
    commands: CommandSender,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl TcpStreamInner {
    fn close(&self) {
        let _ = self.commands.try_send(StackCommand::TcpClose {
            handle: self.handle,
        });
    }
}

/// The read half of a TCP stream after calling [`TcpStream::into_split`].
pub struct OwnedReadHalf {
    inner: Arc<TcpStreamInner>,
}

impl OwnedReadHalf {
    /// Returns the local address this socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Returns the remote address this socket is connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr
    }

    /// Read data from the stream.
    ///
    /// Returns the number of bytes read, or 0 if the connection is closed.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::TcpRecv {
                handle: self.inner.handle,
                max_len: buf.len(),
                response: tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let data = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }
}

impl Drop for OwnedReadHalf {
    fn drop(&mut self) {
        // Only close the socket if this is the last reference
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.close();
        }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Create a future for this read operation
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Try to send the command
        match self.inner.commands.try_send(StackCommand::TcpRecv {
            handle: self.inner.handle,
            max_len: buf.remaining(),
            response: tx,
        }) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register waker and return pending
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stack thread gone",
                )));
            }
        }

        // Poll the receiver
        let mut rx = Box::pin(rx);
        match rx.as_mut().poll(cx) {
            Poll::Ready(Ok(Ok(data))) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stack thread gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The write half of a TCP stream after calling [`TcpStream::into_split`].
pub struct OwnedWriteHalf {
    inner: Arc<TcpStreamInner>,
}

impl OwnedWriteHalf {
    /// Returns the local address this socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Returns the remote address this socket is connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.inner
            .commands
            .send(StackCommand::TcpSend {
                handle: self.inner.handle,
                data: buf.to_vec(),
                response: tx,
            })
            .await
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
}

impl Drop for OwnedWriteHalf {
    fn drop(&mut self) {
        // Only close the socket if this is the last reference
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.close();
        }
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Create a future for this write operation
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Try to send the command
        match self.inner.commands.try_send(StackCommand::TcpSend {
            handle: self.inner.handle,
            data: buf.to_vec(),
            response: tx,
        }) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register waker and return pending
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stack thread gone",
                )));
            }
        }

        // Poll the receiver
        let mut rx = Box::pin(rx);
        match rx.as_mut().poll(cx) {
            Poll::Ready(Ok(Ok(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stack thread gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data is sent immediately to the stack, no buffering
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.close();
        Poll::Ready(Ok(()))
    }
}

/// A UDP socket.
///
/// This provides an async send/recv interface similar to `tokio::net::UdpSocket`,
/// but backed by smoltcp running in a dedicated thread.
pub struct UdpSocket {
    handle: SocketHandle,
    commands: CommandSender,
    local_addr: SocketAddr,
}

impl UdpSocket {
    /// Create a UdpSocket from an existing socket handle.
    pub(crate) fn from_handle(
        handle: SocketHandle,
        commands: CommandSender,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            handle,
            commands,
            local_addr,
        }
    }

    /// Returns the local address this socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
            .await
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
            .await
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
        // Use try_send for non-blocking close (fire-and-forget)
        let _ = self.commands.try_send(StackCommand::UdpClose {
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
    commands: CommandSender,
}

impl TcpListener {
    /// Create a TcpListener from an existing socket handle.
    pub(crate) fn from_handle(
        handle: SocketHandle,
        local_addr: SocketAddr,
        commands: CommandSender,
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
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))?;

        let (stream_handle, local_addr, peer_addr) = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stack thread gone"))??;

        Ok((
            TcpStream::from_handle(stream_handle, self.commands.clone(), local_addr, peer_addr),
            peer_addr,
        ))
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the listener.
    pub fn close(&self) {
        // Use try_send for non-blocking close (fire-and-forget)
        let _ = self.commands.try_send(StackCommand::TcpListenerClose {
            handle: self.handle,
        });
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.close();
    }
}
