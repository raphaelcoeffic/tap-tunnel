//! Async socket types backed by smoltcp.
//!
//! These types provide a familiar async socket API (similar to tokio::net)
//! but backed by the smoltcp userspace TCP/IP stack.

use crate::CommandSender;
use crate::stack::{StackCommand, TcpChannels, UdpChannels};
use smoltcp::iface::SocketHandle;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

/// A TCP stream connected to a remote endpoint.
///
/// This provides an async read/write interface similar to `tokio::net::TcpStream`,
/// but backed by smoltcp running as an async task.
pub struct TcpStream {
    handle: SocketHandle,
    commands: CommandSender,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_notify: Arc<Notify>,
    read_rx: mpsc::Receiver<Vec<u8>>,
    /// Buffered data from a previous read that didn't fit in the caller's buffer.
    read_buf: Vec<u8>,
}

impl TcpStream {
    /// Create a TcpStream from channels (new channel-based API).
    pub(crate) fn from_channels(
        handle: SocketHandle,
        commands: CommandSender,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        channels: TcpChannels,
    ) -> Self {
        Self {
            handle,
            commands,
            local_addr,
            peer_addr,
            write_tx: channels.write_tx,
            write_notify: channels.write_notify,
            read_rx: channels.read_rx,
            read_buf: Vec::new(),
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
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Serve from internal buffer first
        if !self.read_buf.is_empty() {
            let len = self.read_buf.len().min(buf.len());
            buf[..len].copy_from_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return Ok(len);
        }

        match self.read_rx.recv().await {
            Some(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                Ok(len)
            }
            None => Ok(0), // EOF
        }
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx.send(buf.to_vec()).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone")
        })?;
        // Notify stack that there's data to send
        self.write_notify.notify_one();
        Ok(buf.len())
    }

    /// Write all data to the stream.
    pub async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).await?;
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

// AsyncRead/AsyncWrite implementations for TcpStream
impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve from internal buffer first
        if !self.read_buf.is_empty() {
            let len = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.read_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Use try_send for non-blocking write
        match self.write_tx.try_send(buf.to_vec()) {
            Ok(()) => {
                self.write_notify.notify_one();
                Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full - return WouldBlock to indicate we can't write yet
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "channel full",
                )))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone"),
            )),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // Data is pushed immediately
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
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
        use std::mem::ManuallyDrop;

        // Wrap self in ManuallyDrop to prevent drop from running
        let this = ManuallyDrop::new(self);

        let inner = Arc::new(TcpStreamInner {
            handle: this.handle,
            commands: this.commands.clone(),
            local_addr: this.local_addr,
            peer_addr: this.peer_addr,
        });

        // Safety: we're taking ownership of the fields and won't drop `this`
        let read_rx = unsafe { std::ptr::read(&this.read_rx) };
        let read_buf = unsafe { std::ptr::read(&this.read_buf) };
        let write_tx = unsafe { std::ptr::read(&this.write_tx) };
        let write_notify = unsafe { std::ptr::read(&this.write_notify) };

        let read_half = OwnedReadHalf {
            inner: Arc::clone(&inner),
            read_rx,
            read_buf,
        };

        let write_half = OwnedWriteHalf {
            inner,
            write_tx,
            write_notify,
        };

        (read_half, write_half)
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
    read_rx: mpsc::Receiver<Vec<u8>>,
    /// Buffered data from a previous read that didn't fit in the caller's buffer.
    read_buf: Vec<u8>,
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
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Serve from internal buffer first
        if !self.read_buf.is_empty() {
            let len = self.read_buf.len().min(buf.len());
            buf[..len].copy_from_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return Ok(len);
        }

        match self.read_rx.recv().await {
            Some(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                Ok(len)
            }
            None => Ok(0), // EOF
        }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve from internal buffer first
        if !self.read_buf.is_empty() {
            let len = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.read_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
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

/// The write half of a TCP stream after calling [`TcpStream::into_split`].
pub struct OwnedWriteHalf {
    inner: Arc<TcpStreamInner>,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_notify: Arc<Notify>,
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
        self.write_tx.send(buf.to_vec()).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone")
        })?;
        self.write_notify.notify_one();
        Ok(buf.len())
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

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Use try_send for non-blocking write
        match self.write_tx.try_send(buf.to_vec()) {
            Ok(()) => {
                self.write_notify.notify_one();
                Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full - return WouldBlock to indicate we can't write yet
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "channel full",
                )))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone"),
            )),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.close();
        Poll::Ready(Ok(()))
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

/// A UDP socket.
///
/// This provides an async send/recv interface similar to `tokio::net::UdpSocket`,
/// but backed by smoltcp running as an async task.
pub struct UdpSocket {
    handle: SocketHandle,
    commands: CommandSender,
    local_addr: SocketAddr,
    write_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    write_notify: Arc<Notify>,
    read_rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl UdpSocket {
    /// Create a UdpSocket from channels (new channel-based API).
    pub(crate) fn from_channels(
        handle: SocketHandle,
        commands: CommandSender,
        local_addr: SocketAddr,
        channels: UdpChannels,
    ) -> Self {
        Self {
            handle,
            commands,
            local_addr,
            write_tx: channels.write_tx,
            write_notify: channels.write_notify,
            read_rx: tokio::sync::Mutex::new(channels.read_rx),
        }
    }

    /// Returns the local address this socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send data to the specified address.
    pub async fn send_to(
        &self,
        buf: &[u8],
        addr: SocketAddr,
    ) -> io::Result<usize> {
        self.write_tx
            .send((buf.to_vec(), addr))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone")
            })?;
        self.write_notify.notify_one();
        Ok(buf.len())
    }

    /// Receive data and the source address.
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr)> {
        let mut read_rx = self.read_rx.lock().await;
        match read_rx.recv().await {
            Some((data, addr)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok((len, addr))
            }
            None => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))
            }
        }
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
/// but backed by smoltcp running as an async task.
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
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone")
            })?;

        let (stream_handle, local_addr, peer_addr, channels) =
            rx.await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "stack task gone")
            })??;

        Ok((
            TcpStream::from_channels(
                stream_handle,
                self.commands.clone(),
                local_addr,
                peer_addr,
                channels,
            ),
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
