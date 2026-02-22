use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// Size of the IPC socket send/receive buffers in bytes.
///
/// Large buffers prevent backpressure from propagating to the data path
/// under heavy bidirectional load. 2MB accommodates ~9000 Ethernet frames.
const IPC_SOCKET_BUFFER_SIZE: i32 = 2 * 1024 * 1024;

/// Set socket buffer sizes for high-throughput IPC.
fn set_socket_buffers(fd: &OwnedFd) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        let ret = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                opt,
                &IPC_SOCKET_BUFFER_SIZE as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Create a Unix socketpair for IPC between parent and child.
///
/// Returns (parent_fd, child_fd). Uses SOCK_STREAM with length-prefix
/// framing for high-throughput buffered I/O.
pub fn create_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];

    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let parent_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // Increase socket buffer sizes for high-throughput frame relay
    set_socket_buffers(&parent_fd)?;
    set_socket_buffers(&child_fd)?;

    Ok((parent_fd, child_fd))
}

/// Connect to a STREAM socket at the given path.
///
/// Used by the library to connect to a proxy running in socket-path mode.
pub fn connect_stream(path: &Path) -> io::Result<OwnedFd> {
    // Create STREAM socket
    let fd = unsafe {
        libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Build sockaddr_un
    let path_bytes = path.as_os_str().as_encoded_bytes();
    if path_bytes.len() >= 108 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long (max 107 bytes)",
        ));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    addr.sun_path[..path_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(
            path_bytes.as_ptr() as *const i8,
            path_bytes.len(),
        )
    });

    // Connect
    let ret = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}
