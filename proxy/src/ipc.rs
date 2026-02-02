use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// Create a listening SEQPACKET socket at the given path.
///
/// The socket is bound to the given path and set to listen for incoming connections.
pub fn create_seqpacket_listener(path: &Path) -> io::Result<OwnedFd> {
    // Create SEQPACKET socket
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Remove existing socket file if present
    let _ = std::fs::remove_file(path);

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
        std::slice::from_raw_parts(path_bytes.as_ptr() as *const i8, path_bytes.len())
    });

    // Bind
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Listen with backlog of 1 (only one client expected)
    let ret = unsafe { libc::listen(fd.as_raw_fd(), 1) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

/// Accept a connection on a SEQPACKET listener.
///
/// Blocks until a client connects. Returns the connected socket FD.
pub fn accept_seqpacket(listener: &OwnedFd) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
