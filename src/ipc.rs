use std::io;
use std::path::Path;

/// Create a Unix socketpair for IPC between parent and child.
///
/// Returns (parent_fd, child_fd). Uses SOCK_STREAM with length-prefixed
/// framing to preserve message boundaries.
#[cfg(target_os = "linux")]
pub fn create_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

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

    Ok((parent_fd, child_fd))
}

/// Connect to a STREAM socket at the given path.
///
/// Used by the library to connect to a proxy running in socket-path mode.
/// Uses `std::os::unix::net::UnixStream` for cross-platform compatibility.
pub fn connect_stream(path: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(path)
}
