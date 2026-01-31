use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

/// Create a Unix socketpair for IPC between parent and child.
///
/// Returns (parent_fd, child_fd). Uses SOCK_SEQPACKET to preserve
/// message boundaries (each IP packet is a single message).
pub fn create_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];

    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
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

// TODO: add some unit tests
//  - send a couple small frames
//  - recv and verify that packets are received frame by frame
