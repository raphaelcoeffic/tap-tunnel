use nix::sched::{setns, CloneFlags};
use std::fs::File;
use std::io;
use std::os::fd::AsFd;

/// Join the user and network namespaces of the given PID.
///
/// This first joins the user namespace (which grants capabilities within
/// that namespace), then joins the network namespace (which is now allowed
/// due to the capabilities from the user namespace).
pub fn join_namespace(pid: u32) -> io::Result<()> {
    // Join user namespace first - this grants us capabilities in that namespace
    let user_ns_path = format!("/proc/{}/ns/user", pid);
    let user_ns_file = File::open(&user_ns_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open user namespace {}: {}", user_ns_path, e),
        )
    })?;

    setns(user_ns_file.as_fd(), CloneFlags::CLONE_NEWUSER).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("failed to join user namespace: {}", e),
        )
    })?;

    // Now join network namespace - allowed because we have caps in the user ns
    let net_ns_path = format!("/proc/{}/ns/net", pid);
    let net_ns_file = File::open(&net_ns_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open network namespace {}: {}", net_ns_path, e),
        )
    })?;

    setns(net_ns_file.as_fd(), CloneFlags::CLONE_NEWNET).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("failed to join network namespace: {}", e),
        )
    })?;

    Ok(())
}
