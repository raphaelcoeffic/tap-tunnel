use std::fs::OpenOptions;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use ipnet::{Ipv4Net, Ipv6Net};
use netconfig_rs::Interface;
use netconfig_rs::sys::InterfaceExt;

/// ioctl request code for TUNSETIFF
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// ioctl request code for TUNSETSNDBUF - set the TAP device send buffer size
const TUNSETSNDBUF: libc::c_ulong = 0x400454d4;

/// ioctl request code for SIOCSIFTXQLEN - set interface TX queue length
const SIOCSIFTXQLEN: libc::c_ulong = 0x8943;

/// Structure for SIOCSIFTXQLEN ioctl
#[repr(C)]
struct IfReqTxqlen {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_qlen: libc::c_int,
    _padding: [u8; 18], // Pad to match struct ifreq size
}

/// TAP device flags
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

/// Structure for ioctl TUNSETIFF request
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22], // Pad to match struct ifreq size
}

/// Create a TAP interface with the given name.
/// Returns the file descriptor for the TAP device.
pub fn create_tap(name: &str) -> io::Result<OwnedFd> {
    // Open /dev/net/tun
    let tun_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let fd = tun_file.as_raw_fd();

    // Prepare the ifreq structure
    let mut ifr = IfReq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_flags: IFF_TAP | IFF_NO_PI,
        _padding: [0; 22],
    };

    // Copy interface name (truncate if too long)
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    // Call ioctl to create the TAP interface
    let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const IfReq) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Increase TAP device send buffer for high-throughput forwarding.
    // The default (~212KB) limits throughput under bidirectional load.
    let sndbuf: libc::c_int = 2 * 1024 * 1024; // 2MB
    let ret = unsafe {
        libc::ioctl(fd, TUNSETSNDBUF, &sndbuf as *const libc::c_int)
    };
    if ret < 0 {
        log::debug!("TUNSETSNDBUF failed (non-fatal): {}", io::Error::last_os_error());
    }

    // Prevent the file from being closed when tun_file is dropped
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    std::mem::forget(tun_file);

    Ok(owned_fd)
}

/// Set the TX queue length on a network interface.
fn set_txqueuelen(name: &str, qlen: i32) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr = IfReqTxqlen {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_qlen: qlen,
        _padding: [0; 18],
    };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    let ret = unsafe { libc::ioctl(sock, SIOCSIFTXQLEN, &ifr as *const IfReqTxqlen) };
    unsafe { libc::close(sock) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Configure a network interface: optionally add an IP address and set MTU,
/// bring it up, and return its MAC address.
pub fn configure_interface(
    name: &str,
    addr: Option<(IpAddr, u8)>,
    mtu: Option<u16>,
) -> io::Result<[u8; 6]> {
    let iface = Interface::try_from_name(name).map_err(|e| io::Error::other(e.to_string()))?;

    if let Some((ip, prefix_len)) = addr {
        let net = match ip {
            IpAddr::V4(v4) => ipnet::IpNet::V4(
                Ipv4Net::new(v4, prefix_len).map_err(|e| io::Error::other(e.to_string()))?,
            ),
            IpAddr::V6(v6) => ipnet::IpNet::V6(
                Ipv6Net::new(v6, prefix_len).map_err(|e| io::Error::other(e.to_string()))?,
            ),
        };
        iface
            .add_address(net)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    if let Some(mtu) = mtu {
        iface
            .set_mtu(mtu as u32)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    // Increase TX queue length for high-throughput forwarding.
    // The default (500) is insufficient when the kernel forwards
    // between TAP interfaces at high packet rates.
    if let Err(e) = set_txqueuelen(name, 5000) {
        log::debug!("set_txqueuelen failed (non-fatal): {}", e);
    }

    iface
        .set_up(true)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mac = iface
        .hwaddress()
        .map_err(|e| io::Error::other(e.to_string()))?;

    Ok(mac)
}
