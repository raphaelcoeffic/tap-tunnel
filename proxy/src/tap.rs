use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// ioctl request code for TUNSETIFF
const TUNSETIFF: libc::c_ulong = 0x400454ca;

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

    // Prevent the file from being closed when tun_file is dropped
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    std::mem::forget(tun_file);

    Ok(owned_fd)
}

/// Get the MAC address of a network interface by name.
pub fn get_interface_mac(name: &str) -> io::Result<[u8; 6]> {
    #[repr(C)]
    struct IfReqHwAddr {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_hwaddr: libc::sockaddr,
    }

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr = IfReqHwAddr {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_hwaddr: unsafe { std::mem::zeroed() },
    };

    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    const SIOCGIFHWADDR: libc::c_ulong = 0x8927;
    let ret = unsafe { libc::ioctl(sock, SIOCGIFHWADDR, &ifr as *const IfReqHwAddr) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = ifr.ifr_hwaddr.sa_data[i] as u8;
    }

    Ok(mac)
}

/// Configure an IP address (IPv4 or IPv6) on a network interface.
///
/// Uses netlink RTM_NEWADDR to add the address directly, avoiding
/// a dependency on iproute2 (`ip` command).
pub fn configure_interface_ip(
    name: &str,
    addr: std::net::IpAddr,
    prefix_len: u8,
) -> io::Result<()> {
    // Netlink constants (not all available in libc crate)
    const RTM_NEWADDR: u16 = 20;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_EXCL: u16 = 0x200;
    const IFA_LOCAL: u16 = 2;
    const IFA_ADDRESS: u16 = 1;
    const NLMSG_ERROR: u16 = 2;

    // Get interface index
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }

    // Determine address family and bytes
    let (family, addr_bytes): (u8, Vec<u8>) = match addr {
        std::net::IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    };

    // rtattr: 4-byte header (2 len + 2 type) + payload, padded to 4 bytes
    let rta_len = 4u16 + addr_bytes.len() as u16;
    let rta_padded = ((rta_len as usize) + 3) & !3;

    // nlmsghdr (16) + ifaddrmsg (8) + 2 rtattrs
    let msg_len: u32 = 16 + 8 + (2 * rta_padded) as u32;

    let mut buf = vec![0u8; msg_len as usize];

    // nlmsghdr (16 bytes)
    let nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    buf[0..4].copy_from_slice(&msg_len.to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
    buf[6..8].copy_from_slice(&nlmsg_flags.to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid

    // ifaddrmsg (8 bytes) at offset 16
    buf[16] = family; // ifa_family
    buf[17] = prefix_len; // ifa_prefixlen
    buf[18] = 0; // ifa_flags
    buf[19] = 0; // ifa_scope (RT_SCOPE_UNIVERSE)
    buf[20..24].copy_from_slice(&ifindex.to_ne_bytes()); // ifa_index

    // First rtattr: IFA_ADDRESS at offset 24
    let off = 24;
    buf[off..off + 2].copy_from_slice(&rta_len.to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&IFA_ADDRESS.to_ne_bytes());
    buf[off + 4..off + 4 + addr_bytes.len()].copy_from_slice(&addr_bytes);

    // Second rtattr: IFA_LOCAL
    let off = 24 + rta_padded;
    buf[off..off + 2].copy_from_slice(&rta_len.to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&IFA_LOCAL.to_ne_bytes());
    buf[off + 4..off + 4 + addr_bytes.len()].copy_from_slice(&addr_bytes);

    // Open netlink socket
    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    // Send the message
    let sent = unsafe { libc::send(sock, buf.as_ptr() as *const _, buf.len(), 0) };
    if sent < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err);
    }

    // Read ACK response
    let mut resp = [0u8; 1024];
    let n = unsafe { libc::recv(sock, resp.as_mut_ptr() as *mut _, resp.len(), 0) };
    unsafe { libc::close(sock) };

    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // Parse response: nlmsghdr (16 bytes) + nlmsgerr (4 bytes error + 16 bytes orig header)
    let n = n as usize;
    if n < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink response too short",
        ));
    }

    let resp_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if resp_type == NLMSG_ERROR {
        let error = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
        if error < 0 {
            return Err(io::Error::from_raw_os_error(-error));
        }
        // error == 0 means ACK (success)
    }

    Ok(())
}

/// Bring a network interface up.
pub fn bring_interface_up(name: &str) -> io::Result<()> {
    #[repr(C)]
    struct IfReqFlags {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _padding: [u8; 22],
    }

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr = IfReqFlags {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_flags: 0,
        _padding: [0; 22],
    };

    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    // Get current flags
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    const IFF_UP: libc::c_short = 0x1;

    let ret = unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &ifr as *const IfReqFlags) };
    if ret < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error());
    }

    // Set IFF_UP flag
    ifr.ifr_flags |= IFF_UP;

    let ret = unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &ifr as *const IfReqFlags) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
