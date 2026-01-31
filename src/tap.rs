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

/// Configure an IPv4 address on a network interface.
pub fn configure_interface_ip(
    name: &str,
    addr: std::net::Ipv4Addr,
    prefix_len: u8,
) -> io::Result<()> {
    #[repr(C)]
    struct IfReqAddr {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_addr: libc::sockaddr,
    }

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    // Helper to set name in ifreq
    let set_name = |ifr: &mut IfReqAddr, name: &str| {
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
    };

    // Set IP address
    let mut ifr_addr: IfReqAddr = unsafe { std::mem::zeroed() };
    set_name(&mut ifr_addr, name);

    let sin = &mut ifr_addr.ifr_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
        (*sin).sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
    }

    const SIOCSIFADDR: libc::c_ulong = 0x8916;
    let ret = unsafe { libc::ioctl(sock, SIOCSIFADDR, &ifr_addr as *const IfReqAddr) };
    if ret < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error());
    }

    // Set netmask
    let mut ifr_mask: IfReqAddr = unsafe { std::mem::zeroed() };
    set_name(&mut ifr_mask, name);

    let netmask = if prefix_len >= 32 {
        0xFFFFFFFFu32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };

    let sin = &mut ifr_mask.ifr_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
        (*sin).sin_addr.s_addr = netmask.to_be();
    }

    const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
    let ret = unsafe { libc::ioctl(sock, SIOCSIFNETMASK, &ifr_mask as *const IfReqAddr) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
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
