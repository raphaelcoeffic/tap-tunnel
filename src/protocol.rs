//! Protocol for communication between library and proxy.
//!
//! All messages are prefixed with a 1-byte type:
//! - 0x00: Control message (JSON payload)
//! - 0x01: Ethernet frame (raw bytes)

use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Size of the length prefix in bytes (4 bytes, little-endian u32).
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Maximum message size (16 MB safety limit).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Message type byte for control messages.
pub const MSG_TYPE_CONTROL: u8 = 0x00;

/// Message type byte for Ethernet frames.
pub const MSG_TYPE_FRAME: u8 = 0x01;

/// Client hello message sent at connection start.
///
/// This is currently an empty struct but allows for future extensibility
/// (e.g., version negotiation, capability flags).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientHello {
    // Empty - client manages its own IPs
}

/// Proxy configuration sent to client after handshake.
///
/// The proxy only provides its identity (TAP IP, MAC, prefix).
/// The client is responsible for picking and managing its own IPs from the subnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// IP address of the TAP interface (gateway for client).
    pub tap_ip: IpAddr,
    /// MAC address of the TAP interface.
    pub tap_mac: [u8; 6],
    /// Subnet prefix length.
    pub prefix_len: u8,
    /// IP-level MTU of the TAP interface.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_mtu() -> u16 {
    1500
}

/// Command sent from the library to the proxy over the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum ProxyCommand {
    /// Add a route to the TAP interface.
    AddRoute {
        id: u64,
        destination: IpAddr,
        prefix_len: u8,
    },
    /// Remove a route from the TAP interface.
    RemoveRoute {
        id: u64,
        destination: IpAddr,
        prefix_len: u8,
    },
}

/// Response from the proxy to a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// Request ID matching the command.
    pub id: u64,
    /// Error message, if the command failed.
    pub error: Option<String>,
}

/// Decoded message from the wire.
#[derive(Debug)]
pub enum Message {
    /// Control message with JSON payload.
    Control(Vec<u8>),
    /// Ethernet frame.
    Frame(Vec<u8>),
}

/// Encode a control message for transmission.
pub fn encode_control<T: Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let json =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut buf = Vec::with_capacity(1 + json.len());
    buf.push(MSG_TYPE_CONTROL);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode a control message from JSON bytes.
pub fn decode_control<T: for<'de> Deserialize<'de>>(data: &[u8]) -> io::Result<T> {
    serde_json::from_slice(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Encode an Ethernet frame for transmission.
pub fn encode_frame(frame: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + frame.len());
    buf.push(MSG_TYPE_FRAME);
    buf.extend_from_slice(frame);
    buf
}

/// Decode a message from the wire.
pub fn decode_message(data: &[u8]) -> io::Result<Message> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty message"));
    }

    let msg_type = data[0];
    let payload = data[1..].to_vec();

    match msg_type {
        MSG_TYPE_CONTROL => Ok(Message::Control(payload)),
        MSG_TYPE_FRAME => Ok(Message::Frame(payload)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown message type: 0x{:02x}", msg_type),
        )),
    }
}

// ============================================================================
// Length-prefixed framing for SOCK_STREAM transport
// ============================================================================

/// Write a length-prefixed message (blocking).
///
/// Wire format: `[4-byte LE length][payload]`
pub fn write_framed(writer: &mut impl io::Write, msg: &[u8]) -> io::Result<()> {
    let len = msg.len();
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            ),
        ));
    }
    writer.write_all(&(len as u32).to_le_bytes())?;
    writer.write_all(msg)?;
    Ok(())
}

/// Read a length-prefixed message (blocking).
///
/// Returns the payload bytes. Returns `UnexpectedEof` if the connection closes.
pub fn read_framed(reader: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "framed message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            ),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a length-prefixed message (async).
pub async fn write_framed_async(
    writer: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    msg: &[u8],
) -> io::Result<()> {
    let len = msg.len();
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            ),
        ));
    }
    writer.write_all(&(len as u32).to_le_bytes()).await?;
    writer.write_all(msg).await?;
    Ok(())
}

/// Read a length-prefixed message (async).
///
/// Returns the payload bytes. Returns `UnexpectedEof` if the connection closes.
pub async fn read_framed_async(
    reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "framed message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            ),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Compute the default client IP from the TAP IP (tap_ip + 1).
pub fn default_client_ip(tap_ip: IpAddr) -> IpAddr {
    match tap_ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from_be_bytes(v4.octets());
            IpAddr::V4(Ipv4Addr::from(ip_u32 + 1))
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            // Increment the last byte (simple +1 for adjacent addresses)
            for i in (0..16).rev() {
                let (val, overflow) = octets[i].overflowing_add(1);
                octets[i] = val;
                if !overflow {
                    break;
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// Validate that an IP is in the same subnet as the TAP IP.
pub fn validate_ip_in_subnet(ip: IpAddr, tap_ip: IpAddr, prefix_len: u8) -> bool {
    match (ip, tap_ip) {
        (IpAddr::V4(ip), IpAddr::V4(tap)) => {
            let mask = if prefix_len >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix_len)
            };
            let ip_u32 = u32::from_be_bytes(ip.octets());
            let tap_u32 = u32::from_be_bytes(tap.octets());
            (ip_u32 & mask) == (tap_u32 & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(tap)) => {
            let ip_bits = u128::from_be_bytes(ip.octets());
            let tap_bits = u128::from_be_bytes(tap.octets());
            let mask = if prefix_len >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (ip_bits & mask) == (tap_bits & mask)
        }
        // Different address families are never in the same subnet
        _ => false,
    }
}

impl std::fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tap_ip={}, tap_mac={}, prefix_len={}, mtu={}",
            self.tap_ip,
            PrettyHwAddr(&self.tap_mac),
            self.prefix_len,
            self.mtu
        )
    }
}

struct PrettyHwAddr<'a>(&'a [u8; 6]);

impl<'a> std::fmt::Display for PrettyHwAddr<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let _ = write!(
            f,
            "{:<02x}-{:<02x}-{:<02x}-{:<02x}-{:<02x}-{:<02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_control() {
        let hello = ClientHello::default();

        let encoded = encode_control(&hello).unwrap();
        assert_eq!(encoded[0], MSG_TYPE_CONTROL);

        let _decoded: ClientHello = decode_control(&encoded[1..]).unwrap();
        // ClientHello is now empty, so just verify it deserializes
    }

    #[test]
    fn test_encode_decode_frame() {
        let frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        let encoded = encode_frame(&frame);
        assert_eq!(encoded[0], MSG_TYPE_FRAME);
        assert_eq!(&encoded[1..], &frame[..]);

        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            Message::Frame(f) => assert_eq!(f, frame),
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn test_default_client_ip_v4() {
        assert_eq!(
            default_client_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn test_default_client_ip_v6() {
        let tap_ip: IpAddr = "fd00::1".parse().unwrap();
        let client_ip = default_client_ip(tap_ip);
        assert_eq!(client_ip, "fd00::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_validate_ip_in_subnet_v4() {
        let tap_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(validate_ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            tap_ip,
            24
        ));
        assert!(!validate_ip_in_subnet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)),
            tap_ip,
            24
        ));
    }

    #[test]
    fn test_validate_ip_in_subnet_v6() {
        let tap_ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(validate_ip_in_subnet(
            "fd00::5".parse().unwrap(),
            tap_ip,
            64
        ));
        assert!(!validate_ip_in_subnet(
            "fd01::5".parse().unwrap(),
            tap_ip,
            64
        ));
    }

    #[test]
    fn test_framed_roundtrip() {
        let msg = b"hello framed world";
        let mut buf = Vec::new();
        write_framed(&mut buf, msg).unwrap();

        // Verify wire format: 4-byte LE length + payload
        assert_eq!(buf.len(), LENGTH_PREFIX_SIZE + msg.len());
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, msg.len());

        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = read_framed(&mut cursor).unwrap();
        assert_eq!(&decoded, msg);
    }

    #[test]
    fn test_framed_empty_message() {
        let msg = b"";
        let mut buf = Vec::new();
        write_framed(&mut buf, msg).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = read_framed(&mut cursor).unwrap();
        assert_eq!(&decoded, msg);
    }

    #[test]
    fn test_framed_oversized_write_rejected() {
        let msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let mut buf = Vec::new();
        let result = write_framed(&mut buf, &msg);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_framed_oversized_read_rejected() {
        // Craft a frame header claiming a size larger than MAX_MESSAGE_SIZE
        let fake_len = (MAX_MESSAGE_SIZE as u32 + 1).to_le_bytes();
        let mut cursor = std::io::Cursor::new(fake_len.to_vec());
        let result = read_framed(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_framed_async_roundtrip() {
        let msg = b"async framed message";
        let mut buf = Vec::new();
        write_framed_async(&mut buf, msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = read_framed_async(&mut cursor).await.unwrap();
        assert_eq!(&decoded, msg);
    }

    #[test]
    fn test_validate_ip_mixed_families() {
        let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6: IpAddr = "fd00::1".parse().unwrap();
        assert!(!validate_ip_in_subnet(v6, v4, 24));
        assert!(!validate_ip_in_subnet(v4, v6, 64));
    }
}
