//! Protocol for communication between library and proxy.
//!
//! All messages are prefixed with a 1-byte type:
//! - 0x00: Control message (JSON payload)
//! - 0x01: Ethernet frame (raw bytes)

use serde::{Deserialize, Serialize};
use std::io;
use std::net::Ipv4Addr;

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
    pub tap_ip: Ipv4Addr,
    /// MAC address of the TAP interface.
    pub tap_mac: [u8; 6],
    /// Subnet prefix length.
    pub prefix_len: u8,
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

/// Compute the default client IP from the TAP IP (tap_ip + 1).
pub fn default_client_ip(tap_ip: Ipv4Addr) -> Ipv4Addr {
    let octets = tap_ip.octets();
    let ip_u32 = u32::from_be_bytes(octets);
    Ipv4Addr::from(ip_u32 + 1)
}

/// Validate that an IP is in the same subnet as the TAP IP.
pub fn validate_ip_in_subnet(ip: Ipv4Addr, tap_ip: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };

    let ip_u32 = u32::from_be_bytes(ip.octets());
    let tap_u32 = u32::from_be_bytes(tap_ip.octets());

    (ip_u32 & mask) == (tap_u32 & mask)
}

impl std::fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tap_ip={}, tap_mac={}, prefix_len={}",
            self.tap_ip,
            PrettyHwAddr(&self.tap_mac),
            self.prefix_len
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
    fn test_default_client_ip() {
        assert_eq!(
            default_client_ip(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 2)
        );
    }

    #[test]
    fn test_validate_ip_in_subnet() {
        let tap_ip = Ipv4Addr::new(10, 0, 0, 1);
        assert!(validate_ip_in_subnet(
            Ipv4Addr::new(10, 0, 0, 5),
            tap_ip,
            24
        ));
        assert!(!validate_ip_in_subnet(
            Ipv4Addr::new(10, 0, 1, 5),
            tap_ip,
            24
        ));
    }
}
