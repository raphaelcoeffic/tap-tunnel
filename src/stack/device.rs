//! smoltcp Device implementation that bridges to the TAP proxy via channels.

use log::{trace, warn};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, Ipv4Packet,
};
use tokio::sync::mpsc::{Receiver, Sender, error::TryRecvError};

/// smoltcp device that communicates with the TAP proxy via channels.
///
/// Frames received from the proxy are queued in `rx`, and frames to transmit
/// are sent via `tx`.
pub struct ProxyDevice {
    rx: Receiver<Vec<u8>>,
    tx: Sender<Vec<u8>>,
    mtu: usize,
}

impl ProxyDevice {
    /// Create a new ProxyDevice with the given channels and MTU.
    pub fn new(rx: Receiver<Vec<u8>>, tx: Sender<Vec<u8>>, mtu: usize) -> Self {
        Self { rx, tx, mtu }
    }
}

impl Device for ProxyDevice {
    type RxToken<'a> = ProxyRxToken;
    type TxToken<'a> = ProxyTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.rx.try_recv() {
            Ok(frame) => {
                log_frame("RX", &frame);
                Some((ProxyRxToken { frame }, ProxyTxToken { tx: &self.tx }))
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                warn!("device rx channel disconnected");
                None
            }
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(ProxyTxToken { tx: &self.tx })
    }
}

/// RxToken for receiving a frame from the proxy.
pub struct ProxyRxToken {
    frame: Vec<u8>,
}

impl RxToken for ProxyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

/// TxToken for transmitting a frame to the proxy.
pub struct ProxyTxToken<'a> {
    tx: &'a Sender<Vec<u8>>,
}

impl<'a> TxToken for ProxyTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        log_frame("TX", &buffer);

        // Best effort send - if channel is full/disconnected, drop the frame
        if let Err(e) = self.tx.try_send(buffer) {
            warn!("failed to send frame to proxy: {:?}", e);
        }
        result
    }
}

/// Log an Ethernet frame at trace level with parsed details.
fn log_frame(direction: &str, frame: &[u8]) {
    if !log::log_enabled!(log::Level::Trace) {
        return;
    }

    if let Ok(eth) = EthernetFrame::new_checked(frame) {
        match eth.ethertype() {
            EthernetProtocol::Ipv4 => {
                if let Ok(ip) = Ipv4Packet::new_checked(eth.payload()) {
                    trace!(
                        "{} {} bytes: IPv4 {} -> {} proto={:?}",
                        direction,
                        frame.len(),
                        ip.src_addr(),
                        ip.dst_addr(),
                        ip.next_header()
                    );
                } else {
                    trace!("{} {} bytes: IPv4 (malformed)", direction, frame.len());
                }
            }
            EthernetProtocol::Arp => {
                if let Ok(arp) = ArpPacket::new_checked(eth.payload())
                    && let Ok(arp) = ArpRepr::parse(&arp)
                {
                    if let ArpRepr::EthernetIpv4 {
                        operation,
                        source_protocol_addr,
                        target_protocol_addr,
                        ..
                    } = arp
                    {
                        trace!(
                            "{} {} bytes: ARP {} -> {} {}",
                            direction,
                            frame.len(),
                            source_protocol_addr,
                            target_protocol_addr,
                            arp_op_str(operation)
                        );
                    }
                } else {
                    trace!("{} {} bytes: ARP (malformed)", direction, frame.len());
                }
            }
            EthernetProtocol::Ipv6 => {
                trace!("{} {} bytes: IPv6", direction, frame.len());
            }
            other => {
                trace!("{} {} bytes: ethertype={:?}", direction, frame.len(), other);
            }
        }
    } else {
        trace!("{} {} bytes: (invalid frame)", direction, frame.len());
    }
}

fn arp_op_str(operation: ArpOperation) -> &'static str {
    match operation {
        ArpOperation::Request => "Request",
        ArpOperation::Reply => "Reply",
        _ => "Unknown",
    }
}
