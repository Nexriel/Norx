//! Packet handling module
//!
//! This module defines the packet structure and functions for packet processing.

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

/// Protocol types supported by Norx
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    Unknown(u8),
}

impl From<IpNextHeaderProtocol> for Protocol {
    fn from(protocol: IpNextHeaderProtocol) -> Self {
        match protocol {
            IpNextHeaderProtocols::Tcp => Protocol::TCP,
            IpNextHeaderProtocols::Udp => Protocol::UDP,
            IpNextHeaderProtocols::Icmp => Protocol::ICMP,
            IpNextHeaderProtocols::Icmpv6 => Protocol::ICMPv6,
            _ => Protocol::Unknown(protocol.0),
        }
    }
}

/// Represents a network packet with metadata
#[derive(Debug, Clone)]
pub struct NorxPacket {
    /// Raw packet data
    pub data: Vec<u8>,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port (for TCP/UDP)
    pub src_port: Option<u16>,
    /// Destination port (for TCP/UDP)
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: Protocol,
    /// Timestamp when the packet was captured
    pub timestamp: SystemTime,
    /// Packet length
    pub length: usize,
    /// TCP flags (if applicable)
    pub tcp_flags: Option<u8>,
}

impl NorxPacket {
    /// Create a new packet from raw Ethernet frame data
    pub fn from_ethernet_frame(data: &[u8], timestamp: SystemTime) -> Option<Self> {
        if data.len() < 14 {
            return None; // Too small to be an Ethernet frame
        }

        let ethernet: EthernetPacket<'_> = EthernetPacket::new(data)?;
        
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4: Ipv4Packet<'_> = Ipv4Packet::new(ethernet.payload())?;
                let src_ip: IpAddr = IpAddr::V4(Ipv4Addr::from(ipv4.get_source()));
                let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::from(ipv4.get_destination()));
                let protocol: Protocol = Protocol::from(ipv4.get_next_level_protocol());
                
                let (src_port, dst_port, tcp_flags) = match protocol {
                    Protocol::TCP => {
                        let tcp: TcpPacket<'_> = TcpPacket::new(ipv4.payload())?;
                        (Some(tcp.get_source()), Some(tcp.get_destination()), Some(tcp.get_flags()))
                    },
                    Protocol::UDP => {
                        let udp: UdpPacket<'_> = UdpPacket::new(ipv4.payload())?;
                        (Some(udp.get_source()), Some(udp.get_destination()), None)
                    },
                    _ => (None, None, None),
                };
                
                Some(Self {
                    data: data.to_vec(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    timestamp,
                    length: data.len(),
                    tcp_flags,
                })
            },
            EtherTypes::Ipv6 => {
                let ipv6: Ipv6Packet<'_> = Ipv6Packet::new(ethernet.payload())?;
                let src_ip: IpAddr = IpAddr::V6(Ipv6Addr::from(ipv6.get_source()));
                let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::from(ipv6.get_destination()));
                let protocol: Protocol = Protocol::from(ipv6.get_next_header());
                
                let (src_port, dst_port, tcp_flags) = match protocol {
                    Protocol::TCP => {
                        let tcp: TcpPacket<'_> = TcpPacket::new(ipv6.payload())?;
                        (Some(tcp.get_source()), Some(tcp.get_destination()), Some(tcp.get_flags()))
                    },
                    Protocol::UDP => {
                        let udp: UdpPacket<'_> = UdpPacket::new(ipv6.payload())?;
                        (Some(udp.get_source()), Some(udp.get_destination()), None)
                    },
                    _ => (None, None, None),
                };
                
                Some(Self {
                    data: data.to_vec(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    timestamp,
                    length: data.len(),
                    tcp_flags,
                })
            },
            _ => None, // Unsupported EtherType
        }
    }

    /// Get a tuple of (source IP, source port, destination IP, destination port) for flow tracking
    pub fn flow_tuple(&self) -> (IpAddr, Option<u16>, IpAddr, Option<u16>) {
        (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }

    /// Create a NorxPacket from a pcap packet
    pub fn from_packet(packet: pcap::Packet) -> Self {
        // Extract the raw data from the packet
        let data = packet.data.to_vec();
        
        // Extract timestamp from the packet header
        let timestamp = SystemTime::UNIX_EPOCH + Duration::new(
            packet.header.ts.tv_sec as u64,
            packet.header.ts.tv_usec as u32 * 1000
        );
        
        // Try to parse as an Ethernet frame
        if let Some(norx_packet) = Self::from_ethernet_frame(&data, timestamp) {
            return norx_packet;
        }
        
        // Fallback to a minimal packet with unknown protocol
        Self {
            data,
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: None,
            dst_port: None,
            protocol: Protocol::Unknown(0),
            timestamp,
            length: data.len(),
            tcp_flags: None,
        }
    }
    
    /// Get the payload of the packet (application layer data)
    pub fn payload(&self) -> Option<&[u8]> {
        // This is a simplified implementation
        // A real implementation would need to parse the packet more carefully
        let ethernet: EthernetPacket<'_> = EthernetPacket::new(&self.data)?;
        
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4: Ipv4Packet<'_> = Ipv4Packet::new(ethernet.payload())?;
                
                match self.protocol {
                    Protocol::TCP => {
                        let tcp: TcpPacket<'_> = TcpPacket::new(ipv4.payload())?;
                        Some(tcp.payload())
                    },
                    Protocol::UDP => {
                        let udp: UdpPacket<'_> = UdpPacket::new(ipv4.payload())?;
                        Some(udp.payload())
                    },
                    _ => Some(ipv4.payload()),
                }
            },
            EtherTypes::Ipv6 => {
                let ipv6: Ipv6Packet<'_> = Ipv6Packet::new(ethernet.payload())?;
                
                match self.protocol {
                    Protocol::TCP => {
                        let tcp: TcpPacket<'_> = TcpPacket::new(ipv6.payload())?;
                        Some(tcp.payload())
                    },
                    Protocol::UDP => {
                        let udp: UdpPacket<'_> = UdpPacket::new(ipv6.payload())?;
                        Some(udp.payload())
                    },
                    _ => Some(ipv6.payload()),
                }
            },
            _ => None,
        }
    }
}