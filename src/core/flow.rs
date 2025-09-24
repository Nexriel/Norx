//! Flow tracking module
//!
//! This module handles flow tracking and session reassembly.

use crate::core::packet::{NorxPacket, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Unique identifier for a flow
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
}

impl FlowKey {
    /// Create a new flow key from a packet
    pub fn from_packet(packet: &NorxPacket) -> Self {
        Self {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        }
    }

    /// Create a reversed flow key (swapping source and destination)
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

/// Flow direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    /// Client to server (original direction)
    ToServer,
    /// Server to client (reply direction)
    ToClient,
}

/// Flow state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// New flow, not established yet
    New,
    /// Established flow (e.g., TCP connection established)
    Established,
    /// Flow is closing (e.g., TCP FIN received)
    Closing,
    /// Flow is closed (e.g., TCP connection closed)
    Closed,
}

/// Represents a network flow (session)
#[derive(Debug)]
pub struct Flow {
    /// Flow key
    pub key: FlowKey,
    /// Flow state
    pub state: FlowState,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Flow creation timestamp
    pub created: SystemTime,
    /// Bytes from client to server
    pub bytes_to_server: usize,
    /// Bytes from server to client
    pub bytes_to_client: usize,
    /// Packets from client to server
    pub packets_to_server: usize,
    /// Packets from server to client
    pub packets_to_client: usize,
    /// Reassembled data from client to server
    pub data_to_server: Vec<u8>,
    /// Reassembled data from server to client
    pub data_to_client: Vec<u8>,
    /// TCP sequence tracking (if applicable)
    pub tcp_state: Option<TcpState>,
}

/// TCP connection state tracking
#[derive(Debug)]
pub struct TcpState {
    /// Client sequence number
    pub client_seq: u32,
    /// Server sequence number
    pub server_seq: u32,
    /// Client window size
    pub client_window: u16,
    /// Server window size
    pub server_window: u16,
    /// TCP flags seen in the flow
    pub flags_seen: u8,
}

/// Flow manager for tracking all active flows
pub struct FlowManager {
    /// Active flows
    flows: Mutex<HashMap<FlowKey, Arc<Mutex<Flow>>>>,
    /// Flow timeout in seconds
    timeout: Duration,
    /// Maximum number of flows to track
    max_flows: usize,
}

impl FlowManager {
    /// Create a new flow manager
    pub fn new(timeout_secs: u64, max_flows: usize) -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(timeout_secs),
            max_flows,
        }
    }

    /// Get or create a flow for a packet
    pub fn get_or_create_flow(&self, packet: &NorxPacket) -> Arc<Mutex<Flow>> {
        let mut flows: std::sync::MutexGuard<'_, HashMap<FlowKey, Arc<Mutex<Flow>>>> =
            self.flows.lock().unwrap();

        // Create flow key from packet
        let key: FlowKey = FlowKey::from_packet(packet);

        // Check if flow exists
        if let Some(flow) = flows.get(&key) {
            return Arc::clone(flow);
        }

        // Check if reverse flow exists
        let reverse_key: FlowKey = key.reversed();
        if let Some(flow) = flows.get(&reverse_key) {
            return Arc::clone(flow);
        }

        // Create new flow
        let now = SystemTime::now();
        let flow = Arc::new(Mutex::new(Flow {
            key: key.clone(),
            state: FlowState::New,
            last_seen: now,
            created: now,
            bytes_to_server: 0,
            bytes_to_client: 0,
            packets_to_server: 0,
            packets_to_client: 0,
            data_to_server: Vec::new(),
            data_to_client: Vec::new(),
            tcp_state: if packet.protocol == Protocol::TCP {
                Some(TcpState {
                    client_seq: 0,
                    server_seq: 0,
                    client_window: 0,
                    server_window: 0,
                    flags_seen: 0,
                })
            } else {
                None
            },
        }));

        // Check if we need to clean up old flows
        if flows.len() >= self.max_flows {
            self.cleanup_expired_flows();
        }

        // Insert new flow
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    /// Update a flow with a new packet
    pub fn update_flow(&self, flow: &Arc<Mutex<Flow>>, packet: &NorxPacket) -> FlowDirection {
        let mut flow: std::sync::MutexGuard<'_, Flow> = flow.lock().unwrap();
        let direction: FlowDirection = if FlowKey::from_packet(packet) == flow.key {
            FlowDirection::ToServer
        } else {
            FlowDirection::ToClient
        };

        // Update flow state
        flow.last_seen = packet.timestamp;

        match direction {
            FlowDirection::ToServer => {
                flow.bytes_to_server += packet.length;
                flow.packets_to_server += 1;
                if let Some(payload) = packet.payload() {
                    flow.data_to_server.extend_from_slice(payload);
                }
            }
            FlowDirection::ToClient => {
                flow.bytes_to_client += packet.length;
                flow.packets_to_client += 1;
                if let Some(payload) = packet.payload() {
                    flow.data_to_client.extend_from_slice(payload);
                }
            }
        }

        // Update TCP state if applicable
        if packet.protocol == Protocol::TCP && packet.tcp_flags.is_some() {
            if let Some(tcp_state) = &mut flow.tcp_state {
                tcp_state.flags_seen |= packet.tcp_flags.unwrap();
            }
        }

        direction
      } 
}