//! Stream preprocessor module for Norx
//!
//! This module handles TCP stream reassembly for protocol analysis.

use crate::core::flow::{Flow, FlowDirection, FlowState};
use crate::core::packet::{NorxPacket, Protocol};
use crate::preprocessors::{Preprocessor, PreprocessorResult};
use std::sync::{Arc, Mutex};
use tracing::{debug, trace, warn};

/// TCP stream reassembly preprocessor
pub struct StreamPreprocessor {
    /// Maximum stream size to track
    max_stream_size: usize,
}

impl StreamPreprocessor {
    /// Create a new stream preprocessor
    pub fn new(max_stream_size: usize) -> Self {
        Self {
            max_stream_size,
        }
    }
    
    /// Process a TCP packet for stream reassembly
    fn process_tcp(&self, packet: &NorxPacket, flow: &Arc<Mutex<Flow>>, direction: FlowDirection) -> PreprocessorResult {
        let mut result: PreprocessorResult = PreprocessorResult::new("stream");
        let mut flow_guard: std::sync::MutexGuard<'_, Flow> = flow.lock().unwrap();
        
        // Check for TCP flags
        if let Some(tcp_flags) = packet.tcp_flags {
            // SYN flag (0x02)
            if tcp_flags & 0x02 != 0 {
                if direction == FlowDirection::ToServer {
                    flow_guard.state = FlowState::New;
                    debug!("New TCP connection from {:?}:{:?} to {:?}:{:?}", 
                          flow_guard.key.src_ip, flow_guard.key.src_port,
                          flow_guard.key.dst_ip, flow_guard.key.dst_port);
                } else if flow_guard.state == FlowState::New {
                    flow_guard.state = FlowState::Established;
                    debug!("TCP connection established between {:?}:{:?} and {:?}:{:?}", 
                          flow_guard.key.src_ip, flow_guard.key.src_port,
                          flow_guard.key.dst_ip, flow_guard.key.dst_port);
                }
            }
            
            // FIN flag (0x01) or RST flag (0x04)
            if tcp_flags & 0x01 != 0 || tcp_flags & 0x04 != 0 {
                if flow_guard.state == FlowState::Established {
                    flow_guard.state = FlowState::Closing;
                    debug!("TCP connection closing between {:?}:{:?} and {:?}:{:?}", 
                          flow_guard.key.src_ip, flow_guard.key.src_port,
                          flow_guard.key.dst_ip, flow_guard.key.dst_port);
                } else if flow_guard.state == FlowState::Closing {
                    flow_guard.state = FlowState::Closed;
                    debug!("TCP connection closed between {:?}:{:?} and {:?}:{:?}", 
                          flow_guard.key.src_ip, flow_guard.key.src_port,
                          flow_guard.key.dst_ip, flow_guard.key.dst_port);
                }
            }
        }
        
        // Get payload data
        if let Some(payload) = packet.payload() {
            if !payload.is_empty() {
                // Add payload to the appropriate direction's data buffer
                match direction {
                    FlowDirection::ToServer => {
                        // Check if we need to truncate to avoid memory issues
                        if flow_guard.data_to_server.len() + payload.len() > self.max_stream_size {
                            warn!("TCP stream to server exceeds maximum size, truncating");
                            flow_guard.data_to_server.clear();
                        }
                        flow_guard.data_to_server.extend_from_slice(payload);
                        trace!("Added {} bytes to server stream", payload.len());
                    },
                    FlowDirection::ToClient => {
                        // Check if we need to truncate to avoid memory issues
                        if flow_guard.data_to_client.len() + payload.len() > self.max_stream_size {
                            warn!("TCP stream to client exceeds maximum size, truncating");
                            flow_guard.data_to_client.clear();
                        }
                        flow_guard.data_to_client.extend_from_slice(payload);
                        trace!("Added {} bytes to client stream", payload.len());
                    },
                }
                
                // Set the data in the result
                result = result.data(payload.to_vec());
            }
        }
        
        result
    }
}

impl Preprocessor for StreamPreprocessor {
    fn name(&self) -> &'static str {
        "stream"
    }
    
    fn can_process(&self, packet: &NorxPacket) -> bool {
        // Only process TCP packets
        packet.protocol == Protocol::TCP
    }
    
    fn process_packet(&self, packet: &NorxPacket, flow: &Arc<Mutex<Flow>>, direction: FlowDirection) -> PreprocessorResult {
        match packet.protocol {
            Protocol::TCP => self.process_tcp(packet, flow, direction),
            _ => PreprocessorResult::new("stream"),
        }
    }
    
    fn reset(&self) {
        // Nothing to reset for this preprocessor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::FlowKey;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;
    
    #[test]
    fn test_stream_preprocessor() {
        // Create a stream preprocessor
        let preprocessor: StreamPreprocessor = StreamPreprocessor::new(1024 * 1024);
        
        // Create a test packet
        let packet: NorxPacket = NorxPacket {
            data: vec![0; 100],
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: Protocol::TCP,
            timestamp: SystemTime::now(),
            length: 100,
            tcp_flags: Some(0x02), // SYN flag
        };
        
        // Create a test flow
        let flow_key: FlowKey = FlowKey::from_packet(&packet);
        let flow: Arc<Mutex<Flow>> = Arc::new(Mutex::new(Flow {
            key: flow_key,
            state: FlowState::New,
            last_seen: SystemTime::now(),
            created: SystemTime::now(),
            bytes_to_server: 0,
            bytes_to_client: 0,
            packets_to_server: 0,
            packets_to_client: 0,
            data_to_server: Vec::new(),
            data_to_client: Vec::new(),
            tcp_state: None,
        }));
        
        // Process the packet
        let result = preprocessor.process_packet(&packet, &flow, FlowDirection::ToServer);
        
        // Check the result
        assert_eq!(result.preprocessor, "stream");
        assert_eq!(flow.lock().unwrap().state, FlowState::New);
    }
}