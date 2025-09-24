//! Protocol decoders module for Norx
//!
//! This module contains protocol-specific decoders for HTTP, DNS, TLS, and other protocols.

pub mod http;
pub mod dns;
pub mod tls;

use crate::core::packet::NorxPacket;
use std::sync::Arc;

/// Protocol decoder trait
pub trait ProtocolDecoder: Send + Sync {
    /// Protocol name
    fn name(&self) -> &'static str;
    
    /// Check if this decoder can handle the given packet
    fn can_decode(&self, packet: &NorxPacket) -> bool;
    
    /// Decode the packet
    fn decode(&self, packet: &NorxPacket) -> Option<Box<dyn ProtocolData>>;
}

/// Protocol data trait for decoded protocol information
pub trait ProtocolData: std::fmt::Debug {
    /// Get protocol name
    fn protocol_name(&self) -> &'static str;
    
    /// Get a field value by name
    fn get_field(&self, name: &str) -> Option<String>;
    
    /// Get all field names
    fn field_names(&self) -> Vec<&'static str>;
    
    /// Convert to a map of field names to values
    fn to_map(&self) -> std::collections::HashMap<&'static str, String>;
}

/// Protocol decoder registry
pub struct ProtocolDecoderRegistry {
    decoders: Vec<Arc<dyn ProtocolDecoder>>,
}

impl ProtocolDecoderRegistry {
    /// Create a new protocol decoder registry
    pub fn new() -> Self {
        Self {
            decoders: Vec::new(),
        }
    }
    
    /// Register a protocol decoder
    pub fn register(&mut self, decoder: Arc<dyn ProtocolDecoder>) {
        self.decoders.push(decoder);
    }
    
    /// Decode a packet with all registered decoders
    pub fn decode_packet(&self, packet: &NorxPacket) -> Vec<Box<dyn ProtocolData>> {
        let mut results: Vec<Box<dyn ProtocolData>> = Vec::new();
        
        for decoder in &self.decoders {
            if decoder.can_decode(packet) {
                if let Some(data) = decoder.decode(packet) {
                    results.push(data);
                }
            }
        }
        
        results
    }
    
    /// Get all registered decoders
    pub fn get_decoders(&self) -> &[Arc<dyn ProtocolDecoder>] {
        &self.decoders
    }
    
    /// Get a decoder by name
    pub fn get_decoder_by_name(&self, name: &str) -> Option<Arc<dyn ProtocolDecoder>> {
        self.decoders.iter()
            .find(|d: &&Arc<dyn ProtocolDecoder>| d.name() == name)
            .cloned()
    }
}