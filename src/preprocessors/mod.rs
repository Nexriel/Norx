//! Preprocessors module for Norx
//!
//! This module contains preprocessors for traffic analysis and protocol normalization.

pub mod stream;

use crate::core::packet::NorxPacket;
use crate::core::flow::{Flow, FlowDirection};
use std::sync::Arc;

/// Preprocessor trait for traffic analysis
pub trait Preprocessor: Send + Sync {
    /// Get the name of the preprocessor
    fn name(&self) -> &'static str;
    
    /// Check if this preprocessor can handle the given packet
    fn can_process(&self, packet: &NorxPacket) -> bool;
    
    /// Process a packet
    fn process_packet(&self, packet: &NorxPacket, flow: &Arc<std::sync::Mutex<Flow>>, direction: FlowDirection) -> PreprocessorResult;
    
    /// Reset the preprocessor state
    fn reset(&self);
}

/// Result of preprocessor processing
#[derive(Debug, Clone)]
pub struct PreprocessorResult {
    /// Preprocessor name
    pub preprocessor: String,
    /// Whether the packet was modified
    pub modified: bool,
    /// Whether the packet should be dropped
    pub drop: bool,
    /// Extracted data or metadata
    pub data: Option<Vec<u8>>,
    /// Additional information
    pub info: Option<String>,
}

impl PreprocessorResult {
    /// Create a new preprocessor result
    pub fn new(preprocessor: &str) -> Self {
        Self {
            preprocessor: preprocessor.to_string(),
            modified: false,
            drop: false,
            data: None,
            info: None,
        }
    }
    
    /// Set the modified flag
    pub fn modified(mut self, modified: bool) -> Self {
        self.modified = modified;
        self
    }
    
    /// Set the drop flag
    pub fn drop(mut self, drop: bool) -> Self {
        self.drop = drop;
        self
    }
    
    /// Set the data
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
    
    /// Set the info
    pub fn info(mut self, info: String) -> Self {
        self.info = Some(info);
        self
    }
}

/// Preprocessor registry for managing preprocessors
pub struct PreprocessorRegistry {
    /// Registered preprocessors
    preprocessors: Vec<Arc<dyn Preprocessor>>,
}

impl PreprocessorRegistry {
    /// Create a new preprocessor registry
    pub fn new() -> Self {
        Self {
            preprocessors: Vec::new(),
        }
    }
    
    /// Register a preprocessor
    pub fn register(&mut self, preprocessor: Arc<dyn Preprocessor>) {
        self.preprocessors.push(preprocessor);
    }
    
    /// Process a packet with all registered preprocessors
    pub fn process_packet(&self, packet: &NorxPacket, flow: &Arc<std::sync::Mutex<Flow>>, direction: FlowDirection) -> Vec<PreprocessorResult> {
        let mut results: Vec<PreprocessorResult> = Vec::new();
        
        for preprocessor in &self.preprocessors {
            if preprocessor.can_process(packet) {
                let result: PreprocessorResult = preprocessor.process_packet(packet, flow, direction);
                results.push(result);
            }
        }
        
        results
    }
    
    /// Get a preprocessor by name
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Preprocessor>> {
        self.preprocessors.iter()
            .find(|p: &&Arc<dyn Preprocessor>| p.name() == name)
            .cloned()
    }
    
    /// Get all registered preprocessors
    pub fn get_all(&self) -> &[Arc<dyn Preprocessor>] {
        &self.preprocessors
    }
    
    /// Reset all preprocessors
    pub fn reset_all(&self) {
        for preprocessor in &self.preprocessors {
            preprocessor.reset();
        }
    }
}