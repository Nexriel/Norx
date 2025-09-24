//! Packet capture module for Norx
//!
//! This module handles packet acquisition from network interfaces and PCAP files.

pub mod pcap;

use crate::core::packet::NorxPacket;
use std::sync::mpsc;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("PCAP error: {0}")]
    PcapError(String),

    #[error("Interface error: {0}")]
    InterfaceError(String),

    #[error("Capture error: {0}")]
    CaptureError(String),
}

/// Capture statistics
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    /// Number of packets captured
    pub packets_captured: usize,
    /// Number of packets dropped
    pub packets_dropped: usize,
    /// Number of bytes captured
    pub bytes_captured: usize,
    /// Start time
    pub start_time: Option<SystemTime>,
}

/// Packet source trait for different capture methods
pub trait PacketSource: Send + 'static {
    /// Start capturing packets
    fn start_capture(&mut self, sender: mpsc::Sender<NorxPacket>) -> Result<(), CaptureError>;
    
    /// Stop capturing packets
    fn stop_capture(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
    
    /// Get capture statistics
    fn get_stats(&self) -> CaptureStats {
        CaptureStats::default()
    }
    
    /// Set BPF filter
    fn set_filter(&mut self, _filter: &str) -> Result<(), CaptureError> {
        Ok(())
    }
}

/// List available network interfaces
pub fn list_interfaces() -> Result<Vec<String>, CaptureError> {
    match pcap::list_devices() {
        Ok(devices) => Ok(devices.into_iter().filter_map(|d| d.name).collect()),
        Err(e) => Err(CaptureError::InterfaceError(e.to_string())),
    }
}

/// Create a packet source from a network interface
pub fn create_interface_source(interface: &str, promiscuous: bool, buffer_size: usize) -> Result<Box<dyn PacketSource>, CaptureError> {
    // TODO: Implement interface capture
    Err(CaptureError::InterfaceError("Interface capture not implemented yet".to_string()))
}

/// Create a packet source from a PCAP file
pub fn create_pcap_source(file_path: &str, buffer_size: usize) -> Result<Box<dyn PacketSource>, CaptureError> {
    let reader: pcap::PcapReader = pcap::PcapReader::new(file_path, buffer_size)?;
    Ok(Box::new(reader))
}