//! PCAP file reader module for Norx
//!
//! This module handles reading packets from PCAP files.

use crate::capture::{CaptureError, CaptureStats, PacketSource};
use crate::core::packet::NorxPacket;
use pcap::{Capture, Offline};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::SystemTime;

/// PCAP file reader for offline packet analysis
pub struct PcapReader {
    /// PCAP file path
    file_path: String,
    /// Buffer size
    buffer_size: usize,
    /// Capture handle
    capture: Option<Capture<Offline>>,
    /// Capture thread handle
    capture_thread: Option<thread::JoinHandle<()>>,
    /// Flag to stop the capture thread
    running: Arc<Mutex<bool>>,
    /// Capture statistics
    stats: Arc<Mutex<CaptureStats>>,
}

impl PcapReader {
    /// Create a new PCAP reader
    pub fn new(file_path: &str, buffer_size: usize) -> Result<Self, CaptureError> {
        // Open the PCAP file
        let capture: Capture<Offline> = Capture::from_file(file_path)
            .map_err(|e: pcap::Error| CaptureError::PcapError(e.to_string()))?;
        
        Ok(Self {
            file_path: file_path.to_string(),
            buffer_size,
            capture: Some(capture),
            capture_thread: None,
            running: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(CaptureStats {
                start_time: Some(SystemTime::now()),
                ..Default::default()
            })),
        })
    }
}

impl PacketSource for PcapReader {
    fn start_capture(&mut self, sender: mpsc::Sender<NorxPacket>) -> Result<(), CaptureError> {
        // Check if already running
        let mut running: std::sync::MutexGuard<'_, bool> = self.running.lock().unwrap();
        if *running {
            return Err(CaptureError::CaptureError("Capture already running".to_string()));
        }
        
        // Take ownership of the capture handle
        let mut capture: Capture<Offline> = self.capture.take().ok_or_else(|| {
            CaptureError::CaptureError("Capture handle not available".to_string())
        })?;
        
        // Set the running flag
        *running = true;
        let running_clone: Arc<Mutex<bool>> = Arc::clone(&self.running);
        let stats_clone: Arc<Mutex<CaptureStats>> = Arc::clone(&self.stats);
        
        // Start the capture thread
        let handle: thread::JoinHandle<()> = thread::spawn(move || {
            while *running_clone.lock().unwrap() {
                // Try to get the next packet
                match capture.next_packet() {
                    Ok(packet) => {
                        // Update statistics
                        let mut stats: std::sync::MutexGuard<'_, CaptureStats> = stats_clone.lock().unwrap();
                        stats.packets_captured += 1;
                        stats.bytes_captured += packet.len();

                        // Send the packet to the sender
                        let norx_packet: NorxPacket = NorxPacket::from_packet(packet);
                        if let Err(_) = sender.send(norx_packet) {
                            // Receiver has been dropped, stop the capture
                            *running_clone.lock().unwrap() = false;
                            break;
                        }
                    },
                    Err(e) => {
                        // Check if we've reached the end of the file
                        if e.to_string().contains("no more packets") {
                            // End of file reached, stop the capture
                            *running_clone.lock().unwrap() = false;
                            break;
                        } else {
                            // Update statistics for dropped packets
                            let stats: &mut CaptureStats = &mut *stats_clone.lock().unwrap();
                            stats.packets_dropped += 1;
                            // No bytes_dropped field in CaptureStats, so we don't update it
                        }
                    },
                }
            }
        });

        // Store the handle
        self.capture_thread = Some(handle);

        Ok(())
    }
    
    fn stop_capture(&mut self) -> Result<(), CaptureError> {
        // Set the running flag to false
        let mut running = self.running.lock().unwrap();
        if !*running {
            return Ok(());
        }
        
        *running = false;
        
        // Join the capture thread if it exists
        if let Some(handle) = self.capture_thread.take() {
            // Ignore any errors from joining the thread
            let _ = handle.join();
        }
        
        Ok(())
    }
    
    fn get_stats(&self) -> CaptureStats {
        // Return a clone of the stats
        self.stats.lock().unwrap().clone()
    }
}