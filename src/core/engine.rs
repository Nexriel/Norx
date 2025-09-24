//! Core detection engine implementation
//!
//! This module implements the main detection engine for Norx.

use crate::core::flow::{Flow, FlowDirection, FlowManager};
use crate::core::packet::NorxPacket;
use crate::rules::{Rule, RuleAction, RuleMatch, RuleSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{debug, error, info, warn};

/// Detection engine for Norx
pub struct DetectionEngine {
    /// Rule set for detection
    rule_set: Arc<Mutex<RuleSet>>,
    /// Flow manager for tracking sessions
    flow_manager: Arc<FlowManager>,
    /// Statistics
    stats: Mutex<DetectionStats>,
}

/// Detection statistics
#[derive(Debug, Default)]
pub struct DetectionStats {
    /// Number of packets processed
    pub packets_processed: usize,
    /// Number of flows tracked
    pub flows_tracked: usize,
    /// Number of alerts generated
    pub alerts_generated: usize,
    /// Number of packets dropped
    pub packets_dropped: usize,
    /// Start time
    pub start_time: SystemTime,
    /// Last update time
    pub last_update: SystemTime,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new(rule_set: Arc<Mutex<RuleSet>>, flow_timeout: u64, max_flows: usize) -> Self {
        let flow_manager: Arc<FlowManager> = Arc::new(FlowManager::new(flow_timeout, max_flows));
        let stats: Mutex<DetectionStats> = Mutex::new(DetectionStats {
            start_time: SystemTime::now(),
            last_update: SystemTime::now(),
            ..Default::default()
        });
        
        Self {
            rule_set,
            flow_manager,
            stats,
        }
    }

    /// Process a packet for detection
    pub fn process_packet(&self, packet: &NorxPacket) -> Vec<RuleMatch> {
        // Update statistics
        {
            let mut stats: std::sync::MutexGuard<'_, DetectionStats> = self.stats.lock().unwrap();
            stats.packets_processed += 1;
            stats.last_update = SystemTime::now();
        }
        
        // Get or create flow for this packet
        let flow: Arc<Mutex<Flow>> = self.flow_manager.get_or_create_flow(packet);
        let direction: FlowDirection = self.flow_manager.update_flow(&flow, packet);
        
        // Update flow statistics
        {
            let mut stats: std::sync::MutexGuard<'_, DetectionStats> = self.stats.lock().unwrap();
            stats.flows_tracked = self.flow_manager.flow_count();
        }
        
        // Apply rules to the packet
        let rule_set: std::sync::MutexGuard<'_, RuleSet> = self.rule_set.lock().unwrap();
        let matches: Vec<RuleMatch> = rule_set.apply_rules(packet, &flow, direction);
        
        // Update alert statistics
        if !matches.is_empty() {
            let mut stats: std::sync::MutexGuard<'_, DetectionStats> = self.stats.lock().unwrap();
            stats.alerts_generated += matches.len();
        }
        
        matches
    }

    /// Get current detection statistics
    pub fn get_stats(&self) -> DetectionStats {
        let stats: std::sync::MutexGuard<'_, DetectionStats> = self.stats.lock().unwrap();
        stats.clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats: std::sync::MutexGuard<'_, DetectionStats> = self.stats.lock().unwrap();
        *stats = DetectionStats {
            start_time: SystemTime::now(),
            last_update: SystemTime::now(),
            ..Default::default()
        };
    }

    /// Get the flow manager
    pub fn flow_manager(&self) -> Arc<FlowManager> {
        Arc::clone(&self.flow_manager)
    }
}