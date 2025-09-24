//! Metrics collection utilities for Norx
//!
//! This module provides metrics collection and reporting functionality.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Performance metrics for Norx
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Start time
    pub start_time: SystemTime,
    /// Packets processed
    packets_processed: Arc<AtomicU64>,
    /// Packets dropped
    packets_dropped: Arc<AtomicU64>,
    /// Alerts generated
    alerts_generated: Arc<AtomicU64>,
    /// Flows tracked
    flows_tracked: Arc<AtomicU64>,
    /// Bytes processed
    bytes_processed: Arc<AtomicU64>,
    /// Processing time in microseconds
    processing_time_us: Arc<AtomicU64>,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMetrics {
    /// Create new performance metrics
    pub fn new() -> Self {
        Self {
            start_time: SystemTime::now(),
            packets_processed: Arc::new(AtomicU64::new(0)),
            packets_dropped: Arc::new(AtomicU64::new(0)),
            alerts_generated: Arc::new(AtomicU64::new(0)),
            flows_tracked: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            processing_time_us: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record a processed packet
    pub fn record_packet(&self, size: usize, processing_time: Duration) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed.fetch_add(size as u64, Ordering::Relaxed);
        self.processing_time_us.fetch_add(processing_time.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a dropped packet
    pub fn record_dropped_packet(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an alert
    pub fn record_alert(&self) {
        self.alerts_generated.fetch_add(1, Ordering::Relaxed);
    }

    /// Update flow count
    pub fn update_flow_count(&self, count: u64) {
        self.flows_tracked.store(count, Ordering::Relaxed);
    }

    /// Get packets processed
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    /// Get packets dropped
    pub fn packets_dropped(&self) -> u64 {
        self.packets_dropped.load(Ordering::Relaxed)
    }

    /// Get alerts generated
    pub fn alerts_generated(&self) -> u64 {
        self.alerts_generated.load(Ordering::Relaxed)
    }

    /// Get flows tracked
    pub fn flows_tracked(&self) -> u64 {
        self.flows_tracked.load(Ordering::Relaxed)
    }

    /// Get bytes processed
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    /// Get average processing time per packet in microseconds
    pub fn avg_processing_time_us(&self) -> f64 {
        let packets = self.packets_processed();
        if packets == 0 {
            return 0.0;
        }
        
        let total_time: u64 = self.processing_time_us.load(Ordering::Relaxed);
        total_time as f64 / packets as f64
    }

    /// Get packets per second
    pub fn packets_per_second(&self) -> f64 {
        let packets: u64 = self.packets_processed();
        match self.start_time.elapsed() {
            Ok(elapsed) => {
                let seconds = elapsed.as_secs_f64();
                if seconds > 0.0 {
                    packets as f64 / seconds
                } else {
                    0.0
                }
            },
            Err(_) => 0.0,
        }
    }

    /// Get bytes per second
    pub fn bytes_per_second(&self) -> f64 {
        let bytes: u64 = self.bytes_processed();
        match self.start_time.elapsed() {
            Ok(elapsed) => {
                let seconds = elapsed.as_secs_f64();
                if seconds > 0.0 {
                    bytes as f64 / seconds
                } else {
                    0.0
                }
            },
            Err(_) => 0.0,
        }
    }

    /// Reset metrics
    pub fn reset(&self) {
        self.packets_processed.store(0, Ordering::Relaxed);
        self.packets_dropped.store(0, Ordering::Relaxed);
        self.alerts_generated.store(0, Ordering::Relaxed);
        self.flows_tracked.store(0, Ordering::Relaxed);
        self.bytes_processed.store(0, Ordering::Relaxed);
        self.processing_time_us.store(0, Ordering::Relaxed);
    }

    /// Format metrics as a string
    pub fn format(&self) -> String {
        let uptime: String = match self.start_time.elapsed() {
            Ok(elapsed) => format!("{:.2}s", elapsed.as_secs_f64()),
            Err(_) => "unknown".to_string(),
        };
        
        format!(
            "Uptime: {}\n\
             Packets: {} processed, {} dropped\n\
             Alerts: {}\n\
             Flows: {}\n\
             Throughput: {:.2f} packets/sec, {:.2f} MB/sec\n\
             Avg processing time: {:.2f} µs/packet",
            uptime,
            self.packets_processed(),
            self.packets_dropped(),
            self.alerts_generated(),
            self.flows_tracked(),
            self.packets_per_second(),
            self.bytes_per_second() / (1024.0 * 1024.0),
            self.avg_processing_time_us()
        )
    }
}

/// Metric timer for measuring execution time
pub struct MetricTimer {
    /// Start time
    start: Instant,
    /// Metrics to update
    metrics: Arc<PerformanceMetrics>,
    /// Packet size
    packet_size: usize,
}

impl MetricTimer {
    /// Create a new metric timer
    pub fn new(metrics: Arc<PerformanceMetrics>, packet_size: usize) -> Self {
        Self {
            start: Instant::now(),
            metrics,
            packet_size,
        }
    }
}

impl Drop for MetricTimer {
    fn drop(&mut self) {
        let duration: Duration = self.start.elapsed();
        self.metrics.record_packet(self.packet_size, duration);
    }
}