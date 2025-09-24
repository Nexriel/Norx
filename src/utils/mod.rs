//! Utilities module for Norx
//!
//! This module contains common utilities for logging, error handling, and metrics.

pub mod logger;
pub mod metrics;

use std::time::{Duration, SystemTime};

/// Format a duration as a human-readable string
pub fn format_duration(duration: Duration) -> String {
    let total_seconds: u64 = duration.as_secs();
    let hours: u64 = total_seconds / 3600;
    let minutes: u64 = (total_seconds % 3600) / 60;
    let seconds: u64 = total_seconds % 60;
    let millis: u32 = duration.subsec_millis();
    
    if hours > 0 {
        format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
    } else {
        format!("{:02}:{:02}.{:03}", minutes, seconds, millis)
    }
}

/// Format a timestamp as a human-readable string
pub fn format_timestamp(timestamp: SystemTime) -> String {
    let datetime = chrono::DateTime::<chrono::Utc>::from(timestamp);
    datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// Format a size in bytes as a human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    
    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes < TB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    }
}