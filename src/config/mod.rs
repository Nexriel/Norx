//! Configuration module for Norx
//!
//! This module handles loading and validating configuration from files and command line arguments.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

/// Main configuration structure for Norx
#[derive(Debug, Serialize, Deserialize)]
pub struct NorxConfig {
    pub general: GeneralConfig,
    pub capture: CaptureConfig,
    pub detection: DetectionConfig,
    pub logging: LoggingConfig,
}

/// General configuration options
#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub daemon: bool,
    pub threads: usize,
    pub rules_path: String,
}

/// Packet capture configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub pcap_file: Option<String>,
    pub bpf_filter: Option<String>,
    pub promiscuous: bool,
    pub buffer_size: usize,
}

/// Detection engine configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub enabled: bool,
    pub rule_files: Vec<String>,
    pub preprocessors: Vec<String>,
    pub max_pattern_size: usize,
    pub flow_timeout: u64,
}

/// Logging and alerting configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_file: Option<String>,
    pub alert_file: Option<String>,
    pub syslog: bool,
    pub stats_interval: u64,
}

impl Default for NorxConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                daemon: false,
                threads: num_cpus::get(),
                rules_path: "rules".to_string(),
            },
            capture: CaptureConfig {
                interface: None,
                pcap_file: None,
                bpf_filter: None,
                promiscuous: true,
                buffer_size: 65536,
            },
            detection: DetectionConfig {
                enabled: true,
                rule_files: vec!["default.rules".to_string()],
                preprocessors: vec!["stream".to_string(), "http".to_string()],
                max_pattern_size: 1024,
                flow_timeout: 60,
            },
            logging: LoggingConfig {
                log_level: "info".to_string(),
                log_file: None,
                alert_file: Some("alerts.log".to_string()),
                syslog: false,
                stats_interval: 300,
            },
        }
    }
}

impl NorxConfig {
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let config_str = std::fs::read_to_string(path)?;
        let config: NorxConfig = toml::from_str(&config_str)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate general config
        if self.general.threads == 0 {
            return Err(ConfigError::ValidationError(
                "Number of threads must be greater than 0".to_string(),
            ));
        }

        // Validate capture config
        if self.capture.interface.is_none() && self.capture.pcap_file.is_none() {
            return Err(ConfigError::ValidationError(
                "Either interface or pcap_file must be specified".to_string(),
            ));
        }

        // Validate detection config
        if self.detection.enabled && self.detection.rule_files.is_empty() {
            return Err(ConfigError::ValidationError(
                "No rule files specified for detection".to_string(),
            ));
        }

        Ok(())
    }
}