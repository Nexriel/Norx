//! Core engine module for Norx
//!
//! This module contains the core engine logic for packet handling, flow tracking, and detection.

pub mod engine;
pub mod flow;
pub mod packet;

use crate::config::NorxConfig;
use crate::rules::RuleSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The main Norx engine that coordinates all components
pub struct NorxEngine {
    config: Arc<NorxConfig>,
    rule_set: Arc<RwLock<RuleSet>>,
    // Other components will be added here
}

impl NorxEngine {
    /// Create a new Norx engine with the given configuration
    pub fn new(config: NorxConfig) -> Self {
        let config: Arc<NorxConfig> = Arc::new(config);
        let rule_set: Arc<RwLock<RuleSet>> = Arc::new(RwLock::new(RuleSet::new()));
        
        Self {
            config,
            rule_set,
        }
    }

    /// Initialize the engine and all its components
    pub async fn init(&mut self) -> anyhow::Result<()> {
        // TODO: Initialize all components
        // TODO: Load rules
        // TODO: Initialize preprocessors
        // TODO: Initialize detection engine
        Ok(())
    }

    /// Start the engine
    pub async fn start(&self) -> anyhow::Result<()> {
        // TODO: Start packet capture
        // TODO: Start detection engine
        // TODO: Start preprocessors
        Ok(())
    }

    /// Stop the engine
    pub async fn stop(&self) -> anyhow::Result<()> {
        // TODO: Stop all components
        Ok(())
    }

    /// Reload rules
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        // TODO: Reload rules without stopping the engine
        Ok(())
    }
}