//! Norx - A high-performance network intrusion detection and prevention system
//! 
//! This is the main entry point for the Norx application.

mod config;
mod core;
mod protocols;
mod rules;
mod utils;
mod capture;
mod preprocessors;

use anyhow::Result;
use clap::Parser;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level};

use crate::config::NorxConfig;
use crate::core::NorxEngine;
use crate::utils::logger;

/// Command line arguments for Norx
#[derive(Parser, Debug)]
#[clap(author = "Norx Team", version, about = "A high-performance network intrusion detection and prevention system")]
struct Args {
    /// Path to the configuration file
    #[clap(short, long, default_value = "config/norx.toml")]
    config: String,

    /// Path to the rules directory
    #[clap(short, long)]
    rules_path: Option<String>,

    /// Interface to capture packets from
    #[clap(short, long)]
    interface: Option<String>,

    /// PCAP file to read packets from
    #[clap(short, long)]
    pcap: Option<String>,

    /// Verbose output
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    // Load configuration
    let mut config: NorxConfig = if Path::new(&args.config).exists() {
        info!("Loading configuration from {}", args.config);
        match NorxConfig::from_file(&args.config) {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to load configuration: {}", e);
                NorxConfig::default()
            }
        }
    } else {
        warn!("Configuration file not found, using default configuration");
        NorxConfig::default()
    };

    // Override configuration with command line arguments
    if let Some(rules_path) = args.rules_path {
        config.general.rules_path = rules_path;
    }

    if let Some(interface) = args.interface {
        config.capture.interface = Some(interface);
    }

    if let Some(pcap) = args.pcap {
        config.capture.pcap_file = Some(pcap);
    }

    // Initialize logging with configuration
    let log_level_str: Level = config.logging.log_level.parse::<Level>().unwrap_or(log_level);
    logger::init_logging(log_level_str, config.logging.log_file.as_deref());

    info!("Starting Norx - Network Intrusion Detection System");
    info!("Rules path: {}", config.general.rules_path);

    // Create and initialize the Norx engine
    let mut engine: NorxEngine = NorxEngine::new(config);
    engine.init().await?;

    // Start the engine
    engine.start().await?;

    info!("Norx started successfully");

    // Wait for Ctrl+C
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let tx: Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>> = Arc::new(RwLock::new(Some(tx)));

    ctrlc::set_handler(move || {
        let tx: Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>> = Arc::clone(&tx);
        tokio::spawn(async move {
            if let Some(tx) = tx.write().await.take() {
                let _ = tx.send(());
            }
        });
    })
    .expect("Error setting Ctrl-C handler");

    // Wait for shutdown signal
    let _ = rx.await;
    info!("Shutting down...");

    // Stop the engine
    engine.stop().await?;

    info!("Norx stopped successfully");
    Ok(())
}
