//! Logging utilities for Norx
//!
//! This module provides logging functionality for the Norx IDS.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Custom event formatter for Norx logs
pub struct NorxFormatter;

impl<S, N> FormatEvent<S, N> for NorxFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        // Format timestamp
        let now = chrono::Local::now();
        write!(writer, "[{} ", now.format("%Y-%m-%d %H:%M:%S%.3f"))?;
        
        // Format level
        let level = *event.metadata().level();
        match level {
            Level::TRACE => write!(writer, "TRACE")?,
            Level::DEBUG => write!(writer, "DEBUG")?,
            Level::INFO => write!(writer, "INFO ")?,
            Level::WARN => write!(writer, "WARN ")?,
            Level::ERROR => write!(writer, "ERROR")?,
        }
        write!(writer, "] ")?;
        
        // Format module path
        if let Some(module_path) = event.metadata().module_path() {
            write!(writer, "[{}] ", module_path)?;
        }
        
        // Format fields
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        
        writeln!(writer)
    }
}

/// File logger that writes to a specified file
pub struct FileLogger {
    file: Mutex<Option<std::fs::File>>,
}

impl FileLogger {
    /// Create a new file logger
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Self {
        let file = if let Some(path) = path {
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                Ok(file) => Some(file),
                Err(e) => {
                    eprintln!("Failed to open log file: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        Self {
            file: Mutex::new(file),
        }
    }
    
    /// Write a message to the log file
    pub fn write(&self, message: &str) -> io::Result<()> {
        if let Some(file) = &mut *self.file.lock().unwrap() {
            writeln!(file, "{}", message)?;
            file.flush()
        } else {
            Ok(())
        }
    }
}

/// Initialize the logging system
pub fn init_logging(log_level: Level, log_file: Option<&str>) {
    let file_logger: FileLogger = FileLogger::new(log_file.map(Path::new));
    
    let subscriber: tracing_subscriber::FmtSubscriber<tracing_subscriber::fmt::format::DefaultFields, NorxFormatter> = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .event_format(NorxFormatter)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default subscriber");
}

/// Log an alert message
pub fn log_alert(message: &str, file_logger: &FileLogger) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let alert_message: String = format!("[{}] [ALERT] {}", timestamp, message);
    
    // Log to console
    println!("{}", alert_message);
    
    // Log to file
    if let Err(e) = file_logger.write(&alert_message) {
        eprintln!("Failed to write alert to log file: {}", e);
    }
}