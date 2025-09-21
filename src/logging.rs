//! Comprehensive logging and observability framework
//!
//! Provides structured logging with:
//! - Multiple output formats (JSON, pretty, compact)
//! - File rotation and archiving
//! - Contextual logging with span tracking
//! - Performance metrics integration
//! - Security event logging

use anyhow::{Context, Result};
use std::{
    io,
    path::PathBuf,
};
use tracing::{Level, info, warn};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};
use crate::{
    config::LoggingConfig,
    error::ScannerError,
};

/// Initialize the logging system based on configuration
pub fn init_logging() -> Result<()> {
    init_logging_with_config(&LoggingConfig::default())
}

/// Initialize logging with specific configuration
pub fn init_logging_with_config(config: &LoggingConfig) -> Result<()> {
    let env_filter = create_env_filter(&config.level)?;
    
    let registry = Registry::default().with(env_filter);
    
    match config.format.as_str() {
        "json" => {
            let console_layer = fmt::layer()
                .json()
                .with_writer(io::stderr)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true);
            
            registry.with(console_layer).init();
        }
        _ => {
            let console_layer = fmt::layer()
                .pretty()
                .with_writer(io::stderr)
                .with_target(false);
            
            registry.with(console_layer).init();
        }
    }
    
    info!("Logging system initialized with level: {}", config.level);
    Ok(())
}

/// Create environment filter from log level string
fn create_env_filter(level: &str) -> Result<EnvFilter> {
    let base_level = match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => return Err(ScannerError::config(format!("Invalid log level: {}", level)).into()),
    };
    
    // Create filter with module-specific levels
    let filter = EnvFilter::builder()
        .with_default_directive(base_level.into())
        .from_env()
        .context("Failed to create environment filter")?
        // Add specific module filtering
        .add_directive("hyper=info".parse()?)
        .add_directive("reqwest=info".parse()?)
        .add_directive("trust_dns_resolver=info".parse()?)
        .add_directive("pnet=warn".parse()?);
    
    Ok(filter)
}


/// Structured logging macros and utilities
#[macro_export]
macro_rules! log_scan_start {
    ($scan_type:expr, $target:expr) => {
        tracing::info!(
            scan_type = $scan_type,
            target = $target,
            event = "scan_start",
            "Starting {} scan of {}",
            $scan_type,
            $target
        );
    };
}

#[macro_export]
macro_rules! log_scan_complete {
    ($scan_type:expr, $target:expr, $duration:expr, $results:expr) => {
        tracing::info!(
            scan_type = $scan_type,
            target = $target,
            duration_ms = $duration.as_millis(),
            results_count = $results,
            event = "scan_complete",
            "Completed {} scan of {} in {}ms with {} results",
            $scan_type,
            $target,
            $duration.as_millis(),
            $results
        );
    };
}

#[macro_export]
macro_rules! log_port_discovery {
    ($host:expr, $port:expr, $state:expr, $service:expr) => {
        tracing::info!(
            host = %$host,
            port = $port,
            state = $state,
            service = $service,
            event = "port_discovery",
            "Discovered port {}:{} - {} ({})",
            $host,
            $port,
            $state,
            $service.unwrap_or("unknown")
        );
    };
}

#[macro_export]
macro_rules! log_service_detection {
    ($host:expr, $port:expr, $service:expr, $version:expr) => {
        tracing::info!(
            host = %$host,
            port = $port,
            service = $service,
            version = $version,
            event = "service_detection",
            "Detected service {}:{} - {} {}",
            $host,
            $port,
            $service,
            $version.unwrap_or("unknown version")
        );
    };
}

#[macro_export]
macro_rules! log_security_event {
    ($event_type:expr, $description:expr, $severity:expr) => {
        tracing::warn!(
            event_type = $event_type,
            description = $description,
            severity = $severity,
            event = "security_event",
            "Security event: {} - {} (severity: {})",
            $event_type,
            $description,
            $severity
        );
    };
}

#[macro_export]
macro_rules! log_error_with_context {
    ($error:expr, $context:expr) => {
        tracing::error!(
            error = %$error,
            context = $context,
            severity = %$error.severity(),
            recoverable = $error.is_recoverable(),
            event = "error",
            "Error in {}: {}",
            $context,
            $error
        );
    };
}

#[macro_export]
macro_rules! log_performance_metric {
    ($metric_name:expr, $value:expr, $unit:expr) => {
        tracing::debug!(
            metric_name = $metric_name,
            value = $value,
            unit = $unit,
            event = "performance_metric",
            "Performance metric: {} = {} {}",
            $metric_name,
            $value,
            $unit
        );
    };
}

/// Specialized logging for different scan phases
pub struct ScanLogger {
    scan_id: String,
    scan_type: String,
    target: String,
}

impl ScanLogger {
    pub fn new<S: Into<String>>(scan_id: S, scan_type: S, target: S) -> Self {
        Self {
            scan_id: scan_id.into(),
            scan_type: scan_type.into(),
            target: target.into(),
        }
    }
    
    pub fn log_phase_start(&self, phase: &str) {
        tracing::info!(
            scan_id = %self.scan_id,
            scan_type = %self.scan_type,
            target = %self.target,
            phase = phase,
            event = "phase_start",
            "Starting {} phase for {} scan of {}",
            phase,
            self.scan_type,
            self.target
        );
    }
    
    pub fn log_phase_complete(&self, phase: &str, duration: std::time::Duration) {
        tracing::info!(
            scan_id = %self.scan_id,
            scan_type = %self.scan_type,
            target = %self.target,
            phase = phase,
            duration_ms = duration.as_millis(),
            event = "phase_complete",
            "Completed {} phase in {}ms",
            phase,
            duration.as_millis()
        );
    }
    
    pub fn log_progress(&self, current: usize, total: usize, phase: &str) {
        let percentage = (current as f64 / total as f64) * 100.0;
        tracing::debug!(
            scan_id = %self.scan_id,
            phase = phase,
            current = current,
            total = total,
            percentage = format!("{:.1}%", percentage),
            event = "progress",
            "Progress: {}/{} ({}%) in {} phase",
            current,
            total,
            format!("{:.1}%", percentage),
            phase
        );
    }
}

/// Performance and timing utilities
pub struct TimingLogger {
    name: String,
    start_time: std::time::Instant,
}

impl TimingLogger {
    pub fn start<S: Into<String>>(name: S) -> Self {
        let name = name.into();
        tracing::trace!(
            operation = %name,
            event = "timing_start",
            "Starting timing for: {}",
            name
        );
        
        Self {
            name,
            start_time: std::time::Instant::now(),
        }
    }
    
    pub fn checkpoint(&self, checkpoint_name: &str) {
        let elapsed = self.start_time.elapsed();
        tracing::debug!(
            operation = %self.name,
            checkpoint = checkpoint_name,
            elapsed_ms = elapsed.as_millis(),
            event = "timing_checkpoint",
            "Checkpoint '{}' in '{}': {}ms",
            checkpoint_name,
            self.name,
            elapsed.as_millis()
        );
    }
}

impl Drop for TimingLogger {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed();
        tracing::info!(
            operation = %self.name,
            duration_ms = elapsed.as_millis(),
            event = "timing_complete",
            "Completed '{}' in {}ms",
            self.name,
            elapsed.as_millis()
        );
    }
}

/// Audit logging for security and compliance
pub fn log_audit_event(
    user: Option<&str>,
    action: &str,
    resource: &str,
    result: &str,
    details: Option<&str>,
) {
    tracing::warn!(
        user = user.unwrap_or("system"),
        action = action,
        resource = resource,
        result = result,
        details = details.unwrap_or(""),
        timestamp = chrono::Utc::now().to_rfc3339(),
        event = "audit",
        "Audit: {} performed {} on {} with result: {}",
        user.unwrap_or("system"),
        action,
        resource,
        result
    );
}

/// Initialize tracing span for request tracking
#[macro_export]
macro_rules! trace_span {
    ($name:expr) => {
        tracing::info_span!($name, span_id = %uuid::Uuid::new_v4())
    };
    ($name:expr, $($key:ident = $value:expr),*) => {
        tracing::info_span!($name, span_id = %uuid::Uuid::new_v4(), $($key = $value),*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_env_filter_creation() {
        let filter = create_env_filter("info");
        assert!(filter.is_ok());
    }
    
    #[test]
    fn test_invalid_log_level() {
        let filter = create_env_filter("invalid");
        assert!(filter.is_err());
    }
    
    #[test]
    fn test_scan_logger() {
        let logger = ScanLogger::new("test-scan", "tcp", "192.168.1.1");
        logger.log_phase_start("discovery");
        logger.log_progress(50, 100, "discovery");
        logger.log_phase_complete("discovery", Duration::from_millis(500));
    }
}
