//! Configuration management system
//!
//! Provides centralized configuration management with support for:
//! - TOML/YAML configuration files
//! - Environment variables
//! - Command-line overrides
//! - Hot reloading capabilities

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{debug, info};

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Scanning configuration
    pub scanning: ScanningConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Output configuration
    pub output: OutputConfig,
    /// Performance tuning
    pub performance: PerformanceConfig,
    /// Security and evasion settings
    pub security: SecurityConfig,
    /// File persistence settings
    pub persistence: PersistenceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningConfig {
    /// Default scan type (tcp_connect, syn, udp, etc.)
    pub default_scan_type: String,
    /// Default port range to scan
    pub default_ports: String,
    /// Enable service detection by default
    pub service_detection: bool,
    /// Enable OS detection by default
    pub os_detection: bool,
    /// Enable vulnerability scanning
    pub vuln_scanning: bool,
    /// Default timing template (0-5, paranoid to insane)
    pub timing_template: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Default interface to use for scanning
    pub default_interface: Option<String>,
    /// DNS resolution timeout in seconds
    pub dns_timeout_secs: u64,
    /// Connection timeout for TCP scans in seconds
    pub connection_timeout_secs: u64,
    /// Enable IPv6 support
    pub ipv6_enabled: bool,
    /// Source IP for spoofing (if allowed)
    pub source_ip: Option<String>,
    /// Source port range for scanning
    pub source_port_range: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Logging level (trace, debug, info, warn, error)
    pub level: String,
    /// Output format (json, pretty, compact)
    pub format: String,
    /// Log file path (None for stdout only)
    pub file_path: Option<PathBuf>,
    /// Maximum log file size in MB
    pub max_file_size_mb: u64,
    /// Number of archived log files to keep
    pub max_archived_files: u32,
    /// Enable structured logging
    pub structured: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            file_path: None,
            max_file_size_mb: 100,
            max_archived_files: 5,
            structured: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default output format (human, json, xml, csv)
    pub default_format: String,
    /// Output directory for scan results
    pub output_dir: PathBuf,
    /// Enable real-time progress display
    pub show_progress: bool,
    /// Include timestamps in output
    pub include_timestamps: bool,
    /// Maximum lines to display in console output
    pub max_console_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,
    /// Maximum concurrent host discoveries
    pub max_concurrent_hosts: usize,
    /// Scan batch size for large networks
    pub scan_batch_size: usize,
    /// Worker thread pool size
    pub worker_threads: usize,
    /// Memory limit for scan results (MB)
    pub memory_limit_mb: usize,
    /// Enable adaptive scanning speed
    pub adaptive_timing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable packet fragmentation
    pub packet_fragmentation: bool,
    /// Use decoy scanning
    pub use_decoys: bool,
    /// Number of decoy IPs to use
    pub decoy_count: u8,
    /// Enable source IP spoofing
    pub ip_spoofing: bool,
    /// Randomize scan order
    pub randomize_order: bool,
    /// Maximum scan rate (packets per second)
    pub max_scan_rate: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    /// Base directory for data storage
    pub data_dir: PathBuf,
    /// Enable automatic result saving
    pub auto_save: bool,
    /// Scan history retention days
    pub history_retention_days: u32,
    /// Maximum storage size (MB)
    pub max_storage_mb: usize,
    /// Compression level for stored data (0-9)
    pub compression_level: u8,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            scanning: ScanningConfig {
                default_scan_type: "tcp_connect".to_string(),
                default_ports: "1-1000".to_string(),
                service_detection: true,
                os_detection: true,
                vuln_scanning: false,
                timing_template: 3, // Normal timing
            },
            network: NetworkConfig {
                default_interface: None,
                dns_timeout_secs: 10,
                connection_timeout_secs: 3,
                ipv6_enabled: true,
                source_ip: None,
                source_port_range: None,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "pretty".to_string(),
                file_path: None,
                max_file_size_mb: 100,
                max_archived_files: 5,
                structured: false,
            },
            output: OutputConfig {
                default_format: "human".to_string(),
                output_dir: PathBuf::from("./scan_results"),
                show_progress: true,
                include_timestamps: true,
                max_console_lines: 1000,
            },
            performance: PerformanceConfig {
                max_concurrent_scans: 1000,
                max_concurrent_hosts: 100,
                scan_batch_size: 1000,
                worker_threads: 0, // 0 means auto-detect
                memory_limit_mb: 512,
                adaptive_timing: true,
            },
            security: SecurityConfig {
                packet_fragmentation: false,
                use_decoys: false,
                decoy_count: 3,
                ip_spoofing: false,
                randomize_order: true,
                max_scan_rate: None,
            },
            persistence: PersistenceConfig {
                data_dir: PathBuf::from("./data"),
                auto_save: true,
                history_retention_days: 30,
                max_storage_mb: 1024,
                compression_level: 6,
            },
        }
    }
}

impl AppConfig {
    /// Load configuration from file with environment variable overrides
    pub async fn load<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref();
        
        info!("Loading configuration from: {}", config_path.display());
        
        let mut settings = config::Config::builder();
        
        // Start with default configuration
        settings = settings.add_source(config::Config::try_from(&Self::default())?);
        
        // Load from config file if it exists
        if config_path.exists() {
            debug!("Found configuration file, loading settings");
            settings = settings.add_source(config::File::from(config_path));
        } else {
            info!("No configuration file found, using defaults");
            // Create default config file
            Self::create_default_config(config_path).await?;
        }
        
        // Override with environment variables (prefixed with NMAP_)
        settings = settings.add_source(
            config::Environment::with_prefix("NMAP")
                .separator("_")
                .try_parsing(true)
        );
        
        let config: AppConfig = settings
            .build()
            .context("Failed to build configuration")?
            .try_deserialize()
            .context("Failed to deserialize configuration")?;
        
        // Validate configuration
        config.validate()?;
        
        info!("Configuration loaded successfully");
        Ok(config)
    }
    
    /// Create a default configuration file
    async fn create_default_config<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await
                .context("Failed to create config directory")?;
        }
        
        let default_config = Self::default();
        let config_content = toml::to_string_pretty(&default_config)
            .context("Failed to serialize default configuration")?;
        
        tokio::fs::write(path, config_content).await
            .context("Failed to write default configuration file")?;
        
        info!("Created default configuration file: {}", path.display());
        Ok(())
    }
    
    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate timing template
        if self.scanning.timing_template > 5 {
            return Err(anyhow::anyhow!("Timing template must be between 0-5"));
        }
        
        // Validate logging level
        match self.logging.level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {},
            _ => return Err(anyhow::anyhow!("Invalid logging level: {}", self.logging.level)),
        }
        
        // Validate output format
        match self.output.default_format.to_lowercase().as_str() {
            "human" | "json" | "xml" | "csv" => {},
            _ => return Err(anyhow::anyhow!("Invalid output format: {}", self.output.default_format)),
        }
        
        // Validate performance settings
        if self.performance.max_concurrent_scans == 0 {
            return Err(anyhow::anyhow!("max_concurrent_scans must be greater than 0"));
        }
        
        // 0 means auto-detect, which is valid
        
        debug!("Configuration validation passed");
        Ok(())
    }
    
    /// Get the effective scan timeout based on timing template
    pub fn scan_timeout(&self) -> Duration {
        match self.scanning.timing_template {
            0 => Duration::from_secs(300), // Paranoid
            1 => Duration::from_secs(120), // Sneaky
            2 => Duration::from_secs(60),  // Polite
            3 => Duration::from_secs(30),  // Normal
            4 => Duration::from_secs(10),  // Aggressive
            5 => Duration::from_secs(3),   // Insane
            _ => Duration::from_secs(30),  // Default to normal
        }
    }
    
    /// Get scan delay based on timing template
    pub fn scan_delay(&self) -> Duration {
        match self.scanning.timing_template {
            0 => Duration::from_millis(5000), // Paranoid
            1 => Duration::from_millis(1000), // Sneaky
            2 => Duration::from_millis(400),  // Polite
            3 => Duration::from_millis(0),    // Normal
            4 => Duration::from_millis(0),    // Aggressive
            5 => Duration::from_millis(0),    // Insane
            _ => Duration::from_millis(0),    // Default to normal
        }
    }
    
    /// Get DNS timeout as Duration
    pub fn dns_timeout(&self) -> Duration {
        Duration::from_secs(self.network.dns_timeout_secs)
    }
    
    /// Get connection timeout as Duration
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.network.connection_timeout_secs)
    }
}
