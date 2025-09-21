//! Command-line interface definition
//!
//! Provides comprehensive CLI argument parsing with support for:
//! - Multiple scan types and options
//! - Target specification (IPs, ranges, hostnames)
//! - Output format control
//! - Performance and timing options
//! - Security and evasion settings

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "nmap_scanner",
    about = "High-performance network scanning tool",
    long_about = "A professional network scanning tool implementing nmap features with modern Rust architecture"
)]
pub struct Cli {
    /// Targets to scan (IPs, hostnames, CIDR ranges)
    #[arg(required = true, help = "Target specifications (e.g., 192.168.1.1, example.com, 192.168.1.0/24)")]
    pub targets: Vec<String>,

    // Scan Types
    #[arg(short = 's', long, help = "TCP SYN scan (requires root)")]
    pub syn_scan: bool,

    #[arg(long, help = "TCP connect scan")]
    pub tcp_scan: bool,

    #[arg(short = 'U', long, help = "UDP scan")]
    pub udp_scan: bool,

    #[arg(short = 'F', long, help = "FIN scan")]
    pub fin_scan: bool,

    #[arg(long, help = "Xmas scan (FIN, PSH, URG flags)")]
    pub xmas_scan: bool,

    #[arg(long, help = "Null scan (no flags set)")]
    pub null_scan: bool,

    #[arg(short = 'P', long, help = "Ping sweep (host discovery)")]
    pub ping_scan: bool,

    #[arg(long, help = "ACK scan")]
    pub ack_scan: bool,

    #[arg(long, help = "Window scan")]
    pub window_scan: bool,

    // Port Specification
    #[arg(short = 'p', long, help = "Port specification (e.g., 22,80,443 or 1-1000)")]
    pub ports: Option<String>,

    #[arg(long, help = "Scan all 65535 ports")]
    pub all_ports: bool,

    #[arg(long, help = "Scan top N most common ports", value_name = "N")]
    pub top_ports: Option<usize>,

    // Host Discovery
    #[arg(long, help = "Skip host discovery (treat all hosts as online)")]
    pub skip_discovery: bool,

    #[arg(long, help = "Ping only (no port scan)")]
    pub ping_only: bool,

    // Service and OS Detection
    #[arg(short = 'A', long, help = "Enable OS detection, version detection, script scanning, and traceroute")]
    pub aggressive: bool,

    #[arg(short = 'O', long, help = "Enable OS detection")]
    pub os_detection: bool,

    #[arg(short = 'V', long, help = "Enable version detection")]
    pub version_detection: bool,

    #[arg(long, help = "Enable vulnerability scanning")]
    pub vuln_scan: bool,

    // Timing and Performance
    #[arg(short = 'T', long, help = "Timing template (0-5: paranoid, sneaky, polite, normal, aggressive, insane)", value_name = "LEVEL")]
    pub timing: Option<u8>,

    #[arg(long, help = "Maximum number of parallel scans", value_name = "NUM")]
    pub max_parallelism: Option<usize>,

    #[arg(long, help = "Minimum scan delay in milliseconds", value_name = "MS")]
    pub scan_delay: Option<u64>,

    #[arg(long, help = "Maximum scan rate (packets per second)", value_name = "RATE")]
    pub max_rate: Option<u32>,

    #[arg(long, help = "Host timeout in seconds", value_name = "SECS")]
    pub host_timeout: Option<u64>,

    // Firewall/IDS Evasion
    #[arg(short = 'f', long, help = "Fragment packets")]
    pub fragment: bool,

    #[arg(short = 'D', long, help = "Cloak scan with decoys", value_name = "DECOY_LIST")]
    pub decoy: Option<String>,

    #[arg(short = 'S', long, help = "Spoof source IP address", value_name = "IP")]
    pub spoof_ip: Option<String>,

    #[arg(long, help = "Use specified source port", value_name = "PORT")]
    pub source_port: Option<u16>,

    #[arg(long, help = "Randomize target order")]
    pub randomize: bool,

    // Network Interface
    #[arg(short = 'e', long, help = "Use specified network interface", value_name = "INTERFACE")]
    pub interface: Option<String>,

    // DNS Resolution
    #[arg(short = 'n', long, help = "Never do DNS resolution")]
    pub no_dns: bool,

    #[arg(short = 'R', long, help = "Always resolve DNS (default)")]
    pub always_dns: bool,

    #[arg(long, help = "Use system DNS servers")]
    pub system_dns: bool,

    #[arg(long, help = "Custom DNS servers", value_name = "SERVER_LIST")]
    pub dns_servers: Option<String>,

    // IPv6 Support
    #[arg(short = '6', long, help = "Enable IPv6 scanning")]
    pub ipv6: bool,

    // Output Options
    #[arg(short = 'o', long, help = "Output file path", value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[arg(long, help = "Output format", value_enum, value_name = "FORMAT")]
    pub format: Option<OutputFormat>,

    #[arg(short = 'v', long, help = "Increase verbosity level", action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(short = 'q', long, help = "Quiet mode (minimal output)")]
    pub quiet: bool,

    #[arg(long, help = "Show progress indicator")]
    pub progress: bool,

    #[arg(long, help = "Include timestamps in output")]
    pub timestamps: bool,

    // Scripting Options
    #[arg(long, help = "Run specified scripts", value_name = "SCRIPT_LIST")]
    pub scripts: Option<String>,

    #[arg(long, help = "Run all scripts in category", value_name = "CATEGORY")]
    pub script_category: Option<String>,

    #[arg(long, help = "Script arguments", value_name = "ARGS")]
    pub script_args: Option<String>,

    // Configuration
    #[arg(short = 'c', long, help = "Configuration file path", value_name = "FILE", default_value = "config.toml")]
    pub config_path: PathBuf,

    #[arg(long, help = "Validate configuration and exit")]
    pub validate_config: bool,

    // Advanced Options
    #[arg(long, help = "Enable debug mode")]
    pub debug: bool,

    #[arg(long, help = "Dry run (show what would be scanned)")]
    pub dry_run: bool,

    #[arg(long, help = "Resume from previous scan", value_name = "SESSION_ID")]
    pub resume: Option<String>,

    #[arg(long, help = "List available network interfaces and exit")]
    pub list_interfaces: bool,

    #[arg(long, help = "Test network connectivity and exit")]
    pub test_connectivity: bool,

    // Reporting Options
    #[arg(long, help = "Generate detailed report")]
    pub detailed_report: bool,

    #[arg(long, help = "Include raw packet data in report")]
    pub include_raw_data: bool,

    #[arg(long, help = "Export to multiple formats")]
    pub multi_format: bool,

    // Performance Monitoring
    #[arg(long, help = "Enable performance monitoring")]
    pub monitor_performance: bool,

    #[arg(long, help = "Memory usage limit in MB", value_name = "MB")]
    pub memory_limit: Option<usize>,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum OutputFormat {
    /// Human-readable output
    Human,
    /// JSON format
    Json,
    /// XML format
    Xml,
    /// CSV format
    Csv,
    /// YAML format
    Yaml,
    /// Grepable format
    Grepable,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Human => write!(f, "human"),
            Self::Json => write!(f, "json"),
            Self::Xml => write!(f, "xml"),
            Self::Csv => write!(f, "csv"),
            Self::Yaml => write!(f, "yaml"),
            Self::Grepable => write!(f, "grepable"),
        }
    }
}

impl Cli {
    /// Validate CLI arguments and resolve conflicts
    pub fn validate(&self) -> Result<(), String> {
        // Validate timing template
        if let Some(timing) = self.timing {
            if timing > 5 {
                return Err("Timing template must be between 0-5".to_string());
            }
        }

        // Validate port specifications
        if let Some(ports) = &self.ports {
            self.validate_port_spec(ports)?;
        }

        // Check for conflicting options
        if self.quiet && self.verbose > 0 {
            return Err("Cannot use both quiet and verbose modes".to_string());
        }

        if self.ping_only && (self.tcp_scan || self.syn_scan || self.udp_scan) {
            return Err("Cannot use ping-only with port scanning options".to_string());
        }

        // Validate decoy specification
        if let Some(decoys) = &self.decoy {
            self.validate_decoy_spec(decoys)?;
        }

        // Validate DNS server specification
        if let Some(dns_servers) = &self.dns_servers {
            self.validate_dns_servers(dns_servers)?;
        }

        // Check for root privileges if needed
        if self.syn_scan || self.fragment || self.spoof_ip.is_some() {
            #[cfg(unix)]
            if nix::unistd::getuid().is_root() == false {
                return Err("SYN scan, fragmentation, and IP spoofing require root privileges".to_string());
            }
        }

        Ok(())
    }

    /// Get the effective verbosity level
    pub fn verbosity_level(&self) -> u8 {
        if self.quiet {
            0
        } else if self.debug {
            5
        } else {
            1 + self.verbose
        }
    }

    /// Check if any scan type is explicitly specified
    pub fn has_scan_type(&self) -> bool {
        self.syn_scan
            || self.tcp_scan
            || self.udp_scan
            || self.fin_scan
            || self.xmas_scan
            || self.null_scan
            || self.ping_scan
            || self.ack_scan
            || self.window_scan
    }

    /// Get effective timing template
    pub fn effective_timing(&self) -> u8 {
        self.timing.unwrap_or(3) // Default to normal timing
    }

    /// Get list of enabled scan types
    pub fn enabled_scan_types(&self) -> Vec<&'static str> {
        let mut types = Vec::new();

        if self.syn_scan { types.push("syn"); }
        if self.tcp_scan { types.push("tcp_connect"); }
        if self.udp_scan { types.push("udp"); }
        if self.fin_scan { types.push("fin"); }
        if self.xmas_scan { types.push("xmas"); }
        if self.null_scan { types.push("null"); }
        if self.ping_scan { types.push("ping"); }
        if self.ack_scan { types.push("ack"); }
        if self.window_scan { types.push("window"); }

        types
    }

    /// Parse port specification
    fn validate_port_spec(&self, ports: &str) -> Result<(), String> {
        for part in ports.split(',') {
            if part.contains('-') {
                // Range specification
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(format!("Invalid port range: {}", part));
                }
                
                let start: u16 = range_parts[0].parse()
                    .map_err(|_| format!("Invalid port number: {}", range_parts[0]))?;
                let end: u16 = range_parts[1].parse()
                    .map_err(|_| format!("Invalid port number: {}", range_parts[1]))?;
                
                if start == 0 || end == 0 || start > end {
                    return Err(format!("Invalid port range: {}-{}", start, end));
                }
            } else {
                // Single port
                let port: u16 = part.parse()
                    .map_err(|_| format!("Invalid port number: {}", part))?;
                if port == 0 {
                    return Err("Port 0 is not valid".to_string());
                }
            }
        }
        Ok(())
    }

    /// Validate decoy specification
    fn validate_decoy_spec(&self, decoys: &str) -> Result<(), String> {
        for decoy in decoys.split(',') {
            if decoy == "ME" || decoy == "RND" {
                continue; // Special keywords
            }
            
            // Validate as IP address
            if decoy.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("Invalid decoy IP address: {}", decoy));
            }
        }
        Ok(())
    }

    /// Validate DNS server specification
    fn validate_dns_servers(&self, servers: &str) -> Result<(), String> {
        for server in servers.split(',') {
            if server.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("Invalid DNS server IP address: {}", server));
            }
        }
        Ok(())
    }
}

/// CLI helper functions

/// Parse target specification into individual targets
pub fn parse_target_spec(spec: &str) -> Result<Vec<String>, String> {
    let mut targets = Vec::new();
    
    if spec.contains('/') {
        // CIDR notation
        targets.extend(expand_cidr(spec)?);
    } else if spec.contains('-') && spec.chars().any(|c| c.is_ascii_digit()) {
        // IP range notation (e.g., 192.168.1.1-100)
        targets.extend(expand_ip_range(spec)?);
    } else {
        // Single target (IP or hostname)
        targets.push(spec.to_string());
    }
    
    Ok(targets)
}

/// Expand CIDR notation to individual IPs
fn expand_cidr(cidr: &str) -> Result<Vec<String>, String> {
    // Implementation would expand CIDR ranges
    // For now, return the CIDR as-is for processing by scanning engine
    Ok(vec![cidr.to_string()])
}

/// Expand IP range notation
fn expand_ip_range(range: &str) -> Result<Vec<String>, String> {
    // Implementation would expand ranges like 192.168.1.1-100
    // For now, return the range as-is for processing by scanning engine
    Ok(vec![range.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_validation() {
        let cli = Cli::parse_from(&["nmap_scanner", "127.0.0.1", "-p", "22,80,443"]);
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_invalid_port_range() {
        let cli = Cli::parse_from(&["nmap_scanner", "127.0.0.1", "-p", "100-50"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_timing_validation() {
        let cli = Cli::parse_from(&["nmap_scanner", "127.0.0.1", "-T", "6"]);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_conflicting_options() {
        let cli = Cli::parse_from(&["nmap_scanner", "127.0.0.1", "-q", "-v"]);
        assert!(cli.validate().is_err());
    }
}
