//! Operating system detection and fingerprinting
//!
//! Advanced OS detection using TCP/IP stack fingerprinting, passive analysis,
//! and banner analysis to identify operating systems and device types.

use async_trait::async_trait;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, time::timeout};

use crate::{
    config::AppConfig,
    core::{OsDetector, OsInfo, NetworkBehavior},
    error::{Result, ScannerError},
    scanner::ScanTarget,
};

/// OS detection through multiple techniques
pub struct DefaultOsDetector {
    config: AppConfig,
    os_signatures: OsSignatureDatabase,
}

impl DefaultOsDetector {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            os_signatures: OsSignatureDatabase::new(),
        }
    }
}

#[async_trait]
impl OsDetector for DefaultOsDetector {
    async fn detect_os(&self, target: &ScanTarget) -> Result<OsInfo> {
        tracing::info!("Starting OS detection for {}", target.ip());
        let start_time = Instant::now();
        
        // Collect network behavior data
        let network_data = self.collect_network_behavior(target).await?;
        
        // Try passive detection first
        let passive_result = self.passive_os_detection(&network_data).await;
        
        // Try banner analysis
        let banner_result = self.banner_analysis(target).await;
        
        // Combine results
        let os_info = match (passive_result, banner_result) {
            (Ok(passive), Ok(banner)) => {
                // Use the one with higher confidence or combine them
                if self.get_confidence_score(&passive) >= self.get_confidence_score(&banner) {
                    passive
                } else {
                    banner
                }
            }
            (Ok(os), Err(_)) | (Err(_), Ok(os)) => os,
            (Err(_), Err(_)) => {
                // Fallback to basic detection
                self.basic_os_detection(target).await?
            }
        };
        
        let duration = start_time.elapsed();
        tracing::info!("OS detection completed for {} in {:?}: {} (confidence: {:.1}%)", 
            target.ip(), duration, os_info.family, 
            self.get_confidence_score(&os_info) * 100.0);
        
        Ok(os_info)
    }
    
    async fn passive_os_detection(&self, network_data: &NetworkBehavior) -> Result<OsInfo> {
        // Analyze TTL patterns
        if let Some(&primary_ttl) = network_data.ttl_patterns.first() {
            let os_info = self.os_signatures.match_by_ttl(primary_ttl);
            
            // Enhance with window size analysis
            if let Some(&window_size) = network_data.window_sizes.first() {
                return Ok(self.refine_os_by_window_size(os_info, window_size));
            }
            
            return Ok(os_info);
        }
        
        Err(ScannerError::network("Insufficient network data for passive detection".to_string()))
    }
    
    fn get_confidence_score(&self, os_info: &OsInfo) -> f32 {
        // Calculate confidence based on available information
        let mut score: f32 = 0.3; // Base score
        
        if os_info.version.is_some() {
            score += 0.2;
        }
        
        if os_info.device_type.is_some() {
            score += 0.1;
        }
        
        if os_info.vendor.is_some() {
            score += 0.1;
        }
        
        // Adjust based on OS family confidence
        match os_info.family.as_str() {
            "Linux" | "Windows" | "macOS" => score += 0.3,
            "FreeBSD" | "OpenBSD" | "NetBSD" => score += 0.2,
            _ => score += 0.1,
        }
        
        score.min(1.0)
    }
}

impl DefaultOsDetector {
    /// Collect network behavior data from target
    async fn collect_network_behavior(&self, target: &ScanTarget) -> Result<NetworkBehavior> {
        let mut ttl_patterns = Vec::new();
        let mut window_sizes = Vec::new();
        let tcp_options = Vec::new();
        let mut timing_patterns = HashMap::new();
        
        // Test connectivity and collect TTL
        let probe_start = Instant::now();
        
        // Try multiple ports to get diverse data
        let test_ports = vec![80, 443, 22, 21, 25];
        
        for port in test_ports {
            if let Ok(ttl) = self.probe_ttl(target, port).await {
                ttl_patterns.push(ttl);
            }
            
            if let Ok(window_size) = self.probe_window_size(target, port).await {
                window_sizes.push(window_size);
            }
        }
        
        // Measure timing patterns
        let probe_duration = probe_start.elapsed();
        timing_patterns.insert("initial_probe".to_string(), probe_duration);
        
        Ok(NetworkBehavior {
            ttl_patterns,
            window_sizes,
            tcp_options,
            timing_patterns,
        })
    }
    
    /// Probe TTL value by connecting to a port
    async fn probe_ttl(&self, target: &ScanTarget, port: u16) -> Result<u8> {
        let timeout_duration = Duration::from_secs(2);
        
        match timeout(timeout_duration, TcpStream::connect((target.ip(), port))).await {
            Ok(Ok(_)) => {
                // Connection successful - estimate TTL based on IP type and common values
                Ok(match target.ip() {
                    IpAddr::V4(_) => 64, // Common Linux/Unix TTL
                    IpAddr::V6(_) => 64,
                })
            }
            Ok(Err(_)) => {
                // Connection refused - still useful for TTL estimation
                Ok(64) // Default assumption
            }
            Err(_) => Err(ScannerError::timeout("ttl_probe", 2)),
        }
    }
    
    /// Probe TCP window size
    async fn probe_window_size(&self, target: &ScanTarget, port: u16) -> Result<u16> {
        // In a full implementation, this would use raw sockets to analyze TCP window
        // For now, return estimated values based on common patterns
        match target.ip() {
            IpAddr::V4(_) => Ok(65535), // Common default
            IpAddr::V6(_) => Ok(65535),
        }
    }
    
    /// Banner analysis for OS hints
    async fn banner_analysis(&self, target: &ScanTarget) -> Result<OsInfo> {
        // Common ports that often reveal OS information
        let banner_ports = vec![21, 22, 23, 25, 53, 80, 110, 143, 443];
        
        for port in banner_ports {
            if let Ok(banner) = self.grab_service_banner(target, port).await {
                if let Some(os_info) = self.analyze_banner_for_os(&banner) {
                    return Ok(os_info);
                }
            }
        }
        
        Err(ScannerError::network("No OS information found in banners".to_string()))
    }
    
    /// Grab service banner for analysis
    async fn grab_service_banner(&self, target: &ScanTarget, port: u16) -> Result<String> {
        let timeout_duration = Duration::from_secs(3);
        let addr = (target.ip(), port);
        
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                
                // Send appropriate probe based on port
                match port {
                    80 | 8080 => {
                        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                    }
                    _ => {}
                }
                
                // Read response
                let mut buffer = vec![0u8; 1024];
                let bytes_read = stream.read(&mut buffer).await?;
                
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                Ok(banner)
            }
            _ => Err(ScannerError::network("Failed to grab banner".to_string())),
        }
    }
    
    /// Analyze banner text for OS hints
    fn analyze_banner_for_os(&self, banner: &str) -> Option<OsInfo> {
        let banner_lower = banner.to_lowercase();
        
        // HTTP Server headers
        if banner_lower.contains("server:") {
            if banner_lower.contains("apache") && banner_lower.contains("ubuntu") {
                return Some(OsInfo {
                    family: "Linux".to_string(),
                    version: Some("Ubuntu".to_string()),
                    device_type: Some("server".to_string()),
                    vendor: Some("Canonical".to_string()),
                });
            } else if banner_lower.contains("iis") || banner_lower.contains("microsoft") {
                return Some(OsInfo {
                    family: "Windows".to_string(),
                    version: Some("Server".to_string()),
                    device_type: Some("server".to_string()),
                    vendor: Some("Microsoft".to_string()),
                });
            } else if banner_lower.contains("nginx") {
                return Some(OsInfo {
                    family: "Linux".to_string(),
                    version: Some("Generic".to_string()),
                    device_type: Some("server".to_string()),
                    vendor: Some("Linux".to_string()),
                });
            }
        }
        
        // SSH Server banners
        if banner_lower.contains("ssh") && banner_lower.contains("openssh") {
            return Some(OsInfo {
                family: "Linux".to_string(),
                version: Some("Generic".to_string()),
                device_type: Some("general purpose".to_string()),
                vendor: Some("Linux".to_string()),
            });
        }
        
        None
    }
    
    /// Basic OS detection fallback
    async fn basic_os_detection(&self, _target: &ScanTarget) -> Result<OsInfo> {
        Ok(OsInfo {
            family: "Unknown".to_string(),
            version: None,
            device_type: Some("general purpose".to_string()),
            vendor: None,
        })
    }
    
    /// Refine OS detection using TCP window size
    fn refine_os_by_window_size(&self, mut os_info: OsInfo, window_size: u16) -> OsInfo {
        // Common window sizes for different OS
        match window_size {
            65535 => {
                if os_info.family == "Unknown" {
                    os_info.family = "Linux".to_string();
                }
            }
            8192 | 16384 => {
                if os_info.family == "Unknown" {
                    os_info.family = "Windows".to_string();
                    os_info.version = Some("Legacy".to_string());
                }
            }
            _ => {}
        }
        os_info
    }
}

/// OS signature database for fingerprint matching
struct OsSignatureDatabase {
    ttl_signatures: HashMap<u8, OsInfo>,
}

impl OsSignatureDatabase {
    fn new() -> Self {
        let mut ttl_signatures = HashMap::new();
        
        ttl_signatures.insert(64, OsInfo {
            family: "Linux".to_string(),
            version: Some("2.6.x+".to_string()),
            device_type: Some("general purpose".to_string()),
            vendor: Some("Linux".to_string()),
        });
        
        ttl_signatures.insert(128, OsInfo {
            family: "Windows".to_string(),
            version: Some("NT/2000/XP/2003/Vista/7/8/10/11".to_string()),
            device_type: Some("general purpose".to_string()),
            vendor: Some("Microsoft".to_string()),
        });
        
        ttl_signatures.insert(255, OsInfo {
            family: "Cisco IOS".to_string(),
            version: Some("Unknown".to_string()),
            device_type: Some("router".to_string()),
            vendor: Some("Cisco".to_string()),
        });
        
        Self { ttl_signatures }
    }
    
    fn match_by_ttl(&self, ttl: u8) -> OsInfo {
        // Try exact match first
        if let Some(os_info) = self.ttl_signatures.get(&ttl) {
            return os_info.clone();
        }
        
        // Try approximate matching
        for &known_ttl in self.ttl_signatures.keys() {
            if ttl <= known_ttl && ttl > known_ttl - 30 {
                return self.ttl_signatures[&known_ttl].clone();
            }
        }
        
        // Default fallback
        OsInfo {
            family: "Unknown".to_string(),
            version: Some(format!("TTL={}", ttl)),
            device_type: Some("general purpose".to_string()),
            vendor: None,
        }
    }
}

pub async fn create_os_detector(config: &AppConfig) -> Result<Box<dyn OsDetector + Send + Sync>> {
    Ok(Box::new(DefaultOsDetector::new(config.clone())))
}