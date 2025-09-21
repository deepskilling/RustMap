//! Service detection and version identification
//!
//! Provides basic service detection through banner grabbing and port analysis

use async_trait::async_trait;
use std::{collections::HashMap, time::Duration};
use tokio::{net::TcpStream, time::timeout, io::{AsyncReadExt, AsyncWriteExt}};
use crate::{
    config::AppConfig,
    core::{ServiceDetector, ServiceInfo, VersionInfo, PortDiscovery, Protocol},
    error::{Result, ScannerError},
    scanner::ScanTarget,
};

pub struct DefaultServiceDetector {
    config: AppConfig,
    service_probes: HashMap<u16, ServiceProbe>,
}

#[derive(Clone)]
struct ServiceProbe {
    service_name: &'static str,
    probe_data: Option<&'static [u8]>,
    expected_responses: Vec<&'static str>,
}

impl DefaultServiceDetector {
    pub fn new(config: AppConfig) -> Self {
        let service_probes = Self::build_service_probes();
        Self { 
            config,
            service_probes,
        }
    }
    
    fn build_service_probes() -> HashMap<u16, ServiceProbe> {
        let mut probes = HashMap::new();
        
        // HTTP
        probes.insert(80, ServiceProbe {
            service_name: "http",
            probe_data: Some(b"GET / HTTP/1.0\r\n\r\n"),
            expected_responses: vec!["HTTP/", "Server:", "Content-"],
        });
        
        probes.insert(8080, ServiceProbe {
            service_name: "http-alt",
            probe_data: Some(b"GET / HTTP/1.0\r\n\r\n"),
            expected_responses: vec!["HTTP/", "Server:", "Content-"],
        });
        
        // HTTPS
        probes.insert(443, ServiceProbe {
            service_name: "https",
            probe_data: None, // TLS handshake would be complex
            expected_responses: vec![],
        });
        
        // SSH
        probes.insert(22, ServiceProbe {
            service_name: "ssh",
            probe_data: None, // Just read banner
            expected_responses: vec!["SSH-", "OpenSSH", "Dropbear"],
        });
        
        // FTP
        probes.insert(21, ServiceProbe {
            service_name: "ftp",
            probe_data: None, // Just read banner
            expected_responses: vec!["220", "FTP", "Welcome"],
        });
        
        // SMTP
        probes.insert(25, ServiceProbe {
            service_name: "smtp",
            probe_data: Some(b"EHLO nmap-scanner\r\n"),
            expected_responses: vec!["220", "SMTP", "ESMTP"],
        });
        
        // DNS
        probes.insert(53, ServiceProbe {
            service_name: "domain",
            probe_data: None, // DNS query would be complex
            expected_responses: vec![],
        });
        
        // Telnet
        probes.insert(23, ServiceProbe {
            service_name: "telnet",
            probe_data: None,
            expected_responses: vec!["login:", "Password:", "Welcome"],
        });
        
        probes
    }
}

#[async_trait]
impl ServiceDetector for DefaultServiceDetector {
    async fn detect_service(&self, target: &ScanTarget, port: u16) -> Result<ServiceInfo> {
        let timeout_duration = self.config.connection_timeout();
        
        // Get service probe for this port
        let probe = self.service_probes.get(&port);
        let service_name = probe.map(|p| p.service_name).unwrap_or("unknown");
        
        // Attempt banner grabbing
        let (banner, confidence) = match self.grab_banner(target, port, probe, timeout_duration).await {
            Ok((banner, confidence)) => (Some(banner), confidence),
            Err(_) => {
                // Fallback to port-based identification
                (None, if probe.is_some() { 0.5 } else { 0.1 })
            }
        };
        
        // Extract version info if possible
        let version = if let Some(ref banner_text) = banner {
            self.extract_version_info(service_name, banner_text)
        } else {
            None
        };
        
        Ok(ServiceInfo {
            target: target.clone(),
            port,
            protocol: Protocol::Tcp, // We only do TCP service detection for now
            service_name: service_name.to_string(),
            version,
            banner,
            confidence,
        })
    }
    
    async fn detect_services(&self, discoveries: &[PortDiscovery]) -> Result<Vec<ServiceInfo>> {
        let mut services = Vec::new();
        
        for discovery in discoveries {
            // Only detect services for open TCP ports
            if matches!(discovery.protocol, Protocol::Tcp) && 
               matches!(discovery.state, crate::core::PortState::Open) {
                
                match self.detect_service(&discovery.target, discovery.port).await {
                    Ok(service_info) => {
                        tracing::debug!(
                            "Detected service: {}:{} -> {} (confidence: {:.1}%)",
                            service_info.target.ip(),
                            service_info.port,
                            service_info.service_name,
                            service_info.confidence * 100.0
                        );
                        services.push(service_info);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Service detection failed for {}:{}: {}",
                            discovery.target.ip(),
                            discovery.port,
                            e
                        );
                    }
                }
            }
        }
        
        tracing::info!("Service detection completed: {} services identified", services.len());
        Ok(services)
    }
    
    async fn get_version_info(&self, service: &ServiceInfo) -> Result<Option<VersionInfo>> {
        // If we already extracted version info during detection, return it
        Ok(service.version.clone())
    }
}

impl DefaultServiceDetector {
    async fn grab_banner(
        &self, 
        target: &ScanTarget, 
        port: u16, 
        probe: Option<&ServiceProbe>,
        timeout_duration: Duration
    ) -> Result<(String, f32)> {
        let addr = std::net::SocketAddr::new(target.ip(), port);
        
        // Connect to the service
        let mut stream = timeout(timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| ScannerError::timeout("banner_grab", timeout_duration.as_secs()))?
            .map_err(|e| ScannerError::network(format!("Failed to connect: {}", e)))?;
        
        let mut banner = String::new();
        let mut confidence = 0.3; // Base confidence for successful connection
        
        // Send probe data if available
        if let Some(probe_info) = probe {
            if let Some(probe_data) = probe_info.probe_data {
                if let Err(e) = timeout(Duration::from_secs(2), stream.write_all(probe_data)).await {
                    tracing::debug!("Failed to send probe data: {:?}", e);
                }
            }
        }
        
        // Read response
        let mut buffer = [0u8; 1024];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                banner = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                confidence = 0.7; // Higher confidence if we got a banner
                
                // Check for expected responses to increase confidence
                if let Some(probe_info) = probe {
                    for expected in &probe_info.expected_responses {
                        if banner.contains(expected) {
                            confidence = 0.9;
                            break;
                        }
                    }
                }
            }
            Ok(Ok(_)) => {
                // Connection successful but no data
                confidence = 0.4;
            }
            Ok(Err(e)) => {
                return Err(ScannerError::network(format!("Failed to read banner: {}", e)));
            }
            Err(_) => {
                // Timeout reading banner
                confidence = 0.3;
            }
        }
        
        Ok((banner.trim().to_string(), confidence))
    }
    
    fn extract_version_info(&self, service_name: &str, banner: &str) -> Option<VersionInfo> {
        let mut extra_info = HashMap::new();
        
        match service_name {
            "http" | "http-alt" => {
                // Extract server information from HTTP headers
                if let Some(server_line) = banner.lines().find(|line| line.starts_with("Server:")) {
                    let server_info = server_line.strip_prefix("Server:").unwrap_or("").trim();
                    if let Some((product, version)) = self.parse_http_server(server_info) {
                        extra_info.insert("server".to_string(), server_info.to_string());
                        return Some(VersionInfo {
                            product: product.to_string(),
                            version: version.to_string(),
                            extra_info,
                        });
                    }
                }
            }
            "ssh" => {
                // SSH banner format: SSH-2.0-OpenSSH_8.3p1
                if let Some(ssh_version) = banner.strip_prefix("SSH-") {
                    if let Some((_, software)) = ssh_version.split_once('-') {
                        if let Some((product, version)) = software.split_once('_') {
                            extra_info.insert("protocol_version".to_string(), "2.0".to_string());
                            return Some(VersionInfo {
                                product: product.to_string(),
                                version: version.to_string(),
                                extra_info,
                            });
                        }
                    }
                }
            }
            "ftp" => {
                // FTP banner often contains version info
                if banner.contains("220") {
                    // Simple extraction for common FTP servers
                    if banner.contains("vsftpd") {
                        if let Some(version) = self.extract_version_number(&banner, "vsftpd") {
                            return Some(VersionInfo {
                                product: "vsftpd".to_string(),
                                version,
                                extra_info,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        
        None
    }
    
    fn parse_http_server<'a>(&self, server_info: &'a str) -> Option<(&'a str, &'a str)> {
        // Common formats: "Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0"
        if let Some(slash_pos) = server_info.find('/') {
            let product = &server_info[..slash_pos];
            let version_part = &server_info[slash_pos + 1..];
            
            // Extract just the version number (before any space or additional info)
            let version = version_part.split_whitespace().next().unwrap_or(version_part);
            
            Some((product, version))
        } else {
            None
        }
    }
    
    fn extract_version_number(&self, text: &str, product: &str) -> Option<String> {
        // Look for version patterns like "product 1.2.3" or "product-1.2.3"
        let patterns = [
            format!("{} ", product),
            format!("{}-", product),
            format!("{}(", product),
        ];
        
        for pattern in &patterns {
            if let Some(pos) = text.find(pattern) {
                let after_pattern = &text[pos + pattern.len()..];
                
                // Extract version-like string (digits, dots, maybe alpha)
                let version: String = after_pattern
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                    .collect();
                
                if !version.is_empty() {
                    return Some(version);
                }
            }
        }
        
        None
    }
}

pub async fn create_service_detector(config: &AppConfig) -> Result<Box<dyn ServiceDetector + Send + Sync>> {
    Ok(Box::new(DefaultServiceDetector::new(config.clone())))
}
