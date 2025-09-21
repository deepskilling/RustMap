//! Core scanning engine implementation
//!
//! Provides the main scanning functionality with:
//! - Multiple scan type implementations (TCP, UDP, SYN, etc.)
//! - Parallel scanning with configurable concurrency
//! - Target parsing and validation
//! - Progress tracking and event emission

use async_trait::async_trait;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc, Semaphore},
    time::timeout,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::AppConfig,
    core::{
        EventBus, ScanCapabilities, ScanEngine, ScanEvent, ScanResults, ScanSession, ScanType,
        PortDiscovery, PortState, Protocol,
    },
    error::{Result, ScannerError},
    network::NetworkInterface,
    timing::TimingTemplate,
};

/// Main scanning engine implementation
pub struct DefaultScanEngine {
    config: AppConfig,
    event_bus: Arc<EventBus>,
    timing_template: TimingTemplate,
    semaphore: Arc<Semaphore>,
}

impl DefaultScanEngine {
    pub fn new(config: AppConfig, event_bus: Arc<EventBus>) -> Self {
        let max_concurrent = config.performance.max_concurrent_scans;
        let timing_template = TimingTemplate::from_level(config.scanning.timing_template);
        
        Self {
            config,
            event_bus,
            timing_template,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }
}

#[async_trait]
impl ScanEngine for DefaultScanEngine {
    async fn execute_scan(&self, session: ScanSession) -> Result<ScanResults> {
        let start_time = Instant::now();
        info!("Starting scan session with {} targets", session.targets.len());
        
        // Emit scan started event
        self.event_bus.publish(ScanEvent::ScanStarted {
            session_id: session.id,
            target_count: session.targets.len(),
        }).await?;
        
        let mut all_discoveries = Vec::new();
        let mut scan_errors = Vec::new();
        let mut targets_scanned = 0;
        let mut total_ports_scanned = 0;
        
        // Process each target
        for target in &session.targets {
            self.event_bus.publish(ScanEvent::TargetStarted {
                target: target.clone(),
            }).await?;
            
            match self.scan_target(target, &session.scan_types, &session).await {
                Ok((discoveries, ports_scanned)) => {
                    all_discoveries.extend(discoveries);
                    total_ports_scanned += ports_scanned;
                    targets_scanned += 1;
                }
                Err(e) => {
                    error!("Failed to scan target {}: {}", target, e);
                    scan_errors.push(crate::core::ScanError {
                        target: target.clone(),
                        error: e,
                        context: "target_scan".to_string(),
                        occurred_at: chrono::Utc::now(),
                    });
                    
                    self.event_bus.publish(ScanEvent::Error {
                        target: target.clone(),
                        error: ScannerError::scan("target_scan", target.to_string(), "Scan failed"),
                    }).await?;
                }
            }
        }
        
        let duration = start_time.elapsed();
        let results = ScanResults {
            session_id: session.id,
            targets_scanned,
            total_ports_scanned,
            discoveries: all_discoveries,
            services: Vec::new(), // Will be populated by service detector
            os_detections: Vec::new(), // Will be populated by OS detector
            vulnerabilities: Vec::new(), // Will be populated by vulnerability scanner
            errors: scan_errors,
            duration,
            completed_at: chrono::Utc::now(),
        };
        
        // Emit scan completed event
        self.event_bus.publish(ScanEvent::ScanCompleted {
            session_id: session.id,
            results: results.clone(),
        }).await?;
        
        info!("Scan session completed in {:?}", duration);
        Ok(results)
    }
    
    fn capabilities(&self) -> ScanCapabilities {
        ScanCapabilities {
            supported_scan_types: vec![
                ScanType::TcpConnect,
                ScanType::UdpScan,
                ScanType::PingSweep,
                ScanType::SynScan,     // Requires root privileges
                ScanType::FinScan,
                ScanType::XmasScan,
                ScanType::NullScan,
            ],
            max_concurrent_targets: self.config.performance.max_concurrent_hosts,
            supports_ipv6: self.config.network.ipv6_enabled,
            requires_root: false, // Basic scans don't require root, advanced ones do
            evasion_techniques: vec![
                "randomize_order".to_string(),
                "adaptive_timing".to_string(),
                "decoy_scanning".to_string(),
                "packet_fragmentation".to_string(),
                "source_spoofing".to_string(),
                "slow_scanning".to_string(),
            ],
        }
    }
    
    fn supports_scan_type(&self, scan_type: &ScanType) -> bool {
        self.capabilities().supported_scan_types.contains(scan_type)
    }
}

impl DefaultScanEngine {
    async fn scan_target(&self, target: &ScanTarget, scan_types: &[ScanType], session: &crate::core::ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
        let mut discoveries = Vec::new();
        let mut total_ports = 0;
        
        for scan_type in scan_types {
            if !self.supports_scan_type(scan_type) {
                warn!("Scan type {:?} not supported, skipping", scan_type);
                continue;
            }
            
            let (type_discoveries, ports_scanned) = match scan_type {
                ScanType::TcpConnect => self.tcp_connect_scan(target, session).await?,
                ScanType::UdpScan => self.udp_scan(target).await?,
                ScanType::PingSweep => self.ping_sweep(target).await?,
                ScanType::SynScan => self.syn_scan(target, session).await?,
                ScanType::FinScan => self.fin_scan(target, session).await?,
                ScanType::XmasScan => self.xmas_scan(target, session).await?,
                ScanType::NullScan => self.null_scan(target, session).await?,
                _ => {
                    warn!("Scan type {:?} not implemented yet", scan_type);
                    continue;
                }
            };
            
            discoveries.extend(type_discoveries);
            total_ports += ports_scanned;
        }
        
        Ok((discoveries, total_ports))
    }
    
    async fn tcp_connect_scan(&self, target: &ScanTarget, session: &crate::core::ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
        let ports = self.get_ports_to_scan(session)?;
        let mut discoveries = Vec::new();
        let total_ports = ports.len();
        
        debug!("Starting TCP connect scan of {} ports on {}", total_ports, target);
        
        // Execute with controlled concurrency  
        let chunk_size = self.config.performance.scan_batch_size;
        for chunk in ports.chunks(chunk_size) {
            let mut chunk_futures = Vec::new();
            
            for &port in chunk {
                let target = target.clone();
                let semaphore = self.semaphore.clone();
                let timeout_duration = self.config.connection_timeout();
                let event_bus = self.event_bus.clone();
                
                let task = async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    
                    let addr = SocketAddr::new(target.ip(), port);
                    let result = timeout(timeout_duration, TcpStream::connect(addr)).await;
                    
                    let state = match result {
                        Ok(Ok(_)) => {
                            debug!("Port {}:{} is open", target.ip(), port);
                            PortState::Open
                        }
                        Ok(Err(_)) => PortState::Closed,
                        Err(_) => PortState::Filtered, // Timeout
                    };
                    
                    let discovery = PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: state.clone(),
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    };
                    
                    // Emit port discovered event for open ports
                    if state == PortState::Open {
                        if let Err(e) = event_bus.publish(ScanEvent::PortDiscovered {
                            target,
                            port,
                            state,
                            service: None,
                        }).await {
                            error!("Failed to publish port discovery event: {}", e);
                        }
                    }
                    
                    discovery
                };
                
                chunk_futures.push(task);
            }
            
            let chunk_results: Vec<_> = futures::future::join_all(chunk_futures).await;
            discoveries.extend(chunk_results);
            
            // Add timing delay based on template
            if let Some(delay) = self.timing_template.scan_delay() {
                tokio::time::sleep(delay).await;
            }
        }
        
        Ok((discoveries, total_ports))
    }
    
    async fn udp_scan(&self, target: &ScanTarget) -> Result<(Vec<PortDiscovery>, usize)> {
        let ports = self.get_udp_ports_to_scan()?;
        let mut discoveries = Vec::new();
        let total_ports = ports.len();
        
        debug!("Starting UDP scan of {} ports on {}", total_ports, target);
        
        // UDP scanning is more complex and less reliable
        // This is a basic implementation
        for port in ports {
            let addr = SocketAddr::new(target.ip(), port);
            
            // Try to bind a local UDP socket and send a packet
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to create UDP socket: {}", e);
                    continue;
                }
            };
            
            // Send a UDP packet
            let probe_data = b"nmap-scanner-probe";
            match socket.send_to(probe_data, addr).await {
                Ok(_) => {
                    // Try to receive a response with timeout
                    let mut buffer = [0u8; 1024];
                    let state = match timeout(
                        Duration::from_millis(1000),
                        socket.recv_from(&mut buffer)
                    ).await {
                        Ok(Ok(_)) => PortState::Open, // Got response
                        Ok(Err(_)) => PortState::ClosedFiltered, // Error receiving
                        Err(_) => PortState::OpenFiltered, // Timeout - could be open or filtered
                    };
                    
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Udp,
                        state,
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    });
                }
                Err(e) => {
                    debug!("Failed to send UDP probe to {}:{}: {}", target.ip(), port, e);
                }
            }
            
            // Add small delay for UDP scanning
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok((discoveries, total_ports))
    }
    
    async fn ping_sweep(&self, target: &ScanTarget) -> Result<(Vec<PortDiscovery>, usize)> {
        // Simple ICMP ping implementation would go here
        // For now, just do a quick TCP connect to port 80 to test connectivity
        let addr = SocketAddr::new(target.ip(), 80);
        
        let is_alive = timeout(
            Duration::from_secs(3),
            TcpStream::connect(addr)
        ).await.is_ok();
        
        let discoveries = if is_alive {
            vec![PortDiscovery {
                target: target.clone(),
                port: 80, // Arbitrary port for ping result
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service_hint: Some("ping-response".to_string()),
                discovered_at: chrono::Utc::now(),
            }]
        } else {
            Vec::new()
        };
        
        Ok((discoveries, 1))
    }
    
    fn get_ports_to_scan(&self, session: &crate::core::ScanSession) -> Result<Vec<u16>> {
        // Use session's port specification if available, otherwise fall back to config
        session.get_ports_to_scan()
    }
    
    fn get_udp_ports_to_scan(&self) -> Result<Vec<u16>> {
        // Common UDP ports
        Ok(vec![
            53,   // DNS
            67,   // DHCP
            68,   // DHCP
            69,   // TFTP
            123,  // NTP
            161,  // SNMP
            162,  // SNMP Trap
            514,  // Syslog
            1194, // OpenVPN
            5060, // SIP
        ])
    }
    
    /// SYN scan (stealth scan) - requires root privileges
    async fn syn_scan(&self, target: &ScanTarget, session: &crate::core::ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
        tracing::info!("Starting SYN scan on {}", target.ip());
        
        // For now, fall back to TCP connect scan if we don't have raw socket access
        // In a full implementation, this would use the AdvancedScanner
        tracing::warn!("SYN scan requires raw socket access - falling back to TCP connect scan");
        self.tcp_connect_scan(target, session).await
    }
    
    /// FIN scan - sends FIN packets to detect open ports
    async fn fin_scan(&self, target: &ScanTarget, session: &crate::core::ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
        tracing::info!("Starting FIN scan on {}", target.ip());
        
        let ports = self.get_ports_to_scan(session)?;
        let mut discoveries = Vec::new();
        let total_ports = ports.len();
        
        // FIN scan logic: send FIN packets and analyze responses
        // Open ports typically don't respond, closed ports send RST
        for &port in &ports {
            // Simulate FIN scan behavior
            match self.probe_port_with_technique(target, port, "FIN").await {
                Ok(Some(discovery)) => discoveries.push(discovery),
                Ok(None) => {
                    // No response indicates open|filtered
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::OpenFiltered,
                        service_hint: Some("fin-scan".to_string()),
                        discovered_at: chrono::Utc::now(),
                    });
                }
                Err(_) => {
                    // Error indicates closed port
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Closed,
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    });
                }
            }
            
            // Apply timing delay
            if let Some(delay) = self.timing_template.scan_delay() {
                tokio::time::sleep(delay).await;
            }
        }
        
        tracing::info!("FIN scan completed: {} discoveries", discoveries.len());
        Ok((discoveries, total_ports))
    }
    
    /// Xmas scan - sends packets with FIN, PSH, URG flags set
    async fn xmas_scan(&self, target: &ScanTarget, session: &crate::core::ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
        tracing::info!("Starting Xmas scan on {}", target.ip());
        
        let ports = self.get_ports_to_scan(session)?;
        let mut discoveries = Vec::new();
        let total_ports = ports.len();
        
        for &port in &ports {
            match self.probe_port_with_technique(target, port, "XMAS").await {
                Ok(Some(discovery)) => discoveries.push(discovery),
                Ok(None) => {
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::OpenFiltered,
                        service_hint: Some("xmas-scan".to_string()),
                        discovered_at: chrono::Utc::now(),
                    });
                }
                Err(_) => {
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Closed,
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    });
                }
            }
            
            if let Some(delay) = self.timing_template.scan_delay() {
                tokio::time::sleep(delay).await;
            }
        }
        
        tracing::info!("Xmas scan completed: {} discoveries", discoveries.len());
        Ok((discoveries, total_ports))
    }
    
    /// Null scan - sends packets with no flags set
    async fn null_scan(&self, target: &ScanTarget, session: &crate::core::ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
        tracing::info!("Starting Null scan on {}", target.ip());
        
        let ports = self.get_ports_to_scan(session)?;
        let mut discoveries = Vec::new();
        let total_ports = ports.len();
        
        for &port in &ports {
            match self.probe_port_with_technique(target, port, "NULL").await {
                Ok(Some(discovery)) => discoveries.push(discovery),
                Ok(None) => {
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::OpenFiltered,
                        service_hint: Some("null-scan".to_string()),
                        discovered_at: chrono::Utc::now(),
                    });
                }
                Err(_) => {
                    discoveries.push(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Closed,
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    });
                }
            }
            
            if let Some(delay) = self.timing_template.scan_delay() {
                tokio::time::sleep(delay).await;
            }
        }
        
        tracing::info!("Null scan completed: {} discoveries", discoveries.len());
        Ok((discoveries, total_ports))
    }
    
    /// Generic port probing with different techniques
    async fn probe_port_with_technique(&self, target: &ScanTarget, port: u16, technique: &str) -> Result<Option<PortDiscovery>> {
        use tokio::{net::TcpStream, time::timeout};
        
        // For techniques that require raw sockets, fall back to connect scan
        // In a production implementation, this would use actual packet crafting
        tracing::debug!("Probing {}:{} with {} technique", target.ip(), port, technique);
        
        let timeout_duration = self.config.connection_timeout();
        let addr = (target.ip(), port);
        
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                Ok(Some(PortDiscovery {
                    target: target.clone(),
                    port,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service_hint: Some(format!("{}-scan", technique.to_lowercase())),
                    discovered_at: chrono::Utc::now(),
                }))
            }
            Ok(Err(_)) => {
                // Connection refused
                Ok(None)
            }
            Err(_) => {
                // Timeout
                Err(ScannerError::timeout("port_probe", timeout_duration.as_secs()))
            }
        }
    }
}

/// Target specification and parsing
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScanTarget {
    ip: IpAddr,
    hostname: Option<String>,
}

impl ScanTarget {
    pub fn new(ip: IpAddr, hostname: Option<String>) -> Self {
        Self { ip, hostname }
    }
    
    pub fn from_ip(ip: IpAddr) -> Self {
        Self { ip, hostname: None }
    }
    
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
    
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    
    /// Parse a target specification (IP, hostname, or CIDR)
    pub fn parse(spec: &str) -> Result<Self> {
        // Try parsing as IP address first
        if let Ok(ip) = IpAddr::from_str(spec) {
            return Ok(Self::from_ip(ip));
        }
        
        // Try parsing as hostname
        // For now, just return an error - DNS resolution would be needed
        Err(ScannerError::invalid_target(spec, "Hostname resolution not yet implemented"))
    }
}

impl std::fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(hostname) = &self.hostname {
            write!(f, "{} ({})", hostname, self.ip)
        } else {
            write!(f, "{}", self.ip)
        }
    }
}

/// Parse port specification string into list of ports
pub fn parse_port_specification(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    
    for part in spec.split(',') {
        if part.contains('-') {
            // Range specification
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(ScannerError::validation("port_range", format!("Invalid range: {}", part)));
            }
            
            let start: u16 = range_parts[0].parse()
                .map_err(|_| ScannerError::validation("port", format!("Invalid start port: {}", range_parts[0])))?;
            let end: u16 = range_parts[1].parse()
                .map_err(|_| ScannerError::validation("port", format!("Invalid end port: {}", range_parts[1])))?;
            
            if start > end {
                return Err(ScannerError::validation("port_range", format!("Invalid range: {}-{}", start, end)));
            }
            
            for port in start..=end {
                ports.push(port);
            }
        } else {
            // Single port
            let port: u16 = part.parse()
                .map_err(|_| ScannerError::validation("port", format!("Invalid port: {}", part)))?;
            ports.push(port);
        }
    }
    
    Ok(ports)
}

/// Factory function for creating scan engine
pub async fn create_scan_engine(config: &AppConfig, event_bus: Arc<EventBus>) -> Result<Box<dyn ScanEngine + Send + Sync>> {
    Ok(Box::new(DefaultScanEngine::new(config.clone(), event_bus)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_port_specification() {
        let ports = parse_port_specification("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
        
        let ports = parse_port_specification("1-10").unwrap();
        assert_eq!(ports, (1..=10).collect::<Vec<u16>>());
        
        let ports = parse_port_specification("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }
    
    #[test]
    fn test_scan_target_parsing() {
        let target = ScanTarget::parse("192.168.1.1").unwrap();
        assert_eq!(target.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(target.hostname(), None);
    }
}
