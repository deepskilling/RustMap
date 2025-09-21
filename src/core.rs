//! Core application framework and traits
//!
//! Defines the main application structure and core traits following SOLID principles:
//! - Single Responsibility: Each trait has a single, well-defined purpose
//! - Open/Closed: Extensible through trait implementations
//! - Liskov Substitution: All implementations can be swapped seamlessly
//! - Interface Segregation: Small, focused trait interfaces
//! - Dependency Inversion: High-level modules depend on abstractions

use async_trait::async_trait;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::{
    cli::Cli,
    config::AppConfig,
    error::{Result, ScannerError},
    persistence::ScanDataStore,
    reporting::ReportGenerator,
    scanner::ScanTarget,
};

/// Main application orchestrator
pub struct Application {
    config: AppConfig,
    scan_engine: Box<dyn ScanEngine + Send + Sync>,
    service_detector: Box<dyn ServiceDetector + Send + Sync>,
    os_detector: Box<dyn OsDetector + Send + Sync>,
    report_generator: Box<dyn ReportGenerator + Send + Sync>,
    data_store: Box<dyn ScanDataStore + Send + Sync>,
    event_bus: Arc<EventBus>,
}

impl Application {
    /// Create a new application instance with default implementations
    pub async fn new(config: AppConfig) -> Result<Self> {
        let event_bus = Arc::new(EventBus::new());
        
        // Create default implementations
        let scan_engine = crate::scanner::create_scan_engine(&config, event_bus.clone()).await?;
        let service_detector = crate::service::create_service_detector(&config).await?;
        let os_detector = crate::os_detection::create_os_detector(&config).await?;
        let report_generator = crate::reporting::create_report_generator(&config).await?;
        let data_store = crate::persistence::create_data_store(&config).await?;
        
        Ok(Self {
            config,
            scan_engine,
            service_detector,
            os_detector,
            report_generator,
            data_store,
            event_bus,
        })
    }
    
    /// Run the application with CLI arguments
    pub async fn run(&mut self, cli: Cli) -> Result<()> {
        tracing::info!("Starting application run");
        
        // Parse targets from CLI
        let targets = self.parse_targets(&cli.targets)?;
        
        // Create scan session with CLI port specification
        let session = ScanSession::new(
            targets,
            self.determine_scan_types(&cli)?,
            self.config.clone(),
        );
        
        // Apply CLI port specification if provided
        let session = if let Some(port_spec) = &cli.ports {
            session.with_port_specification(port_spec.clone())
        } else if cli.all_ports {
            session.with_port_specification("1-65535".to_string())
        } else if let Some(top_n) = cli.top_ports {
            session.with_top_ports(top_n)
        } else {
            session
        };
        
        // Execute scan session (clone session for later storage)
        let session_id = session.id;
        let session_for_storage = session.clone();
        let mut results = self.execute_scan_session(session).await?;
        
        // Log summary of scan results
        tracing::info!("Scan completed: {} discoveries across {} ports", 
            results.discoveries.len(), results.total_ports_scanned);
        
        // Perform service detection if enabled
        if self.config.scanning.service_detection && !results.discoveries.is_empty() {
            tracing::info!("Starting service detection on {} discovered ports", results.discoveries.len());
            match self.service_detector.detect_services(&results.discoveries).await {
                Ok(services) => {
                    results.services = services;
                    tracing::info!("Service detection completed: {} services identified", results.services.len());
                }
                Err(e) => {
                    tracing::warn!("Service detection failed: {}", e);
                }
            }
        }
        
        // Perform OS detection if enabled (via CLI or config)
        if cli.os_detection || self.config.scanning.os_detection {
            tracing::info!("Starting OS detection");
            for target in &session_for_storage.targets {
                match self.os_detector.detect_os(target).await {
                    Ok(os_info) => {
                        let confidence = self.os_detector.get_confidence_score(&os_info);
                        results.os_detections.push(OsDetection {
                            target: target.clone(),
                            os_info,
                            confidence,
                            detection_method: OsDetectionMethod::CombinedMethods,
                        });
                        
                        // Emit OS detected event
                        if let Err(e) = self.event_bus.publish(ScanEvent::OsDetected {
                            target: target.clone(),
                            os_info: results.os_detections.last().unwrap().os_info.clone(),
                            confidence,
                        }).await {
                            tracing::warn!("Failed to publish OS detection event: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("OS detection failed for {}: {}", target.ip(), e);
                    }
                }
            }
            tracing::info!("OS detection completed: {} systems identified", results.os_detections.len());
        }
        
        // Generate reports
        self.generate_reports(&results, &cli).await?;
        
        // Store results if enabled
        if self.config.persistence.auto_save {
            // Store both session and results
            self.data_store.store_scan_session(&session_for_storage).await?;
            self.data_store.store_scan_results(&results).await?;
            tracing::info!("Scan data auto-saved (session: {})", session_id);
        }
        
        tracing::info!("Application run completed successfully");
        Ok(())
    }
    
    async fn execute_scan_session(&mut self, session: ScanSession) -> Result<ScanResults> {
        let session_id = Uuid::new_v4();
        tracing::info!(session_id = %session_id, "Starting scan session");
        
        // Subscribe to events
        let mut event_receiver = self.event_bus.subscribe().await?;
        
        // Start scan
        let scan_future = self.scan_engine.execute_scan(session);
        
        // Handle events in parallel
        let event_future = self.handle_events(event_receiver);
        
        // Wait for scan to complete
        let (scan_result, _) = tokio::try_join!(scan_future, event_future)?;
        
        tracing::info!(session_id = %session_id, "Scan session completed");
        Ok(scan_result)
    }
    
    async fn handle_events(&self, mut receiver: mpsc::Receiver<ScanEvent>) -> Result<()> {
        while let Some(event) = receiver.recv().await {
            match event {
                ScanEvent::PortDiscovered { target, port, state, service } => {
                    crate::log_port_discovery!(target.ip(), port, state.as_str(), service.as_deref());
                }
                ScanEvent::ServiceDetected { target, port, service, version } => {
                    crate::log_service_detection!(target.ip(), port, service, version.as_deref());
                }
                ScanEvent::VulnerabilityFound { target, vulnerability } => {
                    tracing::warn!(
                        target = %target.ip(),
                        vulnerability = %vulnerability,
                        "Vulnerability discovered"
                    );
                }
                ScanEvent::Error { target, error } => {
                    crate::log_error_with_context!(error, format!("scanning {}", target.ip()));
                }
                ScanEvent::ScanCompleted { session_id, results: _ } => {
                    tracing::debug!("Scan completed event received for session {}", session_id);
                    break; // Exit the event loop when scan is complete
                }
                _ => {}
            }
        }
        Ok(())
    }
    
    fn parse_targets(&self, target_specs: &[String]) -> Result<Vec<ScanTarget>> {
        // Implementation would parse various target formats
        // - IP addresses (192.168.1.1)
        // - CIDR ranges (192.168.1.0/24)
        // - Hostname ranges (host1-100.example.com)
        // - Domain names (example.com)
        
        target_specs
            .iter()
            .map(|spec| ScanTarget::parse(spec))
            .collect()
    }
    
    fn determine_scan_types(&self, cli: &Cli) -> Result<Vec<ScanType>> {
        let mut scan_types = Vec::new();
        
        if cli.tcp_scan { scan_types.push(ScanType::TcpConnect); }
        if cli.syn_scan { scan_types.push(ScanType::SynScan); }
        if cli.udp_scan { scan_types.push(ScanType::UdpScan); }
        if cli.ping_scan { scan_types.push(ScanType::PingSweep); }
        if cli.fin_scan { scan_types.push(ScanType::FinScan); }
        if cli.xmas_scan { scan_types.push(ScanType::XmasScan); }
        if cli.null_scan { scan_types.push(ScanType::NullScan); }
        
        if scan_types.is_empty() {
            // Default to configured scan type
            scan_types.push(ScanType::from_str(&self.config.scanning.default_scan_type)?);
        }
        
        Ok(scan_types)
    }
    
    async fn generate_reports(&self, results: &ScanResults, cli: &Cli) -> Result<()> {
        if let Some(output_path) = &cli.output {
            let format = cli.format.as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| self.config.output.default_format.clone());
            
            tracing::info!("Generating {} report: {}", format, output_path.display());
            self.report_generator
                .generate_report(results, &format, output_path)
                .await?;
        }
        
        Ok(())
    }
}

/// Core scanning engine trait - orchestrates all scanning operations
#[async_trait]
pub trait ScanEngine {
    /// Execute a complete scan session
    async fn execute_scan(&self, session: ScanSession) -> Result<ScanResults>;
    
    /// Get scanning capabilities of this engine
    fn capabilities(&self) -> ScanCapabilities;
    
    /// Check if engine supports a specific scan type
    fn supports_scan_type(&self, scan_type: &ScanType) -> bool;
}

/// Service detection trait - identifies services on discovered ports
#[async_trait]
pub trait ServiceDetector {
    /// Detect service on a specific port
    async fn detect_service(&self, target: &ScanTarget, port: u16) -> Result<ServiceInfo>;
    
    /// Detect services on multiple ports concurrently
    async fn detect_services(&self, discoveries: &[PortDiscovery]) -> Result<Vec<ServiceInfo>>;
    
    /// Get version information for a detected service
    async fn get_version_info(&self, service: &ServiceInfo) -> Result<Option<VersionInfo>>;
}

/// Operating system detection trait
#[async_trait]
pub trait OsDetector {
    /// Detect operating system for a target
    async fn detect_os(&self, target: &ScanTarget) -> Result<OsInfo>;
    
    /// Perform passive OS detection based on network behavior
    async fn passive_os_detection(&self, network_data: &NetworkBehavior) -> Result<OsInfo>;
    
    /// Get confidence score for OS detection
    fn get_confidence_score(&self, os_info: &OsInfo) -> f32;
}

/// Vulnerability scanner trait
#[async_trait]
pub trait VulnerabilityScanner {
    /// Scan for vulnerabilities on a target
    async fn scan_vulnerabilities(&self, target: &ScanTarget) -> Result<Vec<Vulnerability>>;
    
    /// Check for specific CVEs
    async fn check_cve(&self, target: &ScanTarget, cve_id: &str) -> Result<bool>;
    
    /// Get vulnerability database version
    fn database_version(&self) -> String;
}

/// Network utility trait for low-level operations
#[async_trait]
pub trait NetworkUtility {
    /// Perform traceroute to target
    async fn traceroute(&self, target: &ScanTarget) -> Result<Vec<HopInfo>>;
    
    /// Resolve hostname to IP addresses
    async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>>;
    
    /// Perform reverse DNS lookup
    async fn reverse_lookup(&self, ip: IpAddr) -> Result<Option<String>>;
}

/// Event bus for inter-component communication
pub struct EventBus {
    subscribers: RwLock<Vec<mpsc::Sender<ScanEvent>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: RwLock::new(Vec::new()),
        }
    }
    
    pub async fn subscribe(&self) -> Result<mpsc::Receiver<ScanEvent>> {
        let (tx, rx) = mpsc::channel(1000);
        self.subscribers.write().await.push(tx);
        Ok(rx)
    }
    
    pub async fn publish(&self, event: ScanEvent) -> Result<()> {
        let subscribers = self.subscribers.read().await;
        for sender in subscribers.iter() {
            if sender.send(event.clone()).await.is_err() {
                // Subscriber disconnected, clean up later
                tracing::debug!("Event subscriber disconnected");
            }
        }
        Ok(())
    }
}

/// Core data structures

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanSession {
    pub id: Uuid,
    pub targets: Vec<ScanTarget>,
    pub scan_types: Vec<ScanType>,
    pub config: AppConfig,
    pub port_specification: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ScanSession {
    pub fn new(targets: Vec<ScanTarget>, scan_types: Vec<ScanType>, config: AppConfig) -> Self {
        Self {
            id: Uuid::new_v4(),
            targets,
            scan_types,
            config,
            port_specification: None,
            created_at: chrono::Utc::now(),
        }
    }
    
    pub fn with_port_specification(mut self, port_spec: String) -> Self {
        self.port_specification = Some(port_spec);
        self
    }
    
    pub fn with_top_ports(mut self, top_n: usize) -> Self {
        // Create port specification for top N ports
        let top_ports = get_top_ports(top_n);
        let port_spec = top_ports.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.port_specification = Some(port_spec);
        self
    }
    
    pub fn get_ports_to_scan(&self) -> Result<Vec<u16>> {
        if let Some(ref port_spec) = self.port_specification {
            crate::scanner::parse_port_specification(port_spec)
        } else {
            // Fall back to config default
            crate::scanner::parse_port_specification(&self.config.scanning.default_ports)
        }
    }
}

/// Get top N most common ports
fn get_top_ports(n: usize) -> Vec<u16> {
    // Top common ports in order of frequency
    let top_ports = vec![
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 993, 143, 53, 135, 3306, 8080, 1723, 111, 995, 
        113, 119, 8443, 587, 1433, 3128, 8008, 5432, 9100, 3000, 8000, 8888, 1521, 4899, 5060, 
        5666, 1194, 2049, 6000, 6001, 10000, 1900, 5431, 2301, 8009, 7001, 8001, 8031, 8081, 
        9080, 9090, 9999, 9998, 5555, 1755, 4000, 5003, 8001, 8090, 9000, 9001, 1080, 1025, 
        1026, 1027, 1028, 1029, 1110, 1433, 5000, 5001, 5002, 5003, 5004, 1234, 1812, 1813, 
        2000, 2001, 2002, 2003, 2004, 2005, 3001, 3002, 3003, 3004, 3005, 4001, 4002, 4003,
    ];
    
    top_ports.into_iter().take(n).collect()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResults {
    pub session_id: Uuid,
    pub targets_scanned: usize,
    pub total_ports_scanned: usize,
    pub discoveries: Vec<PortDiscovery>,
    pub services: Vec<ServiceInfo>,
    pub os_detections: Vec<OsDetection>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub errors: Vec<ScanError>,
    pub duration: Duration,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortDiscovery {
    pub target: ScanTarget,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service_hint: Option<String>,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub target: ScanTarget,
    pub port: u16,
    pub protocol: Protocol,
    pub service_name: String,
    pub version: Option<VersionInfo>,
    pub banner: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsDetection {
    pub target: ScanTarget,
    pub os_info: OsInfo,
    pub confidence: f32,
    pub detection_method: OsDetectionMethod,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsInfo {
    pub family: String,
    pub version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub target: ScanTarget,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub cvss_score: Option<f32>,
}

impl std::fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.title, self.severity)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionInfo {
    pub product: String,
    pub version: String,
    pub extra_info: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct NetworkBehavior {
    pub ttl_patterns: Vec<u8>,
    pub window_sizes: Vec<u16>,
    pub tcp_options: Vec<String>,
    pub timing_patterns: HashMap<String, Duration>,
}

#[derive(Debug, Clone)]
pub struct HopInfo {
    pub hop_number: u8,
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub rtt: Vec<Duration>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanError {
    pub target: ScanTarget,
    pub error: ScannerError,
    pub context: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

/// Enums for various scan types and states

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScanType {
    TcpConnect,
    SynScan,
    UdpScan,
    FinScan,
    XmasScan,
    NullScan,
    PingSweep,
    AckScan,
    WindowScan,
}

impl ScanType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp_connect" | "tcp" => Ok(Self::TcpConnect),
            "syn" | "syn_scan" => Ok(Self::SynScan),
            "udp" | "udp_scan" => Ok(Self::UdpScan),
            "fin" | "fin_scan" => Ok(Self::FinScan),
            "xmas" | "xmas_scan" => Ok(Self::XmasScan),
            "null" | "null_scan" => Ok(Self::NullScan),
            "ping" | "ping_sweep" => Ok(Self::PingSweep),
            "ack" | "ack_scan" => Ok(Self::AckScan),
            "window" | "window_scan" => Ok(Self::WindowScan),
            _ => Err(ScannerError::validation("scan_type", format!("Unknown scan type: {}", s))),
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp_connect",
            Self::SynScan => "syn_scan",
            Self::UdpScan => "udp_scan",
            Self::FinScan => "fin_scan",
            Self::XmasScan => "xmas_scan",
            Self::NullScan => "null_scan",
            Self::PingSweep => "ping_sweep",
            Self::AckScan => "ack_scan",
            Self::WindowScan => "window_scan",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Unfiltered => "unfiltered",
            Self::OpenFiltered => "open|filtered",
            Self::ClosedFiltered => "closed|filtered",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OsDetectionMethod {
    TcpFingerprinting,
    PassiveAnalysis,
    BannerGrabbing,
    CombinedMethods,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum VulnerabilitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanCapabilities {
    pub supported_scan_types: Vec<ScanType>,
    pub max_concurrent_targets: usize,
    pub supports_ipv6: bool,
    pub requires_root: bool,
    pub evasion_techniques: Vec<String>,
}

/// Events for the event bus
#[derive(Debug, Clone)]
pub enum ScanEvent {
    ScanStarted {
        session_id: Uuid,
        target_count: usize,
    },
    TargetStarted {
        target: ScanTarget,
    },
    PortDiscovered {
        target: ScanTarget,
        port: u16,
        state: PortState,
        service: Option<String>,
    },
    ServiceDetected {
        target: ScanTarget,
        port: u16,
        service: String,
        version: Option<String>,
    },
    VulnerabilityFound {
        target: ScanTarget,
        vulnerability: Vulnerability,
    },
    OsDetected {
        target: ScanTarget,
        os_info: OsInfo,
        confidence: f32,
    },
    ScanProgress {
        session_id: Uuid,
        completed: usize,
        total: usize,
    },
    ScanCompleted {
        session_id: Uuid,
        results: ScanResults,
    },
    Error {
        target: ScanTarget,
        error: ScannerError,
    },
}
