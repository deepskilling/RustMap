# 📚 RustMap Complete Documentation

**Comprehensive API Reference and Implementation Guide**

*Professional network scanning tool by [Deepskilling Inc](https://deepskilling.com)*

---

## 📖 Table of Contents

1. [**Architecture Overview**](#-architecture-overview)
2. [**Core Modules**](#-core-modules)
3. [**Scanning Engine**](#-scanning-engine)
4. [**Advanced Scanning**](#-advanced-scanning)
5. [**Service Detection**](#-service-detection)
6. [**OS Detection**](#-os-detection)
7. [**Firewall Evasion**](#-firewall-evasion)
8. [**Output & Reporting**](#-output--reporting)
9. [**Configuration System**](#-configuration-system)
10. [**Error Handling**](#-error-handling)
11. [**Logging Framework**](#-logging-framework)
12. [**Performance & Metrics**](#-performance--metrics)
13. [**API Reference**](#-api-reference)
14. [**Examples & Use Cases**](#-examples--use-cases)

---

## 🏗️ Architecture Overview

### SOLID Principles Implementation

RustMap is built following SOLID principles for maintainable, extensible code:

- **Single Responsibility**: Each module handles one specific concern
- **Open/Closed**: Extensible via traits without modifying existing code
- **Liskov Substitution**: All implementations are interchangeable
- **Interface Segregation**: Small, focused traits and interfaces
- **Dependency Inversion**: Depends on abstractions, not concretions

### System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Layer     │────│  Application    │────│   Configuration │
│   (User Input)  │    │     Core        │    │     Manager     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Event System   │    │ Scanning Engine │    │ Metrics/Logging │
│   (Pub/Sub)     │    │   (Core Logic)  │    │   (Observability)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Output/Reports  │    │ Service/OS Det. │    │  Persistence    │
│  (Multi-format) │    │  (Fingerprint)  │    │ (File Storage)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## 🔧 Core Modules

### Application Core (`src/core.rs`)

The central orchestration layer that coordinates all components.

#### `Application` Struct
```rust
pub struct Application {
    pub config: AppConfig,
    pub scanner: Arc<dyn ScanEngine>,
    pub service_detector: Arc<dyn ServiceDetector>,
    pub os_detector: Arc<dyn OsDetector>,
    pub advanced_scanner: Arc<Mutex<dyn AdvancedScanEngine>>,
    pub firewall_evasion: Arc<dyn EvasionTechniques>,
    pub event_bus: Arc<EventBus>,
    pub metrics: Arc<MetricsCollector>,
    pub persistence: Arc<dyn PersistenceManager>,
}
```

#### Key Methods

**`Application::new(config: AppConfig) -> Result<Self>`**
- **Purpose**: Initialize application with all components
- **Dependencies**: Creates scanner, detectors, event system
- **Error Handling**: Returns configuration or initialization errors
- **Performance**: Lazy initialization of heavy components

**`Application::run(cli: Cli) -> Result<()>`**
- **Purpose**: Main execution flow orchestration
- **Process Flow**:
  1. Parse targets and create scan session
  2. Execute primary scanning (TCP/UDP/SYN/etc.)
  3. Perform service detection if enabled
  4. Run OS detection if requested  
  5. Generate and output reports
  6. Persist results to storage
- **Event Publishing**: Emits events for each major step
- **Error Recovery**: Continues execution on non-fatal errors

#### Data Structures

**`ScanTarget`**
```rust
pub struct ScanTarget {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ports: Option<Vec<u16>>,
}
```

**`ScanResults`**
```rust
pub struct ScanResults {
    pub session_id: String,
    pub scan_start: DateTime<Utc>,
    pub scan_end: DateTime<Utc>,
    pub targets_scanned: usize,
    pub ports_scanned: usize,
    pub discoveries: Vec<PortDiscovery>,
    pub service_detections: Vec<ServiceDetection>,
    pub os_detections: Vec<OsDetection>,
    pub scan_statistics: ScanStatistics,
}
```

**`ScanEvent` Enum**
```rust
pub enum ScanEvent {
    ScanStarted { session_id: String, targets: Vec<ScanTarget> },
    PortDiscovered { target: ScanTarget, port: u16, state: PortState },
    ServiceDetected { target: ScanTarget, port: u16, service: ServiceInfo },
    OsDetected { target: ScanTarget, os_info: OsInfo, confidence: f32 },
    ScanCompleted { session_id: String, results: ScanResults },
    ScanError { target: Option<ScanTarget>, error: String },
}
```

---

## 🔍 Scanning Engine

### Core Scanner (`src/scanner.rs`)

The main scanning engine implementing various port scanning techniques.

#### `DefaultScanEngine` Implementation

**`execute_scan(session: ScanSession) -> Result<ScanResults>`**
- **Purpose**: Execute comprehensive scan based on session configuration
- **Concurrency**: Parallel target scanning using tokio tasks
- **Progress Tracking**: Real-time progress updates via events
- **Resource Management**: Controlled concurrent connections

**Scan Type Implementations:**

#### TCP Connect Scan
```rust
async fn tcp_connect_scan(&self, target: &ScanTarget, session: &ScanSession) -> Result<(Vec<PortDiscovery>, usize)>
```
- **Method**: Standard TCP three-way handshake
- **Stealth Level**: Low (fully logged by target)
- **Speed**: Fast, reliable
- **Requirements**: No special privileges
- **Use Case**: General purpose scanning

#### UDP Scan  
```rust
async fn udp_scan(&self, target: &ScanTarget) -> Result<(Vec<PortDiscovery>, usize)>
```
- **Method**: UDP packet probe with ICMP response analysis
- **Challenges**: Stateless protocol, slow responses
- **Detection Logic**: 
  - No response → Open|Filtered
  - ICMP unreachable → Closed
  - Response received → Open
- **Timeout Handling**: Extended timeouts for UDP reliability

#### Ping Sweep
```rust
async fn ping_sweep(&self, target: &ScanTarget) -> Result<(Vec<PortDiscovery>, usize)>
```
- **Method**: ICMP echo request/reply
- **Purpose**: Host discovery before port scanning
- **Fallback**: TCP ping to port 80 if ICMP blocked
- **Performance**: Very fast host enumeration

#### SYN Scan (Stealth)
```rust
async fn syn_scan(&self, target: &ScanTarget, session: &ScanSession) -> Result<(Vec<PortDiscovery>, usize)>
```
- **Method**: Send SYN, analyze response, don't complete handshake
- **Stealth Level**: High (half-open connections)
- **Requirements**: Raw socket access (root privileges)
- **Detection**: SYN/ACK = Open, RST = Closed, No response = Filtered

#### Advanced Scan Types
```rust
async fn fin_scan(&self, target: &ScanTarget, session: &ScanSession) -> Result<(Vec<PortDiscovery>, usize)>
async fn xmas_scan(&self, target: &ScanTarget, session: &ScanSession) -> Result<(Vec<PortDiscovery>, usize)>
async fn null_scan(&self, target: &ScanTarget, session: &ScanSession) -> Result<(Vec<PortDiscovery>, usize)>
```
- **FIN Scan**: FIN flag set, exploits RFC compliance
- **Xmas Scan**: FIN+PSH+URG flags (packet "lit up like Christmas tree")
- **Null Scan**: No flags set, minimal packet footprint
- **Stealth**: Very high, bypasses many firewalls
- **Limitations**: Less reliable than SYN scan

### Scan Capabilities

```rust
pub struct ScanCapabilities {
    pub supported_scan_types: Vec<ScanType>,
    pub max_concurrent_targets: usize,
    pub supports_ipv6: bool,
    pub requires_root: bool,
    pub evasion_techniques: Vec<String>,
}
```

---

## ⚡ Advanced Scanning

### Raw Socket Scanner (`src/advanced_scanner.rs`)

Professional-grade scanning using raw sockets for maximum control.

#### `AdvancedScanner` Implementation

**`init_raw_socket() -> Result<()>`**
- **Purpose**: Initialize raw socket with proper permissions
- **Platform Handling**: Cross-platform socket creation
- **Privilege Check**: Validates root/administrator access
- **Socket Configuration**: Sets IP header inclusion options

**`syn_scan(target: &ScanTarget, port: u16) -> Result<PortState>`**
- **Packet Crafting**: Manual TCP header construction
- **Timing Analysis**: Response time measurement
- **State Detection**:
  ```rust
  match response_flags {
      SYN | ACK => PortState::Open,
      RST => PortState::Closed,
      _ => PortState::Filtered,
  }
  ```

**`packet_crafting` Module Functions:**
```rust
fn craft_tcp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, flags: u8) -> Vec<u8>
fn calculate_tcp_checksum(packet: &[u8]) -> u16
fn craft_ip_header(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload_len: u16) -> Vec<u8>
```

#### Privilege Management

**`has_root_privileges() -> bool`**
- **Unix/Linux**: Checks effective UID = 0
- **Windows**: Validates administrator token
- **macOS**: Verifies root access for raw sockets

### Scan Techniques

#### Stealth Scanning Patterns
```rust
pub enum StealthLevel {
    Normal,      // Standard scan timing
    Polite,      // Longer delays between probes  
    Sneaky,      // Very slow, minimal footprint
    Paranoid,    // Extremely slow, maximum stealth
}
```

---

## 🔎 Service Detection

### Service Detector (`src/service.rs`)

Identifies services running on discovered open ports.

#### `DefaultServiceDetector` Implementation

**`detect_service(target: &ScanTarget, port: u16) -> Result<ServiceInfo>`**
- **Multi-stage Detection**:
  1. Port-based service assumption
  2. Banner grabbing
  3. Probe-response analysis
  4. Version fingerprinting

#### Detection Methods

**Banner Grabbing**
```rust
async fn grab_banner(&self, target: &ScanTarget, port: u16) -> Result<String>
```
- **Protocols Supported**: HTTP, SSH, FTP, SMTP, POP3, IMAP
- **Timeout Handling**: Service-specific timeouts
- **Data Collection**: Service banners, version strings

**Service Probing**
```rust
async fn probe_service(&self, target: &ScanTarget, port: u16, service_type: &str) -> Result<ServiceInfo>
```
- **Active Probing**: Send protocol-specific requests
- **Response Analysis**: Parse service responses
- **Version Extraction**: Extract version information

#### Supported Services

| Service | Port(s) | Detection Method | Version Detection |
|---------|---------|------------------|------------------|
| HTTP    | 80,8080,8000 | Banner + Headers | Server header parsing |
| HTTPS   | 443,8443 | TLS handshake | Certificate analysis |
| SSH     | 22 | Protocol banner | Version string parsing |
| FTP     | 21 | Welcome banner | Server identification |
| SMTP    | 25,587,465 | EHLO response | Server capabilities |
| DNS     | 53 | Query response | Version.bind query |
| Telnet  | 23 | Login prompt | System identification |

#### ServiceInfo Structure
```rust
pub struct ServiceInfo {
    pub service_name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: HashMap<String, String>,
    pub cpe: Option<String>,
    pub confidence: f32,
}
```

---

## 🖥️ OS Detection

### OS Detector (`src/os_detection.rs`)

Advanced operating system fingerprinting and device identification.

#### Detection Methodologies

**Active OS Detection**
```rust
async fn detect_os_active(&self, target: &ScanTarget) -> Result<OsInfo>
```
- **TCP Stack Fingerprinting**: Analyzes TCP implementation differences
- **Probe Techniques**:
  - Initial SYN probe analysis
  - TCP window size examination  
  - TTL (Time To Live) analysis
  - TCP options parsing
  - Fragment handling behavior

**Passive OS Detection**  
```rust
async fn passive_os_detection(&self, network_data: &NetworkBehavior) -> Result<OsInfo>
```
- **Traffic Analysis**: Monitors existing network traffic
- **Pattern Recognition**: Identifies OS-specific behaviors
- **Non-intrusive**: No additional packets sent

#### Fingerprinting Techniques

**TTL Analysis**
```rust
fn analyze_ttl_patterns(&self, ttl_values: &[u8]) -> OsFamily
```
- **Windows**: Typically 128, 64
- **Linux**: Usually 64
- **macOS**: Generally 64
- **Network Equipment**: Various patterns

**TCP Window Size Analysis**
```rust
fn analyze_window_sizes(&self, window_sizes: &[u16]) -> Vec<OsHint>
```
- **Default Window Sizes**: OS-specific defaults
- **Scaling Behavior**: Window scaling patterns
- **Maximum Segment Size**: MSS patterns

**TCP Options Fingerprinting**
```rust
fn analyze_tcp_options(&self, options: &[String]) -> Vec<OsHint>
```
- **Option Ordering**: OS-specific option sequences
- **SACK Implementation**: Selective ACK patterns
- **Timestamp Behavior**: TCP timestamp handling

#### Confidence Scoring

```rust
pub fn get_confidence_score(&self, os_info: &OsInfo) -> f32
```
- **Base Score**: 0.3 (minimum confidence)
- **Version Info**: +0.2 if version detected
- **CPE Match**: +0.2 if Common Platform Enumeration found
- **TTL Match**: +0.1 if TTL patterns match
- **Window Match**: +0.1 if window sizes match
- **Maximum**: 1.0 (100% confidence)

#### OsInfo Structure
```rust
pub struct OsInfo {
    pub os_family: String,        // e.g., "Linux", "Windows"
    pub os_name: Option<String>,  // e.g., "Ubuntu", "Windows 10"
    pub version: Option<String>,  // e.g., "22.04", "21H2"
    pub device_type: String,      // e.g., "general purpose", "router"
    pub cpe: Option<String>,      // CPE identifier
    pub network_behavior: NetworkBehavior,
}

pub struct NetworkBehavior {
    pub ttl_patterns: Vec<u8>,
    pub window_sizes: Vec<u16>, 
    pub tcp_options: Vec<String>,
    pub fragment_behavior: Option<String>,
}
```

---

## 🛡️ Firewall Evasion

### Evasion Techniques (`src/firewall_evasion.rs`)

Advanced techniques to bypass firewalls, IDS, and security systems.

#### `FirewallEvasion` Implementation

**Decoy Scanning**
```rust
async fn decoy_scan(&self, targets: &[ScanTarget], ports: &[u16], decoy_count: usize) -> Result<Vec<PortDiscovery>>
```
- **Concept**: Hide real scan among fake scans from decoy IPs
- **Implementation**: Simultaneous scans from multiple source IPs
- **Effectiveness**: Makes attack attribution difficult
- **Configuration**: Customizable decoy count and IP selection

**Packet Fragmentation**
```rust
async fn fragment_packets(&self, targets: &[ScanTarget], ports: &[u16]) -> Result<Vec<PortDiscovery>>
```
- **Purpose**: Split packets to evade signature detection
- **Method**: Fragment IP packets at unusual boundaries
- **Bypass**: Many IDS systems don't reassemble fragments
- **Challenges**: Some modern systems detect fragmentation attacks

**Source IP Spoofing**
```rust
async fn spoof_source_ip(&self, targets: &[ScanTarget], ports: &[u16], spoofed_ip: IpAddr) -> Result<Vec<PortDiscovery>>
```
- **Technique**: Use fake source IP addresses
- **Limitations**: Responses go to spoofed IP (blind scanning)
- **Use Cases**: Reconnaissance, attack attribution confusion
- **Requirements**: Raw socket access, careful routing

#### Timing-based Evasion

**Slow Scanning**
```rust
async fn slow_scan(&self, targets: &[ScanTarget], ports: &[u16], profile_name: &str) -> Result<Vec<PortDiscovery>>
```
- **Rate Limiting**: Extremely slow probe rates
- **IDS Evasion**: Below detection thresholds
- **Timing Profiles**:
  ```rust
  pub struct TimingProfile {
      pub min_delay_ms: u64,
      pub max_delay_ms: u64,
      pub jitter_percentage: f32,
  }
  ```

**Timing Templates**
- **Paranoid (T0)**: 5+ minute delays between probes
- **Sneaky (T1)**: 15 second delays  
- **Polite (T2)**: 0.4 second delays
- **Normal (T3)**: No delays (default)
- **Aggressive (T4)**: Parallel scanning
- **Insane (T5)**: Maximum speed

#### Advanced Evasion

**Idle Scanning**
```rust
async fn idle_scan(&self, targets: &[ScanTarget], zombie_ip: IpAddr, ports: &[u16]) -> Result<Vec<PortDiscovery>>
```
- **Concept**: Use "zombie" host to perform scan
- **Stealth**: Attacker's IP never directly contacts target
- **Requirements**: Predictable IP ID incrementation on zombie
- **Complexity**: Most advanced evasion technique

**Traffic Noise Generation**
```rust
async fn generate_noise(&self, target_network: &str, intensity: NoiseLevel) -> Result<()>
```
- **Purpose**: Hide real scans in background noise
- **Methods**: Random port probes, fake service requests
- **Intensity Levels**: Low, Medium, High noise generation
- **Risk**: May trigger additional security attention

#### Scan Randomization

**Order Randomization**
```rust
async fn randomize_scan_order(&self, targets: &[ScanTarget], ports: &[u16]) -> Result<Vec<PortDiscovery>>
```
- **Port Order**: Randomize port scanning sequence
- **Target Order**: Randomize target scanning sequence  
- **Timing**: Random delays between probes
- **Pattern Breaking**: Avoid predictable scan patterns

---

## 📊 Output & Reporting

### Report Generation (`src/reporting.rs`)

Multi-format report generation with professional layouts.

#### Supported Output Formats

**JSON Reports**
```rust
async fn generate_json_report(&self, results: &ScanResults) -> Result<String>
```
- **Structure**: Hierarchical JSON with full scan data
- **Usage**: API integration, automated processing
- **Features**: Timestamps, statistics, detailed findings
- **Example**:
```json
{
  "session_id": "scan-2025-01-20-12-34-56",
  "scan_start": "2025-01-20T12:34:56Z",
  "targets_scanned": 1,
  "discoveries": [
    {
      "target": "192.168.1.1",
      "port": 80,
      "state": "open",
      "service": "http",
      "version": "Apache/2.4.41"
    }
  ]
}
```

**XML Reports (Nmap Compatible)**
```rust
async fn generate_xml_report(&self, results: &ScanResults) -> Result<String>
```
- **Compatibility**: Nmap XML schema compatible
- **Tool Integration**: Works with existing Nmap tools
- **Validation**: Schema-validated XML output
- **Processing**: Can be parsed by security tools

**Human-Readable Reports**
```rust
async fn generate_human_report(&self, results: &ScanResults) -> Result<String>
```
- **Format**: Markdown with clear sections
- **Readability**: Executive summary, detailed findings
- **Visualization**: Tables, bullet points, status indicators
- **Sections**:
  - Executive Summary
  - Scan Configuration
  - Host Discovery Results
  - Port Scan Results  
  - Service Detection Results
  - OS Detection Results
  - Recommendations

**CSV Export**
```rust
async fn generate_csv_report(&self, results: &ScanResults) -> Result<String>
```
- **Usage**: Spreadsheet analysis, data processing
- **Columns**: Target, Port, State, Service, Version, Confidence
- **Import**: Compatible with Excel, Google Sheets
- **Automation**: Easy to parse programmatically

#### Report Customization

**Report Configuration**
```rust
pub struct ReportConfig {
    pub include_closed_ports: bool,
    pub include_scan_statistics: bool,
    pub include_timing_info: bool,
    pub detailed_service_info: bool,
    pub include_os_detection: bool,
    pub executive_summary: bool,
}
```

**Template System**
```rust
pub trait ReportTemplate {
    fn format_scan_results(&self, results: &ScanResults) -> Result<String>;
    fn format_port_discovery(&self, discovery: &PortDiscovery) -> String;
    fn format_service_detection(&self, detection: &ServiceDetection) -> String;
}
```

---

## ⚙️ Configuration System

### Configuration Management (`src/config.rs`)

Hierarchical configuration system supporting multiple sources.

#### Configuration Structure

**Main Configuration**
```rust
pub struct AppConfig {
    pub scanning: ScanningConfig,
    pub performance: PerformanceConfig,
    pub network: NetworkConfig,
    pub output: OutputConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
}
```

#### Configuration Sections

**Scanning Configuration**
```rust
pub struct ScanningConfig {
    pub default_scan_type: String,      // "tcp_connect", "syn_scan"
    pub default_ports: String,          // "1-1000", "top-100"
    pub service_detection: bool,        // Enable service detection
    pub os_detection: bool,             // Enable OS detection  
    pub vuln_scanning: bool,            // Enable vulnerability scanning
    pub timing_template: u8,            // 0-5 timing template
}
```

**Performance Configuration**
```rust
pub struct PerformanceConfig {
    pub max_concurrent_hosts: usize,    // Parallel host scanning
    pub scan_batch_size: usize,         // Ports per batch
    pub worker_threads: usize,          // Thread pool size (0=auto)
    pub connection_timeout_secs: u64,   // TCP connection timeout
    pub dns_timeout_secs: u64,          // DNS resolution timeout
}
```

**Network Configuration**
```rust
pub struct NetworkConfig {
    pub interface: Option<String>,       // Network interface name
    pub source_ip: Option<IpAddr>,      // Source IP for scanning
    pub ipv6_enabled: bool,             // IPv6 support
    pub dns_servers: Vec<IpAddr>,       // Custom DNS servers
    pub max_retries: u32,               // Connection retry attempts
}
```

#### Configuration Loading

**Hierarchical Loading**
```rust
impl AppConfig {
    pub fn load(config_path: &str) -> Result<Self> {
        // 1. Load default configuration
        // 2. Override with config file
        // 3. Override with environment variables
        // 4. Override with command line arguments
    }
}
```

**Environment Variable Support**
- `RUSTMAP_SCAN_TYPE`: Override default scan type
- `RUSTMAP_PORTS`: Override default port range
- `RUSTMAP_THREADS`: Override worker thread count
- `RUSTMAP_TIMEOUT`: Override connection timeout

**Configuration Validation**
```rust
impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        // Validate port ranges
        // Check timing template bounds
        // Verify network interface exists
        // Validate IP addresses
    }
}
```

---

## 🚨 Error Handling

### Error System (`src/error.rs`)

Comprehensive error handling with context and recovery strategies.

#### Error Categories

**`ScannerError` Enum**
```rust
pub enum ScannerError {
    Network(String),           // Network connectivity issues
    Permission(String, String), // Permission/privilege errors
    Configuration(String),     // Invalid configuration
    Timeout(String, u64),     // Operation timeouts
    IO(String, std::io::Error), // File system errors
    Parse(String),            // Data parsing errors
    Service(String),          // Service detection errors
    Internal(String),         // Internal logic errors
}
```

#### Error Context and Recovery

**Network Errors**
```rust
impl ScannerError {
    pub fn network(msg: String) -> Self {
        ScannerError::Network(msg)
    }
    
    pub fn is_recoverable(&self) -> bool {
        matches!(self, 
            ScannerError::Network(_) | 
            ScannerError::Timeout(_, _)
        )
    }
}
```

**Permission Errors**
```rust
impl ScannerError {
    pub fn permission(operation: &str, reason: &str) -> Self {
        ScannerError::Permission(operation.to_string(), reason.to_string())
    }
    
    pub fn requires_elevation(&self) -> bool {
        matches!(self, ScannerError::Permission(_, _))
    }
}
```

#### Error Recovery Strategies

**Retry Logic**
```rust
pub async fn retry_with_backoff<T, F, Fut>(
    operation: F,
    max_attempts: usize,
    base_delay: Duration,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    // Exponential backoff retry implementation
}
```

**Graceful Degradation**
```rust
impl DefaultScanEngine {
    async fn scan_with_fallback(&self, target: &ScanTarget) -> Result<Vec<PortDiscovery>> {
        // Try advanced scan first
        if let Ok(results) = self.syn_scan(target).await {
            return Ok(results);
        }
        
        // Fallback to basic scan
        warn!("Advanced scan failed, falling back to TCP connect scan");
        self.tcp_connect_scan(target).await
    }
}
```

---

## 📝 Logging Framework

### Logging System (`src/logging.rs`)

Structured, configurable logging with multiple output targets.

#### Logging Configuration

**Log Levels**
- **ERROR**: Critical errors requiring attention
- **WARN**: Warning conditions, degraded functionality  
- **INFO**: General informational messages
- **DEBUG**: Detailed debugging information
- **TRACE**: Very detailed tracing information

**Output Destinations**
```rust
pub struct LoggingConfig {
    pub level: String,                    // Log level filter
    pub format: LogFormat,               // Output format
    pub outputs: Vec<LogOutput>,         // Output destinations
    pub enable_colors: bool,             // Colorized output
    pub include_timestamps: bool,        // Timestamp inclusion
    pub include_module_path: bool,       // Module path in logs
}

pub enum LogOutput {
    Console,                    // Standard output
    File(PathBuf),             // Log file
    RotatingFile {             // Rotating log files
        path: PathBuf,
        max_size_mb: u64,
        max_files: u32,
    },
    Syslog,                    // System log
}
```

#### Structured Logging

**Event-based Logging**
```rust
use tracing::{info, warn, error, debug, trace, instrument};

#[instrument(skip(self), fields(target = %target.ip()))]
async fn scan_target(&self, target: &ScanTarget) -> Result<Vec<PortDiscovery>> {
    info!("Starting scan of target");
    
    let start_time = Instant::now();
    let results = self.perform_scan(target).await;
    let duration = start_time.elapsed();
    
    match &results {
        Ok(discoveries) => {
            info!(
                discoveries_count = discoveries.len(),
                duration_ms = duration.as_millis(),
                "Scan completed successfully"
            );
        }
        Err(error) => {
            error!(
                error = %error,
                duration_ms = duration.as_millis(), 
                "Scan failed"
            );
        }
    }
    
    results
}
```

**Contextual Information**
```rust
// Automatic context from span
let span = info_span!("port_scan", target = %target_ip, port = port);
let _enter = span.enter();

info!("Attempting connection");  // Automatically includes target and port
```

#### Performance Monitoring

**Timing Integration**
```rust
use tracing::instrument;

#[instrument]
async fn service_detection(&self, target: &ScanTarget, port: u16) -> Result<ServiceInfo> {
    // Automatic timing and error logging
    let service_info = self.detect_service_internal(target, port).await?;
    Ok(service_info)
}
```

---

## 📈 Performance & Metrics

### Metrics Collection (`src/metrics.rs`)

Real-time performance monitoring and statistics collection.

#### Metrics Categories

**Scan Performance Metrics**
```rust
pub struct ScanMetrics {
    pub scan_duration_seconds: f64,
    pub targets_scanned: u64,
    pub ports_scanned: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub timeouts: u64,
    pub average_response_time_ms: f64,
}
```

**System Resource Metrics**
```rust
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub active_connections: u32,
    pub thread_count: u32,
}
```

**Detection Accuracy Metrics**
```rust
pub struct DetectionMetrics {
    pub service_detection_rate: f64,
    pub os_detection_rate: f64,
    pub service_accuracy: f64,
    pub os_accuracy: f64,
    pub false_positive_rate: f64,
}
```

#### Metrics Collection

**Real-time Monitoring**
```rust
use metrics::{counter, histogram, gauge};

impl DefaultScanEngine {
    async fn scan_port(&self, target: &ScanTarget, port: u16) -> Result<PortState> {
        counter!("ports_scanned_total").increment(1);
        
        let start_time = Instant::now();
        let result = self.probe_port(target, port).await;
        let duration = start_time.elapsed();
        
        histogram!("port_scan_duration_ms").record(duration.as_millis() as f64);
        
        match &result {
            Ok(PortState::Open) => counter!("ports_open_total").increment(1),
            Ok(PortState::Closed) => counter!("ports_closed_total").increment(1),
            Ok(PortState::Filtered) => counter!("ports_filtered_total").increment(1),
            Err(_) => counter!("scan_errors_total").increment(1),
        }
        
        result
    }
}
```

**Health Checks**
```rust
pub struct HealthCheck {
    pub status: HealthStatus,
    pub last_check: DateTime<Utc>,
    pub details: HashMap<String, String>,
}

pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl MetricsCollector {
    pub async fn health_check(&self) -> HealthCheck {
        let mut status = HealthStatus::Healthy;
        let mut details = HashMap::new();
        
        // Check system resources
        if self.get_cpu_usage() > 90.0 {
            status = HealthStatus::Degraded;
            details.insert("cpu".to_string(), "High CPU usage".to_string());
        }
        
        // Check memory usage
        if self.get_memory_usage() > 90.0 {
            status = HealthStatus::Degraded;  
            details.insert("memory".to_string(), "High memory usage".to_string());
        }
        
        HealthCheck {
            status,
            last_check: Utc::now(),
            details,
        }
    }
}
```

#### Performance Optimization

**Connection Pooling**
```rust
pub struct ConnectionPool {
    max_connections: usize,
    active_connections: Arc<Semaphore>,
    connection_cache: Arc<Mutex<HashMap<String, Connection>>>,
}
```

**Batch Processing**
```rust
impl DefaultScanEngine {
    async fn scan_ports_batch(&self, target: &ScanTarget, ports: &[u16]) -> Result<Vec<PortDiscovery>> {
        let batch_size = self.config.performance.scan_batch_size;
        let mut all_discoveries = Vec::new();
        
        for port_batch in ports.chunks(batch_size) {
            let batch_results = stream::iter(port_batch)
                .map(|&port| self.scan_port(target, port))
                .buffer_unordered(self.config.performance.max_concurrent_hosts)
                .try_collect::<Vec<_>>()
                .await?;
            
            all_discoveries.extend(batch_results);
        }
        
        Ok(all_discoveries)
    }
}
```

---

## 🔌 API Reference

### Public API

The RustMap library can be used as a Rust crate in other applications.

#### Basic Usage Example

```rust
use nmap_scanner::{
    config::AppConfig,
    core::{Application, ScanTarget},
    cli::Cli,
};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = AppConfig::load("config.toml")?;
    
    // Create application instance
    let mut app = Application::new(config).await?;
    
    // Create scan target
    let target = ScanTarget {
        ip: "192.168.1.1".parse::<IpAddr>()?,
        hostname: Some("router.local".to_string()),
        ports: None, // Use default port range
    };
    
    // Create CLI configuration
    let cli = Cli {
        targets: vec!["192.168.1.1".to_string()],
        tcp_scan: true,
        service_detection: true,
        os_detection: true,
        format: Some("json".to_string()),
        output: Some("scan_results.json".to_string()),
        ..Default::default()
    };
    
    // Execute scan
    let results = app.run(cli).await?;
    
    println!("Scan completed successfully!");
    Ok(())
}
```

#### Advanced API Usage

**Custom Scanner Implementation**
```rust
use nmap_scanner::{
    scanner::{ScanEngine, ScanSession, ScanResults},
    core::ScanTarget,
};
use async_trait::async_trait;

pub struct CustomScanner {
    // Custom implementation fields
}

#[async_trait]
impl ScanEngine for CustomScanner {
    async fn execute_scan(&self, session: ScanSession) -> Result<ScanResults> {
        // Custom scanning logic
        todo!("Implement custom scanning")
    }
    
    fn capabilities(&self) -> ScanCapabilities {
        // Define scanner capabilities
        todo!("Define capabilities")
    }
}
```

**Event Handling**
```rust
use nmap_scanner::{
    core::{EventBus, ScanEvent},
    event::EventHandler,
};

pub struct CustomEventHandler;

#[async_trait]
impl EventHandler<ScanEvent> for CustomEventHandler {
    async fn handle(&self, event: ScanEvent) -> Result<()> {
        match event {
            ScanEvent::PortDiscovered { target, port, state } => {
                println!("Found {}:{} - {}", target.ip(), port, state);
            }
            ScanEvent::ScanCompleted { session_id, results } => {
                println!("Scan {} completed with {} discoveries", 
                        session_id, results.discoveries.len());
            }
            _ => {}
        }
        Ok(())
    }
}
```

### Trait Definitions

#### Core Traits

**`ScanEngine`**
```rust
#[async_trait]
pub trait ScanEngine: Send + Sync {
    async fn execute_scan(&self, session: ScanSession) -> Result<ScanResults>;
    fn capabilities(&self) -> ScanCapabilities;
    async fn health_check(&self) -> Result<HealthStatus>;
}
```

**`ServiceDetector`**  
```rust
#[async_trait]
pub trait ServiceDetector: Send + Sync {
    async fn detect_service(&self, target: &ScanTarget, port: u16) -> Result<ServiceInfo>;
    async fn detect_version(&self, target: &ScanTarget, port: u16, service: &str) -> Result<Option<String>>;
    fn supported_services(&self) -> Vec<String>;
}
```

**`OsDetector`**
```rust
#[async_trait] 
pub trait OsDetector: Send + Sync {
    async fn detect_os(&self, target: &ScanTarget) -> Result<OsInfo>;
    async fn passive_os_detection(&self, network_data: &NetworkBehavior) -> Result<OsInfo>;
    fn get_confidence_score(&self, os_info: &OsInfo) -> f32;
}
```

---

## 💡 Examples & Use Cases

### Common Scanning Scenarios

#### Network Discovery
```rust
// Discover all hosts in a subnet
let cli = Cli {
    targets: vec!["192.168.1.0/24".to_string()],
    ping_scan: true,
    format: Some("json".to_string()),
    output: Some("network_discovery.json".to_string()),
    ..Default::default()
};
```

#### Web Server Assessment
```rust  
// Comprehensive web server scanning
let cli = Cli {
    targets: vec!["webserver.example.com".to_string()],
    tcp_scan: true,
    ports: Some("80,443,8080,8443,3000,3001,4000,4001,5000,5001".to_string()),
    service_detection: true,
    os_detection: true,
    format: Some("xml".to_string()),
    output: Some("webserver_scan.xml".to_string()),
    timing_template: Some(3), // Normal timing
    ..Default::default()
};
```

#### Stealth Reconnaissance
```rust
// Maximum stealth scanning
let cli = Cli {
    targets: vec!["target.internal".to_string()],
    fin_scan: true,  // Stealth scan type
    ports: Some("22,80,443,3389,5985,5986".to_string()),
    timing_template: Some(1), // Sneaky timing
    format: Some("json".to_string()),
    output: Some("stealth_scan.json".to_string()),
    ..Default::default()
};
```

#### Security Assessment
```rust
// Comprehensive security assessment
let cli = Cli {
    targets: vec!["internal-server.company.com".to_string()],
    syn_scan: true,  // Requires root
    ports: Some("1-65535".to_string()),  // Full port range
    service_detection: true,
    os_detection: true,
    vuln_scanning: Some(true),
    format: Some("xml".to_string()),
    output: Some("security_assessment.xml".to_string()),
    timing_template: Some(4), // Aggressive timing
    ..Default::default()
};
```

### Integration Examples

#### CI/CD Pipeline Integration
```rust
// Automated security scanning in CI/CD
use nmap_scanner::{config::AppConfig, core::Application, cli::Cli};

pub async fn security_scan_pipeline(target: &str) -> Result<bool> {
    let config = AppConfig::load("ci_config.toml")?;
    let mut app = Application::new(config).await?;
    
    let cli = Cli {
        targets: vec![target.to_string()],
        tcp_scan: true,
        ports: Some("21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6379".to_string()),
        service_detection: true,
        format: Some("json".to_string()),
        output: Some("pipeline_scan.json".to_string()),
        timing_template: Some(4),
        ..Default::default()
    };
    
    match app.run(cli).await {
        Ok(_) => {
            // Parse results and check for security issues
            let results = parse_scan_results("pipeline_scan.json")?;
            Ok(validate_security_posture(&results))
        }
        Err(e) => {
            eprintln!("Security scan failed: {}", e);
            Ok(false)
        }
    }
}
```

#### Monitoring Integration
```rust
// Integration with monitoring systems
use nmap_scanner::metrics::MetricsCollector;
use prometheus::Registry;

pub async fn setup_monitoring() -> Result<()> {
    let registry = Registry::new();
    let metrics = MetricsCollector::new();
    
    // Register metrics with Prometheus
    metrics.register_with_registry(&registry)?;
    
    // Start metrics server
    tokio::spawn(async move {
        let metrics_server = warp::path("metrics")
            .map(move || {
                let encoder = prometheus::TextEncoder::new();
                let metric_families = registry.gather();
                encoder.encode_to_string(&metric_families).unwrap()
            });
        
        warp::serve(metrics_server)
            .run(([0, 0, 0, 0], 9090))
            .await;
    });
    
    Ok(())
}
```

### Custom Extensions

#### Custom Service Detection
```rust
use nmap_scanner::service::{ServiceDetector, ServiceInfo};

pub struct CustomServiceDetector;

#[async_trait]
impl ServiceDetector for CustomServiceDetector {
    async fn detect_service(&self, target: &ScanTarget, port: u16) -> Result<ServiceInfo> {
        match port {
            9200 => {
                // Custom Elasticsearch detection
                let banner = self.grab_banner(target, port).await?;
                if banner.contains("elasticsearch") {
                    Ok(ServiceInfo {
                        service_name: "elasticsearch".to_string(),
                        version: extract_es_version(&banner),
                        product: Some("Elasticsearch".to_string()),
                        confidence: 0.9,
                        ..Default::default()
                    })
                } else {
                    Err(ScannerError::service("Unknown service on port 9200".to_string()))
                }
            }
            _ => {
                // Delegate to default detector
                Err(ScannerError::service("Service not recognized".to_string()))
            }
        }
    }
    
    fn supported_services(&self) -> Vec<String> {
        vec!["elasticsearch".to_string()]
    }
}
```

---

## 🔗 References

### External Resources

- **Network Scanning Techniques**: [Nmap Network Scanning](https://nmap.org/book/)
- **TCP/IP Protocol Details**: [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)
- **OS Fingerprinting**: [Remote OS Detection via TCP/IP Stack Fingerprinting](https://nmap.org/osdetect/)
- **Firewall Evasion**: [Bypassing Firewalls and Intrusion Detection Systems](https://nmap.org/book/firewalls.html)

### Related Tools and Standards

- **Nmap Compatibility**: Output format compatibility with Nmap XML
- **CVE Integration**: Common Vulnerabilities and Exposures database
- **CPE Matching**: Common Platform Enumeration for OS identification
- **OWASP Standards**: Open Web Application Security Project guidelines

---

**RustMap Documentation** - *Complete Implementation Reference*

**© 2025 Deepskilling Inc** | [Website](https://deepskilling.com) | [Contact](mailto:contact@deepskilling.com)

*Built with ❤️ and Rust for the cybersecurity community*
