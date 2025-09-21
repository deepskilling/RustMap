//! Comprehensive metrics and monitoring system
//!
//! Provides application performance monitoring with:
//! - Real-time performance metrics
//! - Resource usage tracking
//! - Scan statistics and analytics
//! - Health checks and system status
//! - Prometheus metrics export

use metrics::{counter, gauge, histogram};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use sysinfo::{CpuExt, System, SystemExt};

use crate::{
    config::AppConfig,
    core::{ScanResults, ScanType},
    error::Result,
};

/// Main metrics collector and exporter
pub struct MetricsCollector {
    start_time: Instant,
    scan_counters: Arc<RwLock<ScanCounters>>,
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,
    system_metrics: Arc<RwLock<SystemMetrics>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            scan_counters: Arc::new(RwLock::new(ScanCounters::default())),
            performance_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
        }
    }

    /// Initialize metrics system with configuration
    pub async fn init_with_config(config: &AppConfig) -> Result<Self> {
        let collector = Self::new();
        
        // Prometheus metrics disabled for now
        if false {
            collector.setup_prometheus_exporter("").await?;
        }
        
        // Start system metrics collection
        collector.start_system_monitoring().await;
        
        Ok(collector)
    }

    /// Record scan start event
    pub async fn record_scan_start(&self, scan_type: &ScanType, target_count: usize) {
        let mut counters = self.scan_counters.write().await;
        counters.scans_started.fetch_add(1, Ordering::Relaxed);
        counters.targets_queued.fetch_add(target_count as u64, Ordering::Relaxed);
        
        // Prometheus metrics
        counter!("scans_started_total", 1, "scan_type" => scan_type.as_str());
        gauge!("targets_queued", target_count as f64);
    }

    /// Record scan completion
    pub async fn record_scan_completion(&self, results: &ScanResults) {
        let mut counters = self.scan_counters.write().await;
        counters.scans_completed.fetch_add(1, Ordering::Relaxed);
        counters.total_ports_scanned.fetch_add(results.total_ports_scanned as u64, Ordering::Relaxed);
        counters.services_discovered.fetch_add(results.services.len() as u64, Ordering::Relaxed);
        counters.vulnerabilities_found.fetch_add(results.vulnerabilities.len() as u64, Ordering::Relaxed);
        
        // Performance metrics
        let mut perf = self.performance_metrics.write().await;
        perf.record_scan_duration(results.duration);
        perf.record_throughput(results.total_ports_scanned, results.duration);
        
        // Prometheus metrics
        counter!("scans_completed_total", 1);
        counter!("ports_scanned_total", results.total_ports_scanned as u64);
        counter!("services_discovered_total", results.services.len() as u64);
        counter!("vulnerabilities_found_total", results.vulnerabilities.len() as u64);
        histogram!("scan_duration_seconds", results.duration.as_secs_f64());
    }

    /// Record port discovery
    pub async fn record_port_discovery(&self, port: u16, is_open: bool) {
        let mut counters = self.scan_counters.write().await;
        if is_open {
            counters.open_ports_found.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.closed_ports_found.fetch_add(1, Ordering::Relaxed);
        }
        
        counter!("ports_discovered_total", 1, "state" => if is_open { "open" } else { "closed" });
    }

    /// Record error occurrence
    pub async fn record_error(&self, error_type: &str, is_recoverable: bool) {
        let counters = self.scan_counters.write().await;
        counters.errors_encountered.fetch_add(1, Ordering::Relaxed);
        if !is_recoverable {
            counters.fatal_errors.fetch_add(1, Ordering::Relaxed);
        }
        
        let error_type_owned = error_type.to_string();
        counter!("errors_total", 1, "type" => error_type_owned, "recoverable" => is_recoverable.to_string());
    }

    /// Get current scan statistics
    pub async fn get_scan_stats(&self) -> ScanStats {
        let counters = self.scan_counters.read().await;
        let perf = self.performance_metrics.read().await;
        
        ScanStats {
            scans_started: counters.scans_started.load(Ordering::Relaxed),
            scans_completed: counters.scans_completed.load(Ordering::Relaxed),
            targets_queued: counters.targets_queued.load(Ordering::Relaxed),
            targets_completed: counters.targets_completed.load(Ordering::Relaxed),
            total_ports_scanned: counters.total_ports_scanned.load(Ordering::Relaxed),
            open_ports_found: counters.open_ports_found.load(Ordering::Relaxed),
            closed_ports_found: counters.closed_ports_found.load(Ordering::Relaxed),
            services_discovered: counters.services_discovered.load(Ordering::Relaxed),
            vulnerabilities_found: counters.vulnerabilities_found.load(Ordering::Relaxed),
            errors_encountered: counters.errors_encountered.load(Ordering::Relaxed),
            fatal_errors: counters.fatal_errors.load(Ordering::Relaxed),
            average_scan_duration: perf.average_scan_duration,
            current_throughput: perf.current_throughput,
            uptime: self.start_time.elapsed(),
        }
    }

    /// Get system health status
    pub async fn get_health_status(&self) -> HealthStatus {
        let system = self.system_metrics.read().await;
        let scan_stats = self.get_scan_stats().await;
        
        let memory_health = if system.memory_usage_percent < 80.0 { 
            ComponentHealth::Healthy 
        } else if system.memory_usage_percent < 95.0 { 
            ComponentHealth::Warning 
        } else { 
            ComponentHealth::Critical 
        };
        
        let cpu_health = if system.cpu_usage_percent < 80.0 { 
            ComponentHealth::Healthy 
        } else if system.cpu_usage_percent < 95.0 { 
            ComponentHealth::Warning 
        } else { 
            ComponentHealth::Critical 
        };
        
        let error_rate = if scan_stats.scans_completed > 0 {
            (scan_stats.errors_encountered as f64 / scan_stats.scans_completed as f64) * 100.0
        } else {
            0.0
        };
        
        let error_health = if error_rate < 5.0 { 
            ComponentHealth::Healthy 
        } else if error_rate < 15.0 { 
            ComponentHealth::Warning 
        } else { 
            ComponentHealth::Critical 
        };
        
        let overall_status = match (&memory_health, &cpu_health, &error_health) {
            (ComponentHealth::Healthy, ComponentHealth::Healthy, ComponentHealth::Healthy) => ComponentHealth::Healthy,
            (ComponentHealth::Critical, _, _) | (_, ComponentHealth::Critical, _) | (_, _, ComponentHealth::Critical) => ComponentHealth::Critical,
            _ => ComponentHealth::Warning,
        };
        
        HealthStatus {
            overall: overall_status,
            components: HashMap::from([
                ("memory".to_string(), memory_health),
                ("cpu".to_string(), cpu_health),
                ("error_rate".to_string(), error_health),
            ]),
            uptime: self.start_time.elapsed(),
            last_check: chrono::Utc::now(),
        }
    }

    /// Start background system monitoring
    async fn start_system_monitoring(&self) {
        let system_metrics = self.system_metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            let mut system = System::new_all();
            
            loop {
                interval.tick().await;
                system.refresh_all();
                
                let mut metrics = system_metrics.write().await;
                metrics.update_from_system(&system);
                
                // Update Prometheus metrics
                gauge!("memory_usage_percent", metrics.memory_usage_percent);
                gauge!("cpu_usage_percent", metrics.cpu_usage_percent);
                gauge!("network_connections", metrics.network_connections as f64);
                gauge!("file_descriptors", metrics.file_descriptors as f64);
            }
        });
    }

    /// Setup Prometheus metrics exporter (disabled for now)
    async fn setup_prometheus_exporter(&self, _addr: &str) -> Result<()> {
        // Disabled for now due to dependency issues
        Ok(())
    }
}

/// Scan counters and statistics
#[derive(Default)]
struct ScanCounters {
    scans_started: AtomicU64,
    scans_completed: AtomicU64,
    targets_queued: AtomicU64,
    targets_completed: AtomicU64,
    total_ports_scanned: AtomicU64,
    open_ports_found: AtomicU64,
    closed_ports_found: AtomicU64,
    services_discovered: AtomicU64,
    vulnerabilities_found: AtomicU64,
    errors_encountered: AtomicU64,
    fatal_errors: AtomicU64,
}

/// Performance metrics tracking
#[derive(Default)]
struct PerformanceMetrics {
    scan_durations: Vec<Duration>,
    average_scan_duration: Duration,
    current_throughput: f64, // ports per second
}

impl PerformanceMetrics {
    fn record_scan_duration(&mut self, duration: Duration) {
        self.scan_durations.push(duration);
        
        // Keep only last 100 measurements
        if self.scan_durations.len() > 100 {
            self.scan_durations.remove(0);
        }
        
        // Calculate average
        let total: Duration = self.scan_durations.iter().sum();
        self.average_scan_duration = total / self.scan_durations.len() as u32;
    }
    
    fn record_throughput(&mut self, ports_scanned: usize, duration: Duration) {
        if duration.as_secs_f64() > 0.0 {
            self.current_throughput = ports_scanned as f64 / duration.as_secs_f64();
        }
    }
}

/// System resource metrics
#[derive(Default)]
struct SystemMetrics {
    memory_usage_percent: f64,
    cpu_usage_percent: f64,
    network_connections: u64,
    file_descriptors: u64,
    disk_usage_percent: f64,
}

impl SystemMetrics {
    fn update_from_system(&mut self, system: &sysinfo::System) {
        self.memory_usage_percent = (system.used_memory() as f64 / system.total_memory() as f64) * 100.0;
        self.cpu_usage_percent = system.global_cpu_info().cpu_usage() as f64;
        
        // Network and file descriptor monitoring would need additional platform-specific code
        // For now, placeholder values
        self.network_connections = 0;
        self.file_descriptors = 0;
        self.disk_usage_percent = 0.0;
    }
}

/// Public API structures

#[derive(Debug, Clone)]
pub struct ScanStats {
    pub scans_started: u64,
    pub scans_completed: u64,
    pub targets_queued: u64,
    pub targets_completed: u64,
    pub total_ports_scanned: u64,
    pub open_ports_found: u64,
    pub closed_ports_found: u64,
    pub services_discovered: u64,
    pub vulnerabilities_found: u64,
    pub errors_encountered: u64,
    pub fatal_errors: u64,
    pub average_scan_duration: Duration,
    pub current_throughput: f64,
    pub uptime: Duration,
}

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub overall: ComponentHealth,
    pub components: HashMap<String, ComponentHealth>,
    pub uptime: Duration,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComponentHealth {
    Healthy,
    Warning,
    Critical,
}

impl std::fmt::Display for ComponentHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Performance monitoring utilities

pub struct PerformanceTimer {
    name: String,
    start: Instant,
    checkpoints: Vec<(String, Instant)>,
}

impl PerformanceTimer {
    pub fn new(name: String) -> Self {
        let start = Instant::now();
        histogram!("operation_start_total", 1.0, "operation" => name.clone());
        
        Self {
            name,
            start,
            checkpoints: Vec::new(),
        }
    }
    
    pub fn checkpoint(&mut self, checkpoint_name: &str) {
        self.checkpoints.push((checkpoint_name.to_string(), Instant::now()));
        
        let elapsed = self.start.elapsed();
        let checkpoint_copy = checkpoint_name.to_string();
        histogram!("operation_checkpoint_seconds", elapsed.as_secs_f64(), 
                  "operation" => self.name.clone(), 
                  "checkpoint" => checkpoint_copy);
    }
    
    pub fn complete(self) -> Duration {
        let duration = self.start.elapsed();
        histogram!("operation_duration_seconds", duration.as_secs_f64(), "operation" => self.name);
        duration
    }
}

/// Resource usage monitor
pub struct ResourceMonitor {
    initial_memory: u64,
    peak_memory: u64,
    start_time: Instant,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        let initial_memory = Self::get_memory_usage();
        Self {
            initial_memory,
            peak_memory: initial_memory,
            start_time: Instant::now(),
        }
    }
    
    pub fn check_memory(&mut self) {
        let current_memory = Self::get_memory_usage();
        if current_memory > self.peak_memory {
            self.peak_memory = current_memory;
        }
        
        gauge!("current_memory_usage_bytes", current_memory as f64);
        gauge!("peak_memory_usage_bytes", self.peak_memory as f64);
    }
    
    pub fn get_stats(&self) -> ResourceStats {
        ResourceStats {
            initial_memory_bytes: self.initial_memory,
            peak_memory_bytes: self.peak_memory,
            current_memory_bytes: Self::get_memory_usage(),
            runtime_duration: self.start_time.elapsed(),
        }
    }
    
    fn get_memory_usage() -> u64 {
        // Platform-specific memory usage detection
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(status) = fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                return kb * 1024; // Convert KB to bytes
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback - return 0 if unable to determine
        0
    }
}

#[derive(Debug, Clone)]
pub struct ResourceStats {
    pub initial_memory_bytes: u64,
    pub peak_memory_bytes: u64,
    pub current_memory_bytes: u64,
    pub runtime_duration: Duration,
}

/// Macro for easy performance timing
#[macro_export]
macro_rules! time_operation {
    ($name:expr, $operation:expr) => {{
        let timer = crate::metrics::PerformanceTimer::new($name.to_string());
        let result = $operation;
        timer.complete();
        result
    }};
}

/// Extension trait for monitoring configuration
pub trait MonitoringConfig {
    fn prometheus_address(&self) -> Option<&String>;
    fn metrics_enabled(&self) -> bool;
    fn health_check_interval(&self) -> Duration;
}

impl MonitoringConfig for AppConfig {
    fn prometheus_address(&self) -> Option<&String> {
        // Would need to add this field to AppConfig
        None
    }
    
    fn metrics_enabled(&self) -> bool {
        true // Default to enabled
    }
    
    fn health_check_interval(&self) -> Duration {
        Duration::from_secs(30) // Default 30 second intervals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new();
        let stats = collector.get_scan_stats().await;
        
        assert_eq!(stats.scans_started, 0);
        assert_eq!(stats.scans_completed, 0);
    }
    
    #[test]
    fn test_performance_timer() {
        let mut timer = PerformanceTimer::new("test_operation".to_string());
        std::thread::sleep(Duration::from_millis(10));
        timer.checkpoint("midpoint");
        std::thread::sleep(Duration::from_millis(10));
        
        let duration = timer.complete();
        assert!(duration >= Duration::from_millis(20));
    }
}
