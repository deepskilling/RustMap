//! Comprehensive error handling system
//!
//! Provides structured error types with contextual information for:
//! - Network errors (connection failures, timeouts, etc.)
//! - Configuration errors (invalid settings, missing files)
//! - Scanning errors (permission denied, invalid targets)
//! - IO errors (file operations, persistence failures)
//! - Security errors (privilege escalation failures, blocked operations)

use std::{
    fmt,
    net::{AddrParseError, IpAddr},
    io,
};
use thiserror::Error;

/// Main result type used throughout the application
pub type Result<T> = std::result::Result<T, ScannerError>;

/// Comprehensive error enum covering all application error scenarios
#[derive(Error, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ScannerError {
    /// Configuration related errors
    #[error("Configuration error: {message}")]
    Configuration { message: String },
    
    /// Network connectivity and protocol errors
    #[error("Network error: {message}")]
    Network { message: String },
    
    /// Target specification and resolution errors
    #[error("Invalid target: {target} - {reason}")]
    InvalidTarget { target: String, reason: String },
    
    /// Permission and privilege errors
    #[error("Permission denied: {operation} - {reason}")]
    Permission { operation: String, reason: String },
    
    /// Scanning operation errors
    #[error("Scan error: {scan_type} on {target} - {message}")]
    Scan {
        scan_type: String,
        target: String,
        message: String,
    },
    
    /// Service detection and fingerprinting errors
    #[error("Service detection error: {service} on {host}:{port} - {message}")]
    ServiceDetection {
        service: String,
        host: IpAddr,
        port: u16,
        message: String,
    },
    
    /// Operating system detection errors
    #[error("OS detection error: {host} - {message}")]
    OsDetection { host: IpAddr, message: String },
    
    /// Scripting engine errors
    #[error("Script error: {script_name} - {message}")]
    Script { script_name: String, message: String },
    
    /// Output and reporting errors
    #[error("Output error: {format} - {message}")]
    Output { format: String, message: String },
    
    /// File I/O and persistence errors
    #[error("IO error: {operation} - {message}")]
    Io { operation: String, message: String },
    
    /// Rate limiting and throttling errors
    #[error("Rate limit exceeded: {resource} - {message}")]
    RateLimit { resource: String, message: String },
    
    /// Timeout errors with contextual information
    #[error("Timeout: {operation} after {duration_secs}s")]
    Timeout {
        operation: String,
        duration_secs: u64,
    },
    
    /// Resource exhaustion errors
    #[error("Resource exhausted: {resource} - {message}")]
    ResourceExhausted { resource: String, message: String },
    
    /// Validation errors for user input
    #[error("Validation error: {field} - {message}")]
    Validation { field: String, message: String },
    
    /// Security policy violations
    #[error("Security violation: {policy} - {message}")]
    Security { policy: String, message: String },
    
    /// Generic internal errors with context
    #[error("Internal error: {context} - {message}")]
    Internal { context: String, message: String },
}

impl ScannerError {
    /// Create a configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
    
    /// Create a network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
        }
    }
    
    /// Create an invalid target error
    pub fn invalid_target<T: Into<String>, R: Into<String>>(target: T, reason: R) -> Self {
        Self::InvalidTarget {
            target: target.into(),
            reason: reason.into(),
        }
    }
    
    /// Create a permission error
    pub fn permission<O: Into<String>, R: Into<String>>(operation: O, reason: R) -> Self {
        Self::Permission {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
    
    /// Create a scan error
    pub fn scan<T: Into<String>, G: Into<String>, M: Into<String>>(
        scan_type: T,
        target: G,
        message: M,
    ) -> Self {
        Self::Scan {
            scan_type: scan_type.into(),
            target: target.into(),
            message: message.into(),
        }
    }
    
    /// Create a service detection error
    pub fn service_detection<S: Into<String>, M: Into<String>>(
        service: S,
        host: IpAddr,
        port: u16,
        message: M,
    ) -> Self {
        Self::ServiceDetection {
            service: service.into(),
            host,
            port,
            message: message.into(),
        }
    }
    
    /// Create an OS detection error
    pub fn os_detection<M: Into<String>>(host: IpAddr, message: M) -> Self {
        Self::OsDetection {
            host,
            message: message.into(),
        }
    }
    
    /// Create a script error
    pub fn script<N: Into<String>, M: Into<String>>(script_name: N, message: M) -> Self {
        Self::Script {
            script_name: script_name.into(),
            message: message.into(),
        }
    }
    
    /// Create an output error
    pub fn output<F: Into<String>, M: Into<String>>(format: F, message: M) -> Self {
        Self::Output {
            format: format.into(),
            message: message.into(),
        }
    }
    
    /// Create an IO error
    pub fn io<O: Into<String>, M: Into<String>>(operation: O, message: M) -> Self {
        Self::Io {
            operation: operation.into(),
            message: message.into(),
        }
    }
    
    /// Create a timeout error
    pub fn timeout<O: Into<String>>(operation: O, duration_secs: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            duration_secs,
        }
    }
    
    /// Create a rate limit error
    pub fn rate_limit<R: Into<String>, M: Into<String>>(resource: R, message: M) -> Self {
        Self::RateLimit {
            resource: resource.into(),
            message: message.into(),
        }
    }
    
    /// Create a validation error
    pub fn validation<F: Into<String>, M: Into<String>>(field: F, message: M) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }
    
    /// Create a security error
    pub fn security<P: Into<String>, M: Into<String>>(policy: P, message: M) -> Self {
        Self::Security {
            policy: policy.into(),
            message: message.into(),
        }
    }
    
    /// Create an internal error
    pub fn internal<C: Into<String>, M: Into<String>>(context: C, message: M) -> Self {
        Self::Internal {
            context: context.into(),
            message: message.into(),
        }
    }
    
    /// Check if error is recoverable (can be retried)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Network { .. } |
            Self::Timeout { .. } |
            Self::RateLimit { .. } |
            Self::ResourceExhausted { .. }
        )
    }
    
    /// Check if error is a permission issue
    pub fn is_permission_error(&self) -> bool {
        matches!(self, Self::Permission { .. } | Self::Security { .. })
    }
    
    /// Check if error is a configuration issue
    pub fn is_config_error(&self) -> bool {
        matches!(self, Self::Configuration { .. } | Self::Validation { .. })
    }
    
    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Internal { .. } => ErrorSeverity::Critical,
            Self::Permission { .. } | Self::Security { .. } => ErrorSeverity::High,
            Self::Configuration { .. } | Self::Validation { .. } => ErrorSeverity::High,
            Self::Scan { .. } | Self::ServiceDetection { .. } | Self::OsDetection { .. } => ErrorSeverity::Medium,
            Self::Network { .. } | Self::Timeout { .. } => ErrorSeverity::Medium,
            Self::InvalidTarget { .. } | Self::Output { .. } => ErrorSeverity::Low,
            Self::Script { .. } | Self::RateLimit { .. } | Self::ResourceExhausted { .. } => ErrorSeverity::Low,
            Self::Io { .. } => ErrorSeverity::Medium,
        }
    }
}

/// Error severity levels for logging and monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// Implement conversions from common error types
impl From<io::Error> for ScannerError {
    fn from(error: io::Error) -> Self {
        Self::io("IO operation", error.to_string())
    }
}

impl From<AddrParseError> for ScannerError {
    fn from(error: AddrParseError) -> Self {
        Self::invalid_target("IP address", error.to_string())
    }
}

impl From<std::num::ParseIntError> for ScannerError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::validation("number parsing", error.to_string())
    }
}

impl From<serde_json::Error> for ScannerError {
    fn from(error: serde_json::Error) -> Self {
        Self::output("JSON", error.to_string())
    }
}

impl From<config::ConfigError> for ScannerError {
    fn from(error: config::ConfigError) -> Self {
        Self::config(error.to_string())
    }
}

impl From<anyhow::Error> for ScannerError {
    fn from(error: anyhow::Error) -> Self {
        Self::internal("anyhow", error.to_string())
    }
}

/// Error context trait for adding context to errors
pub trait ErrorContext<T> {
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
        
    fn with_target_context(self, target: &str) -> Result<T>;
    fn with_scan_context(self, scan_type: &str, target: &str) -> Result<T>;
}

impl<T, E: Into<ScannerError>> ErrorContext<T> for std::result::Result<T, E> {
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let original_error = e.into();
            ScannerError::internal("context", f())
        })
    }
    
    fn with_target_context(self, target: &str) -> Result<T> {
        self.map_err(|e| {
            let original_error = e.into();
            match original_error {
                ScannerError::Network { message } => {
                    ScannerError::scan("network", target, message)
                }
                other => other,
            }
        })
    }
    
    fn with_scan_context(self, scan_type: &str, target: &str) -> Result<T> {
        self.map_err(|e| {
            let original_error = e.into();
            match original_error {
                ScannerError::Network { message } => {
                    ScannerError::scan(scan_type, target, message)
                }
                other => other,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_creation() {
        let error = ScannerError::network("Connection refused");
        assert!(matches!(error, ScannerError::Network { .. }));
        assert!(error.is_recoverable());
    }
    
    #[test]
    fn test_error_severity() {
        let config_error = ScannerError::config("Invalid setting");
        assert_eq!(config_error.severity(), ErrorSeverity::High);
        
        let network_error = ScannerError::network("Timeout");
        assert_eq!(network_error.severity(), ErrorSeverity::Medium);
    }
    
    #[test]
    fn test_error_context() {
        let result: std::result::Result<(), io::Error> = Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Connection refused"
        ));
        
        let error = result.with_target_context("192.168.1.1").unwrap_err();
        assert!(matches!(error, ScannerError::Scan { .. }));
    }
}
