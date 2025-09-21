//! # Nmap Scanner - Professional Network Scanning Tool
//! 
//! A high-performance network scanning tool implemented in Rust following SOLID principles.
//! 
//! ## Features
//! 
//! - **Port Scanning**: TCP Connect, SYN, UDP, FIN, Xmas, Null scans
//! - **Service Detection**: Service identification and version detection
//! - **OS Detection**: Operating system fingerprinting
//! - **Firewall/IDS Evasion**: Packet fragmentation, decoy scans, timing templates
//! - **Scripting Engine**: NSE-like vulnerability and authentication scripts
//! - **Multiple Output Formats**: Human-readable, JSON, XML, CSV
//! - **High Performance**: Async architecture with configurable parallelism
//! 
//! ## Architecture
//! 
//! This crate follows SOLID principles with clear separation of concerns:
//! 
//! - **Single Responsibility**: Each module has a single, well-defined purpose
//! - **Open/Closed**: Extensible through traits without modifying existing code
//! - **Liskov Substitution**: Implementations can be swapped seamlessly
//! - **Interface Segregation**: Small, focused interfaces
//! - **Dependency Inversion**: High-level modules don't depend on low-level details

pub mod cli;
pub mod config;
pub mod core;
pub mod error;
pub mod logging;
pub mod metrics;
pub mod persistence;

// Core scanning modules
pub mod scanner;
pub mod service;
pub mod os_detection;
pub mod evasion;
pub mod scripting;

// Output and reporting
pub mod output;
pub mod reporting;

// Utilities
pub mod network;
pub mod timing;
pub mod utils;
pub mod advanced_scanner;
pub mod firewall_evasion;

// Re-exports for convenience
pub use crate::{
    config::AppConfig,
    core::Application,
    error::{Result, ScannerError},
};
