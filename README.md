# RustMap 🦀🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/deepskilling/RustMap.svg)](https://github.com/deepskilling/RustMap/releases)

**Professional network scanning tool implementing nmap features in modern Rust**

*Developed by [Deepskilling Inc](https://deepskilling.com) - Advancing cybersecurity through innovative technology*

---

## 🎯 Overview

RustMap is an enterprise-grade network scanning tool that implements comprehensive nmap functionality using modern Rust architecture. Built with performance, security, and reliability in mind, it provides advanced network discovery, port scanning, OS detection, and firewall evasion capabilities.

## ✨ Key Features

### 🔍 **Advanced Scanning Capabilities**
- **TCP Connect Scan**: Full connection establishment scanning
- **SYN Scan**: Stealth scanning with raw socket support (requires root)
- **FIN Scan**: Stealthy scanning using FIN packets
- **Xmas Scan**: Advanced evasion with FIN+PSH+URG flags
- **Null Scan**: Maximum stealth with no TCP flags set
- **UDP Scan**: Comprehensive UDP port discovery
- **Ping Sweep**: Network host discovery and reachability testing

### 💻 **Operating System Detection**
- Multi-method OS fingerprinting (TCP stack analysis)
- Banner grabbing and analysis for OS identification
- Passive detection using TTL patterns and timing analysis
- Comprehensive signature database for Linux, Windows, network devices
- Confidence scoring and detection method reporting

### 🛡️ **Firewall & IDS Evasion**
- Decoy scanning with multiple spoofed source addresses
- Packet fragmentation to bypass deep packet inspection
- Source IP spoofing capabilities (requires raw sockets)
- Advanced timing profiles: Paranoid, Sneaky, Polite, Normal
- Scan randomization and background noise generation

### 🌐 **Service Detection**
- Banner grabbing across HTTP, SSH, FTP, SMTP, DNS, Telnet
- Service version identification and parsing
- Protocol-specific probing and response analysis
- Concurrent service detection across multiple ports

### 📊 **Professional Reporting**
- Multiple output formats: JSON, XML, CSV, Human-readable
- Real-time progress reporting and scan statistics
- Structured scan results with timestamps and metadata
- Export capabilities for integration with security tools

## 🚀 Quick Start

### Prerequisites
- Rust 1.70 or later
- For advanced scans (SYN, raw sockets): Root/Administrator privileges

### Installation

#### From Source
```bash
git clone https://github.com/deepskilling/RustMap.git
cd RustMap
cargo build --release
```

#### Using Cargo
```bash
cargo install nmap_scanner
```

### Basic Usage

```bash
# Basic TCP scan
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com

# Advanced stealth scan with OS detection
sudo ./target/release/nmap_scanner --syn-scan -p 1-1000 -O target.com

# Comprehensive scan with all features
./target/release/nmap_scanner --fin-scan -p 22,53,80,443 target.com -O -V --format json -o results.json

# Firewall evasion scan
sudo ./target/release/nmap_scanner --null-scan --decoy-scan target.com
```

## 📋 Command Line Interface

### Scan Types
```bash
-s, --syn-scan        TCP SYN scan (requires root)
    --tcp-scan        TCP connect scan
-U, --udp-scan        UDP scan
-F, --fin-scan        FIN scan
    --xmas-scan       Xmas scan (FIN, PSH, URG flags)
    --null-scan       Null scan (no flags set)
-P, --ping-scan       Ping sweep (host discovery)
```

### Port Specification
```bash
-p, --ports <PORTS>   Port specification (e.g., 22,80,443 or 1-1000)
    --top-ports <N>   Scan top N most common ports
    --all-ports       Scan all 65535 ports
```

### Detection Options
```bash
-O, --os-detection    Enable OS detection
-V, --version-detection Enable version detection
-A                    Enable all detection (OS + Version + Scripts)
```

### Output Options
```bash
-o, --output <FILE>   Output file
    --format <FORMAT> Output format (json, xml, csv, human)
-v, --verbose         Verbose output
```

### Performance & Timing
```bash
-T <TIMING>          Timing template (0-5: paranoid, sneaky, polite, normal, aggressive, insane)
    --min-rate <N>    Minimum packets per second
    --max-rate <N>    Maximum packets per second
```

## ⚙️ Configuration

RustMap uses TOML configuration files. The default configuration is in `config.toml`:

```toml
[scanning]
default_scan_type = "tcp_connect"
default_ports = "1-1000"
service_detection = true
os_detection = true
timing_template = 3

[network]
dns_timeout_secs = 10
connection_timeout_secs = 3

[performance]
max_concurrent_hosts = 100
scan_batch_size = 100
worker_threads = 0  # 0 = auto-detect
```

## 🏗️ Architecture

RustMap is built using SOLID principles with a modular, async architecture:

```
src/
├── main.rs              # Application entry point
├── core.rs              # SOLID architecture core
├── scanner.rs           # Main scanning engine
├── advanced_scanner.rs  # Raw socket implementations
├── os_detection.rs      # OS fingerprinting
├── firewall_evasion.rs  # Evasion techniques
├── service.rs           # Service detection
├── cli.rs               # Command-line interface
├── config.rs            # Configuration management
├── error.rs             # Error handling
├── logging.rs           # Structured logging
├── metrics.rs           # Performance monitoring
├── persistence.rs       # Data storage
└── reporting.rs         # Output generation
```

## 🧪 Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Run with coverage
cargo tarpaulin --out Html
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Deepskilling Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

## 🏢 About Deepskilling Inc

**Deepskilling Inc** is a leading technology company specializing in cybersecurity solutions and advanced network tools. We are committed to developing innovative, enterprise-grade security software that empowers organizations to protect their digital infrastructure.

- 🌐 **Website**: [deepskilling.com](https://deepskilling.com)
- 📧 **Contact**: [contact@deepskilling.com](mailto:contact@deepskilling.com)
- 💼 **LinkedIn**: [Deepskilling Inc](https://linkedin.com/company/deepskilling)
- 🐦 **Twitter**: [@deepskilling](https://twitter.com/deepskilling)

### Our Mission
*Advancing cybersecurity through innovative technology and empowering organizations with professional-grade security tools.*

## ⚠️ Legal Disclaimer

RustMap is designed for legitimate security testing and network administration purposes. Users are responsible for ensuring compliance with applicable laws and regulations. Unauthorized network scanning may violate local, state, or federal laws.

**Use responsibly and only on networks you own or have explicit permission to test.**

## 🙏 Acknowledgments

- Inspired by the original [nmap](https://nmap.org/) project by Gordon Lyon
- Built with the amazing [Rust](https://rust-lang.org/) programming language
- Uses [Tokio](https://tokio.rs/) for high-performance async I/O
- Thanks to the Rust community for excellent crates and tools

---

**RustMap** - *Professional Network Scanning in Rust* | **© 2025 Deepskilling Inc**