# 🚀 RustMap Quick Start Guide

**Get up and running with RustMap in minutes!**

*Professional network scanning tool by [Deepskilling Inc](https://deepskilling.com)*

---

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows
- **Rust**: Version 1.70 or later
- **Memory**: 512MB RAM minimum (2GB+ recommended for large scans)
- **Network**: Internet access for installation and target scanning

### Permissions
- **Basic scans**: Standard user privileges
- **Advanced scans** (SYN, raw sockets): Root/Administrator privileges

---

## 🛠️ Installation

### Option 1: From Source (Recommended)
```bash
# Clone the repository
git clone https://github.com/deepskilling/RustMap.git
cd RustMap

# Build the project
cargo build --release

# The binary will be available at:
./target/release/nmap_scanner
```

### Option 2: Using Cargo
```bash
cargo install nmap_scanner
```

### Option 3: Download Binary
Visit [GitHub Releases](https://github.com/deepskilling/RustMap/releases) and download the binary for your platform.

---

## 🎯 Your First Scan

### 1. Basic Port Scan
```bash
# Scan common ports on localhost
./target/release/nmap_scanner --tcp-scan -p 22,80,443 127.0.0.1

# Expected output:
# ✅ Port 22: closed
# ✅ Port 80: closed  
# ✅ Port 443: closed
```

### 2. Scan a Website
```bash
# Scan a public website (replace with your target)
./target/release/nmap_scanner --tcp-scan -p 80,443 google.com

# Expected output:
# ✅ Port 80: open (HTTP)
# ✅ Port 443: open (HTTPS)
```

### 3. Save Results to File
```bash
# Scan and save to JSON
./target/release/nmap_scanner --tcp-scan -p 80,443 google.com \
  --format json -o results.json

# View the results
cat results.json
```

---

## 🔍 Common Scan Types

### TCP Connect Scan (Default)
```bash
# Basic TCP connection scan
./target/release/nmap_scanner --tcp-scan -p 1-1000 target.com
```

### Service Detection
```bash
# Identify services and versions
./target/release/nmap_scanner --tcp-scan -p 22,80,443 target.com -V
```

### OS Detection
```bash
# Detect operating system
./target/release/nmap_scanner --tcp-scan -p 22,80,443 target.com -O
```

### Comprehensive Scan
```bash
# Everything: OS + Service detection + Multiple ports
./target/release/nmap_scanner --tcp-scan -p 1-10000 target.com -O -V \
  --format json -o comprehensive_scan.json
```

---

## 🛡️ Advanced Scans (Require Root)

### Stealth SYN Scan
```bash
# Requires root/sudo privileges
sudo ./target/release/nmap_scanner --syn-scan -p 1-1000 target.com
```

### FIN Scan (Stealth)
```bash
# FIN packet scan for firewall evasion
sudo ./target/release/nmap_scanner --fin-scan -p 80,443 target.com
```

### Xmas Scan (Maximum Stealth)
```bash
# Sets FIN, PSH, and URG flags
sudo ./target/release/nmap_scanner --xmas-scan -p 1-1000 target.com
```

### Null Scan (No Flags)
```bash
# No TCP flags set - very stealthy
sudo ./target/release/nmap_scanner --null-scan -p 80,443 target.com
```

---

## 📊 Output Formats

### JSON Output
```bash
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com \
  --format json -o scan.json

# View formatted JSON
cat scan.json | jq .
```

### XML Output (Nmap Compatible)
```bash
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com \
  --format xml -o scan.xml
```

### CSV for Spreadsheets
```bash
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com \
  --format csv -o scan.csv
```

### Human Readable Report
```bash
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com \
  --format human -o scan.md
```

---

## 🎛️ Port Specification

### Individual Ports
```bash
# Scan specific ports
-p 22,80,443,8080,8443
```

### Port Ranges
```bash
# Scan port ranges
-p 1-1000
-p 1-100,200-300,443,8080
```

### Common Port Sets
```bash
# Top 100 most common ports
--top-ports 100

# Top 1000 ports
--top-ports 1000

# All 65535 ports (slow!)
--all-ports
```

---

## ⚡ Performance Tuning

### Fast Scan
```bash
# Aggressive timing (may be detected)
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com -T 4
```

### Stealth Scan
```bash
# Slow and stealthy (harder to detect)
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com -T 1
```

### Custom Configuration
```bash
# Edit config.toml for persistent settings
nano config.toml

# Key settings:
# - max_concurrent_hosts = 50
# - scan_batch_size = 100  
# - timing_template = 3
```

---

## 🔧 Configuration File

### Create Custom Config
```bash
# Copy default config
cp config.toml my_config.toml

# Edit your settings
nano my_config.toml

# Use custom config
./target/release/nmap_scanner --config my_config.toml [other options]
```

### Key Configuration Options
```toml
[scanning]
default_scan_type = "tcp_connect"
default_ports = "1-1000"
service_detection = true
os_detection = true
timing_template = 3

[performance]
max_concurrent_hosts = 100
scan_batch_size = 100
worker_threads = 0  # 0 = auto-detect

[network]
dns_timeout_secs = 10
connection_timeout_secs = 3
```

---

## 🐛 Troubleshooting

### Permission Denied
```bash
# Problem: Raw socket access denied
# Solution: Use sudo for advanced scans
sudo ./target/release/nmap_scanner --syn-scan -p 80 target.com
```

### DNS Resolution Fails
```bash
# Problem: Cannot resolve hostname
# Solution: Use IP address or check DNS
./target/release/nmap_scanner --tcp-scan -p 80 192.168.1.1
```

### Firewall Blocking
```bash
# Problem: All ports show filtered
# Solution: Try stealth scans
sudo ./target/release/nmap_scanner --fin-scan -p 80 target.com
```

### Slow Performance
```bash
# Problem: Scan is very slow
# Solution: Reduce port range or increase timing
./target/release/nmap_scanner --tcp-scan -p 80,443 target.com -T 4
```

### Too Many Open Files
```bash
# Problem: System resource limits
# Solution: Reduce concurrent connections
# Edit config.toml: max_concurrent_hosts = 50
```

---

## 📚 Next Steps

### Learn More
- 📖 **[Complete Documentation](DOCS.md)** - Detailed function reference
- 🏗️ **[Architecture Guide](README.md#architecture)** - System design overview
- 🤝 **[Contributing](CONTRIBUTING.md)** - How to contribute
- ❓ **[FAQ](FAQ.md)** - Common questions and answers

### Real-World Examples
```bash
# Network Discovery
./target/release/nmap_scanner --ping-scan 192.168.1.0/24

# Web Server Analysis  
./target/release/nmap_scanner --tcp-scan -p 80,443,8080,8443 \
  webserver.com -V --format json -o webserver_analysis.json

# Security Assessment
sudo ./target/release/nmap_scanner --syn-scan -p 1-65535 \
  target.internal -O -V --format xml -o security_scan.xml
```

### Advanced Topics
- **Firewall Evasion**: Learn stealth techniques
- **Custom Scripts**: Extend functionality  
- **API Integration**: Use as a library
- **Performance Optimization**: Large network scanning

---

## ⚠️ Legal Notice

**Use RustMap responsibly and only on networks you own or have explicit permission to test.**

- ✅ **Authorized use**: Your own networks, penetration testing with permission
- ❌ **Unauthorized use**: Scanning networks without permission (may be illegal)

---

## 🆘 Getting Help

### Community Support
- 🐛 **Issues**: [GitHub Issues](https://github.com/deepskilling/RustMap/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/deepskilling/RustMap/discussions)
- 📧 **Contact**: [contact@deepskilling.com](mailto:contact@deepskilling.com)

### Professional Support
**Deepskilling Inc** provides professional support, training, and consulting services.

**Ready to scan?** Start with your first command:
```bash
./target/release/nmap_scanner --tcp-scan -p 80,443 google.com
```

---

**RustMap** - *Professional Network Scanning* | **© 2025 Deepskilling Inc**
