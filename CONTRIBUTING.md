# 🤝 Contributing to RustMap

**Welcome to the RustMap community!** We appreciate your interest in contributing to our professional network scanning tool.

*By [Deepskilling Inc](https://deepskilling.com)*

---

## 📋 Table of Contents

1. [**Getting Started**](#-getting-started)
2. [**Development Setup**](#-development-setup)
3. [**Project Structure**](#-project-structure)
4. [**Coding Standards**](#-coding-standards)
5. [**Testing Guidelines**](#-testing-guidelines)
6. [**Pull Request Process**](#-pull-request-process)
7. [**Issue Reporting**](#-issue-reporting)
8. [**Security Considerations**](#-security-considerations)
9. [**Documentation Standards**](#-documentation-standards)
10. [**Community Guidelines**](#-community-guidelines)

---

## 🚀 Getting Started

### Prerequisites

- **Rust**: Version 1.70 or later
- **Git**: Version 2.20 or later
- **Platform**: Linux, macOS, or Windows
- **IDE**: VS Code with rust-analyzer (recommended)

### First Steps

1. **Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/RustMap.git
   cd RustMap
   ```

2. **Set Up Upstream**
   ```bash
   git remote add upstream https://github.com/deepskilling/RustMap.git
   git fetch upstream
   ```

3. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## 🛠️ Development Setup

### Environment Setup

1. **Install Dependencies**
   ```bash
   # Install Rust toolchain
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Install development tools
   cargo install cargo-watch cargo-audit cargo-deny
   ```

2. **Build the Project**
   ```bash
   # Debug build
   cargo build
   
   # Release build
   cargo build --release
   
   # Run tests
   cargo test
   ```

3. **Development Tools**
   ```bash
   # Watch for changes and rebuild
   cargo watch -x build -x test
   
   # Format code
   cargo fmt
   
   # Lint code
   cargo clippy
   
   # Security audit
   cargo audit
   ```

### IDE Configuration

**VS Code Extensions (Recommended)**
- `rust-lang.rust-analyzer`: Rust language support
- `vadimcn.vscode-lldb`: Debugging support
- `serayuzgur.crates`: Crate management
- `tamasfe.even-better-toml`: TOML support

**VS Code Settings**
```json
{
    "rust-analyzer.cargo.features": "all",
    "rust-analyzer.checkOnSave.command": "clippy",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

---

## 🏗️ Project Structure

### Directory Layout

```
RustMap/
├── src/                      # Source code
│   ├── lib.rs               # Library root
│   ├── main.rs              # Application entry point
│   ├── cli.rs               # Command-line interface
│   ├── config.rs            # Configuration management
│   ├── core.rs              # Core application logic
│   ├── error.rs             # Error handling
│   ├── logging.rs           # Logging framework
│   ├── metrics.rs           # Performance metrics
│   ├── network.rs           # Network utilities
│   ├── scanner.rs           # Core scanning engine
│   ├── advanced_scanner.rs  # Raw socket scanning
│   ├── service.rs           # Service detection
│   ├── os_detection.rs      # OS fingerprinting
│   ├── firewall_evasion.rs  # Evasion techniques
│   ├── scripting.rs         # NSE-like scripting
│   ├── output.rs            # Output formatting
│   ├── reporting.rs         # Report generation
│   ├── persistence.rs       # Data storage
│   ├── timing.rs            # Timing profiles
│   └── utils.rs             # Utility functions
├── tests/                   # Integration tests
├── benches/                 # Benchmarks
├── examples/                # Example usage
├── docs/                    # Additional documentation
├── config.toml              # Default configuration
├── Cargo.toml               # Project dependencies
├── README.md                # Project overview
├── QUICKSTART.md            # Quick start guide
├── DOCS.md                  # Complete documentation
├── CONTRIBUTING.md          # This file
├── LICENSE                  # MIT license
└── .gitignore              # Git ignore rules
```

### Module Responsibilities

| Module | Purpose | Key Traits/Structs |
|--------|---------|-------------------|
| `cli` | Command-line argument parsing | `Cli` |
| `config` | Configuration management | `AppConfig` |
| `core` | Application orchestration | `Application`, `ScanTarget` |
| `scanner` | Basic scanning logic | `ScanEngine`, `DefaultScanEngine` |
| `advanced_scanner` | Raw socket scanning | `AdvancedScanEngine` |
| `service` | Service detection | `ServiceDetector`, `ServiceInfo` |
| `os_detection` | OS fingerprinting | `OsDetector`, `OsInfo` |
| `firewall_evasion` | Evasion techniques | `EvasionTechniques` |
| `output` | Output formatting | `OutputFormatter` |
| `reporting` | Report generation | `ReportGenerator` |

---

## 📝 Coding Standards

### Rust Style Guidelines

**Follow the official Rust style guide with these specific requirements:**

1. **Code Formatting**
   ```bash
   # Always run before committing
   cargo fmt --all
   ```

2. **Linting**
   ```bash
   # Fix all clippy warnings
   cargo clippy --all-targets --all-features -- -D warnings
   ```

3. **Naming Conventions**
   - **Functions**: `snake_case`
   - **Types**: `PascalCase`
   - **Constants**: `SCREAMING_SNAKE_CASE`
   - **Modules**: `snake_case`

### Code Quality Standards

**Documentation Requirements**
```rust
/// Performs a TCP connect scan on the specified target
///
/// # Arguments
/// * `target` - The scan target containing IP and port information
/// * `session` - The scan session with configuration parameters
///
/// # Returns
/// * `Result<(Vec<PortDiscovery>, usize)>` - Discoveries and total ports scanned
///
/// # Errors
/// * `ScannerError::Network` - Network connectivity issues
/// * `ScannerError::Timeout` - Connection timeouts
///
/// # Example
/// ```rust
/// let target = ScanTarget::new("192.168.1.1".parse()?);
/// let discoveries = scanner.tcp_connect_scan(&target, &session).await?;
/// ```
async fn tcp_connect_scan(&self, target: &ScanTarget, session: &ScanSession) -> Result<(Vec<PortDiscovery>, usize)> {
    // Implementation...
}
```

**Error Handling Standards**
```rust
// ✅ Good: Specific error types with context
return Err(ScannerError::network(format!(
    "Failed to connect to {}:{} - {}",
    target.ip(), port, e
)));

// ❌ Bad: Generic error messages
return Err(ScannerError::internal("something went wrong".to_string()));
```

**Async/Await Best Practices**
```rust
// ✅ Good: Use structured concurrency
let results = stream::iter(ports)
    .map(|port| self.scan_port(target, port))
    .buffer_unordered(max_concurrent)
    .try_collect::<Vec<_>>()
    .await?;

// ❌ Bad: Uncontrolled spawning
for port in ports {
    tokio::spawn(self.scan_port(target, port));
}
```

### Performance Considerations

1. **Memory Efficiency**
   - Use streaming for large datasets
   - Implement connection pooling
   - Clean up resources promptly

2. **Concurrency**
   - Use bounded concurrency
   - Implement backpressure
   - Avoid blocking the async executor

3. **Resource Management**
   - Close sockets promptly
   - Use timeouts for all network operations
   - Monitor system resource usage

---

## 🧪 Testing Guidelines

### Testing Strategy

**Test Categories**
1. **Unit Tests**: Individual function testing
2. **Integration Tests**: Component interaction testing
3. **End-to-End Tests**: Full workflow testing
4. **Performance Tests**: Benchmarking and load testing

### Writing Tests

**Unit Test Example**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_port_state_detection() {
        let scanner = DefaultScanEngine::new(test_config()).await.unwrap();
        let target = ScanTarget::new("127.0.0.1".parse().unwrap());
        
        // Test closed port
        let result = scanner.scan_port(&target, 9999).await;
        assert!(matches!(result, Ok(PortState::Closed)));
        
        // Test open port (assuming something is running on 80)
        // Use mocking for reliable tests
    }

    #[test]
    fn test_target_parsing() {
        let target = ScanTarget::parse("192.168.1.1:80").unwrap();
        assert_eq!(target.ip().to_string(), "192.168.1.1");
        assert_eq!(target.ports(), Some(&vec![80]));
    }
}
```

**Integration Test Example**
```rust
// tests/scanner_integration.rs
use nmap_scanner::{config::AppConfig, core::Application, cli::Cli};

#[tokio::test]
async fn test_full_scan_workflow() {
    let config = AppConfig::test_config();
    let mut app = Application::new(config).await.unwrap();
    
    let cli = Cli {
        targets: vec!["127.0.0.1".to_string()],
        tcp_scan: true,
        ports: Some("80,443".to_string()),
        ..Default::default()
    };
    
    let result = app.run(cli).await;
    assert!(result.is_ok());
}
```

**Mock Usage**
```rust
#[cfg(test)]
mod tests {
    use mockall::predicate::*;
    use super::*;

    #[tokio::test]
    async fn test_service_detection_with_mock() {
        let mut mock_detector = MockServiceDetector::new();
        mock_detector
            .expect_detect_service()
            .with(eq(target), eq(80))
            .times(1)
            .returning(|_, _| Ok(ServiceInfo {
                service_name: "http".to_string(),
                version: Some("Apache/2.4.41".to_string()),
                ..Default::default()
            }));

        let result = mock_detector.detect_service(&target, 80).await;
        assert!(result.is_ok());
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_port_state_detection

# Run with output
cargo test -- --nocapture

# Run integration tests only
cargo test --test '*'

# Run benchmarks
cargo bench
```

### Test Coverage

```bash
# Install coverage tool
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html
```

---

## 🔄 Pull Request Process

### Before Submitting

1. **Sync with upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run quality checks**
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test
   cargo audit
   ```

3. **Update documentation**
   ```bash
   cargo doc --no-deps --open
   ```

### PR Requirements

**Essential Checklist**
- [ ] Code follows Rust style guidelines (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] All tests pass (`cargo test`)
- [ ] Security audit passes (`cargo audit`)
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG.md updated (for notable changes)
- [ ] Commit messages follow convention

**PR Template**
```markdown
## Summary
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Security Considerations
- [ ] No new security vulnerabilities introduced
- [ ] Sensitive data handling reviewed
- [ ] Input validation implemented

## Documentation
- [ ] Code comments updated
- [ ] API documentation updated
- [ ] README/guides updated (if needed)
```

### Commit Message Convention

**Format**: `<type>(<scope>): <subject>`

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

**Examples**:
```bash
feat(scanner): add SYN scan support with raw sockets
fix(service): resolve HTTP banner grabbing timeout
docs(api): update service detection documentation
test(integration): add comprehensive scan workflow tests
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests
2. **Code Review**: Maintainers review for quality and design
3. **Security Review**: Security-focused review for sensitive changes
4. **Documentation Review**: Ensure adequate documentation
5. **Final Approval**: Maintainer approval required for merge

---

## 🐛 Issue Reporting

### Bug Reports

**Template**:
```markdown
## Bug Description
Clear description of the issue

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should have happened

## Actual Behavior
What actually happened

## Environment
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.70.0]
- RustMap version: [e.g., 0.1.0]

## Additional Context
Any other relevant information
```

### Feature Requests

**Template**:
```markdown
## Feature Description
Clear description of the requested feature

## Use Case
Why is this feature needed?

## Proposed Implementation
How might this be implemented?

## Alternatives Considered
Other approaches that were considered
```

### Security Issues

**⚠️ IMPORTANT**: Report security vulnerabilities privately to [security@deepskilling.com](mailto:security@deepskilling.com)

**Do NOT create public issues for security vulnerabilities**

---

## 🔒 Security Considerations

### Security Guidelines

1. **Input Validation**
   - Validate all user inputs
   - Sanitize data before processing
   - Use type-safe parsing

2. **Network Security**
   - Implement proper timeout handling
   - Validate network responses
   - Handle malicious responses gracefully

3. **Privilege Management**
   - Check permissions before operations
   - Drop privileges when not needed
   - Clear documentation of privilege requirements

### Security Review Process

**All security-related changes require:**
- Security-focused code review
- Threat modeling assessment
- Penetration testing (for significant changes)
- Documentation of security implications

### Vulnerability Handling

1. **Private Disclosure**: Report to security@deepskilling.com
2. **Assessment**: Severity and impact evaluation
3. **Fix Development**: Patch development and testing
4. **Coordinated Disclosure**: Public disclosure with fix
5. **Security Advisory**: CVE assignment if applicable

---

## 📚 Documentation Standards

### Documentation Types

1. **Code Documentation**
   - Inline comments for complex logic
   - Function/method documentation
   - Module-level documentation

2. **API Documentation**
   - Public API reference
   - Usage examples
   - Error conditions

3. **User Documentation**
   - Installation guide
   - Usage tutorials
   - Configuration reference

### Documentation Guidelines

**Writing Style**:
- Clear and concise language
- Active voice preferred
- Include code examples
- Explain the "why" not just the "how"

**Example Documentation**:
```rust
/// Performs OS detection using multiple fingerprinting techniques
///
/// This function combines active and passive OS detection methods to
/// identify the operating system running on the target host. It analyzes
/// TCP stack behavior, timing characteristics, and protocol responses.
///
/// # Arguments
/// * `target` - The target host to fingerprint
///
/// # Returns
/// * `Ok(OsInfo)` - Detected OS information with confidence score
/// * `Err(ScannerError)` - Detection failed or insufficient data
///
/// # Examples
/// ```rust
/// let target = ScanTarget::new("192.168.1.1".parse()?);
/// let os_info = detector.detect_os(&target).await?;
/// println!("Detected OS: {} (confidence: {:.2})",
///          os_info.os_name.unwrap_or("Unknown".to_string()),
///          detector.get_confidence_score(&os_info));
/// ```
///
/// # Security Considerations
/// OS detection sends multiple probe packets which may be logged by
/// the target system or detected by intrusion detection systems.
async fn detect_os(&self, target: &ScanTarget) -> Result<OsInfo>
```

---

## 🌟 Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors.

**Our Standards**:
- **Respectful Communication**: Treat all community members with respect
- **Constructive Feedback**: Provide helpful, actionable feedback
- **Collaborative Spirit**: Work together towards common goals
- **Professional Behavior**: Maintain professional standards in all interactions

**Unacceptable Behavior**:
- Harassment, discrimination, or hate speech
- Personal attacks or trolling
- Spam or off-topic discussions
- Sharing others' private information

### Getting Help

**Community Resources**:
- 🐛 **GitHub Issues**: Bug reports and feature requests
- 💬 **GitHub Discussions**: General questions and discussions
- 📧 **Email**: [contact@deepskilling.com](mailto:contact@deepskilling.com)
- 🌐 **Website**: [deepskilling.com](https://deepskilling.com)

**Response Times**:
- Bug reports: Within 48 hours
- Feature requests: Within 1 week
- Security issues: Within 24 hours
- General questions: Within 72 hours

### Recognition

**Contributors** are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Annual contributor highlights

---

## 🚀 Advanced Contribution Areas

### High-Impact Areas

1. **Performance Optimization**
   - Scanning algorithm improvements
   - Memory usage optimization
   - Network efficiency enhancements

2. **New Scan Types**
   - Custom scan technique implementations
   - Protocol-specific scanners
   - Stealth scanning methods

3. **Service Detection**
   - New service signatures
   - Version detection improvements
   - Protocol analyzers

4. **Platform Support**
   - Windows-specific optimizations
   - macOS compatibility improvements
   - Embedded system support

### Research Areas

1. **Machine Learning Integration**
   - ML-based OS detection
   - Anomaly detection
   - Pattern recognition

2. **IPv6 Support**
   - IPv6 scanning techniques
   - Dual-stack implementations
   - IPv6-specific evasion

3. **Cloud Environment Scanning**
   - Container scanning
   - Kubernetes cluster discovery
   - Cloud-native integrations

---

## 📞 Getting Started Checklist

Ready to contribute? Follow this checklist:

- [ ] Read the [Code of Conduct](CODE_OF_CONDUCT.md)
- [ ] Set up your development environment
- [ ] Fork and clone the repository
- [ ] Build the project successfully
- [ ] Run the test suite
- [ ] Choose an issue or propose a feature
- [ ] Create a feature branch
- [ ] Make your changes
- [ ] Add tests for your changes
- [ ] Update documentation
- [ ] Submit a pull request

---

**Thank you for contributing to RustMap!** 🎉

Your contributions help make network security more accessible and effective for everyone.

---

**RustMap Contributing Guide** - *Building the Future of Network Scanning*

**© 2025 Deepskilling Inc** | [Website](https://deepskilling.com) | [Contact](mailto:contact@deepskilling.com)

*Together, we advance cybersecurity through innovation* 🛡️
