//! Advanced scanning techniques requiring raw sockets
//!
//! Implements SYN, FIN, Xmas, Null scans and other advanced techniques
//! that require packet crafting and raw socket access.

use async_trait::async_trait;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::time::timeout;
use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
use rand::Rng;

use crate::{
    config::AppConfig,
    core::{PortDiscovery, PortState, Protocol, ScanEvent},
    error::{Result, ScannerError},
    scanner::ScanTarget,
    timing::TimingTemplate,
};

/// Advanced scanner using raw sockets for stealth scanning
pub struct AdvancedScanner {
    config: AppConfig,
    timing_template: TimingTemplate,
    raw_socket: Option<Socket>,
    source_port_pool: Vec<u16>,
}

impl AdvancedScanner {
    pub async fn new(config: AppConfig) -> Result<Self> {
        let timing_template = TimingTemplate::from_level(config.scanning.timing_template);
        let source_port_pool = Self::generate_source_ports();
        
        Ok(Self {
            config,
            timing_template,
            raw_socket: None,
            source_port_pool,
        })
    }
    
    /// Initialize raw socket (requires root privileges)
    pub async fn init_raw_socket(&mut self) -> Result<()> {
        // Check if we have root privileges
        if !self.has_root_privileges() {
            return Err(ScannerError::permission(
                "advanced_scan", 
                "Raw socket access requires root privileges. Run with sudo or as administrator."
            ));
        }
        
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(SocketProtocol::TCP))?;
        socket.set_header_included_v4(true)?;
        
        self.raw_socket = Some(socket);
        tracing::info!("Raw socket initialized for advanced scanning");
        Ok(())
    }
    
    /// SYN scan (stealth scan) - sends SYN packets and analyzes responses
    pub async fn syn_scan(&self, targets: &[ScanTarget], ports: &[u16]) -> Result<Vec<PortDiscovery>> {
        if self.raw_socket.is_none() {
            return Err(ScannerError::permission("raw_socket", "Raw socket not initialized"));
        }
        
        let mut discoveries = Vec::new();
        let start_time = Instant::now();
        
        tracing::info!("Starting SYN scan on {} targets, {} ports", targets.len(), ports.len());
        
        for target in targets {
            for &port in ports {
                match self.syn_scan_port(target, port).await {
                    Ok(discovery) => {
                        if let Some(disc) = discovery {
                            discoveries.push(disc);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("SYN scan failed for {}:{}: {}", target.ip(), port, e);
                    }
                }
                
                // Apply timing delays
                if let Some(delay) = self.timing_template.scan_delay() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
        
        tracing::info!("SYN scan completed in {:?}, {} discoveries", 
            start_time.elapsed(), discoveries.len());
        
        Ok(discoveries)
    }
    
    /// FIN scan - sends FIN packets to detect open ports
    pub async fn fin_scan(&self, targets: &[ScanTarget], ports: &[u16]) -> Result<Vec<PortDiscovery>> {
        self.flag_scan(targets, ports, TcpFlags::FIN, "FIN").await
    }
    
    /// Xmas scan - sends packets with FIN, PSH, URG flags
    pub async fn xmas_scan(&self, targets: &[ScanTarget], ports: &[u16]) -> Result<Vec<PortDiscovery>> {
        let flags = TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;
        self.flag_scan(targets, ports, flags, "Xmas").await
    }
    
    /// Null scan - sends packets with no flags set
    pub async fn null_scan(&self, targets: &[ScanTarget], ports: &[u16]) -> Result<Vec<PortDiscovery>> {
        self.flag_scan(targets, ports, TcpFlags::empty(), "Null").await
    }
    
    /// Generic flag-based scan implementation
    async fn flag_scan(
        &self,
        targets: &[ScanTarget],
        ports: &[u16],
        flags: TcpFlags,
        scan_name: &str,
    ) -> Result<Vec<PortDiscovery>> {
        if self.raw_socket.is_none() {
            return Err(ScannerError::permission("raw_socket", "Raw socket not initialized"));
        }
        
        let mut discoveries = Vec::new();
        let start_time = Instant::now();
        
        tracing::info!("Starting {} scan on {} targets, {} ports", scan_name, targets.len(), ports.len());
        
        for target in targets {
            for &port in ports {
                match self.flag_scan_port(target, port, flags).await {
                    Ok(discovery) => {
                        if let Some(disc) = discovery {
                            discoveries.push(disc);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("{} scan failed for {}:{}: {}", scan_name, target.ip(), port, e);
                    }
                }
                
                // Apply timing delays
                if let Some(delay) = self.timing_template.scan_delay() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
        
        tracing::info!("{} scan completed in {:?}, {} discoveries", 
            scan_name, start_time.elapsed(), discoveries.len());
        
        Ok(discoveries)
    }
    
    /// Perform SYN scan on a single port
    async fn syn_scan_port(&self, target: &ScanTarget, port: u16) -> Result<Option<PortDiscovery>> {
        let source_port = self.get_random_source_port();
        let tcp_packet = self.craft_tcp_packet(target.ip(), port, source_port, TcpFlags::SYN)?;
        
        // Send packet
        self.send_packet(&tcp_packet, target.ip()).await?;
        
        // Wait for response
        let response = timeout(Duration::from_millis(1000), self.receive_response()).await;
        
        match response {
            Ok(Ok(packet)) => {
                let state = self.analyze_syn_response(&packet, port, source_port)?;
                
                if state != PortState::Filtered {
                    Ok(Some(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state,
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    }))
                } else {
                    Ok(None)
                }
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout - port is likely filtered
                Ok(Some(PortDiscovery {
                    target: target.clone(),
                    port,
                    protocol: Protocol::Tcp,
                    state: PortState::Filtered,
                    service_hint: None,
                    discovered_at: chrono::Utc::now(),
                }))
            }
        }
    }
    
    /// Perform flag-based scan on a single port
    async fn flag_scan_port(&self, target: &ScanTarget, port: u16, flags: TcpFlags) -> Result<Option<PortDiscovery>> {
        let source_port = self.get_random_source_port();
        let tcp_packet = self.craft_tcp_packet(target.ip(), port, source_port, flags)?;
        
        // Send packet
        self.send_packet(&tcp_packet, target.ip()).await?;
        
        // Wait for response
        let response = timeout(Duration::from_millis(1000), self.receive_response()).await;
        
        match response {
            Ok(Ok(packet)) => {
                let state = self.analyze_flag_response(&packet, port, source_port)?;
                
                if state != PortState::Filtered {
                    Ok(Some(PortDiscovery {
                        target: target.clone(),
                        port,
                        protocol: Protocol::Tcp,
                        state,
                        service_hint: None,
                        discovered_at: chrono::Utc::now(),
                    }))
                } else {
                    Ok(None)
                }
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // No response indicates open or filtered port for flag scans
                Ok(Some(PortDiscovery {
                    target: target.clone(),
                    port,
                    protocol: Protocol::Tcp,
                    state: PortState::OpenFiltered,
                    service_hint: None,
                    discovered_at: chrono::Utc::now(),
                }))
            }
        }
    }
    
    /// Craft TCP packet with specified flags
    fn craft_tcp_packet(&self, dest_ip: IpAddr, dest_port: u16, source_port: u16, flags: TcpFlags) -> Result<Vec<u8>> {
        if let IpAddr::V4(ipv4) = dest_ip {
            let mut packet = Vec::new();
            
            // IP Header (20 bytes)
            let ip_header = IpHeader {
                version_ihl: 0x45, // IPv4, header length 20 bytes
                tos: 0,
                total_length: 40, // IP header (20) + TCP header (20)
                identification: rand::thread_rng().gen(),
                flags_fragment: 0x4000, // Don't fragment
                ttl: 64,
                protocol: 6, // TCP
                checksum: 0, // Will be calculated
                source_ip: self.get_source_ip()?,
                dest_ip: ipv4,
            };
            
            packet.extend_from_slice(&ip_header.to_bytes());
            
            // TCP Header (20 bytes)
            let tcp_header = TcpHeader {
                source_port,
                dest_port,
                seq_number: rand::thread_rng().gen(),
                ack_number: 0,
                header_length: 0x50, // 20 bytes
                flags: flags.bits(),
                window_size: 1024,
                checksum: 0, // Will be calculated
                urgent_pointer: 0,
            };
            
            packet.extend_from_slice(&tcp_header.to_bytes());
            
            // Calculate checksums
            self.calculate_checksums(&mut packet)?;
            
            Ok(packet)
        } else {
            Err(ScannerError::validation("ip", "IPv6 not supported for raw scanning yet"))
        }
    }
    
    /// Send raw packet
    async fn send_packet(&self, packet: &[u8], dest_ip: IpAddr) -> Result<()> {
        if let Some(ref socket) = self.raw_socket {
            if let IpAddr::V4(ipv4) = dest_ip {
                let addr = SocketAddr::new(dest_ip, 0);
                socket.send_to(packet, &addr.into())?;
                Ok(())
            } else {
                Err(ScannerError::validation("ip", "IPv6 not supported yet"))
            }
        } else {
            Err(ScannerError::permission("raw_socket", "Raw socket not initialized"))
        }
    }
    
    /// Receive response packet
    async fn receive_response(&self) -> Result<Vec<u8>> {
        if let Some(ref socket) = self.raw_socket {
            use std::mem::MaybeUninit;
            let mut buffer: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 65536];
            let (size, _) = socket.recv_from(&mut buffer)?;
            let mut result = Vec::with_capacity(size);
            for i in 0..size {
                unsafe {
                    result.push(buffer[i].assume_init());
                }
            }
            Ok(result)
        } else {
            Err(ScannerError::permission("raw_socket", "Raw socket not initialized"))
        }
    }
    
    /// Analyze SYN scan response to determine port state
    fn analyze_syn_response(&self, packet: &[u8], expected_port: u16, expected_source: u16) -> Result<PortState> {
        if packet.len() < 40 {
            return Ok(PortState::Filtered);
        }
        
        // Parse IP header to get TCP header offset
        let ip_header_len = ((packet[0] & 0x0F) * 4) as usize;
        if packet.len() < ip_header_len + 20 {
            return Ok(PortState::Filtered);
        }
        
        let tcp_header = &packet[ip_header_len..];
        let source_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
        let dest_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);
        let flags = tcp_header[13];
        
        // Check if this is a response to our probe
        if source_port != expected_port || dest_port != expected_source {
            return Ok(PortState::Filtered);
        }
        
        // Analyze TCP flags
        if flags & 0x12 == 0x12 {
            // SYN+ACK - port is open
            Ok(PortState::Open)
        } else if flags & 0x04 != 0 {
            // RST - port is closed
            Ok(PortState::Closed)
        } else {
            Ok(PortState::Filtered)
        }
    }
    
    /// Analyze flag scan response to determine port state
    fn analyze_flag_response(&self, packet: &[u8], expected_port: u16, expected_source: u16) -> Result<PortState> {
        if packet.len() < 40 {
            return Ok(PortState::OpenFiltered);
        }
        
        let ip_header_len = ((packet[0] & 0x0F) * 4) as usize;
        if packet.len() < ip_header_len + 20 {
            return Ok(PortState::OpenFiltered);
        }
        
        let tcp_header = &packet[ip_header_len..];
        let source_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
        let dest_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);
        let flags = tcp_header[13];
        
        // Check if this is a response to our probe
        if source_port != expected_port || dest_port != expected_source {
            return Ok(PortState::OpenFiltered);
        }
        
        // For FIN/Xmas/Null scans, RST indicates closed port
        if flags & 0x04 != 0 {
            Ok(PortState::Closed)
        } else {
            // No response or unexpected response indicates open|filtered
            Ok(PortState::OpenFiltered)
        }
    }
    
    /// Check if running with root privileges
    fn has_root_privileges(&self) -> bool {
        #[cfg(unix)]
        {
            use nix::unistd::getuid;
            getuid().is_root()
        }
        #[cfg(windows)]
        {
            // Windows privilege checking would go here
            false
        }
    }
    
    /// Get source IP for outgoing packets
    fn get_source_ip(&self) -> Result<Ipv4Addr> {
        if let Some(ref source_ip) = self.config.network.source_ip {
            source_ip.parse()
                .map_err(|_| ScannerError::validation("source_ip", "Invalid source IP address"))
        } else {
            // Use default route IP
            Ok(Ipv4Addr::new(0, 0, 0, 0))
        }
    }
    
    /// Get random source port from pool
    fn get_random_source_port(&self) -> u16 {
        let mut rng = rand::thread_rng();
        self.source_port_pool[rng.gen_range(0..self.source_port_pool.len())]
    }
    
    /// Generate pool of random source ports
    fn generate_source_ports() -> Vec<u16> {
        let mut rng = rand::thread_rng();
        (0..1000)
            .map(|_| rng.gen_range(32768..65535))
            .collect()
    }
    
    /// Calculate IP and TCP checksums
    fn calculate_checksums(&self, packet: &mut [u8]) -> Result<()> {
        // Calculate IP checksum
        let ip_checksum = self.calculate_ip_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        
        // Calculate TCP checksum
        let tcp_checksum = self.calculate_tcp_checksum(&packet)?;
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        
        Ok(())
    }
    
    /// Calculate IP header checksum
    fn calculate_ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum = 0u32;
        
        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }
        
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        !(sum as u16)
    }
    
    /// Calculate TCP checksum with pseudo header
    fn calculate_tcp_checksum(&self, packet: &[u8]) -> Result<u16> {
        if packet.len() < 40 {
            return Err(ScannerError::validation("packet", "Packet too small for TCP checksum"));
        }
        
        let source_ip = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
        let dest_ip = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
        let tcp_length = 20u16; // TCP header length
        
        let mut sum = 0u32;
        
        // Pseudo header
        sum += (source_ip >> 16) + (source_ip & 0xFFFF);
        sum += (dest_ip >> 16) + (dest_ip & 0xFFFF);
        sum += 6; // TCP protocol
        sum += tcp_length as u32;
        
        // TCP header
        let tcp_header = &packet[20..40];
        for chunk in tcp_header.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }
        
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        Ok(!(sum as u16))
    }
}

/// TCP flags bitmask
#[derive(Debug, Clone, Copy)]
struct TcpFlags(u8);

impl TcpFlags {
    const FIN: TcpFlags = TcpFlags(0x01);
    const SYN: TcpFlags = TcpFlags(0x02);
    const RST: TcpFlags = TcpFlags(0x04);
    const PSH: TcpFlags = TcpFlags(0x08);
    const ACK: TcpFlags = TcpFlags(0x10);
    const URG: TcpFlags = TcpFlags(0x20);
    
    const fn empty() -> Self {
        TcpFlags(0)
    }
    
    const fn bits(self) -> u8 {
        self.0
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = Self;
    
    fn bitor(self, other: Self) -> Self {
        TcpFlags(self.0 | other.0)
    }
}

/// IP header structure
#[repr(C)]
struct IpHeader {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
}

impl IpHeader {
    fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0] = self.version_ihl;
        bytes[1] = self.tos;
        bytes[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identification.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        bytes[8] = self.ttl;
        bytes[9] = self.protocol;
        bytes[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.source_ip.octets());
        bytes[16..20].copy_from_slice(&self.dest_ip.octets());
        bytes
    }
}

/// TCP header structure
#[repr(C)]
struct TcpHeader {
    source_port: u16,
    dest_port: u16,
    seq_number: u32,
    ack_number: u32,
    header_length: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

impl TcpHeader {
    fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dest_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq_number.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack_number.to_be_bytes());
        bytes[12] = self.header_length;
        bytes[13] = self.flags;
        bytes[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        bytes
    }
}

/// Create advanced scanner instance
pub async fn create_advanced_scanner(config: &AppConfig) -> Result<AdvancedScanner> {
    AdvancedScanner::new(config.clone()).await
}
