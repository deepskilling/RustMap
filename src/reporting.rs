//! Report generation and output formatting
//!
//! Provides multiple output formats for scan results

use async_trait::async_trait;
use std::path::Path;
use tokio::fs;
use crate::{
    config::AppConfig,
    core::ScanResults,
    error::{Result, ScannerError},
};

#[async_trait]
pub trait ReportGenerator {
    async fn generate_report(&self, results: &ScanResults, format: &str, output_path: &Path) -> Result<()>;
}

pub struct DefaultReportGenerator {
    _config: AppConfig,
}

impl DefaultReportGenerator {
    pub fn new(config: AppConfig) -> Self {
        Self { _config: config }
    }
}

#[async_trait]
impl ReportGenerator for DefaultReportGenerator {
    async fn generate_report(&self, results: &ScanResults, format: &str, output_path: &Path) -> Result<()> {
        // Ensure output directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        let content = match format.to_lowercase().as_str() {
            "json" => self.generate_json_report(results)?,
            "xml" => self.generate_xml_report(results)?,
            "csv" => self.generate_csv_report(results)?,
            "human" => self.generate_human_report(results)?,
            _ => return Err(ScannerError::output(format, "Unsupported output format")),
        };
        
        fs::write(output_path, content).await?;
        tracing::info!("Report generated: {} ({})", output_path.display(), format);
        
        Ok(())
    }
}

impl DefaultReportGenerator {
    fn generate_json_report(&self, results: &ScanResults) -> Result<String> {
        let json = serde_json::to_string_pretty(results)
            .map_err(|e| ScannerError::output("json", format!("JSON serialization failed: {}", e)))?;
        Ok(json)
    }
    
    fn generate_xml_report(&self, results: &ScanResults) -> Result<String> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<nmapresults>\n");
        xml.push_str(&format!("  <session id=\"{}\">\n", results.session_id));
        xml.push_str(&format!("    <targets_scanned>{}</targets_scanned>\n", results.targets_scanned));
        xml.push_str(&format!("    <total_ports_scanned>{}</total_ports_scanned>\n", results.total_ports_scanned));
        xml.push_str(&format!("    <duration>{}</duration>\n", results.duration.as_secs_f64()));
        xml.push_str(&format!("    <completed_at>{}</completed_at>\n", results.completed_at.to_rfc3339()));
        
        xml.push_str("    <discoveries>\n");
        for discovery in &results.discoveries {
            xml.push_str("      <port>\n");
            xml.push_str(&format!("        <target>{}</target>\n", discovery.target.ip()));
            xml.push_str(&format!("        <port>{}</port>\n", discovery.port));
            xml.push_str(&format!("        <protocol>{:?}</protocol>\n", discovery.protocol));
            xml.push_str(&format!("        <state>{}</state>\n", discovery.state.as_str()));
            if let Some(service) = &discovery.service_hint {
                xml.push_str(&format!("        <service>{}</service>\n", service));
            }
            xml.push_str(&format!("        <discovered_at>{}</discovered_at>\n", discovery.discovered_at.to_rfc3339()));
            xml.push_str("      </port>\n");
        }
        xml.push_str("    </discoveries>\n");
        
        xml.push_str("  </session>\n");
        xml.push_str("</nmapresults>\n");
        
        Ok(xml)
    }
    
    fn generate_csv_report(&self, results: &ScanResults) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("target,port,protocol,state,service,discovered_at\n");
        
        for discovery in &results.discoveries {
            csv.push_str(&format!(
                "{},{},{:?},{},{},{}\n",
                discovery.target.ip(),
                discovery.port,
                discovery.protocol,
                discovery.state.as_str(),
                discovery.service_hint.as_deref().unwrap_or("unknown"),
                discovery.discovered_at.to_rfc3339()
            ));
        }
        
        Ok(csv)
    }
    
    fn generate_human_report(&self, results: &ScanResults) -> Result<String> {
        let mut report = String::new();
        
        report.push_str("# Nmap Scanner Results\n\n");
        report.push_str(&format!("Session ID: {}\n", results.session_id));
        report.push_str(&format!("Targets scanned: {}\n", results.targets_scanned));
        report.push_str(&format!("Total ports scanned: {}\n", results.total_ports_scanned));
        report.push_str(&format!("Scan duration: {:.2}s\n", results.duration.as_secs_f64()));
        report.push_str(&format!("Completed at: {}\n\n", results.completed_at.format("%Y-%m-%d %H:%M:%S UTC")));
        
        if !results.discoveries.is_empty() {
            report.push_str("## Port Discoveries\n\n");
            
            // Group by target
            use std::collections::HashMap;
            let mut by_target: HashMap<String, Vec<&crate::core::PortDiscovery>> = HashMap::new();
            for discovery in &results.discoveries {
                by_target.entry(discovery.target.ip().to_string())
                    .or_insert_with(Vec::new)
                    .push(discovery);
            }
            
            for (target, discoveries) in by_target {
                report.push_str(&format!("### Target: {}\n\n", target));
                report.push_str("| Port | Protocol | State | Service |\n");
                report.push_str("|------|----------|-------|----------|\n");
                
                for discovery in discoveries {
                    report.push_str(&format!(
                        "| {} | {:?} | {} | {} |\n",
                        discovery.port,
                        discovery.protocol,
                        discovery.state.as_str(),
                        discovery.service_hint.as_deref().unwrap_or("unknown")
                    ));
                }
                report.push_str("\n");
            }
        }
        
        if !results.services.is_empty() {
            report.push_str("## Services Detected\n\n");
            for service in &results.services {
                report.push_str(&format!(
                    "- {}:{} - {} {}\n",
                    service.target.ip(),
                    service.port,
                    service.service_name,
                    service.version.as_ref()
                        .map(|v| format!("v{}", v.version))
                        .unwrap_or_else(|| "version unknown".to_string())
                ));
            }
            report.push_str("\n");
        }
        
        if !results.errors.is_empty() {
            report.push_str("## Errors\n\n");
            for error in &results.errors {
                report.push_str(&format!("- {}: {}\n", error.target.ip(), error.error));
            }
        }
        
        Ok(report)
    }
}

pub async fn create_report_generator(config: &AppConfig) -> Result<Box<dyn ReportGenerator + Send + Sync>> {
    Ok(Box::new(DefaultReportGenerator::new(config.clone())))
}
