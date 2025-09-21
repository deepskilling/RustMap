//! File-based data persistence system
//!
//! Provides storage and retrieval for:
//! - Scan results and session data
//! - Historical scan records
//! - Configuration backups
//! - Target lists and profiles

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tokio::{
    fs,
    io::AsyncWriteExt,
};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    core::{ScanResults, ScanSession},
    error::{Result, ScannerError},
};

/// Trait for scan data storage operations
#[async_trait]
pub trait ScanDataStore {
    /// Store scan results
    async fn store_scan_results(&self, results: &ScanResults) -> Result<()>;
    
    /// Retrieve scan results by session ID
    async fn get_scan_results(&self, session_id: &Uuid) -> Result<Option<ScanResults>>;
    
    /// List all stored scan sessions
    async fn list_scan_sessions(&self) -> Result<Vec<ScanSessionSummary>>;
    
    /// Store scan session metadata
    async fn store_scan_session(&self, session: &ScanSession) -> Result<()>;
    
    /// Delete old scan data based on retention policy
    async fn cleanup_old_data(&self, retention_days: u32) -> Result<usize>;
    
    /// Export scan data to external format
    async fn export_data(&self, format: ExportFormat, output_path: &Path) -> Result<()>;
}

/// File-based implementation of scan data store
pub struct FileBasedDataStore {
    base_dir: PathBuf,
    compression_enabled: bool,
}

impl FileBasedDataStore {
    pub fn new(base_dir: PathBuf, compression_enabled: bool) -> Self {
        Self {
            base_dir,
            compression_enabled,
        }
    }
    
    pub async fn init(&self) -> Result<()> {
        // Create directory structure
        fs::create_dir_all(&self.base_dir).await?;
        fs::create_dir_all(self.base_dir.join("sessions")).await?;
        fs::create_dir_all(self.base_dir.join("results")).await?;
        fs::create_dir_all(self.base_dir.join("exports")).await?;
        
        tracing::info!("File-based data store initialized at: {}", self.base_dir.display());
        Ok(())
    }
}

#[async_trait]
impl ScanDataStore for FileBasedDataStore {
    async fn store_scan_results(&self, results: &ScanResults) -> Result<()> {
        let file_path = self.base_dir
            .join("results")
            .join(format!("{}.json", results.session_id));
        
        let json_data = serde_json::to_string_pretty(results)?;
        
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(json_data.as_bytes()).await?;
        
        tracing::info!("Stored scan results to: {}", file_path.display());
        Ok(())
    }
    
    async fn get_scan_results(&self, session_id: &Uuid) -> Result<Option<ScanResults>> {
        let file_path = self.base_dir
            .join("results")
            .join(format!("{}.json", session_id));
        
        if !file_path.exists() {
            return Ok(None);
        }
        
        let json_data = fs::read_to_string(&file_path).await?;
        let results: ScanResults = serde_json::from_str(&json_data)?;
        
        Ok(Some(results))
    }
    
    async fn list_scan_sessions(&self) -> Result<Vec<ScanSessionSummary>> {
        let sessions_dir = self.base_dir.join("sessions");
        let mut sessions = Vec::new();
        
        let mut entries = fs::read_dir(&sessions_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.path().extension().map(|ext| ext == "json").unwrap_or(false) {
                let json_data = fs::read_to_string(entry.path()).await?;
                if let Ok(session) = serde_json::from_str::<ScanSession>(&json_data) {
                    sessions.push(ScanSessionSummary {
                        id: session.id,
                        target_count: session.targets.len(),
                        scan_types: session.scan_types,
                        created_at: session.created_at,
                        status: SessionStatus::Completed, // Would track this properly
                    });
                }
            }
        }
        
        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(sessions)
    }
    
    async fn store_scan_session(&self, session: &ScanSession) -> Result<()> {
        let file_path = self.base_dir
            .join("sessions")
            .join(format!("{}.json", session.id));
        
        let json_data = serde_json::to_string_pretty(session)?;
        
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(json_data.as_bytes()).await?;
        
        tracing::info!("Stored scan session to: {}", file_path.display());
        Ok(())
    }
    
    async fn cleanup_old_data(&self, retention_days: u32) -> Result<usize> {
        let cutoff_time = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut deleted_count = 0;
        
        // Clean up old results
        let results_dir = self.base_dir.join("results");
        if results_dir.exists() {
            let mut entries = fs::read_dir(&results_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(created) = metadata.created() {
                        let created_time = chrono::DateTime::<chrono::Utc>::from(created);
                        if created_time < cutoff_time {
                            if fs::remove_file(entry.path()).await.is_ok() {
                                deleted_count += 1;
                            }
                        }
                    }
                }
            }
        }
        
        // Clean up old sessions
        let sessions_dir = self.base_dir.join("sessions");
        if sessions_dir.exists() {
            let mut entries = fs::read_dir(&sessions_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(created) = metadata.created() {
                        let created_time = chrono::DateTime::<chrono::Utc>::from(created);
                        if created_time < cutoff_time {
                            if fs::remove_file(entry.path()).await.is_ok() {
                                deleted_count += 1;
                            }
                        }
                    }
                }
            }
        }
        
        tracing::info!("Cleaned up {} old data files", deleted_count);
        Ok(deleted_count)
    }
    
    async fn export_data(&self, format: ExportFormat, output_path: &Path) -> Result<()> {
        // Get all scan results
        let sessions = self.list_scan_sessions().await?;
        let mut all_results = Vec::new();
        
        for session in sessions {
            if let Ok(Some(results)) = self.get_scan_results(&session.id).await {
                all_results.push(results);
            }
        }
        
        match format {
            ExportFormat::Json => {
                let json_data = serde_json::to_string_pretty(&all_results)?;
                fs::write(output_path, json_data).await?;
            }
            ExportFormat::Csv => {
                let csv_data = self.results_to_csv(&all_results)?;
                fs::write(output_path, csv_data).await?;
            }
            ExportFormat::Xml => {
                // Would implement XML export
                return Err(ScannerError::output("xml", "XML export not implemented yet"));
            }
        }
        
        tracing::info!("Exported data to: {}", output_path.display());
        Ok(())
    }
}

impl FileBasedDataStore {
    fn results_to_csv(&self, results: &[ScanResults]) -> Result<String> {
        let mut csv_content = String::new();
        csv_content.push_str("session_id,target_ip,port,protocol,state,service,timestamp\n");
        
        for result in results {
            for discovery in &result.discoveries {
                csv_content.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    result.session_id,
                    discovery.target.ip(),
                    discovery.port,
                    format!("{:?}", discovery.protocol).to_lowercase(),
                    discovery.state.as_str(),
                    discovery.service_hint.as_deref().unwrap_or("unknown"),
                    discovery.discovered_at.to_rfc3339()
                ));
            }
        }
        
        Ok(csv_content)
    }
}

/// Supporting data structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSessionSummary {
    pub id: Uuid,
    pub target_count: usize,
    pub scan_types: Vec<crate::core::ScanType>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
}

/// Configuration management for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub base_directory: PathBuf,
    pub auto_save_enabled: bool,
    pub compression_enabled: bool,
    pub retention_days: u32,
    pub max_storage_size_mb: usize,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            base_directory: PathBuf::from("./data"),
            auto_save_enabled: true,
            compression_enabled: true,
            retention_days: 30,
            max_storage_size_mb: 1024,
        }
    }
}

/// Target list management
pub struct TargetListManager {
    storage_dir: PathBuf,
}

impl TargetListManager {
    pub fn new(storage_dir: PathBuf) -> Self {
        Self { storage_dir }
    }
    
    pub async fn save_target_list(&self, name: &str, targets: &[String]) -> Result<()> {
        let file_path = self.storage_dir.join(format!("{}.targets", name));
        let content = targets.join("\n");
        fs::write(&file_path, content).await?;
        
        tracing::info!("Saved target list '{}' with {} targets", name, targets.len());
        Ok(())
    }
    
    pub async fn load_target_list(&self, name: &str) -> Result<Vec<String>> {
        let file_path = self.storage_dir.join(format!("{}.targets", name));
        let content = fs::read_to_string(&file_path).await?;
        
        let targets: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        
        Ok(targets)
    }
    
    pub async fn list_target_lists(&self) -> Result<Vec<String>> {
        let mut lists = Vec::new();
        let mut entries = fs::read_dir(&self.storage_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.ends_with(".targets") {
                    let name = file_name.strip_suffix(".targets").unwrap();
                    lists.push(name.to_string());
                }
            }
        }
        
        lists.sort();
        Ok(lists)
    }
}

/// Factory function for creating data store
pub async fn create_data_store(config: &AppConfig) -> Result<Box<dyn ScanDataStore + Send + Sync>> {
    let data_store = FileBasedDataStore::new(
        config.persistence.data_dir.clone(),
        config.persistence.compression_level > 0,
    );
    
    data_store.init().await?;
    Ok(Box::new(data_store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::scanner::ScanTarget;
    use std::net::IpAddr;
    
    #[tokio::test]
    async fn test_file_store_operations() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileBasedDataStore::new(temp_dir.path().to_path_buf(), false);
        store.init().await.unwrap();
        
        // Create test scan results
        let results = ScanResults {
            session_id: Uuid::new_v4(),
            targets_scanned: 1,
            total_ports_scanned: 1000,
            discoveries: vec![],
            services: vec![],
            os_detections: vec![],
            vulnerabilities: vec![],
            errors: vec![],
            duration: std::time::Duration::from_secs(30),
            completed_at: chrono::Utc::now(),
        };
        
        // Store and retrieve
        store.store_scan_results(&results).await.unwrap();
        let retrieved = store.get_scan_results(&results.session_id).await.unwrap();
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, results.session_id);
    }
}
