use anyhow::Result;
use clap::Parser;
use nmap_scanner::{
    cli::Cli,
    config::AppConfig,
    core::Application,
    logging,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging first
    logging::init_logging()?;
    
    info!("Starting nmap_scanner application");
    
    // Parse CLI arguments
    let cli = Cli::parse();
    
    // Load configuration
    let config = AppConfig::load(&cli.config_path).await?;
    
    // Create and run application
    let mut app = Application::new(config).await?;
    app.run(cli).await?;
    
    info!("Application completed successfully");
    Ok(())
}
