mod accounting;
mod acme;
mod config;
mod logging;
mod panel;
mod protocols;
mod runtime;
mod status;
mod ws;

use anyhow::Context;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    logging::init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let config = config::AppConfig::load(&config_path)
        .await
        .with_context(|| format!("load config from {}", config_path.display()))?;

    runtime::run(config).await
}
