//! Authenticated panel configuration updates and recoverable panel migration.
use crate::{
    config::{AppConfig, PanelConfig},
    panel::MachinePanelClient,
    protocols::ProtocolKind,
    runtime::MachineRuntime,
};
use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{fs, io::AsyncWriteExt};
use tracing::{info, warn};

#[derive(Clone, Deserialize)]
pub struct ManagedConfiguration {
    pub revision: u64,
    pub config: AppConfig,
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    source: PanelConfig,
    revision: u64,
    status: String,
    message: String,
}

#[derive(Debug)]
struct RollbackFailed(anyhow::Error);

impl std::fmt::Display for RollbackFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "source runtime could not be restored: {}",
            self.0
        )
    }
}

impl std::error::Error for RollbackFailed {}

pub async fn run(path: &Path, mut config: AppConfig) -> anyhow::Result<()> {
    let mut raw = fs::read_to_string(path).await?;
    let mut runtime = MachineRuntime::start(config.clone()).await?;
    let receipt_path = suffixed(path, ".configuration-status.json");
    let mut receipt: Option<Receipt> = match fs::read(&receipt_path).await {
        Ok(raw) => Some(serde_json::from_slice(&raw).context("read configuration status receipt")?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let signal = shutdown_signal();
    tokio::pin!(signal);
    info!("NodeRS is running; managed configuration sync is active");

    loop {
        tokio::select! {
            result = &mut signal => {
                result?;
                return runtime.shutdown_all().await;
            }
            _ = ticker.tick() => {}
        }
        if let Some(result) = &receipt {
            if deliver_receipt(result).await.is_ok() {
                fs::remove_file(&receipt_path).await?;
                receipt = None;
            }
        }

        let local_raw = match fs::read_to_string(path).await {
            Ok(raw) => raw,
            Err(error) => {
                warn!(%error, "cannot read local configuration; keeping active configuration");
                continue;
            }
        };
        let local_config: AppConfig = match toml::from_str(&local_raw) {
            Ok(config) => config,
            Err(_) => {
                warn!("invalid local configuration; keeping active configuration");
                continue;
            }
        };
        let (candidate, candidate_raw, revision) = if local_config != config {
            (local_config, local_raw, None)
        } else {
            let desired = match runtime.panel().managed_configuration().await {
                Ok(Some(desired)) => desired,
                Ok(None) => continue,
                Err(error) => {
                    warn!(%error, "managed configuration sync failed; keeping active configuration");
                    continue;
                }
            };
            if receipt
                .as_ref()
                .is_some_and(|r| r.source == config.panel && r.revision == desired.revision)
            {
                continue;
            }
            let candidate_raw = toml::to_string_pretty(&desired.config)?;
            (desired.config, candidate_raw, Some(desired.revision))
        };
        let source = config.panel.clone();
        let outcome = if candidate == config {
            Ok(runtime.clone())
        } else {
            switch(&runtime, &candidate, path, &raw, &candidate_raw).await
        };
        let mut fatal_error = None;
        let (status, message) = match outcome {
            Ok(next) => {
                runtime = next;
                config = candidate;
                raw = candidate_raw;
                info!("panel configuration applied and saved");
                ("applied", "configuration applied and saved")
            }
            Err(error) => {
                warn!(%error, "configuration change failed; previous configuration retained");
                // A local migration command may already have replaced the file.
                write_atomic(path, raw.as_bytes()).await?;
                if error.is::<RollbackFailed>() {
                    fatal_error = Some(error);
                }
                (
                    "failed",
                    "configuration could not be applied; previous configuration retained; inspect NodeRS logs",
                )
            }
        };
        if let Some(revision) = revision {
            let result = Receipt {
                source,
                revision,
                status: status.into(),
                message: message.into(),
            };
            write_atomic(&receipt_path, &serde_json::to_vec(&result)?).await?;
            if fatal_error.is_none() && deliver_receipt(&result).await.is_ok() {
                fs::remove_file(&receipt_path).await?;
            } else {
                receipt = Some(result);
            }
        }
        if let Some(error) = fatal_error {
            // Exit after restoring the source file so the service manager can
            // restart it, instead of leaving a partially resumed runtime idle.
            return Err(error);
        }
    }
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("wait for interrupt signal"),
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("wait for interrupt signal")
}

async fn deliver_receipt(result: &Receipt) -> anyhow::Result<()> {
    MachinePanelClient::new(&result.source)?
        .configuration_status(result.revision, &result.status, &result.message)
        .await
}

async fn switch(
    current: &Arc<MachineRuntime>,
    candidate: &AppConfig,
    path: &Path,
    previous: &str,
    next: &str,
) -> anyhow::Result<Arc<MachineRuntime>> {
    validate_target(candidate).await?;
    backup(path, previous.as_bytes()).await?;
    if let Err(error) = current.shutdown_all().await {
        resume_source(current).await?;
        return Err(error);
    }
    let next_runtime = match MachineRuntime::start(candidate.clone()).await {
        Ok(runtime) => runtime,
        Err(error) => {
            resume_source(current).await?;
            return Err(error.context("target runtime could not initialize"));
        }
    };
    // Aerion starts listeners asynchronously. Check that none exited immediately.
    tokio::time::sleep(Duration::from_millis(250)).await;
    if let Err(error) = next_runtime.ensure_running().await {
        let _ = next_runtime.shutdown_all().await;
        resume_source(current).await?;
        return Err(error);
    }
    if let Err(error) = write_atomic(path, next.as_bytes()).await {
        let _ = next_runtime.shutdown_all().await;
        resume_source(current).await?;
        return Err(error);
    }
    Ok(next_runtime)
}

async fn resume_source(current: &Arc<MachineRuntime>) -> anyhow::Result<()> {
    let result = async {
        current.resume().await?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        current.ensure_running().await
    }
    .await;
    result.map_err(|error| anyhow::Error::new(RollbackFailed(error)))
}

async fn validate_target(config: &AppConfig) -> anyhow::Result<()> {
    let panel = &config.panel;
    let url = reqwest::Url::parse(&panel.api).context("parse target panel address")?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "target panel must use HTTP or HTTPS"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "target panel must use a root address without credentials or query"
    );
    ensure!(
        panel.machine_id > 0 && !panel.key.trim().is_empty(),
        "target machine id and key are required"
    );
    let client = MachinePanelClient::new(panel)?;
    client
        .fetch_handshake()
        .await
        .context("authenticate target machine")?;
    let nodes = client.fetch_machine_nodes().await?;
    for node in nodes.nodes {
        if ProtocolKind::parse(&node.node_type).is_none() {
            bail!("target node {} uses unsupported protocol", node.id);
        }
        let client = client.node_client(node.id);
        client
            .fetch_node_config(None)
            .await
            .context("fetch target node configuration")?;
        client
            .fetch_users(None)
            .await
            .context("fetch target node users")?;
    }
    Ok(())
}

pub async fn migrate_file(current: &Path, target: &Path) -> anyhow::Result<()> {
    let raw = fs::read(current).await?;
    let target_raw = fs::read(target).await?;
    let config: AppConfig = toml::from_str(std::str::from_utf8(&target_raw)?)?;
    validate_target(&config).await?;
    let backup_path = backup(current, &raw).await?;
    write_atomic(current, &target_raw).await?;
    println!(
        "Target authenticated; configuration saved. Backup: {}",
        backup_path.display()
    );
    println!(
        "A running NodeRS with managed configuration support reloads within 30 seconds. Otherwise restart the existing service."
    );
    Ok(())
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

async fn backup(path: &Path, raw: &[u8]) -> anyhow::Result<PathBuf> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let target = suffixed(path, &format!(".backup-{nonce}"));
    write_private(&target, raw).await?;
    Ok(target)
}

async fn write_private(path: &Path, raw: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    file.write_all(raw).await?;
    file.sync_all().await?;
    Ok(())
}

async fn write_atomic(path: &Path, raw: &[u8]) -> anyhow::Result<()> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = suffixed(path, &format!(".tmp-{nonce}"));
    write_private(&temporary, raw).await?;
    if let Ok(metadata) = fs::metadata(path).await {
        fs::set_permissions(&temporary, metadata.permissions()).await?;
    }
    fs::rename(&temporary, path).await?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            directory.sync_all()?;
        }
    }
    Ok(())
}
