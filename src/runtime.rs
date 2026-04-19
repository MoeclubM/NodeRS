use anyhow::Context;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::accounting::Accounting;
use crate::config::AppConfig;
use crate::panel::{
    BaseConfig, FetchState, MachineNodeSummary, MachinePanelClient, NodeConfigResponse,
    NodePanelClient, PanelUser, StatusPayload, TrafficReportError,
};
use crate::protocols::{ProtocolController, ProtocolKind};
use crate::status;
use crate::ws;

const DEFAULT_PANEL_PULL_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_PANEL_PUSH_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_STATUS_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_PROTOCOL_ASSET_REFRESH_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_MIN_TRAFFIC_BYTES: u64 = 0;

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let runtime = Arc::new(MachineRuntime::new(config)?);
    runtime.initialize().await?;
    runtime.spawn_background_tasks();

    info!("NodeRS-AnyTLS is running; press Ctrl+C to stop");
    tokio::signal::ctrl_c().await.context("wait for Ctrl+C")?;
    runtime.shutdown_all().await;
    Ok(())
}

pub(crate) struct MachineRuntime {
    panel: MachinePanelClient,
    nodes: RwLock<HashMap<i64, Arc<ManagedNode>>>,
    machine_base_config: RwLock<Option<BaseConfig>>,
    machine_pull_interval: AtomicU64,
    reconcile_lock: AsyncMutex<()>,
}

struct ManagedNode {
    node_id: i64,
    panel: NodePanelClient,
    accounting: Arc<Accounting>,
    controller: ProtocolController,
    machine_base_config: RwLock<Option<BaseConfig>>,
    pull_interval: AtomicU64,
    push_interval: AtomicU64,
    sync_state: AsyncMutex<NodeSyncState>,
    shutdown_tx: watch::Sender<bool>,
    task_handles: Mutex<Vec<JoinHandle<()>>>,
}

#[derive(Default)]
struct NodeSyncState {
    config_etag: Option<String>,
    user_etag: Option<String>,
}

impl MachineRuntime {
    fn new(config: AppConfig) -> anyhow::Result<Self> {
        Ok(Self {
            panel: MachinePanelClient::new(&config.panel)?,
            nodes: RwLock::new(HashMap::new()),
            machine_base_config: RwLock::new(None),
            machine_pull_interval: AtomicU64::new(DEFAULT_PANEL_PULL_INTERVAL_SECONDS),
            reconcile_lock: AsyncMutex::new(()),
        })
    }

    async fn initialize(self: &Arc<Self>) -> anyhow::Result<()> {
        let handshake = self.panel.fetch_handshake().await?;
        self.refresh_machine_nodes().await?;

        if handshake.websocket.enabled {
            let ws_url = handshake.websocket.ws_url.trim();
            if ws_url.is_empty() {
                warn!("Xboard websocket handshake succeeded but ws_url is empty");
            } else {
                ws::spawn_machine_websocket(self.panel.clone(), ws_url.to_string(), self.clone());
            }
        } else {
            info!("Xboard websocket is disabled; using HTTP polling for machine sync");
        }

        Ok(())
    }

    fn spawn_background_tasks(self: &Arc<Self>) {
        self.spawn_machine_sync_task();
        self.spawn_status_task();
        self.spawn_protocol_asset_refresh_task();
    }

    fn spawn_machine_sync_task(self: &Arc<Self>) {
        let runtime = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(runtime.machine_pull_interval())).await;
                if let Err(error) = runtime.refresh_machine_nodes().await {
                    warn!(%error, "machine node sync failed");
                }
            }
        });
    }

    fn spawn_status_task(self: &Arc<Self>) {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(DEFAULT_STATUS_INTERVAL_SECONDS));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let payload = status::collect_status();
                if let Err(error) = runtime.panel.report_machine_status(&payload).await {
                    warn!(%error, "machine status report failed");
                }
                for node in runtime.nodes_snapshot() {
                    if let Err(error) = node.report_status(&payload).await {
                        warn!(node_id = node.node_id, %error, "node status report failed");
                    }
                }
            }
        });
    }

    fn spawn_protocol_asset_refresh_task(self: &Arc<Self>) {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(
                DEFAULT_PROTOCOL_ASSET_REFRESH_INTERVAL_SECONDS,
            ));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                for node in runtime.nodes_snapshot() {
                    if let Err(error) = node.refresh_runtime_assets().await {
                        warn!(node_id = node.node_id, %error, "protocol runtime refresh failed");
                    }
                }
            }
        });
    }

    pub(crate) async fn refresh_machine_nodes(&self) -> anyhow::Result<()> {
        let _guard = self.reconcile_lock.lock().await;
        let response = self.panel.fetch_machine_nodes().await?;
        let base_config = response.base_config.clone();

        self.machine_pull_interval.store(
            pull_interval_seconds(base_config.as_ref()),
            Ordering::Relaxed,
        );
        *self
            .machine_base_config
            .write()
            .expect("machine base config lock poisoned") = base_config.clone();

        for node in self.nodes_snapshot() {
            node.set_machine_base_config(base_config.clone());
        }

        self.reconcile_nodes(response.nodes).await
    }

    pub(crate) async fn handle_sync_nodes(&self) -> anyhow::Result<()> {
        self.refresh_machine_nodes().await
    }

    pub(crate) async fn handle_sync_config(
        &self,
        node_id: i64,
        config: NodeConfigResponse,
    ) -> anyhow::Result<()> {
        let Some(node) = self.node(node_id) else {
            warn!(
                node_id,
                "received sync.config for unknown node; refreshing machine nodes"
            );
            return self.refresh_machine_nodes().await;
        };
        node.apply_remote_config(&config).await
    }

    pub(crate) async fn handle_sync_users(
        &self,
        node_id: i64,
        users: Vec<PanelUser>,
    ) -> anyhow::Result<()> {
        let Some(node) = self.node(node_id) else {
            warn!(
                node_id,
                "received sync.users for unknown node; refreshing machine nodes"
            );
            return self.refresh_machine_nodes().await;
        };
        node.replace_users(&users);
        Ok(())
    }

    pub(crate) async fn refresh_node_users(&self, node_id: i64) -> anyhow::Result<()> {
        let Some(node) = self.node(node_id) else {
            warn!(
                node_id,
                "received sync.user.delta for unknown node; refreshing machine nodes"
            );
            return self.refresh_machine_nodes().await;
        };
        node.sync_users(true).await
    }

    pub(crate) async fn handle_sync_devices(
        &self,
        node_id: i64,
        users: HashMap<String, Vec<String>>,
    ) -> anyhow::Result<()> {
        let Some(node) = self.node(node_id) else {
            warn!(
                node_id,
                "received sync.devices for unknown node; refreshing machine nodes"
            );
            return self.refresh_machine_nodes().await;
        };
        node.set_external_alive_counts(&alive_counts(&users));
        Ok(())
    }

    async fn reconcile_nodes(&self, machine_nodes: Vec<MachineNodeSummary>) -> anyhow::Result<()> {
        let mut desired_nodes = Vec::new();
        for node in machine_nodes {
            let Some(protocol) = ProtocolKind::parse(&node.node_type) else {
                warn!(
                    node_id = node.id,
                    node_type = %node.node_type,
                    "skipping unsupported panel-managed node type"
                );
                continue;
            };
            desired_nodes.push((node, protocol));
        }

        let desired_ids = desired_nodes
            .iter()
            .map(|(node, _)| node.id)
            .collect::<HashSet<_>>();
        let removed = {
            let mut guard = self.nodes.write().expect("nodes lock poisoned");
            let current_ids = guard.keys().copied().collect::<Vec<_>>();
            let mut removed = Vec::new();
            for node_id in current_ids {
                if !desired_ids.contains(&node_id)
                    && let Some(node) = guard.remove(&node_id)
                {
                    removed.push(node);
                }
            }
            removed
        };

        for node in removed {
            info!(node_id = node.node_id, "stopping node removed by panel");
            node.shutdown().await;
        }

        let machine_base_config = self.machine_base_config();
        for (summary, protocol) in desired_nodes {
            if self
                .nodes
                .read()
                .expect("nodes lock poisoned")
                .contains_key(&summary.id)
            {
                continue;
            }

            let node = Arc::new(ManagedNode::new(
                summary.id,
                protocol,
                self.panel.node_client(summary.id),
                machine_base_config.clone(),
            ));
            node.initialize().await?;
            node.spawn_background_tasks();
            self.nodes
                .write()
                .expect("nodes lock poisoned")
                .insert(summary.id, node);
            info!(
                node_id = summary.id,
                protocol = protocol.as_str(),
                "started panel-managed node"
            );
        }

        Ok(())
    }

    async fn shutdown_all(&self) {
        for node in self.nodes_snapshot() {
            node.shutdown().await;
        }
    }

    fn machine_base_config(&self) -> Option<BaseConfig> {
        self.machine_base_config
            .read()
            .expect("machine base config lock poisoned")
            .clone()
    }

    fn machine_pull_interval(&self) -> u64 {
        self.machine_pull_interval.load(Ordering::Relaxed).max(5)
    }

    fn node(&self, node_id: i64) -> Option<Arc<ManagedNode>> {
        self.nodes
            .read()
            .expect("nodes lock poisoned")
            .get(&node_id)
            .cloned()
    }

    fn nodes_snapshot(&self) -> Vec<Arc<ManagedNode>> {
        self.nodes
            .read()
            .expect("nodes lock poisoned")
            .values()
            .cloned()
            .collect()
    }
}

impl ManagedNode {
    fn new(
        node_id: i64,
        protocol: ProtocolKind,
        panel: NodePanelClient,
        machine_base_config: Option<BaseConfig>,
    ) -> Self {
        let accounting = Accounting::new();
        let controller = ProtocolController::new(protocol, accounting.clone());
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            node_id,
            panel,
            accounting,
            controller,
            machine_base_config: RwLock::new(machine_base_config.clone()),
            pull_interval: AtomicU64::new(pull_interval_seconds(machine_base_config.as_ref())),
            push_interval: AtomicU64::new(push_interval_seconds(machine_base_config.as_ref())),
            sync_state: AsyncMutex::new(NodeSyncState::default()),
            shutdown_tx,
            task_handles: Mutex::new(Vec::new()),
        }
    }

    async fn initialize(&self) -> anyhow::Result<()> {
        self.sync_config(true).await?;
        match self.panel.fetch_alive_list().await {
            Ok(alive_list) => self.accounting.set_external_alive_counts(&alive_list.alive),
            Err(error) => warn!(node_id = self.node_id, %error, "initial alive list fetch failed"),
        }
        self.sync_users(true).await
    }

    fn spawn_background_tasks(self: &Arc<Self>) {
        let sync_node = self.clone();
        let mut sync_shutdown = self.shutdown_tx.subscribe();
        self.register_task(tokio::spawn(async move {
            loop {
                if wait_for_interval_or_shutdown(
                    &mut sync_shutdown,
                    Duration::from_secs(sync_node.pull_interval()),
                )
                .await
                {
                    break;
                }

                if let Err(error) = sync_node.sync_config(false).await {
                    warn!(node_id = sync_node.node_id, %error, "config sync failed");
                }

                if let Err(error) = sync_node.sync_users(false).await {
                    warn!(node_id = sync_node.node_id, %error, "user sync failed");
                }

                match sync_node.panel.fetch_alive_list().await {
                    Ok(alive_list) => {
                        let alive_count = alive_list.alive.len();
                        sync_node
                            .accounting
                            .set_external_alive_counts(&alive_list.alive);
                        if alive_count > 0 {
                            debug!(
                                node_id = sync_node.node_id,
                                alive_count, "panel alive list fetched"
                            );
                        }
                    }
                    Err(error) => {
                        warn!(node_id = sync_node.node_id, %error, "alive list fetch failed")
                    }
                }
            }
        }));

        let report_node = self.clone();
        let mut report_shutdown = self.shutdown_tx.subscribe();
        self.register_task(tokio::spawn(async move {
            loop {
                if wait_for_interval_or_shutdown(
                    &mut report_shutdown,
                    Duration::from_secs(report_node.push_interval()),
                )
                .await
                {
                    break;
                }

                let traffic = report_node
                    .accounting
                    .snapshot_traffic(DEFAULT_MIN_TRAFFIC_BYTES);
                match report_node.panel.report_traffic(traffic.clone()).await {
                    Ok(()) => {}
                    Err(TrafficReportError::Definite(error)) => {
                        report_node.accounting.restore_traffic(&traffic);
                        warn!(
                            node_id = report_node.node_id,
                            %error,
                            "traffic report failed before delivery; restored local counters"
                        );
                    }
                    Err(TrafficReportError::Uncertain(error)) => {
                        let dropped_bytes = traffic
                            .values()
                            .map(|[upload, download]| upload + download)
                            .sum::<u64>();
                        warn!(
                            node_id = report_node.node_id,
                            %error,
                            dropped_bytes,
                            users = traffic.len(),
                            "traffic report result was ambiguous; not retrying to avoid double-counting"
                        );
                    }
                }

                let alive = report_node.accounting.snapshot_alive();
                if let Err(error) = report_node.panel.report_alive(alive).await {
                    warn!(node_id = report_node.node_id, %error, "alive report failed");
                }
            }
        }));
    }

    async fn sync_config(&self, force_refresh: bool) -> anyhow::Result<()> {
        let current_etag = {
            let sync_state = self.sync_state.lock().await;
            if force_refresh {
                None
            } else {
                sync_state.config_etag.clone()
            }
        };

        let response = match self
            .panel
            .fetch_node_config(current_etag.as_deref())
            .await?
        {
            FetchState::Modified(remote, etag) => {
                self.sync_state.lock().await.config_etag = etag;
                Some(remote)
            }
            FetchState::NotModified => None,
        };

        if let Some(remote) = response {
            self.apply_remote_config(&remote).await?;
        }

        Ok(())
    }

    async fn sync_users(&self, force_refresh: bool) -> anyhow::Result<()> {
        let current_etag = {
            let sync_state = self.sync_state.lock().await;
            if force_refresh {
                None
            } else {
                sync_state.user_etag.clone()
            }
        };

        let response = match self.panel.fetch_users(current_etag.as_deref()).await? {
            FetchState::Modified(users, etag) => {
                self.sync_state.lock().await.user_etag = etag;
                Some(users.users)
            }
            FetchState::NotModified => None,
        };

        if let Some(users) = response {
            self.replace_users(&users);
        }

        Ok(())
    }

    async fn apply_remote_config(&self, remote: &NodeConfigResponse) -> anyhow::Result<()> {
        let Some(remote_protocol) = ProtocolKind::parse(&remote.protocol) else {
            anyhow::bail!("unsupported remote protocol {}", remote.protocol);
        };
        if remote_protocol != self.controller.kind() {
            anyhow::bail!(
                "remote protocol {} does not match managed node protocol {}",
                remote.protocol,
                self.controller.kind().as_str()
            );
        }

        let machine_base_config = self.machine_base_config();
        let base_config = remote.base_config.as_ref().or(machine_base_config.as_ref());
        self.pull_interval
            .store(pull_interval_seconds(base_config), Ordering::Relaxed);
        self.push_interval
            .store(push_interval_seconds(base_config), Ordering::Relaxed);

        self.controller.apply_remote_config(remote).await
    }

    async fn report_status(&self, payload: &StatusPayload) -> anyhow::Result<()> {
        self.panel.report_status(payload).await
    }

    async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        self.controller.refresh_runtime_assets().await
    }

    async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        let handles = {
            let mut task_handles = self.task_handles.lock().expect("task handle lock poisoned");
            std::mem::take(&mut *task_handles)
        };
        for handle in handles {
            handle.abort();
        }

        self.replace_users(&[]);
        self.accounting.set_external_alive_counts(&HashMap::new());
        self.controller.shutdown().await;
    }

    fn replace_users(&self, users: &[PanelUser]) {
        self.accounting.replace_users(users);
    }

    fn set_external_alive_counts(&self, alive: &HashMap<String, i64>) {
        self.accounting.set_external_alive_counts(alive);
    }

    fn set_machine_base_config(&self, base_config: Option<BaseConfig>) {
        *self
            .machine_base_config
            .write()
            .expect("machine base config lock poisoned") = base_config.clone();
        self.pull_interval.store(
            pull_interval_seconds(base_config.as_ref()),
            Ordering::Relaxed,
        );
        self.push_interval.store(
            push_interval_seconds(base_config.as_ref()),
            Ordering::Relaxed,
        );
    }

    fn machine_base_config(&self) -> Option<BaseConfig> {
        self.machine_base_config
            .read()
            .expect("machine base config lock poisoned")
            .clone()
    }

    fn pull_interval(&self) -> u64 {
        self.pull_interval.load(Ordering::Relaxed).max(5)
    }

    fn push_interval(&self) -> u64 {
        self.push_interval.load(Ordering::Relaxed).max(5)
    }

    fn register_task(&self, handle: JoinHandle<()>) {
        self.task_handles
            .lock()
            .expect("task handle lock poisoned")
            .push(handle);
    }
}

async fn wait_for_interval_or_shutdown(
    shutdown: &mut watch::Receiver<bool>,
    interval: Duration,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(interval) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

fn alive_counts(users: &HashMap<String, Vec<String>>) -> HashMap<String, i64> {
    users
        .iter()
        .map(|(uid, ips)| (uid.clone(), ips.len() as i64))
        .collect()
}

pub(crate) fn pull_interval_seconds(base_config: Option<&BaseConfig>) -> u64 {
    base_config
        .and_then(BaseConfig::pull_interval_seconds)
        .unwrap_or(DEFAULT_PANEL_PULL_INTERVAL_SECONDS)
        .max(5)
}

pub(crate) fn push_interval_seconds(base_config: Option<&BaseConfig>) -> u64 {
    base_config
        .and_then(BaseConfig::push_interval_seconds)
        .unwrap_or(DEFAULT_PANEL_PUSH_INTERVAL_SECONDS)
        .max(5)
}
