//! PxBoard unified `/rpc/v1/nodes/server.*` client with whole-machine snapshot caching.
use crate::{
    config::PanelConfig,
    panel::{
        BaseConfig, FetchState, MachineNodeSummary, MachineNodesResponse, NodeConfigResponse,
        PanelUser, StatusPayload, TrafficReportError, UsersResponse,
    },
};
use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};

const SNAPSHOT_CACHE_WINDOW: Duration = Duration::from_secs(5);

type Outboxes = Arc<Mutex<HashMap<i64, Arc<Mutex<Outbox>>>>>;
#[derive(Clone)]
pub struct PxBoardClient {
    client: Client,
    base: String,
    bearer: String,
    machine_id: i64,
    snapshot: Arc<Mutex<Option<CachedPull>>>,
    outboxes: Outboxes,
}
#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}
#[derive(Deserialize)]
struct RpcErrorEnvelope {
    error: Option<RpcErrorDetail>,
}
#[derive(Deserialize)]
struct RpcErrorDetail {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullResponse {
    revision: String,
    #[serde(default)]
    unchanged: bool,
    #[serde(default = "default_interval_seconds")]
    pull_interval_seconds: u64,
    #[serde(default = "default_interval_seconds")]
    push_interval_seconds: u64,
    #[serde(default)]
    managed_configuration: Option<crate::management::ManagedConfiguration>,
    #[serde(default)]
    nodes: Vec<SnapshotNode>,
}
fn default_interval_seconds() -> u64 {
    30
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotNode {
    id: i64,
    protocol: String,
    #[serde(default)]
    name: String,
    config: Value,
    #[serde(default)]
    users: Vec<User>,
}
#[derive(Clone)]
struct CachedPull {
    fetched_at: Instant,
    revision: String,
    pull_interval_seconds: u64,
    push_interval_seconds: u64,
    managed_configuration: Option<crate::management::ManagedConfiguration>,
    summaries: Vec<MachineNodeSummary>,
    nodes: HashMap<i64, CachedNode>,
}
#[derive(Clone)]
struct CachedNode {
    config: Value,
    config_etag: String,
    users: Vec<PanelUser>,
    users_etag: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    account_id: i64,
    credential: Credential,
    #[serde(default)]
    email: String,
    #[serde(default)]
    speed_limit_mbps: i64,
    #[serde(default)]
    device_limit: i64,
}
#[derive(Serialize, Deserialize)]
struct Credential {
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    password: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Usage {
    account_id: i64,
    upload_bytes: u64,
    download_bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Batch {
    batch_id: String,
    accounts: Vec<Usage>,
}
struct Outbox {
    path: PathBuf,
    batches: VecDeque<Batch>,
}
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl PxBoardClient {
    pub fn new(config: &PanelConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder().timeout(Duration::from_secs(15)).build()?,
            base: config.api.trim_end_matches('/').into(),
            bearer: format_machine_bearer(config.machine_id, &config.key),
            machine_id: config.machine_id,
            snapshot: Arc::new(Mutex::new(None)),
            outboxes: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    async fn rpc<T: DeserializeOwned>(&self, procedure: &str, body: Value) -> anyhow::Result<T> {
        let url = format!("{}/rpc/v1/nodes/{procedure}", self.base);
        let response = self
            .client
            .post(url)
            .header("Authorization", &self.bearer)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("call PxBoard RPC nodes/{procedure}"))?;
        let status = response.status();
        if !status.is_success() {
            let raw = response.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<RpcErrorEnvelope>(&raw)
                .ok()
                .and_then(|env| env.error)
                .map(|err| {
                    if err.code.is_empty() {
                        err.message
                    } else if err.message.is_empty() {
                        err.code
                    } else {
                        format!("{}: {}", err.code, err.message)
                    }
                })
                .filter(|msg| !msg.is_empty())
                .unwrap_or_else(|| raw.trim().to_string());
            if detail.is_empty() {
                bail!("PxBoard RPC nodes/{procedure}: HTTP {status}");
            }
            bail!("PxBoard RPC nodes/{procedure}: HTTP {status} ({detail})");
        }
        Ok(response
            .json::<Envelope<T>>()
            .await
            .context("decode PxBoard response")?
            .data)
    }
    async fn pull_snapshot(&self, max_age: Duration) -> anyhow::Result<CachedPull> {
        let mut guard = self.snapshot.lock().await;
        if max_age > Duration::ZERO
            && let Some(cached) = guard.as_ref()
            && cached.fetched_at.elapsed() < max_age
        {
            return Ok(cached.clone());
        }
        let known_revision = guard
            .as_ref()
            .map(|cached| cached.revision.clone())
            .unwrap_or_default();
        let mut resp: PullResponse = self
            .rpc(
                "server.pull",
                json!({
                    "machineId": self.machine_id,
                    "knownRevision": known_revision,
                }),
            )
            .await?;
        if resp.unchanged {
            if let Some(cached) = guard.as_mut() {
                cached.fetched_at = Instant::now();
                cached.pull_interval_seconds = resp.pull_interval_seconds;
                cached.push_interval_seconds = resp.push_interval_seconds;
                cached.managed_configuration = resp.managed_configuration;
                return Ok(cached.clone());
            }
            resp = self
                .rpc(
                    "server.pull",
                    json!({
                        "machineId": self.machine_id,
                        "knownRevision": "",
                    }),
                )
                .await?;
        }
        let mut summaries = Vec::with_capacity(resp.nodes.len());
        let mut nodes = HashMap::with_capacity(resp.nodes.len());
        for node in resp.nodes {
            let config_etag = sha256_json(&node.config)?;
            let users_etag = sha256_json(&node.users)?;
            let panel_users = node
                .users
                .into_iter()
                .map(|u| PanelUser {
                    id: u.account_id,
                    uuid: u.credential.uuid,
                    password: u.credential.password,
                    email: u.email,
                    speed_limit: u.speed_limit_mbps,
                    device_limit: u.device_limit,
                    alter_id: 0,
                })
                .collect();
            summaries.push(MachineNodeSummary {
                id: node.id,
                node_type: node.protocol,
                name: node.name,
            });
            nodes.insert(
                node.id,
                CachedNode {
                    config: node.config,
                    config_etag,
                    users: panel_users,
                    users_etag,
                },
            );
        }
        let fresh = CachedPull {
            fetched_at: Instant::now(),
            revision: resp.revision,
            pull_interval_seconds: resp.pull_interval_seconds,
            push_interval_seconds: resp.push_interval_seconds,
            managed_configuration: resp.managed_configuration,
            summaries,
            nodes,
        };
        *guard = Some(fresh.clone());
        Ok(fresh)
    }
    pub async fn handshake(&self) -> anyhow::Result<()> {
        let data: Value = self
            .rpc("server.bootstrap", json!({"machineId": self.machine_id}))
            .await?;
        if data["apiVersion"] != "1.0" {
            bail!(
                "unsupported PxBoard machine API version: {}",
                data["apiVersion"]
            );
        }
        Ok(())
    }
    pub async fn managed_configuration(
        &self,
    ) -> anyhow::Result<Option<crate::management::ManagedConfiguration>> {
        Ok(self
            .pull_snapshot(SNAPSHOT_CACHE_WINDOW)
            .await?
            .managed_configuration)
    }
    pub async fn configuration_status(
        &self,
        revision: u64,
        status: &str,
        message: &str,
    ) -> anyhow::Result<()> {
        let _: Value = self
            .rpc(
                "server.ackConfig",
                json!({
                    "machineId": self.machine_id,
                    "revision": revision,
                    "status": status,
                    "message": message,
                }),
            )
            .await?;
        *self.snapshot.lock().await = None;
        Ok(())
    }
    pub async fn nodes(&self) -> anyhow::Result<MachineNodesResponse> {
        let data = self.pull_snapshot(Duration::ZERO).await?;
        Ok(MachineNodesResponse {
            nodes: data.summaries,
            base_config: Some(BaseConfig {
                pull_interval: Some(json!(data.pull_interval_seconds)),
                push_interval: Some(json!(data.push_interval_seconds)),
            }),
        })
    }
    pub async fn config(
        &self,
        id: i64,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<NodeConfigResponse>> {
        let snap = self.pull_snapshot(SNAPSHOT_CACHE_WINDOW).await?;
        let node = snap.nodes.get(&id).with_context(|| {
            format!(
                "PxBoard node {id} is not assigned to machine {}",
                self.machine_id
            )
        })?;
        if etag.is_some_and(|current| current == node.config_etag) {
            return Ok(FetchState::NotModified);
        }
        Ok(FetchState::Modified(
            adapt_pxboard_node_config(node.config.clone())?,
            Some(node.config_etag.clone()),
        ))
    }
    pub async fn users(
        &self,
        id: i64,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<UsersResponse>> {
        let snap = self.pull_snapshot(SNAPSHOT_CACHE_WINDOW).await?;
        let node = snap.nodes.get(&id).with_context(|| {
            format!(
                "PxBoard node {id} is not assigned to machine {}",
                self.machine_id
            )
        })?;
        if etag.is_some_and(|current| current == node.users_etag) {
            return Ok(FetchState::NotModified);
        }
        Ok(FetchState::Modified(
            UsersResponse {
                users: node.users.clone(),
            },
            Some(node.users_etag.clone()),
        ))
    }
    pub async fn alive(&self, id: i64, alive: HashMap<i64, Vec<String>>) -> anyhow::Result<()> {
        let accounts: Vec<_> = alive
            .into_iter()
            .map(|(account_id, ips)| json!({"accountId":account_id,"ips":ips}))
            .collect();
        let _: Value = self
            .rpc(
                "server.telemetry",
                json!({
                    "machineId": self.machine_id,
                    "nodeId": id,
                    "accounts": accounts,
                }),
            )
            .await?;
        Ok(())
    }
    pub async fn status(&self, id: Option<i64>, status: &StatusPayload) -> anyhow::Result<()> {
        if id.is_some() {
            return Ok(());
        }
        let _: Value = self
            .rpc(
                "server.telemetry",
                json!({
                    "machineId": self.machine_id,
                    "status": {
                        "cpuPercent": status.cpu,
                        "memory": status.mem,
                        "swap": status.swap,
                        "disk": status.disk,
                    },
                }),
            )
            .await?;
        Ok(())
    }
    async fn outbox(&self, id: i64) -> anyhow::Result<Arc<Mutex<Outbox>>> {
        let mut boxes = self.outboxes.lock().await;
        if let Some(outbox) = boxes.get(&id) {
            return Ok(outbox.clone());
        }
        let path = std::env::current_dir()?.join(format!(
            "pxboard-{}-{}-node-{id}-traffic.json",
            URL_SAFE_NO_PAD.encode(self.base.as_bytes()),
            self.machine_id
        ));
        let batches = match fs::read(&path).await {
            Ok(raw) => serde_json::from_slice(&raw).context("read PxBoard traffic outbox")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => VecDeque::new(),
            Err(e) => return Err(e.into()),
        };
        let outbox = Arc::new(Mutex::new(Outbox { path, batches }));
        boxes.insert(id, outbox.clone());
        Ok(outbox)
    }
    pub async fn traffic(
        &self,
        id: i64,
        traffic: HashMap<i64, [u64; 2]>,
    ) -> Result<(), TrafficReportError> {
        let outbox = self
            .outbox(id)
            .await
            .map_err(TrafficReportError::Definite)?;
        let mut outbox = outbox.lock().await;
        if !traffic.is_empty() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| TrafficReportError::Definite(e.into()))?
                .as_nanos();
            outbox.batches.push_back(Batch {
                batch_id: format!(
                    "{nonce}-{}-{}",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ),
                accounts: traffic
                    .into_iter()
                    .map(|(account_id, [upload_bytes, download_bytes])| Usage {
                        account_id,
                        upload_bytes,
                        download_bytes,
                    })
                    .collect(),
            });
            if let Err(e) = outbox.save().await {
                outbox.batches.pop_back();
                return Err(TrafficReportError::Definite(e));
            }
        }
        while let Some(batch) = outbox.batches.front().cloned() {
            let body = json!({
                "machineId": self.machine_id,
                "nodeId": id,
                "batchId": batch.batch_id,
                "accounts": batch.accounts,
            });
            self.rpc::<Value>("server.traffic", body)
                .await
                .map_err(TrafficReportError::Uncertain)?;
            outbox.batches.pop_front();
            if let Err(e) = outbox.save().await {
                outbox.batches.push_front(batch);
                return Err(TrafficReportError::Uncertain(e));
            }
        }
        Ok(())
    }

    pub async fn drain_outboxes(&self) -> anyhow::Result<()> {
        let prefix = format!(
            "pxboard-{}-{}-node-",
            URL_SAFE_NO_PAD.encode(self.base.as_bytes()),
            self.machine_id
        );
        let mut entries = fs::read_dir(std::env::current_dir()?).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(id) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix("-traffic.json"))
            else {
                continue;
            };
            let id: i64 = id.parse().context("read pending PxBoard outbox node id")?;
            match self.traffic(id, HashMap::new()).await {
                Ok(()) => {}
                Err(TrafficReportError::Definite(error) | TrafficReportError::Uncertain(error)) => {
                    return Err(
                        error.context("drain all source PxBoard traffic queues before migration")
                    );
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn adapt_pxboard_node_config(data: Value) -> anyhow::Result<NodeConfigResponse> {
    let mut wire = data
        .get("protocolOptions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for alias in [
        "listenIp",
        "serverPort",
        "networkSettings",
        "serverName",
        "tlsSettings",
        "realitySettings",
        "certConfig",
    ] {
        wire.remove(alias);
    }
    let network = data["transport"]["type"].as_str().unwrap_or("tcp");
    let protocol = data["protocol"]
        .as_str()
        .context("missing PxBoard protocol")?;
    let supported = match protocol {
        "vless" | "vmess" | "trojan" => matches!(
            network,
            "" | "tcp"
                | "raw"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "h2"
                | "http"
                | "xhttp"
                | "splithttp"
        ),
        "hysteria2" | "tuic" => matches!(
            network,
            "" | "tcp" | "udp" | "quic" | "hysteria2" | "hy2" | "tuic"
        ),
        "mieru" => matches!(network, "" | "tcp" | "raw" | "udp"),
        "naive" => matches!(
            network,
            "" | "tcp" | "raw" | "http" | "https" | "h2" | "h3" | "http3" | "quic"
        ),
        "flux" => matches!(
            network,
            "" | "tcp"
                | "raw"
                | "udp"
                | "quic"
                | "http"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "h2"
        ),
        _ => matches!(network, "" | "tcp" | "raw"),
    };
    if !supported {
        bail!("PxBoard transport {network} is not supported for {protocol}");
    }
    for field in [
        "routes",
        "custom_routes",
        "customRoutes",
        "custom_outbounds",
        "customOutbounds",
        "fallback",
        "fallbacks",
        "fallbackForAlpn",
        "fallback_for_alpn",
    ] {
        if wire
            .get(field)
            .is_some_and(crate::panel::json_value_is_enabled)
        {
            bail!("PxBoard field {field} is not supported by this NodeRS build");
        }
    }

    let security = &data["security"];
    if protocol == "flux" {
        let mut flux_map = wire
            .remove("flux")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        for (alias, canonical) in [
            ("ipStrategy", "ip_strategy"),
            ("ip_strategy", "ip_strategy"),
            ("standbyChannels", "standby_channels"),
            ("standby_channels", "standby_channels"),
            ("rotationIntervalSec", "rotation_interval_sec"),
            ("rotation_interval_sec", "rotation_interval_sec"),
            ("rotationBytesMb", "rotation_bytes_mb"),
            ("rotation_bytes_mb", "rotation_bytes_mb"),
            ("udp", "udp"),
            ("channels", "channels"),
        ] {
            if let Some(value) = wire.remove(alias)
                && !value.is_null()
            {
                flux_map.entry(canonical.to_string()).or_insert(value);
            }
        }
        if let Some(Value::Array(channels)) = flux_map.get_mut("channels") {
            for item in channels.iter_mut() {
                if let Some(obj) = item.as_object_mut() {
                    normalize_flux_channel_object(obj);
                }
            }
        }
        wire.insert("flux".into(), Value::Object(flux_map));
    }

    for (alias, canonical) in [
        ("method", "cipher"),
        ("security", "cipher"),
        ("serverKey", "server_key"),
    ] {
        if let Some(value) = wire.remove(alias) {
            wire.entry(canonical).or_insert(value);
        }
    }
    if protocol == "shadowsocks" && !wire.contains_key("cipher") {
        wire.insert("cipher".into(), json!("aes-128-gcm"));
    }
    wire.insert("protocol".into(), data["protocol"].clone());
    wire.insert("server_port".into(), data["listen"]["port"].clone());
    wire.insert("listen_ip".into(), data["listen"]["host"].clone());
    wire.insert("host".into(), data["host"].clone());
    wire.insert("network".into(), data["transport"]["type"].clone());
    wire.insert(
        "network_settings".into(),
        data["transport"]["settings"].clone(),
    );
    wire.insert(
        "tls".into(),
        json!(match security["mode"].as_str() {
            Some("reality") => 2,
            Some("tls") => 1,
            _ => 0,
        }),
    );
    wire.insert("server_name".into(), security["serverName"].clone());
    wire.insert("tls_settings".into(), security["tlsSettings"].clone());
    wire.insert("reality_settings".into(), security["reality"].clone());
    wire.insert("cert_config".into(), security["certificate"].clone());
    serde_json::from_value(Value::Object(wire)).context("adapt PxBoard node configuration")
}

fn normalize_flux_channel_object(obj: &mut serde_json::Map<String, Value>) {
    for (alias, canonical) in [
        ("connectHost", "connect_host"),
        ("connectPorts", "connect_ports"),
        ("ipVersion", "ip_version"),
        ("listenIp", "listen_ip"),
        ("listenPorts", "listen_ports"),
        ("httpMode", "http_mode"),
        ("httpHost", "http_host"),
        ("httpPath", "http_path"),
        ("httpHeaders", "http_headers"),
        ("certMode", "cert_mode"),
        ("certPath", "cert_path"),
        ("keyPath", "key_path"),
        ("obfsKey", "obfs_key"),
        ("serverName", "sni"),
    ] {
        if let Some(value) = obj.remove(alias) {
            obj.entry(canonical).or_insert(value);
        }
    }
}

fn format_machine_bearer(machine_id: i64, key: &str) -> String {
    let trimmed = key.trim();
    if trimmed.starts_with("pxm_") {
        format!("Bearer {trimmed}")
    } else {
        format!("Bearer pxm_{machine_id}.{trimmed}")
    }
}

fn sha256_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value).context("serialize PxBoard snapshot fragment")?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}
impl Outbox {
    async fn save(&self) -> anyhow::Result<()> {
        let temporary = self.path.with_extension("json.tmp");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .await?;
        file.write_all(&serde_json::to_vec(&self.batches)?).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(temporary, &self.path).await?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            if let Ok(directory) = std::fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PanelType;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn formats_machine_bearer_without_double_prefix() {
        assert_eq!(
            format_machine_bearer(7, "secret-key"),
            "Bearer pxm_7.secret-key"
        );
        assert_eq!(
            format_machine_bearer(7, "pxm_7.secret-key"),
            "Bearer pxm_7.secret-key"
        );
    }

    #[tokio::test]
    async fn caches_server_pull_and_uses_known_revision_and_etags() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let pull_calls = Arc::new(AtomicUsize::new(0));
        let telemetry_calls = Arc::new(AtomicUsize::new(0));
        let pull_calls_bg = pull_calls.clone();
        let telemetry_calls_bg = telemetry_calls.clone();

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                let mut parts = req.split("\r\n\r\n");
                let head = parts.next().unwrap_or_default();
                let body_str = parts.next().unwrap_or_default();
                assert!(
                    head.lines()
                        .any(|l| l.eq_ignore_ascii_case("Authorization: Bearer pxm_3.test-key")),
                    "missing machine bearer header: {head}"
                );
                let first = head.lines().next().unwrap_or_default();
                let resp_json = if first.starts_with("POST /rpc/v1/nodes/server.bootstrap ") {
                    json!({"data": {"apiVersion": "1.0", "rpcVersion": "1.0", "machineId": 3}})
                } else if first.starts_with("POST /rpc/v1/nodes/server.pull ") {
                    let idx = pull_calls_bg.fetch_add(1, Ordering::SeqCst);
                    let input: Value = serde_json::from_str(body_str).unwrap_or_default();
                    if idx > 0 && input["knownRevision"] == "rev-1" {
                        json!({
                            "data": {
                                "revision": "rev-1",
                                "unchanged": true,
                                "pullIntervalSeconds": 25,
                                "pushIntervalSeconds": 20,
                                "managedConfiguration": null
                            }
                        })
                    } else {
                        json!({
                            "data": {
                                "revision": "rev-1",
                                "unchanged": false,
                                "pullIntervalSeconds": 25,
                                "pushIntervalSeconds": 20,
                                "managedConfiguration": null,
                                "nodes": [{
                                    "id": 11,
                                    "protocol": "mieru",
                                    "name": "osa-mieru",
                                    "config": {
                                        "id": 11,
                                        "protocol": "mieru",
                                        "host": "127.0.0.1",
                                        "listen": {"host": "0.0.0.0", "port": 21011},
                                        "transport": {"type": "tcp", "settings": null},
                                        "security": {"mode": "none"},
                                        "protocolOptions": {}
                                    },
                                    "users": [{
                                        "accountId": 42,
                                        "email": "u@example.com",
                                        "credential": {"uuid": "u-42", "password": "p-42"},
                                        "speedLimitMbps": 0,
                                        "deviceLimit": 2
                                    }]
                                }]
                            }
                        })
                    }
                } else if first.starts_with("POST /rpc/v1/nodes/server.telemetry ") {
                    telemetry_calls_bg.fetch_add(1, Ordering::SeqCst);
                    json!({"data": true})
                } else {
                    json!({"data": true})
                };
                let payload = serde_json::to_vec(&resp_json).unwrap();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.write_all(&payload).await;
            }
        });

        let client = PxBoardClient::new(&PanelConfig {
            panel_type: PanelType::Pxboard,
            api: format!("http://{addr}"),
            key: "test-key".into(),
            machine_id: 3,
        })?;

        client.handshake().await?;
        let nodes = client.nodes().await?;
        assert_eq!(nodes.nodes.len(), 1);
        assert_eq!(nodes.nodes[0].id, 11);
        assert_eq!(pull_calls.load(Ordering::SeqCst), 1);

        // Subsequent config/users/managed_configuration within cache window reuse the snapshot.
        let cfg_etag = match client.config(11, None).await? {
            FetchState::Modified(cfg, Some(etag)) => {
                assert_eq!(cfg.protocol, "mieru");
                assert_eq!(cfg.server_port, 21011);
                etag
            }
            other => panic!("unexpected config state: {other:?}"),
        };
        let usr_etag = match client.users(11, None).await? {
            FetchState::Modified(users, Some(etag)) => {
                assert_eq!(users.users.len(), 1);
                assert_eq!(users.users[0].id, 42);
                etag
            }
            other => panic!("unexpected users state: {other:?}"),
        };
        assert!(client.managed_configuration().await?.is_none());
        assert_eq!(pull_calls.load(Ordering::SeqCst), 1);

        // Matching ETags return NotModified; nodes() forces a server.pull with knownRevision.
        let _ = client.nodes().await?;
        assert_eq!(pull_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            client.config(11, Some(&cfg_etag)).await?,
            FetchState::NotModified
        ));
        assert!(matches!(
            client.users(11, Some(&usr_etag)).await?,
            FetchState::NotModified
        ));

        // Machine-level status sends telemetry, per-node status is a no-op so onlineAccounts stay intact.
        client.status(None, &StatusPayload::default()).await?;
        client.status(Some(11), &StatusPayload::default()).await?;
        assert_eq!(telemetry_calls.load(Ordering::SeqCst), 1);

        server.abort();
        Ok(())
    }
}
