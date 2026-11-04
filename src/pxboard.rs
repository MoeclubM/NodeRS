//! PxBoard's native machine API. Xboard wire types remain an internal runtime detail.
use crate::{
    config::PanelConfig,
    panel::{
        BaseConfig, MachineNodeSummary, MachineNodesResponse, NodeConfigResponse, PanelUser,
        StatusPayload, TrafficReportError, UsersResponse,
    },
};
use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};

type Outboxes = Arc<Mutex<HashMap<i64, Arc<Mutex<Outbox>>>>>;
#[derive(Clone)]
pub struct PxBoardClient {
    client: Client,
    base: String,
    key: String,
    machine_id: i64,
    outboxes: Outboxes,
}
#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Nodes {
    nodes: Vec<Node>,
    pull_interval_seconds: u64,
    push_interval_seconds: u64,
}
#[derive(Deserialize)]
struct Node {
    id: i64,
    protocol: String,
    #[serde(default)]
    name: String,
}
#[derive(Deserialize)]
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
#[derive(Deserialize)]
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
            key: config.key.clone(),
            machine_id: config.machine_id,
            outboxes: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<T> {
        let url = format!(
            "{}/api/v1/extensions/nodes/machines/{}{}",
            self.base, self.machine_id, path
        );
        let mut request = self
            .client
            .request(method, url)
            .header("X-Machine-Key", &self.key);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .context("request PxBoard machine API")?;
        let status = response.status();
        if !status.is_success() {
            bail!("PxBoard machine API {path}: HTTP {status}");
        }
        Ok(response
            .json::<Envelope<T>>()
            .await
            .context("decode PxBoard response")?
            .data)
    }
    pub async fn handshake(&self) -> anyhow::Result<()> {
        let data: Value = self.request(Method::GET, "/handshake", None).await?;
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
        self.request(Method::GET, "/configuration", None).await
    }
    pub async fn configuration_status(
        &self,
        revision: u64,
        status: &str,
        message: &str,
    ) -> anyhow::Result<()> {
        let _: Value = self
            .request(
                Method::POST,
                "/configuration/status",
                Some(json!({
                    "revision": revision, "status": status, "message": message,
                })),
            )
            .await?;
        Ok(())
    }
    pub async fn nodes(&self) -> anyhow::Result<MachineNodesResponse> {
        let data: Nodes = self.request(Method::GET, "/nodes", None).await?;
        Ok(MachineNodesResponse {
            nodes: data
                .nodes
                .into_iter()
                .map(|n| MachineNodeSummary {
                    id: n.id,
                    node_type: n.protocol,
                    name: n.name,
                })
                .collect(),
            base_config: Some(BaseConfig {
                pull_interval: Some(json!(data.pull_interval_seconds)),
                push_interval: Some(json!(data.push_interval_seconds)),
            }),
        })
    }
    pub async fn config(&self, id: i64) -> anyhow::Result<NodeConfigResponse> {
        let data: Value = self
            .request(Method::GET, &format!("/nodes/{id}/config"), None)
            .await?;
        adapt_pxboard_node_config(data)
    }
    pub async fn users(&self, id: i64) -> anyhow::Result<UsersResponse> {
        let users: Vec<User> = self
            .request(Method::GET, &format!("/nodes/{id}/users"), None)
            .await?;
        Ok(UsersResponse {
            users: users
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
                .collect(),
        })
    }
    pub async fn alive(&self, id: i64, alive: HashMap<i64, Vec<String>>) -> anyhow::Result<()> {
        let accounts: Vec<_> = alive
            .into_iter()
            .map(|(account_id, ips)| json!({"accountId":account_id,"ips":ips}))
            .collect();
        let _: Value = self
            .request(
                Method::POST,
                &format!("/nodes/{id}/alive"),
                Some(json!({"accounts":accounts})),
            )
            .await?;
        Ok(())
    }
    pub async fn status(&self, id: Option<i64>, status: &StatusPayload) -> anyhow::Result<()> {
        let path = id
            .map(|id| format!("/nodes/{id}/status"))
            .unwrap_or_else(|| "/status".into());
        let _: Value = self.request(Method::POST, &path, Some(json!({"cpuPercent":status.cpu,"memory":status.mem,"swap":status.swap,"disk":status.disk}))).await?;
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
            let body = serde_json::to_value(&batch)
                .map_err(|e| TrafficReportError::Uncertain(e.into()))?;
            self.request::<Value>(Method::POST, &format!("/nodes/{id}/traffic"), Some(body))
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
            ("obfsKey", "obfs_key"),
            ("obfs_key", "obfs_key"),
            ("defaultSecurity", "security"),
            ("default_security", "security"),
            ("security", "security"),
            ("udp", "udp"),
            ("reality", "reality"),
            ("channels", "channels"),
        ] {
            if let Some(value) = wire.remove(alias)
                && !value.is_null()
            {
                flux_map.entry(canonical.to_string()).or_insert(value);
            }
        }
        if !flux_map.contains_key("security")
            && let Some(mode) = security["mode"].as_str()
            && matches!(mode, "reality" | "tls" | "obfs")
        {
            flux_map.insert("security".into(), json!(mode));
        }
        if let Some(Value::Array(channels)) = flux_map.get_mut("channels") {
            for item in channels.iter_mut() {
                if let Some(obj) = item.as_object_mut() {
                    normalize_flux_channel_object(obj);
                }
            }
        }
        if let Some(Value::Object(r_obj)) = flux_map.get_mut("reality") {
            normalize_flux_reality_object(r_obj);
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
        ("shortId", "short_id"),
        ("shortIds", "short_ids"),
        ("publicKey", "public_key"),
        ("privateKey", "private_key"),
        ("serverName", "sni"),
        ("realityFallback", "reality_fallback"),
        ("realityOpts", "reality"),
        ("reality_opts", "reality"),
    ] {
        if let Some(value) = obj.remove(alias) {
            obj.entry(canonical).or_insert(value);
        }
    }
    if let Some(Value::Object(r_obj)) = obj.get_mut("reality") {
        normalize_flux_reality_object(r_obj);
    }
}

fn normalize_flux_reality_object(obj: &mut serde_json::Map<String, Value>) {
    for (alias, canonical) in [
        ("serverName", "server_name"),
        ("serverNames", "server_names"),
        ("serverPort", "server_port"),
        ("privateKey", "private_key"),
        ("publicKey", "public_key"),
        ("shortId", "short_id"),
        ("shortIds", "short_ids"),
    ] {
        if let Some(value) = obj.remove(alias) {
            obj.entry(canonical).or_insert(value);
        }
    }
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
