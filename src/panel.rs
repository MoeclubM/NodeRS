use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::PanelConfig;

mod cert;

pub use cert::CertConfig;

const DEFAULT_PANEL_TIMEOUT_SECONDS: u64 = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchState<T> {
    Modified(T, Option<String>),
    NotModified,
}

#[derive(Clone)]
pub struct MachinePanelClient {
    client: Client,
    base_url: String,
    token: String,
    machine_id: i64,
}

#[derive(Clone)]
pub struct NodePanelClient {
    machine: MachinePanelClient,
    node_id: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeConfigResponse {
    pub protocol: String,
    #[serde(
        default,
        alias = "listenIp",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub listen_ip: String,
    #[serde(
        alias = "serverPort",
        deserialize_with = "deserialize_u16_from_number_or_string"
    )]
    pub server_port: u16,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub network: String,
    #[serde(default, alias = "networkSettings")]
    pub network_settings: Option<Value>,
    #[serde(
        default,
        alias = "serverName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_name: String,
    #[serde(default)]
    pub tls: Option<Value>,
    #[serde(
        default,
        alias = "tlsSettings",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub tls_settings: NodeTlsSettings,
    #[serde(
        default,
        alias = "realitySettings",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub reality_settings: NodeRealitySettings,
    #[serde(default)]
    pub multiplex: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub host: String,
    #[serde(
        default,
        alias = "security",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cipher: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub plugin: String,
    #[serde(
        default,
        alias = "pluginOpts",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub plugin_opts: String,
    #[serde(
        default,
        alias = "serverKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_key: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub flow: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub decryption: String,
    #[serde(default)]
    pub version: Option<Value>,
    #[serde(default, alias = "upMbps")]
    pub up_mbps: Option<Value>,
    #[serde(default, alias = "downMbps")]
    pub down_mbps: Option<Value>,
    #[serde(default)]
    pub obfs: Option<Value>,
    #[serde(
        default,
        alias = "isObfs",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub is_obfs: bool,
    #[serde(
        default,
        alias = "obfs-password",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub obfs_password: String,
    #[serde(
        default,
        alias = "congestionControl",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub congestion_control: String,
    #[serde(
        default,
        alias = "authTimeout",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub auth_timeout: String,
    #[serde(
        default,
        alias = "zeroRttHandshake",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub zero_rtt_handshake: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub heartbeat: String,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(
        default,
        alias = "trafficPattern",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub traffic_pattern: String,
    #[serde(
        default,
        alias = "noncePattern",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub nonce_pattern: String,
    #[serde(
        default,
        alias = "alpnProtocols",
        alias = "alpn_protocols",
        deserialize_with = "deserialize_string_list_on_null"
    )]
    pub alpn: Vec<String>,
    #[serde(
        default,
        alias = "packetEncoding",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub packet_encoding: String,
    #[serde(
        default,
        alias = "globalPadding",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub global_padding: bool,
    #[serde(
        default,
        alias = "authenticatedLength",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub authenticated_length: bool,
    #[serde(default)]
    pub fallbacks: Option<Value>,
    #[serde(default)]
    pub fallback: Option<Value>,
    #[serde(default, alias = "fallbackForAlpn")]
    pub fallback_for_alpn: Option<Value>,
    #[serde(
        default,
        alias = "ignoreClientBandwidth",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub ignore_client_bandwidth: bool,
    #[serde(default)]
    pub masquerade: Option<Value>,
    #[serde(
        default,
        alias = "udpRelayMode",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub udp_relay_mode: String,
    #[serde(
        default,
        alias = "udpOverStream",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub udp_over_stream: bool,
    #[serde(
        default,
        alias = "paddingScheme",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub padding_scheme: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub routes: Vec<RouteConfig>,
    #[serde(
        default,
        alias = "customOutbounds",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub custom_outbounds: Vec<Value>,
    #[serde(
        default,
        alias = "customRoutes",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub custom_routes: Vec<Value>,
    #[serde(default, alias = "certConfig")]
    pub cert_config: Option<CertConfig>,
    #[serde(default, alias = "baseConfig")]
    pub base_config: Option<BaseConfig>,
}

impl NodeConfigResponse {
    pub fn tls_mode(&self) -> i64 {
        self.tls.as_ref().and_then(tls_mode_from_value).unwrap_or(0)
    }

    pub fn multiplex_enabled(&self) -> bool {
        json_value_enabled(self.multiplex.as_ref())
    }

    pub fn effective_reality_settings(&self) -> NodeRealitySettings {
        if self.tls_mode() != 2 {
            return NodeRealitySettings::default();
        }

        let mut settings = self.tls_settings.reality_settings();
        let reality = &self.reality_settings;

        if reality.allow_insecure {
            settings.allow_insecure = true;
        }
        if !reality.server_name.trim().is_empty() {
            settings.server_name = reality.server_name.clone();
        }
        if !reality.server_names.is_empty() {
            settings.server_names = reality.server_names.clone();
        }
        if reality.server_port != 0 {
            settings.server_port = reality.server_port;
        }
        if !reality.public_key.trim().is_empty() {
            settings.public_key = reality.public_key.clone();
        }
        if !reality.private_key.trim().is_empty() {
            settings.private_key = reality.private_key.clone();
        }
        if !reality.short_id.trim().is_empty() {
            settings.short_id = reality.short_id.clone();
        }
        if !reality.short_ids.is_empty() {
            settings.short_ids = reality.short_ids.clone();
        }

        settings
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeTlsSettings {
    #[serde(
        default,
        alias = "serverName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_name: String,
    #[serde(
        default,
        alias = "serverNames",
        deserialize_with = "deserialize_string_list_on_null"
    )]
    pub server_names: Vec<String>,
    #[serde(
        default,
        alias = "allowInsecure",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub allow_insecure: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub ech: NodeEchSettings,
    #[serde(
        default,
        alias = "serverPort",
        deserialize_with = "deserialize_default_u16_from_number_or_string"
    )]
    pub server_port: u16,
    #[serde(
        default,
        alias = "publicKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub public_key: String,
    #[serde(
        default,
        alias = "privateKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub private_key: String,
    #[serde(
        default,
        alias = "shortId",
        alias = "shortid",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub short_id: String,
    #[serde(
        default,
        alias = "shortIds",
        alias = "shortids",
        deserialize_with = "deserialize_string_list_on_null"
    )]
    pub short_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeRealitySettings {
    #[serde(
        default,
        alias = "allowInsecure",
        deserialize_with = "deserialize_bool_from_any_on_null"
    )]
    pub allow_insecure: bool,
    #[serde(
        default,
        alias = "serverName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_name: String,
    #[serde(
        default,
        alias = "serverNames",
        deserialize_with = "deserialize_string_list_on_null"
    )]
    pub server_names: Vec<String>,
    #[serde(
        default,
        alias = "serverPort",
        deserialize_with = "deserialize_default_u16_from_number_or_string"
    )]
    pub server_port: u16,
    #[serde(
        default,
        alias = "publicKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub public_key: String,
    #[serde(
        default,
        alias = "privateKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub private_key: String,
    #[serde(
        default,
        alias = "shortId",
        alias = "shortid",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub short_id: String,
    #[serde(
        default,
        alias = "shortIds",
        alias = "shortids",
        deserialize_with = "deserialize_string_list_on_null"
    )]
    pub short_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeEchSettings {
    #[serde(default, deserialize_with = "deserialize_bool_from_any_on_null")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub config: String,
    #[serde(
        default,
        alias = "queryServerName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub query_server_name: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub key: String,
    #[serde(
        default,
        alias = "keyPath",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub key_path: String,
    #[serde(
        default,
        alias = "configPath",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub config_path: String,
}

impl NodeEchSettings {
    pub fn is_enabled(&self) -> bool {
        self.enabled
            || !self.config.trim().is_empty()
            || !self.query_server_name.trim().is_empty()
            || !self.key.trim().is_empty()
            || !self.key_path.trim().is_empty()
            || !self.config_path.trim().is_empty()
    }
}

impl NodeTlsSettings {
    pub fn is_configured(&self) -> bool {
        !self.server_name.trim().is_empty() || !self.server_names.is_empty() || self.allow_insecure
    }

    pub fn has_reality_key_material(&self) -> bool {
        self.server_port != 0
            || !self.public_key.trim().is_empty()
            || !self.private_key.trim().is_empty()
            || !self.short_id.trim().is_empty()
            || !self.short_ids.is_empty()
    }

    pub fn reality_settings(&self) -> NodeRealitySettings {
        NodeRealitySettings {
            allow_insecure: self.allow_insecure,
            server_name: self.server_name.clone(),
            server_names: self.server_names.clone(),
            server_port: self.server_port,
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            short_id: self.short_id.clone(),
            short_ids: self.short_ids.clone(),
        }
    }
}

impl NodeRealitySettings {
    pub fn is_configured(&self) -> bool {
        self.allow_insecure
            || !self.server_name.trim().is_empty()
            || !self.server_names.is_empty()
            || self.server_port != 0
            || !self.public_key.trim().is_empty()
            || !self.private_key.trim().is_empty()
            || !self.short_id.trim().is_empty()
            || !self.short_ids.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RouteMatch {
    String(String),
    Strings(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: i64,
    #[serde(default, rename = "match")]
    pub match_value: Option<RouteMatch>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub action: String,
    #[serde(
        default,
        alias = "actionValue",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub action_value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BaseConfig {
    #[serde(default, alias = "pushInterval")]
    pub push_interval: Option<serde_json::Value>,
    #[serde(default, alias = "pullInterval")]
    pub pull_interval: Option<serde_json::Value>,
}

impl BaseConfig {
    pub fn push_interval_seconds(&self) -> Option<u64> {
        value_to_u64(self.push_interval.as_ref())
    }

    pub fn pull_interval_seconds(&self) -> Option<u64> {
        value_to_u64(self.pull_interval.as_ref())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MachineNodesResponse {
    #[serde(default)]
    pub nodes: Vec<MachineNodeSummary>,
    #[serde(default, alias = "baseConfig")]
    pub base_config: Option<BaseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MachineNodeSummary {
    pub id: i64,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UsersResponse {
    pub users: Vec<PanelUser>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct PanelUser {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub uuid: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub password: String,
    #[serde(
        default,
        alias = "alterId",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub alter_id: i64,
    #[serde(
        default,
        alias = "speedLimit",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub speed_limit: i64,
    #[serde(
        default,
        alias = "deviceLimit",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub device_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HandshakeResponse {
    #[serde(default)]
    pub websocket: HandshakeWebSocket,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HandshakeWebSocket {
    #[serde(default, deserialize_with = "deserialize_bool_from_any_on_null")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub ws_url: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusPayload {
    pub cpu: f64,
    pub mem: MemoryStat,
    pub swap: MemoryStat,
    pub disk: MemoryStat,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MemoryStat {
    pub total: u64,
    pub used: u64,
}

#[derive(Debug, Serialize)]
struct ReportPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    traffic: Option<&'a HashMap<i64, [u64; 2]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alive: Option<&'a HashMap<i64, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a StatusPayload>,
}

#[derive(Debug)]
pub enum TrafficReportError {
    Definite(anyhow::Error),
    Uncertain(anyhow::Error),
}

impl MachinePanelClient {
    pub fn new(config: &PanelConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_PANEL_TIMEOUT_SECONDS))
            .build()
            .context("build panel HTTP client")?;
        Ok(Self {
            client,
            base_url: config.api.trim_end_matches('/').to_string(),
            token: config.key.clone(),
            machine_id: config.machine_id,
        })
    }

    pub fn machine_id(&self) -> i64 {
        self.machine_id
    }

    pub fn node_client(&self, node_id: i64) -> NodePanelClient {
        NodePanelClient {
            machine: self.clone(),
            node_id,
        }
    }

    pub fn websocket_url(&self, ws_url: &str) -> anyhow::Result<String> {
        let mut url =
            reqwest::Url::parse(ws_url).with_context(|| format!("parse websocket url {ws_url}"))?;
        match url.scheme() {
            "ws" | "wss" => {}
            "http" => {
                url.set_scheme("ws").map_err(|_| {
                    anyhow::anyhow!("convert websocket scheme to ws failed for {ws_url}")
                })?;
            }
            "https" => {
                url.set_scheme("wss").map_err(|_| {
                    anyhow::anyhow!("convert websocket scheme to wss failed for {ws_url}")
                })?;
            }
            other => bail!("unsupported websocket scheme {other} in {ws_url}"),
        }
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("token", &self.token);
            query.append_pair("machine_id", &self.machine_id.to_string());
        }
        Ok(url.to_string())
    }

    pub async fn fetch_handshake(&self) -> anyhow::Result<HandshakeResponse> {
        let response = self
            .client
            .post(self.url("/api/v2/server/handshake"))
            .query(&self.machine_query())
            .send()
            .await
            .context("request Xboard handshake")?;
        ensure_success(response.status(), "fetch handshake")?;
        response.json().await.context("decode Xboard handshake")
    }

    pub async fn fetch_machine_nodes(&self) -> anyhow::Result<MachineNodesResponse> {
        let response = self
            .client
            .post(self.url("/api/v2/server/machine/nodes"))
            .query(&self.machine_query())
            .send()
            .await
            .context("request Xboard machine nodes")?;
        ensure_success(response.status(), "fetch machine nodes")?;
        response.json().await.context("decode machine nodes")
    }

    pub async fn report_machine_status(&self, payload: &StatusPayload) -> anyhow::Result<()> {
        let response = self
            .client
            .post(self.url("/api/v2/server/machine/status"))
            .query(&self.machine_query())
            .json(payload)
            .send()
            .await
            .context("report machine status")?;
        ensure_success(response.status(), "report machine status")
    }

    fn machine_query(&self) -> Vec<(&str, String)> {
        vec![
            ("token", self.token.clone()),
            ("machine_id", self.machine_id.to_string()),
        ]
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl NodePanelClient {
    pub async fn fetch_node_config(
        &self,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<NodeConfigResponse>> {
        self.fetch_etag("/api/v2/server/config", etag).await
    }

    pub async fn fetch_users(
        &self,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<UsersResponse>> {
        self.fetch_etag("/api/v2/server/user", etag).await
    }

    pub async fn report_traffic(
        &self,
        traffic: HashMap<i64, [u64; 2]>,
    ) -> Result<(), TrafficReportError> {
        if traffic.is_empty() {
            return Ok(());
        }
        let payload = ReportPayload {
            traffic: Some(&traffic),
            alive: None,
            status: None,
        };
        let response = self
            .machine
            .client
            .post(self.machine.url("/api/v2/server/report"))
            .query(&self.query())
            .json(&payload)
            .send()
            .await
            .map_err(classify_send_error)?;
        classify_traffic_status(response.status())
    }

    pub async fn report_alive(&self, alive: HashMap<i64, Vec<String>>) -> anyhow::Result<()> {
        if alive.is_empty() {
            return Ok(());
        }
        let payload = ReportPayload {
            traffic: None,
            alive: Some(&alive),
            status: None,
        };
        let response = self
            .machine
            .client
            .post(self.machine.url("/api/v2/server/report"))
            .query(&self.query())
            .json(&payload)
            .send()
            .await
            .context("report alive")?;
        ensure_success(response.status(), "report alive")
    }

    pub async fn report_status(&self, payload: &StatusPayload) -> anyhow::Result<()> {
        let payload = ReportPayload {
            traffic: None,
            alive: None,
            status: Some(payload),
        };
        let response = self
            .machine
            .client
            .post(self.machine.url("/api/v2/server/report"))
            .query(&self.query())
            .json(&payload)
            .send()
            .await
            .context("report node status")?;
        ensure_success(response.status(), "report node status")
    }

    async fn fetch_etag<T>(&self, path: &str, etag: Option<&str>) -> anyhow::Result<FetchState<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut request = self
            .machine
            .client
            .get(self.machine.url(path))
            .query(&self.query());
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("request {path}"))?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(FetchState::NotModified);
        }
        ensure_success(response.status(), path)?;
        let new_etag = response
            .headers()
            .get("ETag")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let decoded = response
            .json::<T>()
            .await
            .with_context(|| format!("decode {path} response"))?;
        Ok(FetchState::Modified(decoded, new_etag))
    }

    fn query(&self) -> Vec<(&str, String)> {
        vec![
            ("token", self.machine.token.clone()),
            ("machine_id", self.machine.machine_id.to_string()),
            ("node_id", self.node_id.to_string()),
        ]
    }
}

fn ensure_success(status: StatusCode, action: &str) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        bail!("Xboard {action} failed with status {status}")
    }
}

fn value_to_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn value_to_u16(value: &serde_json::Value) -> Option<u16> {
    match value {
        serde_json::Value::Number(number) => {
            number.as_u64().and_then(|value| u16::try_from(value).ok())
        }
        serde_json::Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn value_to_i64(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Bool(value) => Some(i64::from(*value)),
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        serde_json::Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn tls_mode_from_value(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Null => Some(0),
        serde_json::Value::Bool(value) => Some(i64::from(*value)),
        serde_json::Value::Number(_) => value_to_i64(Some(value)),
        serde_json::Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "off" | "no" | "none" | "disabled" => Some(0),
            "1" | "true" | "on" | "yes" | "tls" | "xtls" | "enabled" => Some(1),
            "2" | "reality" => Some(2),
            _ => text.trim().parse().ok(),
        },
        serde_json::Value::Array(items) => Some(i64::from(items.iter().any(json_value_is_enabled))),
        serde_json::Value::Object(object) => {
            if object
                .get("enabled")
                .is_some_and(|value| !json_value_is_enabled(value))
            {
                return Some(0);
            }
            for key in ["mode", "type", "security", "tls"] {
                if let Some(mode) = object.get(key).and_then(tls_mode_from_value) {
                    return Some(mode);
                }
            }
            Some(i64::from(json_value_is_enabled(value)))
        }
    }
}

pub(crate) fn value_to_bool(value: &serde_json::Value) -> Option<bool> {
    match value {
        serde_json::Value::Null => Some(false),
        serde_json::Value::Bool(value) => Some(*value),
        serde_json::Value::Number(_) => value_to_i64(Some(value)).map(|value| value != 0),
        serde_json::Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "off" | "no" | "none" | "disabled" => Some(false),
            "1" | "true" | "on" | "yes" | "enabled" => Some(true),
            _ => None,
        },
        serde_json::Value::Array(items) => Some(items.iter().any(json_value_is_enabled)),
        serde_json::Value::Object(_) => Some(json_value_is_enabled(value)),
    }
}

pub(crate) fn json_value_is_enabled(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(number) => {
            number.as_i64().is_some_and(|value| value != 0)
                || number.as_u64().is_some_and(|value| value != 0)
                || number.as_f64().is_some_and(|value| value != 0.0)
        }
        serde_json::Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            !matches!(
                normalized.as_str(),
                "" | "0" | "false" | "off" | "no" | "none" | "disabled"
            )
        }
        serde_json::Value::Array(items) => items.iter().any(json_value_is_enabled),
        serde_json::Value::Object(object) => {
            if object.is_empty() {
                return false;
            }
            if let Some(enabled) = object.get("enabled") {
                return json_value_is_enabled(enabled);
            }
            object.values().any(json_value_is_enabled)
        }
    }
}

fn json_value_enabled(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(json_value_is_enabled)
}

pub(crate) fn deserialize_bool_from_any_on_null<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        Some(value) => value_to_bool(&value).ok_or_else(|| {
            serde::de::Error::custom(format!("expected bool-like value, got {value}"))
        }),
        None => Ok(false),
    }
}

fn deserialize_default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

pub(crate) fn deserialize_u16_from_number_or_string<'de, D>(
    deserializer: D,
) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    value_to_u16(&value).ok_or_else(|| {
        serde::de::Error::custom(format!(
            "expected u16 number or decimal string, got {value}"
        ))
    })
}

fn deserialize_default_u16_from_number_or_string<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        Some(value) => value_to_u16(&value).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "expected u16 number or decimal string, got {value}"
            ))
        }),
        None => Ok(0),
    }
}

fn deserialize_string_list_on_null<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(value) => cert::value_to_split_strings(&value),
        None => Vec::new(),
    })
}

fn classify_send_error(error: reqwest::Error) -> TrafficReportError {
    let error = anyhow::Error::new(error).context("report traffic");
    if error
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
        .is_some_and(|reqwest| reqwest.is_connect())
    {
        TrafficReportError::Definite(error)
    } else {
        TrafficReportError::Uncertain(error)
    }
}

fn classify_traffic_status(status: StatusCode) -> Result<(), TrafficReportError> {
    if status.is_success() {
        Ok(())
    } else if status.is_client_error() {
        Err(TrafficReportError::Definite(anyhow::anyhow!(
            "Xboard report traffic failed with status {status}"
        )))
    } else {
        Err(TrafficReportError::Uncertain(anyhow::anyhow!(
            "Xboard report traffic failed with status {status}"
        )))
    }
}

#[cfg(test)]
mod tests;
