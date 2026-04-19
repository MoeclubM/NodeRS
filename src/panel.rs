use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::PanelConfig;

const DEFAULT_PANEL_TIMEOUT_SECONDS: u64 = 15;
const DEFAULT_ACME_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const DEFAULT_ACME_CHALLENGE_LISTEN: &str = "0.0.0.0:80";
const DEFAULT_ACME_RENEW_BEFORE_DAYS: u64 = 30;

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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NodeConfigResponse {
    pub protocol: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub listen_ip: String,
    pub server_port: u16,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub network: String,
    #[serde(default, alias = "networkSettings")]
    pub network_settings: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub server_name: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub tls_settings: NodeTlsSettings,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub padding_scheme: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub routes: Vec<RouteConfig>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub custom_outbounds: Vec<Value>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub custom_routes: Vec<Value>,
    #[serde(default)]
    pub cert_config: Option<CertConfig>,
    #[serde(default)]
    pub base_config: Option<BaseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeTlsSettings {
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub server_name: String,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub ech: NodeEchSettings,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeEchSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub config: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub query_server_name: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub key: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub key_path: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct CertConfig {
    #[serde(
        default,
        alias = "mode",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cert_mode: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub cert_path: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub key_path: String,
    #[serde(
        default,
        alias = "cert",
        alias = "certificate",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cert_pem: String,
    #[serde(
        default,
        alias = "key",
        alias = "private_key",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub key_pem: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub domain: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub email: String,
    #[serde(
        default,
        alias = "directory",
        alias = "acme_directory_url",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub directory_url: String,
    #[serde(
        default,
        alias = "http01_listen",
        alias = "acme_challenge_listen",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub challenge_listen: String,
    #[serde(default)]
    pub renew_before_days: Option<u64>,
    #[serde(
        default,
        alias = "acme_account_key_path",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub account_key_path: String,
}

impl CertConfig {
    pub fn cert_mode(&self) -> &str {
        let cert_mode = self.cert_mode.trim();
        if cert_mode.is_empty() {
            "none"
        } else {
            cert_mode
        }
    }

    pub fn cert_pem(&self) -> &str {
        self.cert_pem.trim()
    }

    pub fn key_pem(&self) -> &str {
        self.key_pem.trim()
    }

    pub fn domain(&self) -> &str {
        self.domain.trim()
    }

    pub fn email(&self) -> &str {
        self.email.trim()
    }

    pub fn directory_url(&self) -> &str {
        let directory_url = self.directory_url.trim();
        if directory_url.is_empty() {
            DEFAULT_ACME_DIRECTORY_URL
        } else {
            directory_url
        }
    }

    pub fn challenge_listen(&self) -> &str {
        let challenge_listen = self.challenge_listen.trim();
        if challenge_listen.is_empty() {
            DEFAULT_ACME_CHALLENGE_LISTEN
        } else {
            challenge_listen
        }
    }

    pub fn renew_before_days(&self) -> u64 {
        self.renew_before_days
            .unwrap_or(DEFAULT_ACME_RENEW_BEFORE_DAYS)
    }

    pub fn account_key_path(&self) -> &str {
        self.account_key_path.trim()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RouteMatch {
    String(String),
    Strings(Vec<String>),
}

impl RouteMatch {
    pub fn items(&self) -> Vec<String> {
        let raw = match self {
            Self::String(text) => text.split(',').map(ToString::to_string).collect(),
            Self::Strings(items) => items.clone(),
        };
        raw.into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: i64,
    #[serde(default, rename = "match")]
    pub match_value: Option<RouteMatch>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub action: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub action_value: String,
}

impl RouteConfig {
    pub fn match_items(&self) -> Vec<String> {
        self.match_value
            .as_ref()
            .map(RouteMatch::items)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BaseConfig {
    pub push_interval: Option<serde_json::Value>,
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
    #[serde(default)]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PanelUser {
    pub id: i64,
    pub uuid: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub device_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AliveListResponse {
    #[serde(default)]
    pub alive: HashMap<String, i64>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HandshakeResponse {
    #[serde(default)]
    pub websocket: HandshakeWebSocket,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HandshakeWebSocket {
    #[serde(default)]
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

    pub async fn fetch_alive_list(&self) -> anyhow::Result<AliveListResponse> {
        let response = self
            .machine
            .client
            .get(self.machine.url("/api/v2/server/alivelist"))
            .query(&self.query())
            .send()
            .await
            .context("request Xboard alive list")?;
        ensure_success(response.status(), "fetch alive list")?;
        response.json().await.context("decode alive list")
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

fn deserialize_default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
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
mod tests {
    use super::*;
    use crate::config::PanelConfig;

    #[test]
    fn parses_base_config_numbers() {
        let cfg = BaseConfig {
            push_interval: Some(serde_json::json!(120)),
            pull_interval: Some(serde_json::json!("30")),
        };
        assert_eq!(cfg.push_interval_seconds(), Some(120));
        assert_eq!(cfg.pull_interval_seconds(), Some(30));
    }

    #[test]
    fn parses_route_match_from_string() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 1,
            "match": r" protocol:tcp , regexp:^example\.com$ ",
            "action": "block",
            "action_value": ""
        }))
        .expect("parse route");
        assert_eq!(
            route.match_items(),
            vec![
                "protocol:tcp".to_string(),
                r"regexp:^example\.com$".to_string()
            ]
        );
    }

    #[test]
    fn parses_route_match_from_array() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 2,
            "match": [r"regexp:^example\.org$", "protocol:udp"],
            "action": "block",
            "action_value": ""
        }))
        .expect("parse route");
        assert_eq!(
            route.match_items(),
            vec![
                r"regexp:^example\.org$".to_string(),
                "protocol:udp".to_string()
            ]
        );
    }

    #[test]
    fn accepts_nulls_in_node_config_response() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "network": null,
            "networkSettings": null,
            "server_name": "node.example.com",
            "tls_settings": {
                "server_name": "node.example.com",
                "allow_insecure": false,
                "ech": null
            },
            "padding_scheme": null,
            "routes": null,
            "custom_outbounds": null,
            "custom_routes": null,
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            },
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60
            }
        }))
        .expect("parse config");
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.server_name, "node.example.com");
        assert_eq!(config.network, "");
        assert!(config.network_settings.is_none());
        assert!(config.padding_scheme.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.custom_outbounds.is_empty());
        assert!(config.custom_routes.is_empty());
        assert_eq!(
            config
                .cert_config
                .as_ref()
                .expect("cert config")
                .cert_mode(),
            "file"
        );
    }

    #[test]
    fn ech_fields_mark_remote_config_as_ech_enabled() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "network": "tcp",
            "networkSettings": {
                "header": {
                    "type": "none"
                }
            },
            "server_name": "node.example.com",
            "tls_settings": {
                "server_name": "node.example.com",
                "allow_insecure": false,
                "ech": {
                    "enabled": false,
                    "config_path": "/etc/anytls/ech.json"
                }
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse config");

        assert!(config.tls_settings.ech.is_enabled());
        assert_eq!(config.network, "tcp");
        assert_eq!(
            config.network_settings,
            Some(serde_json::json!({
                "header": {
                    "type": "none"
                }
            }))
        );
        assert_eq!(
            config
                .cert_config
                .as_ref()
                .expect("cert config")
                .cert_mode(),
            "file"
        );
    }

    #[test]
    fn cert_config_accepts_inline_pem_aliases() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "inline",
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cert_mode(), "inline");
        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn cert_config_accepts_acme_aliases_and_defaults() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "acme",
                "cert_path": "/var/lib/noders/anytls/node.example.com/fullchain.pem",
                "key_path": "/var/lib/noders/anytls/node.example.com/privkey.pem",
                "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "http01_listen": "127.0.0.1:8080",
                "acme_account_key_path": "/var/lib/noders/anytls/node.example.com/account.pem"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cert_mode(), "acme");
        assert_eq!(
            cert.directory_url(),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(cert.challenge_listen(), "127.0.0.1:8080");
        assert_eq!(
            cert.account_key_path(),
            "/var/lib/noders/anytls/node.example.com/account.pem"
        );
        assert_eq!(cert.renew_before_days(), 30);
    }

    #[test]
    fn accepts_nulls_in_route_and_user_defaults() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 9,
            "match": null,
            "action": null,
            "action_value": null
        }))
        .expect("parse route");
        assert_eq!(route.action, "");
        assert_eq!(route.action_value, "");

        let user: PanelUser = serde_json::from_value(serde_json::json!({
            "id": 1,
            "uuid": "test-user",
            "device_limit": null
        }))
        .expect("parse user");
        assert_eq!(user.device_limit, 0);
    }

    #[test]
    fn parses_machine_nodes_response() {
        let response: MachineNodesResponse = serde_json::from_value(serde_json::json!({
            "nodes": [
                {
                    "id": 1,
                    "type": "anytls",
                    "name": "alpha"
                }
            ],
            "base_config": {
                "push_interval": 60,
                "pull_interval": 30
            }
        }))
        .expect("parse machine nodes");

        assert_eq!(response.nodes.len(), 1);
        assert_eq!(response.nodes[0].node_type, "anytls");
        assert_eq!(
            response.base_config.unwrap().pull_interval_seconds(),
            Some(30)
        );
    }

    #[test]
    fn websocket_url_uses_machine_credentials() {
        let panel = MachinePanelClient::new(&PanelConfig {
            api: "https://xboard.example.com".to_string(),
            key: "replace-me".to_string(),
            machine_id: 9,
        })
        .expect("panel client");

        let ws_url = panel
            .websocket_url("wss://panel.example.com:8076")
            .expect("websocket url");

        assert!(ws_url.contains("machine_id=9"));
        assert!(ws_url.contains("token=replace-me"));
    }

    #[test]
    fn classifies_traffic_status_by_certainty() {
        assert!(classify_traffic_status(StatusCode::OK).is_ok());
        assert!(matches!(
            classify_traffic_status(StatusCode::BAD_REQUEST),
            Err(TrafficReportError::Definite(_))
        ));
        assert!(matches!(
            classify_traffic_status(StatusCode::INTERNAL_SERVER_ERROR),
            Err(TrafficReportError::Uncertain(_))
        ));
    }
}
