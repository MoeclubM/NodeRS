use anyhow::{Context, anyhow, bail, ensure};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::accounting::Accounting;
use crate::panel::{NodeConfigResponse, PanelUser};

use super::shared::{self, effective_listen_ip};

const DEFAULT_HYSTERIA_BINARY: &str = "hysteria";
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_BUFFER_SIZE: usize = 64 * 1024;
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_millis(200);
const STATS_HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: shared::EffectiveTlsConfig,
    pub auth_mode: AuthMode,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
    pub ignore_client_bandwidth: bool,
    pub congestion: HysteriaCongestion,
    pub disable_udp: bool,
    pub udp_idle_timeout: Option<String>,
    pub obfs: Option<HysteriaObfs>,
    pub traffic_stats_secret: String,
    pub masquerade: Option<HysteriaMasquerade>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaCongestion {
    pub kind: String,
    pub bbr_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaObfs {
    pub kind: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaMasquerade {
    pub kind: String,
    pub file_dir: Option<String>,
    pub proxy_url: Option<String>,
    pub proxy_rewrite_host: bool,
    pub proxy_x_forwarded: bool,
    pub proxy_insecure: bool,
    pub string_content: Option<String>,
    pub string_headers: Vec<(String, String)>,
    pub string_status_code: Option<u16>,
    pub listen_http: Option<String>,
    pub listen_https: Option<String>,
    pub force_https: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningServer {
    listen_ip: String,
    server_port: u16,
    state_dir: PathBuf,
    auth_listen: SocketAddr,
    stats_listen: SocketAddr,
    traffic_stats_secret: String,
}

pub struct ServerController {
    node_id: i64,
    hysteria_binary: String,
    accounting: Arc<Accounting>,
    panel_users: Arc<RwLock<Vec<PanelUser>>>,
    auth_users: Arc<RwLock<HashMap<String, AuthUser>>>,
    auth_ips: Arc<Mutex<HashMap<i64, HashSet<String>>>>,
    auth_server: AuthServer,
    child: AsyncMutex<Option<Child>>,
    stdout_task: Mutex<Option<JoinHandle<()>>>,
    stderr_task: Mutex<Option<JoinHandle<()>>>,
    inner: Mutex<Option<RunningServer>>,
    http_client: Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthUser {
    user_id: i64,
    device_limit: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct StatsTrafficEntry {
    tx: u64,
    rx: u64,
}

type StatsTrafficResponse = HashMap<String, StatsTrafficEntry>;
type StatsOnlineResponse = HashMap<String, i64>;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    addr: String,
    auth: String,
    #[allow(dead_code)]
    tx: u64,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    ok: bool,
    id: String,
}

#[derive(Debug, Serialize)]
struct HysteriaConfigFile {
    listen: String,
    tls: HysteriaTlsConfigFile,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfs: Option<HysteriaObfsConfigFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bandwidth: Option<HysteriaBandwidthConfigFile>,
    congestion: HysteriaCongestionConfigFile,
    #[serde(rename = "ignoreClientBandwidth")]
    ignore_client_bandwidth: bool,
    #[serde(rename = "disableUDP")]
    disable_udp: bool,
    #[serde(skip_serializing_if = "Option::is_none", rename = "udpIdleTimeout")]
    udp_idle_timeout: Option<String>,
    auth: HysteriaAuthConfigFile,
    #[serde(rename = "trafficStats")]
    traffic_stats: HysteriaTrafficStatsConfigFile,
    #[serde(skip_serializing_if = "Option::is_none")]
    masquerade: Option<HysteriaMasqueradeConfigFile>,
}

#[derive(Debug, Serialize)]
struct HysteriaTlsConfigFile {
    cert: String,
    key: String,
    #[serde(rename = "sniGuard")]
    sni_guard: String,
}

#[derive(Debug, Serialize)]
struct HysteriaObfsConfigFile {
    #[serde(rename = "type")]
    kind: String,
    salamander: HysteriaObfsSalamanderConfigFile,
}

#[derive(Debug, Serialize)]
struct HysteriaObfsSalamanderConfigFile {
    password: String,
}

#[derive(Debug, Serialize)]
struct HysteriaBandwidthConfigFile {
    up: String,
    down: String,
}

#[derive(Debug, Serialize)]
struct HysteriaCongestionConfigFile {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "bbrProfile")]
    bbr_profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct HysteriaAuthConfigFile {
    #[serde(rename = "type")]
    kind: String,
    http: HysteriaAuthHttpConfigFile,
}

#[derive(Debug, Serialize)]
struct HysteriaAuthHttpConfigFile {
    url: String,
    insecure: bool,
}

#[derive(Debug, Serialize)]
struct HysteriaTrafficStatsConfigFile {
    listen: String,
    secret: String,
}

#[derive(Debug, Serialize)]
struct HysteriaMasqueradeConfigFile {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<HysteriaMasqueradeFileConfigFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<HysteriaMasqueradeProxyConfigFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    string: Option<HysteriaMasqueradeStringConfigFile>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "listenHTTP")]
    listen_http: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "listenHTTPS")]
    listen_https: Option<String>,
    #[serde(skip_serializing_if = "is_false", rename = "forceHTTPS")]
    force_https: bool,
}

#[derive(Debug, Serialize)]
struct HysteriaMasqueradeFileConfigFile {
    dir: String,
}

#[derive(Debug, Serialize)]
struct HysteriaMasqueradeProxyConfigFile {
    url: String,
    #[serde(rename = "rewriteHost")]
    rewrite_host: bool,
    #[serde(rename = "xForwarded")]
    x_forwarded: bool,
    insecure: bool,
}

#[derive(Debug, Serialize)]
struct HysteriaMasqueradeStringConfigFile {
    content: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "statusCode")]
    status_code: Option<u16>,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let tls = shared::EffectiveTlsConfig::from_remote(remote)?;
        let up_mbps = value_to_optional_u64(remote.up_mbps.as_ref())?;
        let down_mbps = value_to_optional_u64(remote.down_mbps.as_ref())?;
        let udp_idle_timeout = if remote.heartbeat.trim().is_empty() {
            None
        } else {
            Some(remote.heartbeat.trim().to_string())
        };
        let obfs = parse_obfs(remote)?;
        let masquerade = parse_masquerade(remote)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls,
            auth_mode: AuthMode::Http,
            up_mbps,
            down_mbps,
            ignore_client_bandwidth: remote.ignore_client_bandwidth,
            congestion: parse_congestion(remote)?,
            disable_udp: udp_relay_disabled(&remote.udp_relay_mode),
            udp_idle_timeout,
            obfs,
            traffic_stats_secret: random_secret(32),
            masquerade,
        })
    }
}

impl ServerController {
    pub fn new(node_id: i64, hysteria_binary: String, accounting: Arc<Accounting>) -> Self {
        let auth_server = AuthServer::new();
        let http_client = Client::builder()
            .timeout(STATS_HTTP_CLIENT_TIMEOUT)
            .build()
            .expect("build hysteria stats client");
        Self {
            node_id,
            hysteria_binary: if hysteria_binary.trim().is_empty() {
                DEFAULT_HYSTERIA_BINARY.to_string()
            } else {
                hysteria_binary
            },
            accounting,
            panel_users: Arc::new(RwLock::new(Vec::new())),
            auth_users: Arc::new(RwLock::new(HashMap::new())),
            auth_ips: Arc::new(Mutex::new(HashMap::new())),
            auth_server,
            child: AsyncMutex::new(None),
            stdout_task: Mutex::new(None),
            stderr_task: Mutex::new(None),
            inner: Mutex::new(None),
            http_client,
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        let previous_users = self
            .panel_users
            .read()
            .expect("hysteria2 panel users lock poisoned")
            .clone();
        let kick_ids = changed_or_removed_user_ids(&previous_users, users);
        let auth_users = build_auth_users(users)?;
        *self
            .panel_users
            .write()
            .expect("hysteria2 panel users lock poisoned") = users.to_vec();
        *self
            .auth_users
            .write()
            .expect("hysteria2 auth users lock poisoned") = auth_users;
        self.accounting.replace_users(users);
        self.prune_auth_ips(users);
        self.spawn_kick_users(kick_ids);
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        let auth_listen = self
            .auth_server
            .ensure_started(
                self.auth_users.clone(),
                self.auth_ips.clone(),
                self.accounting.clone(),
            )
            .await?;
        let running = {
            self.inner
                .lock()
                .expect("hysteria2 controller poisoned")
                .clone()
        };

        let state_dir = running
            .as_ref()
            .map(|running| running.state_dir.clone())
            .unwrap_or_else(|| PathBuf::from(format!("hysteria2/node-{}", self.node_id)));
        prepare_state_dir(&state_dir).await?;
        let state_dir = absolute_path(&state_dir).await?;
        let stats_listen = running
            .as_ref()
            .map(|running| running.stats_listen)
            .unwrap_or_else(loopback_ephemeral_socket_addr);

        let tls_paths = ensure_tls_materials(&config.tls, &state_dir).await?;
        let config_path = state_dir.join("config.json");
        let stats_listen_text = socket_addr_to_listen_string(stats_listen);
        let auth_url = format!("http://{}/auth", auth_listen);
        let file = build_hysteria_config_file(
            &config,
            socket_addr_to_listen_string(SocketAddr::new(
                parse_ip(&config.listen_ip)?,
                config.server_port,
            )),
            &tls_paths,
            &auth_url,
            &stats_listen_text,
        );
        write_json(&config_path, &file).await?;

        self.restart_child(&config_path, &state_dir).await?;
        self.wait_until_healthy(stats_listen, &config.traffic_stats_secret)
            .await?;

        let mut guard = self.inner.lock().expect("hysteria2 controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            state_dir,
            auth_listen,
            stats_listen,
            traffic_stats_secret: config.traffic_stats_secret,
        });
        info!(
            node_id = self.node_id,
            listen = %format!("{}:{}", guard.as_ref().expect("running server").listen_ip, guard.as_ref().expect("running server").server_port),
            "Hysteria2 listeners started"
        );
        Ok(())
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        let Some(running) = self
            .inner
            .lock()
            .expect("hysteria2 controller poisoned")
            .clone()
        else {
            return Ok(());
        };

        let traffic = self
            .fetch_traffic(&running.stats_listen, &running.traffic_stats_secret)
            .await?;
        for (user_id, [upload, download]) in traffic {
            let counter = self.accounting.traffic_counter(user_id);
            counter.record_upload(upload);
            counter.record_download(download);
        }

        let alive = self
            .fetch_online(&running.stats_listen, &running.traffic_stats_secret)
            .await?;
        let alive_counts = parse_online_counts(&alive);
        let local_alive = self.reconcile_auth_ips(&alive_counts);
        self.accounting.replace_local_alive_ips(&local_alive);
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.stop_child().await;
        if let Some(handle) = self
            .stdout_task
            .lock()
            .expect("hysteria2 stdout task lock poisoned")
            .take()
        {
            handle.abort();
        }
        if let Some(handle) = self
            .stderr_task
            .lock()
            .expect("hysteria2 stderr task lock poisoned")
            .take()
        {
            handle.abort();
        }
        if let Some(running) = self
            .inner
            .lock()
            .expect("hysteria2 controller poisoned")
            .take()
        {
            info!(
                node_id = self.node_id,
                port = running.server_port,
                "Hysteria2 listeners stopped"
            );
        }
        self.auth_server.shutdown().await;
    }

    fn prune_auth_ips(&self, users: &[PanelUser]) {
        let valid_ids = users.iter().map(|user| user.id).collect::<HashSet<_>>();
        self.auth_ips
            .lock()
            .expect("hysteria2 auth ips lock poisoned")
            .retain(|uid, _| valid_ids.contains(uid));
    }

    fn reconcile_auth_ips(&self, online: &HashMap<i64, usize>) -> HashMap<i64, Vec<String>> {
        let mut guard = self
            .auth_ips
            .lock()
            .expect("hysteria2 auth ips lock poisoned");
        guard.retain(|uid, _| online.get(uid).copied().unwrap_or(0) > 0);
        let mut alive = HashMap::new();
        for (uid, count) in online {
            if *count == 0 {
                continue;
            }
            let ips = guard
                .get(uid)
                .map(|ips| ips.iter().take(*count).cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            if !ips.is_empty() {
                alive.insert(*uid, ips);
            }
        }
        alive
    }

    fn spawn_kick_users(&self, kick_ids: HashSet<i64>) {
        if kick_ids.is_empty() {
            return;
        }
        let Some(running) = self
            .inner
            .lock()
            .expect("hysteria2 controller poisoned")
            .clone()
        else {
            return;
        };
        let http_client = self.http_client.clone();
        let ids = kick_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        tokio::spawn(async move {
            let url = format!("http://{}/kick", running.stats_listen);
            let result = http_client
                .post(url)
                .header("Authorization", running.traffic_stats_secret)
                .json(&ids)
                .send()
                .await
                .and_then(|response| response.error_for_status())
                .map(|_| ());
            if let Err(error) = result {
                warn!(%error, "kick Hysteria2 users failed");
            }
        });
    }

    async fn restart_child(&self, config_path: &Path, state_dir: &Path) -> anyhow::Result<()> {
        self.stop_child().await;

        let mut command = Command::new(&self.hysteria_binary);
        command
            .arg("server")
            .arg("--config")
            .arg(config_path)
            .current_dir(state_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "spawn hysteria binary {} for node {}",
                self.hysteria_binary, self.node_id
            )
        })?;

        if let Some(stdout) = child.stdout.take() {
            let node_id = self.node_id;
            let handle = tokio::spawn(async move {
                stream_process_logs(stdout, node_id, "stdout").await;
            });
            *self
                .stdout_task
                .lock()
                .expect("hysteria2 stdout task lock poisoned") = Some(handle);
        }
        if let Some(stderr) = child.stderr.take() {
            let node_id = self.node_id;
            let handle = tokio::spawn(async move {
                stream_process_logs(stderr, node_id, "stderr").await;
            });
            *self
                .stderr_task
                .lock()
                .expect("hysteria2 stderr task lock poisoned") = Some(handle);
        }

        *self.child.lock().await = Some(child);
        Ok(())
    }

    async fn stop_child(&self) {
        let mut guard = self.child.lock().await;
        let Some(mut child) = guard.take() else {
            return;
        };
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    async fn wait_until_healthy(
        &self,
        stats_listen: SocketAddr,
        secret: &str,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + HEALTH_CHECK_TIMEOUT;
        loop {
            if self.fetch_online(&stats_listen, secret).await.is_ok() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("timed out waiting for Hysteria2 stats API to become ready");
            }
            tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
        }
    }

    async fn fetch_traffic(
        &self,
        stats_listen: &SocketAddr,
        secret: &str,
    ) -> anyhow::Result<HashMap<i64, [u64; 2]>> {
        let url = format!("http://{}/traffic?clear=1", stats_listen);
        let response = self
            .http_client
            .get(url)
            .header("Authorization", secret)
            .send()
            .await
            .context("request Hysteria2 /traffic")?;
        ensure!(
            response.status().is_success(),
            "Hysteria2 /traffic returned {}",
            response.status()
        );
        let payload = response
            .json::<StatsTrafficResponse>()
            .await
            .context("decode Hysteria2 /traffic")?;
        let mut mapped = HashMap::new();
        for (id, entry) in payload {
            let Ok(user_id) = id.parse::<i64>() else {
                debug!(node_id = self.node_id, user = %id, "skip non-numeric Hysteria2 traffic id");
                continue;
            };
            mapped.insert(user_id, [entry.tx, entry.rx]);
        }
        Ok(mapped)
    }

    async fn fetch_online(
        &self,
        stats_listen: &SocketAddr,
        secret: &str,
    ) -> anyhow::Result<HashMap<String, i64>> {
        let url = format!("http://{}/online", stats_listen);
        let response = self
            .http_client
            .get(url)
            .header("Authorization", secret)
            .send()
            .await
            .context("request Hysteria2 /online")?;
        ensure!(
            response.status().is_success(),
            "Hysteria2 /online returned {}",
            response.status()
        );
        let payload = response
            .json::<StatsOnlineResponse>()
            .await
            .context("decode Hysteria2 /online")?;
        Ok(payload)
    }
}

#[derive(Default)]
struct AuthServer {
    state: AsyncMutex<Option<AuthServerState>>,
}

struct AuthServerState {
    listen: SocketAddr,
    handle: JoinHandle<()>,
}

impl AuthServer {
    fn new() -> Self {
        Self {
            state: AsyncMutex::new(None),
        }
    }

    async fn ensure_started(
        &self,
        users: Arc<RwLock<HashMap<String, AuthUser>>>,
        auth_ips: Arc<Mutex<HashMap<i64, HashSet<String>>>>,
        accounting: Arc<Accounting>,
    ) -> anyhow::Result<SocketAddr> {
        let mut state = self.state.lock().await;
        if let Some(state) = state.as_ref() {
            return Ok(state.listen);
        }

        let listener = TokioTcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("bind Hysteria2 auth listener")?;
        let listen = listener
            .local_addr()
            .context("read auth listener address")?;
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(value) => value,
                    Err(error) => {
                        debug!(%error, "Hysteria2 auth listener accept failed");
                        break;
                    }
                };
                let users = users.clone();
                let auth_ips = auth_ips.clone();
                let accounting = accounting.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        serve_auth_request(stream, users, auth_ips, accounting).await
                    {
                        debug!(%error, "serve Hysteria2 auth request failed");
                    }
                });
            }
        });
        *state = Some(AuthServerState { listen, handle });
        Ok(listen)
    }

    async fn shutdown(&self) {
        if let Some(state) = self.state.lock().await.take() {
            state.handle.abort();
        }
    }
}

async fn serve_auth_request(
    mut stream: tokio::net::TcpStream,
    users: Arc<RwLock<HashMap<String, AuthUser>>>,
    auth_ips: Arc<Mutex<HashMap<i64, HashSet<String>>>>,
    accounting: Arc<Accounting>,
) -> anyhow::Result<()> {
    let request = timeout(HTTP_REQUEST_TIMEOUT, read_http_request(&mut stream))
        .await
        .context("Hysteria2 auth request timed out")??;
    let response = match handle_auth_request(&request, &users, &auth_ips, &accounting)? {
        Some(response) => build_json_response(200, &response)?,
        None => build_plain_response(404, "not found"),
    };
    stream
        .write_all(response.as_bytes())
        .await
        .context("write Hysteria2 auth response")?;
    stream
        .flush()
        .await
        .context("flush Hysteria2 auth response")?;
    Ok(())
}

fn handle_auth_request(
    request: &HttpRequest,
    users: &Arc<RwLock<HashMap<String, AuthUser>>>,
    auth_ips: &Arc<Mutex<HashMap<i64, HashSet<String>>>>,
    accounting: &Arc<Accounting>,
) -> anyhow::Result<Option<AuthResponse>> {
    if request.method != "POST" || request.path != "/auth" {
        return Ok(None);
    }
    let payload: AuthRequest =
        serde_json::from_slice(&request.body).context("decode auth request")?;
    let source = payload
        .addr
        .parse::<SocketAddr>()
        .map_err(|error| anyhow!(error))
        .context("parse auth addr")?;
    let users = users.read().expect("hysteria2 auth users lock poisoned");
    let Some(user) = users.get(payload.auth.trim()) else {
        return Ok(Some(AuthResponse {
            ok: false,
            id: String::new(),
        }));
    };

    let ip = source.ip().to_string();
    if let Err(error) = accounting.try_mark_local_alive(user.user_id, user.device_limit, &ip) {
        debug!(uid = user.user_id, %ip, %error, "Hysteria2 auth rejected by device limit");
        return Ok(Some(AuthResponse {
            ok: false,
            id: String::new(),
        }));
    }
    auth_ips
        .lock()
        .expect("hysteria2 auth ips lock poisoned")
        .entry(user.user_id)
        .or_default()
        .insert(ip);

    Ok(Some(AuthResponse {
        ok: true,
        id: user.user_id.to_string(),
    }))
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buffer = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.context("read HTTP request")?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() >= HTTP_BUFFER_SIZE
        {
            break;
        }
    }
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .context("HTTP request header terminator is missing")?;
    let header_text = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = header_text.lines();
    let request_line = lines.next().context("HTTP request line is missing")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("HTTP method is missing")?.to_string();
    let path = parts.next().context("HTTP path is missing")?.to_string();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let read = stream.read(&mut chunk).await.context("read HTTP body")?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(HttpRequest { method, path, body })
}

fn build_json_response(status: u16, body: &impl Serialize) -> anyhow::Result<String> {
    let body = serde_json::to_string(body).context("encode JSON response")?;
    Ok(format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    ))
}

fn build_plain_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    )
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        _ => "OK",
    }
}

async fn stream_process_logs<R>(mut reader: R, node_id: i64, stream_name: &'static str)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; 4096];
    let mut pending = Vec::new();
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                debug!(node_id, %error, "read Hysteria2 process log failed");
                break;
            }
        };
        pending.extend_from_slice(&buffer[..read]);
        while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let line = String::from_utf8_lossy(&pending[..position])
                .trim()
                .to_string();
            if !line.is_empty() {
                debug!(node_id, stream = stream_name, message = %line, "Hysteria2 process output");
            }
            pending.drain(..=position);
        }
    }
    if !pending.is_empty() {
        let line = String::from_utf8_lossy(&pending).trim().to_string();
        if !line.is_empty() {
            debug!(node_id, stream = stream_name, message = %line, "Hysteria2 process output");
        }
    }
}

fn build_auth_users(users: &[PanelUser]) -> anyhow::Result<HashMap<String, AuthUser>> {
    let mut mapped = HashMap::new();
    for user in users {
        let auth = effective_auth(user)
            .ok_or_else(|| anyhow!("Hysteria2 user {} requires password or uuid", user.id))?;
        ensure!(
            mapped
                .insert(
                    auth.clone(),
                    AuthUser {
                        user_id: user.id,
                        device_limit: user.device_limit,
                    }
                )
                .is_none(),
            "duplicate Hysteria2 credentials for user {}",
            user.id
        );
    }
    Ok(mapped)
}

fn effective_auth(user: &PanelUser) -> Option<String> {
    let password = user.password.trim();
    if !password.is_empty() {
        return Some(password.to_string());
    }
    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return Some(uuid.to_string());
    }
    None
}

fn changed_or_removed_user_ids(previous: &[PanelUser], current: &[PanelUser]) -> HashSet<i64> {
    let current_by_id = current
        .iter()
        .map(|user| (user.id, effective_auth(user)))
        .collect::<HashMap<_, _>>();
    previous
        .iter()
        .filter_map(|user| {
            let previous_auth = effective_auth(user);
            match current_by_id.get(&user.id) {
                Some(current_auth) if *current_auth == previous_auth => None,
                _ => Some(user.id),
            }
        })
        .collect()
}

fn parse_online_counts(alive: &HashMap<String, i64>) -> HashMap<i64, usize> {
    alive
        .iter()
        .filter_map(|(uid, count)| {
            let uid = uid.parse::<i64>().ok()?;
            let count = usize::try_from((*count).max(0)).ok()?;
            Some((uid, count))
        })
        .collect()
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !hysteria2_version_supported(remote.version.as_ref()) {
        bail!("NodeRS Hysteria2 controller only supports Xboard hysteria version 2");
    }
    if remote.tls_mode() == 2 {
        bail!("Xboard tls mode 2 is not supported by NodeRS Hysteria2 controller yet");
    }
    if remote.reality_settings.is_configured() || remote.tls_settings.has_reality_key_material() {
        bail!("REALITY settings are not supported for Hysteria2 nodes");
    }
    if remote.multiplex_enabled() {
        bail!("Xboard multiplex is not supported by NodeRS Hysteria2 controller");
    }
    if !is_absent_or_empty_object(remote.transport.as_ref()) {
        bail!("Xboard transport is not supported by NodeRS Hysteria2 controller yet");
    }
    if !is_absent_or_empty_object(remote.network_settings.as_ref()) {
        bail!("Xboard networkSettings is not supported by NodeRS Hysteria2 controller yet");
    }
    if remote.fallbacks.is_some() || remote.fallback.is_some() || remote.fallback_for_alpn.is_some()
    {
        bail!("Xboard fallback settings are not supported by NodeRS Hysteria2 controller");
    }
    if !remote.flow.trim().is_empty()
        || !remote.decryption.trim().is_empty()
        || !remote.packet_encoding.trim().is_empty()
        || remote.udp_over_stream
        || !remote.padding_scheme.is_empty()
        || !remote.routes.is_empty()
        || !remote.custom_outbounds.is_empty()
        || !remote.custom_routes.is_empty()
    {
        bail!("unsupported Hysteria2 extension fields in Xboard config");
    }
    if !remote.auth_timeout.trim().is_empty()
        || remote.zero_rtt_handshake
        || !remote.traffic_pattern.trim().is_empty()
    {
        bail!("unsupported Hysteria2 timing/traffic pattern fields in Xboard config");
    }
    let network = remote.network.trim();
    if !network.is_empty() && !network.eq_ignore_ascii_case("udp") {
        bail!("Xboard network must be udp or empty for Hysteria2 nodes");
    }
    Ok(())
}

fn hysteria2_version_supported(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Number(number)) => number.as_u64().is_some_and(|value| value == 2),
        Some(serde_json::Value::String(text)) => text.trim().is_empty() || text.trim() == "2",
        _ => false,
    }
}

fn is_absent_or_empty_object(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => true,
        Some(value) => !crate::panel::json_value_is_enabled(value),
    }
}

fn parse_congestion(remote: &NodeConfigResponse) -> anyhow::Result<HysteriaCongestion> {
    let raw = remote.congestion_control.trim();
    if raw.is_empty() {
        return Ok(HysteriaCongestion {
            kind: "bbr".to_string(),
            bbr_profile: None,
        });
    }
    let normalized = raw.to_ascii_lowercase();
    if normalized == "reno" {
        return Ok(HysteriaCongestion {
            kind: normalized,
            bbr_profile: None,
        });
    }
    if let Some((kind, profile)) = normalized.split_once(':') {
        ensure!(
            kind == "bbr",
            "unsupported Hysteria2 congestion control {raw}"
        );
        let profile = profile.trim();
        ensure!(
            matches!(profile, "standard" | "conservative" | "aggressive"),
            "unsupported Hysteria2 bbr profile {profile}"
        );
        return Ok(HysteriaCongestion {
            kind: kind.to_string(),
            bbr_profile: Some(profile.to_string()),
        });
    }
    ensure!(
        normalized == "bbr",
        "unsupported Hysteria2 congestion control {raw}"
    );
    Ok(HysteriaCongestion {
        kind: normalized,
        bbr_profile: None,
    })
}

fn parse_obfs(remote: &NodeConfigResponse) -> anyhow::Result<Option<HysteriaObfs>> {
    if matches!(
        remote.obfs.as_ref(),
        Some(serde_json::Value::Bool(false) | serde_json::Value::Null)
    ) && remote.obfs_password.trim().is_empty()
    {
        return Ok(None);
    }
    if remote.obfs.is_none() && remote.obfs_password.trim().is_empty() {
        return Ok(None);
    }
    let kind = remote
        .obfs
        .as_ref()
        .and_then(|value| value.get("type"))
        .and_then(|value| value.as_str())
        .unwrap_or("salamander")
        .trim()
        .to_ascii_lowercase();
    ensure!(
        kind == "salamander",
        "unsupported Hysteria2 obfs type {kind}"
    );
    let object_password = remote
        .obfs
        .as_ref()
        .and_then(|value| value.get("password"))
        .or_else(|| {
            remote
                .obfs
                .as_ref()
                .and_then(|value| value.get("salamander"))
                .and_then(|value| value.get("password"))
        })
        .and_then(|value| value.as_str())
        .map(str::trim)
        .unwrap_or_default();
    let password = if remote.obfs_password.trim().is_empty() {
        object_password
    } else {
        remote.obfs_password.trim()
    };
    ensure!(
        !password.is_empty(),
        "Hysteria2 obfs-password is required when obfs is enabled"
    );
    Ok(Some(HysteriaObfs {
        kind,
        password: password.to_string(),
    }))
}

fn parse_masquerade(remote: &NodeConfigResponse) -> anyhow::Result<Option<HysteriaMasquerade>> {
    let Some(value) = remote.masquerade.as_ref() else {
        return Ok(None);
    };
    if let Some(url) = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(HysteriaMasquerade {
            kind: "proxy".to_string(),
            file_dir: None,
            proxy_url: Some(url.to_string()),
            proxy_rewrite_host: true,
            proxy_x_forwarded: false,
            proxy_insecure: false,
            string_content: None,
            string_headers: Vec::new(),
            string_status_code: None,
            listen_http: None,
            listen_https: None,
            force_https: false,
        }));
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Xboard masquerade must be an object for Hysteria2 nodes"))?;
    let kind = object
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    ensure!(!kind.is_empty(), "Hysteria2 masquerade.type is required");
    let listen_http = object
        .get("listenHTTP")
        .or_else(|| object.get("listen_http"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let listen_https = object
        .get("listenHTTPS")
        .or_else(|| object.get("listen_https"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let force_https = object
        .get("forceHTTPS")
        .or_else(|| object.get("force_https"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let mut result = HysteriaMasquerade {
        kind: kind.clone(),
        file_dir: None,
        proxy_url: None,
        proxy_rewrite_host: false,
        proxy_x_forwarded: false,
        proxy_insecure: false,
        string_content: None,
        string_headers: Vec::new(),
        string_status_code: None,
        listen_http,
        listen_https,
        force_https,
    };

    match kind.as_str() {
        "file" => {
            let dir = object
                .get("dir")
                .or_else(|| object.get("directory"))
                .or_else(|| object.get("file").and_then(|value| value.get("dir")))
                .or_else(|| object.get("file").and_then(|value| value.get("directory")))
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Hysteria2 masquerade.file requires dir"))?;
            result.file_dir = Some(dir.to_string());
        }
        "proxy" => {
            let url = object
                .get("url")
                .or_else(|| object.get("proxy").and_then(|value| value.get("url")))
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Hysteria2 masquerade.proxy requires url"))?;
            result.proxy_url = Some(url.to_string());
            result.proxy_rewrite_host = object
                .get("rewriteHost")
                .or_else(|| object.get("rewrite_host"))
                .or_else(|| {
                    object
                        .get("proxy")
                        .and_then(|value| value.get("rewriteHost"))
                })
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            result.proxy_x_forwarded = object
                .get("xForwarded")
                .or_else(|| object.get("x_forwarded"))
                .or_else(|| {
                    object
                        .get("proxy")
                        .and_then(|value| value.get("xForwarded"))
                })
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            result.proxy_insecure = object
                .get("insecure")
                .or_else(|| object.get("proxy").and_then(|value| value.get("insecure")))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
        }
        "string" => {
            let content = object
                .get("content")
                .or_else(|| object.get("string").and_then(|value| value.get("content")))
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Hysteria2 masquerade.string requires content"))?;
            result.string_content = Some(content.to_string());
            result.string_status_code = object
                .get("statusCode")
                .or_else(|| object.get("status_code"))
                .or_else(|| {
                    object
                        .get("string")
                        .and_then(|value| value.get("statusCode"))
                })
                .and_then(value_to_u16);
            let headers = object
                .get("headers")
                .or_else(|| object.get("string").and_then(|value| value.get("headers")));
            if let Some(headers) = headers.and_then(|value| value.as_object()) {
                result.string_headers = headers
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect();
            }
        }
        _ => bail!("unsupported Hysteria2 masquerade type {kind}"),
    }

    Ok(Some(result))
}

fn value_to_optional_u64(value: Option<&serde_json::Value>) -> anyhow::Result<Option<u64>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| anyhow!("Hysteria2 bandwidth must be a non-negative integer"))
            .map(Some),
        Some(serde_json::Value::String(text)) => {
            let text = text.trim();
            if text.is_empty() {
                Ok(None)
            } else {
                text.parse::<u64>()
                    .with_context(|| format!("parse Hysteria2 bandwidth {text}"))
                    .map(Some)
            }
        }
        _ => bail!("Hysteria2 bandwidth must be a number or string"),
    }
}

fn value_to_u16(value: &serde_json::Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .or_else(|| {
            value
                .as_str()
                .and_then(|value| value.trim().parse::<u16>().ok())
        })
}

fn udp_relay_disabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "disabled" | "disable" | "none" | "off" | "false"
    )
}

async fn prepare_state_dir(state_dir: &Path) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(state_dir)
        .await
        .with_context(|| format!("create Hysteria2 state directory {}", state_dir.display()))
}

async fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let current = std::env::current_dir().context("read current directory")?;
    Ok(current.join(path))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsPaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

async fn ensure_tls_materials(
    tls: &shared::EffectiveTlsConfig,
    state_dir: &Path,
) -> anyhow::Result<TlsPaths> {
    let tls_dir = state_dir.join("tls");
    tokio::fs::create_dir_all(&tls_dir)
        .await
        .with_context(|| format!("create Hysteria2 TLS directory {}", tls_dir.display()))?;
    match &tls.source {
        shared::tls::TlsMaterialSource::Files {
            cert_path,
            key_path,
        } => Ok(TlsPaths {
            cert_path: absolute_path(cert_path).await?,
            key_path: absolute_path(key_path).await?,
        }),
        shared::tls::TlsMaterialSource::Inline { cert_pem, key_pem } => {
            let cert_path = tls_dir.join("fullchain.pem");
            let key_path = tls_dir.join("privkey.pem");
            write_atomic(&cert_path, cert_pem).await?;
            write_atomic(&key_path, key_pem).await?;
            Ok(TlsPaths {
                cert_path,
                key_path,
            })
        }
        shared::tls::TlsMaterialSource::SelfSigned { .. }
        | shared::tls::TlsMaterialSource::Acme { .. } => {
            let cert_path = tls_dir.join("fullchain.pem");
            let key_path = tls_dir.join("privkey.pem");
            match &tls.source {
                shared::tls::TlsMaterialSource::SelfSigned { subject_alt_names } => {
                    let generated = rcgen::generate_simple_self_signed(subject_alt_names.clone())
                        .context("generate Hysteria2 self-signed certificate")?;
                    write_atomic(&cert_path, generated.cert.pem().as_bytes()).await?;
                    write_atomic(&key_path, generated.signing_key.serialize_pem().as_bytes())
                        .await?;
                }
                shared::tls::TlsMaterialSource::Acme {
                    cert_path: source_cert_path,
                    key_path: source_key_path,
                    config,
                } => {
                    crate::acme::ensure_certificate(config, source_cert_path, source_key_path)
                        .await
                        .context("ensure Hysteria2 ACME certificate")?;
                    Ok::<(), anyhow::Error>(())?;
                    return Ok(TlsPaths {
                        cert_path: absolute_path(source_cert_path).await?,
                        key_path: absolute_path(source_key_path).await?,
                    });
                }
                _ => unreachable!(),
            }
            Ok(TlsPaths {
                cert_path,
                key_path,
            })
        }
    }
}

fn build_hysteria_config_file(
    config: &EffectiveNodeConfig,
    listen: String,
    tls_paths: &TlsPaths,
    auth_url: &str,
    stats_listen: &str,
) -> HysteriaConfigFile {
    HysteriaConfigFile {
        listen,
        tls: HysteriaTlsConfigFile {
            cert: tls_paths.cert_path.display().to_string(),
            key: tls_paths.key_path.display().to_string(),
            sni_guard: "dns-san".to_string(),
        },
        obfs: config.obfs.as_ref().map(|obfs| HysteriaObfsConfigFile {
            kind: obfs.kind.clone(),
            salamander: HysteriaObfsSalamanderConfigFile {
                password: obfs.password.clone(),
            },
        }),
        bandwidth: match (config.up_mbps, config.down_mbps) {
            (None, None) => None,
            (up, down) => Some(HysteriaBandwidthConfigFile {
                up: format_bandwidth(up),
                down: format_bandwidth(down),
            }),
        },
        congestion: HysteriaCongestionConfigFile {
            kind: config.congestion.kind.clone(),
            bbr_profile: config.congestion.bbr_profile.clone(),
        },
        ignore_client_bandwidth: config.ignore_client_bandwidth,
        disable_udp: config.disable_udp,
        udp_idle_timeout: config.udp_idle_timeout.clone(),
        auth: HysteriaAuthConfigFile {
            kind: match config.auth_mode {
                AuthMode::Http => "http".to_string(),
            },
            http: HysteriaAuthHttpConfigFile {
                url: auth_url.to_string(),
                insecure: false,
            },
        },
        traffic_stats: HysteriaTrafficStatsConfigFile {
            listen: stats_listen.to_string(),
            secret: config.traffic_stats_secret.clone(),
        },
        masquerade: config
            .masquerade
            .as_ref()
            .map(|masquerade| HysteriaMasqueradeConfigFile {
                kind: masquerade.kind.clone(),
                file: masquerade
                    .file_dir
                    .as_ref()
                    .map(|dir| HysteriaMasqueradeFileConfigFile { dir: dir.clone() }),
                proxy: masquerade
                    .proxy_url
                    .as_ref()
                    .map(|url| HysteriaMasqueradeProxyConfigFile {
                        url: url.clone(),
                        rewrite_host: masquerade.proxy_rewrite_host,
                        x_forwarded: masquerade.proxy_x_forwarded,
                        insecure: masquerade.proxy_insecure,
                    }),
                string: masquerade.string_content.as_ref().map(|content| {
                    HysteriaMasqueradeStringConfigFile {
                        content: content.clone(),
                        headers: masquerade.string_headers.iter().cloned().collect(),
                        status_code: masquerade.string_status_code,
                    }
                }),
                listen_http: masquerade.listen_http.clone(),
                listen_https: masquerade.listen_https.clone(),
                force_https: masquerade.force_https,
            }),
    }
}

fn format_bandwidth(mbps: Option<u64>) -> String {
    match mbps {
        Some(0) => "0 mbps".to_string(),
        Some(value) => format!("{value} mbps"),
        None => "0 mbps".to_string(),
    }
}

async fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let rendered = serde_json::to_string_pretty(value).context("serialize Hysteria2 config")?;
    write_atomic(path, rendered.as_bytes()).await
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let temp_path = temp_path(path);
    tokio::fs::write(&temp_path, bytes)
        .await
        .with_context(|| format!("write temporary file {}", temp_path.display()))?;
    if tokio::fs::metadata(path).await.is_ok() {
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("remove existing file {}", path.display()))?;
    }
    tokio::fs::rename(&temp_path, path)
        .await
        .with_context(|| format!("move {} to {}", temp_path.display(), path.display()))
}

fn temp_path(path: &Path) -> PathBuf {
    let suffix = format!("{}.tmp", unix_now());
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(extension) if !extension.is_empty() => {
            path.with_extension(format!("{extension}.{suffix}"))
        }
        _ => path.with_extension(suffix),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_secret(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut output = String::with_capacity(len);
    for _ in 0..len {
        let index = rand::random_range(0..CHARSET.len());
        output.push(CHARSET[index] as char);
    }
    output
}

fn parse_ip(listen_ip: &str) -> anyhow::Result<IpAddr> {
    let normalized = listen_ip.trim();
    if normalized.is_empty() || normalized == "0.0.0.0" {
        return Ok(IpAddr::from([0, 0, 0, 0]));
    }
    if normalized == "::" || normalized == "[::]" {
        return Ok(IpAddr::from([0u16; 8]));
    }
    normalized
        .parse::<IpAddr>()
        .with_context(|| format!("parse Hysteria2 listen_ip {normalized}"))
}

fn loopback_ephemeral_socket_addr() -> SocketAddr {
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind loopback port probe");
    let addr = listener
        .local_addr()
        .expect("read loopback port probe addr");
    drop(listener);
    addr
}

fn socket_addr_to_listen_string(addr: SocketAddr) -> String {
    if addr.ip().is_ipv6() {
        format!("[{}]:{}", addr.ip(), addr.port())
    } else {
        format!("{}:{}", addr.ip(), addr.port())
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::{CertConfig, NodeConfigResponse};
    use serde_json::json;

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "hy2".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            server_name: "node.example.com".to_string(),
            cert_config: Some(CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn parses_hysteria2_remote_config() {
        let mut remote = base_remote();
        remote.up_mbps = Some(json!(100));
        remote.down_mbps = Some(json!(200));
        remote.obfs = Some(json!({ "type": "salamander" }));
        remote.obfs_password = "secret".to_string();
        remote.congestion_control = "bbr:aggressive".to_string();
        remote.ignore_client_bandwidth = true;
        remote.heartbeat = "60s".to_string();
        remote.masquerade = Some(json!({
            "type": "proxy",
            "url": "https://example.com",
            "rewriteHost": true,
            "xForwarded": true,
            "listenHTTP": ":80",
            "listenHTTPS": ":443",
            "forceHTTPS": true
        }));

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("effective config");
        assert_eq!(effective.listen_ip, "0.0.0.0");
        assert_eq!(effective.server_port, 443);
        assert_eq!(effective.up_mbps, Some(100));
        assert_eq!(effective.down_mbps, Some(200));
        assert_eq!(effective.udp_idle_timeout.as_deref(), Some("60s"));
        assert!(effective.ignore_client_bandwidth);
        assert_eq!(effective.congestion.kind, "bbr");
        assert_eq!(
            effective.congestion.bbr_profile.as_deref(),
            Some("aggressive")
        );
        assert_eq!(
            effective.obfs.as_ref().map(|it| it.kind.as_str()),
            Some("salamander")
        );
        assert_eq!(
            effective
                .masquerade
                .as_ref()
                .and_then(|it| it.proxy_url.as_deref()),
            Some("https://example.com")
        );
    }

    #[test]
    fn prefers_password_over_uuid_for_auth() {
        let mapped = build_auth_users(&[PanelUser {
            id: 7,
            uuid: "uuid-secret".to_string(),
            password: "real-password".to_string(),
            ..Default::default()
        }])
        .expect("auth users");
        assert!(mapped.contains_key("real-password"));
        assert!(!mapped.contains_key("uuid-secret"));
    }

    #[test]
    fn rejects_duplicate_auth_credentials() {
        let error = build_auth_users(&[
            PanelUser {
                id: 1,
                password: "dup".to_string(),
                ..Default::default()
            },
            PanelUser {
                id: 2,
                password: "dup".to_string(),
                ..Default::default()
            },
        ])
        .expect_err("duplicate auth should fail");
        assert!(
            error
                .to_string()
                .contains("duplicate Hysteria2 credentials")
        );
    }

    #[test]
    fn renders_hysteria_config_shape() {
        let config = EffectiveNodeConfig {
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            tls: shared::EffectiveTlsConfig::from_remote(&base_remote()).expect("tls config"),
            auth_mode: AuthMode::Http,
            up_mbps: Some(100),
            down_mbps: Some(200),
            ignore_client_bandwidth: true,
            congestion: HysteriaCongestion {
                kind: "bbr".to_string(),
                bbr_profile: Some("standard".to_string()),
            },
            disable_udp: false,
            udp_idle_timeout: Some("60s".to_string()),
            obfs: Some(HysteriaObfs {
                kind: "salamander".to_string(),
                password: "secret".to_string(),
            }),
            traffic_stats_secret: "stats-secret".to_string(),
            masquerade: Some(HysteriaMasquerade {
                kind: "string".to_string(),
                file_dir: None,
                proxy_url: None,
                proxy_rewrite_host: false,
                proxy_x_forwarded: false,
                proxy_insecure: false,
                string_content: Some("hello".to_string()),
                string_headers: vec![("content-type".to_string(), "text/plain".to_string())],
                string_status_code: Some(200),
                listen_http: Some(":80".to_string()),
                listen_https: Some(":443".to_string()),
                force_https: true,
            }),
        };
        let file = build_hysteria_config_file(
            &config,
            ":443".to_string(),
            &TlsPaths {
                cert_path: "/tmp/fullchain.pem".into(),
                key_path: "/tmp/privkey.pem".into(),
            },
            "http://127.0.0.1:8080/auth",
            "127.0.0.1:9999",
        );
        let json = serde_json::to_string_pretty(&file).expect("config json");
        assert!(json.contains("\"listen\": \":443\""));
        assert!(json.contains("\"trafficStats\""));
        assert!(json.contains("\"type\": \"http\""));
        assert!(json.contains("\"listen\": \"127.0.0.1:9999\""));
        assert!(json.contains("\"ignoreClientBandwidth\": true"));
    }

    #[test]
    fn handles_auth_http_request() {
        let users = Arc::new(RwLock::new(
            build_auth_users(&[PanelUser {
                id: 9,
                password: "pw".to_string(),
                ..Default::default()
            }])
            .expect("auth users"),
        ));
        let auth_ips = Arc::new(Mutex::new(HashMap::new()));
        let accounting = Accounting::new();
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/auth".to_string(),
            body: serde_json::to_vec(&json!({
                "addr": "127.0.0.1:1234",
                "auth": "pw",
                "tx": 0
            }))
            .expect("request body"),
        };
        let response = handle_auth_request(&request, &users, &auth_ips, &accounting)
            .expect("handle auth request")
            .expect("auth response");
        assert!(response.ok);
        assert_eq!(response.id, "9");
        assert_eq!(
            accounting.snapshot_alive().get(&9),
            Some(&vec!["127.0.0.1".to_string()])
        );
    }
}
