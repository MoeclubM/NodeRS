use anyhow::{Context, bail, ensure};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::accounting::Accounting;
use crate::acme;
use crate::panel::{NodeConfigResponse, PanelUser};
use crate::protocols::ProtocolKind;

use super::shared::{
    EffectiveTlsConfig, aerion_ech_keys, bind_listeners, bind_udp_sockets, effective_listen_ip, tls,
};

pub struct ServerController {
    protocol: ProtocolKind,
    accounting: Arc<Accounting>,
    core: ::aerion::core::ProxyCore,
    users: RwLock<Vec<PanelUser>>,
    remote: RwLock<Option<NodeConfigResponse>>,
    last_traffic: Mutex<HashMap<String, [u64; 2]>>,
    inner: AsyncMutex<Option<RunningServer>>,
}

struct RunningServer {
    handles: Vec<JoinHandle<()>>,
}

struct AerionTlsIdentity {
    cert_path: PathBuf,
    key_path: PathBuf,
    certificates: Vec<String>,
    key: Option<String>,
}

enum BuiltServerConfig {
    Anytls(::aerion::ServerConfig),
    Hysteria2(::aerion::Hysteria2ServerConfig),
    Mieru(::aerion::MieruServerConfig),
    Naive(::aerion::NaiveServerConfig),
    Trojan(::aerion::TrojanServerConfig),
    Tuic(::aerion::TuicServerConfig),
    Vless(::aerion::VlessServerConfig),
    Vmess(::aerion::VmessServerConfig),
}

impl ServerController {
    pub fn new(protocol: ProtocolKind, accounting: Arc<Accounting>) -> Self {
        Self {
            protocol,
            accounting,
            core: ::aerion::core::ProxyCore::empty(),
            users: RwLock::new(Vec::new()),
            remote: RwLock::new(None),
            last_traffic: Mutex::new(HashMap::new()),
            inner: AsyncMutex::new(None),
        }
    }

    pub fn protocol(&self) -> ProtocolKind {
        self.protocol
    }

    pub async fn apply_remote_config(&self, remote: &NodeConfigResponse) -> anyhow::Result<()> {
        ensure_aerion_supported(self.protocol, remote)?;
        *self.remote.write().await = Some(remote.clone());
        self.restart().await
    }

    pub async fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        self.flush_traffic().await?;
        self.accounting.replace_users(users);
        self.core.replace_users(core_users(self.protocol, users)?)?;
        let active = users
            .iter()
            .map(|user| user.id.to_string())
            .collect::<HashSet<_>>();
        self.last_traffic
            .lock()
            .expect("Aerion traffic lock poisoned")
            .retain(|uid, _| active.contains(uid));
        *self.users.write().await = users.to_vec();
        self.restart().await
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn flush_traffic(&self) -> anyhow::Result<()> {
        let snapshots = self.core.snapshot().await;
        let mut last = self
            .last_traffic
            .lock()
            .expect("Aerion traffic lock poisoned");
        let active = snapshots
            .iter()
            .map(|snapshot| snapshot.user_id.clone())
            .collect::<HashSet<_>>();
        for snapshot in snapshots {
            let uid = snapshot
                .user_id
                .parse::<i64>()
                .with_context(|| format!("parse Aerion user id {}", snapshot.user_id))?;
            let previous = last.entry(snapshot.user_id).or_insert([0, 0]);
            let upload = snapshot.upload_bytes.saturating_sub(previous[0]);
            let download = snapshot.download_bytes.saturating_sub(previous[1]);
            previous[0] = snapshot.upload_bytes;
            previous[1] = snapshot.download_bytes;
            let counter = self.accounting.traffic_counter(uid);
            counter.record_upload(upload);
            counter.record_download(download);
        }
        last.retain(|uid, _| active.contains(uid));
        Ok(())
    }

    pub async fn snapshot_alive(&self) -> anyhow::Result<HashMap<i64, Vec<String>>> {
        let mut alive = HashMap::new();
        for snapshot in self.core.snapshot().await {
            if snapshot.online_ip_list.is_empty() {
                continue;
            }
            let uid = snapshot
                .user_id
                .parse::<i64>()
                .with_context(|| format!("parse Aerion user id {}", snapshot.user_id))?;
            let ips = snapshot
                .online_ip_list
                .into_iter()
                .map(normalize_ip)
                .collect::<Vec<_>>();
            alive.insert(uid, ips);
        }
        Ok(alive)
    }

    pub async fn shutdown(&self) {
        if let Err(error) = self.flush_traffic().await {
            error!(protocol = self.protocol.as_str(), %error, "flush Aerion traffic before shutdown failed");
        }
        self.stop().await;
        self.core.cancel_all_sessions();
    }

    async fn restart(&self) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let remote = self.remote.read().await.clone();
        let users = self.users.read().await.clone();
        let Some(remote) = remote else {
            return Ok(());
        };
        if users.is_empty() {
            self.stop_locked(&mut inner).await;
            return Ok(());
        }

        let config = build_server_config(self.protocol, &remote, &users).await?;
        self.stop_locked(&mut inner).await;
        *inner = Some(spawn_running_server(
            self.protocol,
            config,
            self.core.clone(),
        )?);
        info!(
            protocol = self.protocol.as_str(),
            "Aerion protocol runtime applied"
        );
        Ok(())
    }

    async fn stop(&self) {
        let mut inner = self.inner.lock().await;
        self.stop_locked(&mut inner).await;
    }

    async fn stop_locked(&self, inner: &mut Option<RunningServer>) {
        let old = inner.take();
        if let Some(old) = old {
            self.core.cancel_all_sessions();
            for handle in old.handles {
                handle.abort();
                if let Err(error) = handle.await
                    && !error.is_cancelled()
                {
                    error!(protocol = self.protocol.as_str(), %error, "Aerion server task join failed during stop");
                }
            }
        }
    }
}

fn spawn_running_server(
    protocol: ProtocolKind,
    config: BuiltServerConfig,
    core: ::aerion::core::ProxyCore,
) -> anyhow::Result<RunningServer> {
    let handles = match config {
        BuiltServerConfig::Anytls(config) => {
            let listeners =
                bind_listeners(&config.listen.ip().to_string(), config.listen.port())
                    .with_context(|| format!("bind Aerion AnyTLS server on {}", config.listen))?;
            listeners
                .into_iter()
                .map(|listener| {
                    let config = config.clone();
                    let core = core.clone();
                    spawn_aerion_task(protocol, async move {
                        ::aerion::run_server_listener_with_core(listener, config, core).await
                    })
                })
                .collect()
        }
        BuiltServerConfig::Hysteria2(config) => {
            let sockets = bind_udp_sockets(&config.listen.ip().to_string(), config.listen.port())
                .with_context(|| {
                format!("bind Aerion Hysteria2 server on {}", config.listen)
            })?;
            let mut handles = Vec::new();
            for socket in sockets {
                let socket = socket
                    .into_std()
                    .context("convert Hysteria2 UDP socket to std")?;
                let config = config.clone();
                let core = core.clone();
                handles.push(spawn_aerion_task(protocol, async move {
                    ::aerion::run_hysteria2_server_socket_with_core(socket, config, core).await
                }));
            }
            handles
        }
        BuiltServerConfig::Mieru(config) => {
            if config.transport == ::aerion::MieruTransport::Udp {
                let sockets =
                    bind_udp_sockets(&config.listen.ip().to_string(), config.listen.port())
                        .with_context(|| {
                            format!("bind Aerion Mieru UDP server on {}", config.listen)
                        })?;
                sockets
                    .into_iter()
                    .map(|socket| {
                        let config = config.clone();
                        let core = core.clone();
                        spawn_aerion_task(protocol, async move {
                            ::aerion::run_mieru_packet_server_socket_with_core(socket, config, core)
                                .await
                        })
                    })
                    .collect()
            } else {
                let listeners =
                    bind_listeners(&config.listen.ip().to_string(), config.listen.port())
                        .with_context(|| {
                            format!("bind Aerion Mieru server on {}", config.listen)
                        })?;
                listeners
                    .into_iter()
                    .map(|listener| {
                        let config = config.clone();
                        let core = core.clone();
                        spawn_aerion_task(protocol, async move {
                            ::aerion::run_mieru_server_listener_with_core(listener, config, core)
                                .await
                        })
                    })
                    .collect()
            }
        }
        BuiltServerConfig::Naive(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_naive_server_with_core(config, core).await
        })],
        BuiltServerConfig::Trojan(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_trojan_server_with_core(config, core).await
        })],
        BuiltServerConfig::Tuic(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_tuic_server_with_core(config, core).await
        })],
        BuiltServerConfig::Vless(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_vless_server_with_core(config, core).await
        })],
        BuiltServerConfig::Vmess(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_vmess_server_with_core(config, core).await
        })],
    };
    Ok(RunningServer { handles })
}

fn spawn_aerion_task<F>(protocol: ProtocolKind, future: F) -> JoinHandle<()>
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = future.await {
            error!(protocol = protocol.as_str(), %error, "Aerion server exited");
        }
    })
}

async fn build_server_config(
    protocol: ProtocolKind,
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    match protocol {
        ProtocolKind::Anytls => build_anytls_config(remote, users).await,
        ProtocolKind::Hysteria2 => build_hysteria2_config(remote, users).await,
        ProtocolKind::Mieru => build_mieru_config(remote, users),
        ProtocolKind::Naive => build_naive_config(remote, users).await,
        ProtocolKind::Trojan => build_trojan_config(remote, users).await,
        ProtocolKind::Tuic => build_tuic_config(remote, users).await,
        ProtocolKind::Vless => build_vless_config(remote, users).await,
        ProtocolKind::Vmess => build_vmess_config(remote, users).await,
        ProtocolKind::Shadowsocks => bail!("Shadowsocks is not handled by Aerion controller"),
    }
}

async fn build_anytls_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    require_tcp_network(remote, "AnyTLS")?;
    let tls = tls_config(remote)?;
    ensure!(
        tls.reality.is_none(),
        "REALITY settings are not valid for AnyTLS nodes"
    );
    ensure!(
        tls.alpn.is_empty(),
        "Aerion AnyTLS server does not expose server ALPN configuration"
    );
    let identity = aerion_tls_identity(&tls, "AnyTLS").await?;
    Ok(BuiltServerConfig::Anytls(::aerion::ServerConfig {
        listen: listen_addr(remote)?,
        password: String::new(),
        users: credentials_for_server(ProtocolKind::Anytls, users)?,
        cert_path: identity.cert_path,
        key_path: identity.key_path,
        certificates: identity.certificates,
        key: identity.key,
        padding_scheme: if remote.padding_scheme.is_empty() {
            ::aerion::padding::PaddingScheme::default_lines()
        } else {
            remote.padding_scheme.clone()
        },
        heartbeat_interval_secs: heartbeat_interval_secs(remote)?,
        ech: aerion_ech_keys(&tls, false)?,
    }))
}

async fn build_hysteria2_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_hysteria2_remote(remote)?;
    let tls = tls_config(remote)?;
    ensure!(
        tls.reality.is_none(),
        "HY2 does not support REALITY TLS mode"
    );
    let identity = aerion_tls_identity(&tls, "Hysteria2").await?;
    let (obfs, obfs_password) = hysteria2_obfs(remote)?;
    Ok(BuiltServerConfig::Hysteria2(
        ::aerion::Hysteria2ServerConfig {
            listen: listen_addr(remote)?,
            password: String::new(),
            users: credentials_for_server(ProtocolKind::Hysteria2, users)?,
            cert_path: identity.cert_path,
            key_path: identity.key_path,
            certificates: identity.certificates,
            key: identity.key,
            obfs,
            obfs_password,
            upload_bandwidth: remote.up_mbps.as_ref().map(value_to_u64).transpose()?,
            udp: hysteria2_udp_enabled(&remote.udp_relay_mode),
            cc_rx: hysteria2_cc_rx(remote.up_mbps.as_ref(), remote.ignore_client_bandwidth)?,
            congestion_control: remote.congestion_control.clone(),
        },
    ))
}

fn build_mieru_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    let users = users
        .iter()
        .map(|user| {
            let identity = mieru_identity(user).ok_or_else(|| {
                anyhow::anyhow!("Mieru user {} is missing password/uuid", user.id)
            })?;
            Ok(::aerion::MieruUser::password(identity, identity))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(BuiltServerConfig::Mieru(::aerion::MieruServerConfig {
        listen: listen_addr(remote)?,
        username: String::new(),
        password: String::new(),
        users,
        mtu: 0,
        user_hint_mandatory: false,
        transport: mieru_transport(remote.transport.as_ref())?,
        traffic_pattern: mieru_traffic_pattern(remote)?,
    }))
}

async fn build_naive_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_naive_remote(remote)?;
    let tls = tls_config(remote)?;
    ensure!(
        tls.reality.is_none(),
        "REALITY settings are not valid for Naive nodes"
    );
    let identity = aerion_tls_identity(&tls, "Naive").await?;
    let (primary, extra) = split_primary(credentials_for_server(ProtocolKind::Naive, users)?)?;
    let (username, password) = primary
        .split_once(':')
        .with_context(|| format!("Naive primary credential must be username:password"))?;
    Ok(BuiltServerConfig::Naive(::aerion::NaiveServerConfig {
        listen: listen_addr(remote)?,
        username: username.to_string(),
        password: password.to_string(),
        users: extra,
        cert_path: identity.cert_path,
        key_path: identity.key_path,
        certificates: identity.certificates,
        key: identity.key,
        udp_over_tcp: !is_disabled(&remote.udp_relay_mode),
        tcp: true,
        quic: naive_quic_enabled(remote)?,
        quic_congestion_control: if remote.congestion_control.trim().is_empty() {
            ::aerion::naive::default_naive_quic_congestion_control()
        } else {
            remote.congestion_control.clone()
        },
    }))
}

async fn build_trojan_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_trojan_remote(remote)?;
    let transport = vless_transport(remote)?;
    let tls = tls_config(remote)?;
    ensure!(
        tls.reality.is_none(),
        "Aerion Trojan server does not support REALITY TLS mode"
    );
    let identity = aerion_tls_identity(&tls, "Trojan").await?;
    Ok(BuiltServerConfig::Trojan(::aerion::TrojanServerConfig {
        listen: listen_addr(remote)?,
        password: String::new(),
        users: credentials_for_server(ProtocolKind::Trojan, users)?,
        cert_path: identity.cert_path,
        key_path: identity.key_path,
        certificates: identity.certificates,
        key: identity.key,
        transport,
        ech: aerion_ech_keys(&tls, false)?,
    }))
}

async fn build_tuic_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_tuic_remote(remote)?;
    let tls = tls_config(remote)?;
    ensure!(
        tls.reality.is_none(),
        "TUIC does not support REALITY TLS mode"
    );
    let identity = aerion_tls_identity(&tls, "TUIC").await?;
    let users = users
        .iter()
        .map(|user| {
            let uuid = user.uuid.trim();
            let password = user.password.trim();
            ensure!(!uuid.is_empty(), "TUIC user {} is missing uuid", user.id);
            ensure!(
                !password.is_empty(),
                "TUIC user {} is missing password",
                user.id
            );
            Ok(format!("{uuid}:{password}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(BuiltServerConfig::Tuic(::aerion::TuicServerConfig {
        listen: listen_addr(remote)?,
        uuid: String::new(),
        password: String::new(),
        users,
        cert_path: identity.cert_path,
        key_path: identity.key_path,
        certificates: identity.certificates,
        key: identity.key,
        udp: !is_disabled(&remote.udp_relay_mode),
        congestion_control: remote.congestion_control.clone(),
        alpn_protocols: remote.alpn.clone(),
        heartbeat_interval_secs: heartbeat_interval_secs(remote)?,
    }))
}

async fn build_vless_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_vless_remote(remote)?;
    let credentials = credentials_for_server(ProtocolKind::Vless, users)?;
    let (user_id, rest) = split_primary(credentials)?;
    let transport = vless_transport(remote)?;
    let tls = if vless_tls_enabled(remote) {
        Some(tls_config(remote)?)
    } else {
        None
    };
    let (cert_path, key_path, certificates, key, reality) = match tls.as_ref() {
        Some(tls) if tls.reality.is_some() => (
            PathBuf::new(),
            PathBuf::new(),
            Vec::new(),
            None,
            Some(reality_config(tls, &transport)?),
        ),
        Some(tls) => {
            let identity = aerion_tls_identity(tls, "VLESS").await?;
            (
                identity.cert_path,
                identity.key_path,
                identity.certificates,
                identity.key,
                None,
            )
        }
        None => (PathBuf::new(), PathBuf::new(), Vec::new(), None, None),
    };
    let has_reality = reality.is_some();
    Ok(BuiltServerConfig::Vless(::aerion::VlessServerConfig {
        listen: listen_addr(remote)?,
        user_id,
        users: rest,
        tls: tls.is_some() && !has_reality,
        cert_path,
        key_path,
        certificates,
        key,
        flow: remote.flow.trim().to_string(),
        reality,
        transport,
        ech: match tls.as_ref() {
            Some(tls) => aerion_ech_keys(tls, has_reality)?,
            None => None,
        },
    }))
}

async fn build_vmess_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_vmess_remote(remote, users)?;
    let credentials = credentials_for_server(ProtocolKind::Vmess, users)?;
    let (user_id, rest) = split_primary(credentials)?;
    let transport = vless_transport(remote)?;
    let tls = if remote.tls_mode() == 1 {
        Some(tls_config(remote)?)
    } else {
        None
    };
    let (cert_path, key_path, certificates, key) = if let Some(tls) = tls.as_ref() {
        let identity = aerion_tls_identity(&tls, "VMess").await?;
        (
            Some(identity.cert_path),
            Some(identity.key_path),
            identity.certificates,
            identity.key,
        )
    } else {
        (None, None, Vec::new(), None)
    };
    Ok(BuiltServerConfig::Vmess(::aerion::VmessServerConfig {
        listen: listen_addr(remote)?,
        user_id,
        users: rest,
        tls: remote.tls_mode() == 1,
        cert_path,
        key_path,
        certificates,
        key,
        transport,
        ech: match tls.as_ref() {
            Some(tls) => aerion_ech_keys(tls, false)?,
            None => None,
        },
    }))
}

fn ensure_aerion_supported(
    protocol: ProtocolKind,
    remote: &NodeConfigResponse,
) -> anyhow::Result<()> {
    ensure_no_routing(remote, protocol.as_str())?;
    ensure_no_fallbacks(remote, protocol.as_str())?;
    Ok(())
}

fn ensure_no_routing(remote: &NodeConfigResponse, protocol: &str) -> anyhow::Result<()> {
    if !remote.routes.is_empty()
        || !remote.custom_outbounds.is_empty()
        || !remote.custom_routes.is_empty()
    {
        bail!(
            "Aerion {protocol} server does not support Xboard routing/custom outbounds/custom routes yet"
        );
    }
    Ok(())
}

fn ensure_no_fallbacks(remote: &NodeConfigResponse, protocol: &str) -> anyhow::Result<()> {
    if configured_value(remote.fallback.as_ref())
        || configured_value(remote.fallbacks.as_ref())
        || configured_value(remote.fallback_for_alpn.as_ref())
    {
        bail!("Aerion {protocol} server does not support Xboard fallback configuration yet");
    }
    Ok(())
}

fn require_tcp_network(remote: &NodeConfigResponse, protocol: &str) -> anyhow::Result<()> {
    let network = remote.network.trim().to_ascii_lowercase();
    ensure!(
        network.is_empty() || network == "tcp" || network == "raw",
        "Xboard network must be tcp/raw for {protocol} nodes"
    );
    ensure!(
        remote
            .network_settings
            .as_ref()
            .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
        "Xboard networkSettings is not supported by Aerion {protocol} server"
    );
    ensure!(
        remote
            .transport
            .as_ref()
            .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
        "Xboard transport extension is not supported by Aerion {protocol} server"
    );
    Ok(())
}

fn validate_hysteria2_remote(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    let network = remote.network.trim().to_ascii_lowercase();
    ensure!(
        network.is_empty() || matches!(network.as_str(), "udp" | "quic" | "hysteria2" | "hy2"),
        "HY2 network must be empty, udp, quic, hysteria2 or hy2"
    );
    ensure!(
        !remote.udp_over_stream,
        "HY2 udp_over_stream is not supported by Aerion server"
    );
    ensure!(
        !remote.multiplex_enabled(),
        "HY2 multiplex is not a server-side setting"
    );
    ensure!(
        !configured_value(remote.masquerade.as_ref()),
        "Aerion HY2 server does not support masquerade configuration yet"
    );
    if let Some(version) = &remote.version {
        let version = value_to_u64(version).context("parse HY2 version")?;
        ensure!(version == 2, "HY2 only supports hysteria version 2");
    }
    Ok(())
}

fn validate_naive_remote(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    let network = remote.network.trim().to_ascii_lowercase();
    ensure!(
        network.is_empty()
            || matches!(
                network.as_str(),
                "tcp" | "raw" | "http" | "https" | "h2" | "quic" | "h3" | "http3"
            ),
        "Naive network must be empty, tcp/raw/http/https/h2 or quic/h3/http3"
    );
    ensure!(
        !remote.multiplex_enabled(),
        "Naive multiplex is not a server-side setting"
    );
    ensure!(
        !remote.udp_over_stream,
        "Naive uses native UDP-over-TCP and does not support Xboard udp_over_stream"
    );
    ensure!(
        remote
            .network_settings
            .as_ref()
            .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
        "Xboard networkSettings is not supported by Aerion Naive server"
    );
    Ok(())
}

fn validate_trojan_remote(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    ensure!(
        !matches!(remote.tls_mode(), 2),
        "Aerion Trojan server does not support REALITY TLS mode"
    );
    ensure!(
        !remote.reality_settings.is_configured() && !remote.tls_settings.has_reality_key_material(),
        "REALITY settings are not supported for Trojan nodes"
    );
    Ok(())
}

fn validate_tuic_remote(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    let network = remote.network.trim().to_ascii_lowercase();
    ensure!(
        network.is_empty() || matches!(network.as_str(), "udp" | "quic" | "tuic"),
        "TUIC network must be empty, udp, quic or tuic"
    );
    ensure!(
        !remote.udp_over_stream,
        "TUIC udp_over_stream is not supported by Aerion server"
    );
    ensure!(
        !remote.multiplex_enabled(),
        "TUIC multiplex is not a server-side setting"
    );
    Ok(())
}

fn validate_vless_remote(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !matches!(remote.tls_mode(), 0 | 1 | 2) {
        bail!(
            "Xboard tls mode {} is not supported for VLESS nodes",
            remote.tls_mode()
        );
    }
    if remote.tls_mode() == 0 && remote.tls_settings.is_configured() {
        bail!("Xboard tls_settings requires tls mode 1 or 2 for VLESS nodes");
    }
    let packet_encoding = remote.packet_encoding.trim();
    ensure!(
        packet_encoding.is_empty()
            || packet_encoding.eq_ignore_ascii_case("none")
            || packet_encoding.eq_ignore_ascii_case("xudp"),
        "unsupported VLESS packet_encoding {packet_encoding}"
    );
    if !remote.decryption.trim().is_empty() && !remote.decryption.eq_ignore_ascii_case("none") {
        bail!("Xboard decryption is not supported for VLESS nodes");
    }
    Ok(())
}

fn validate_vmess_remote(remote: &NodeConfigResponse, users: &[PanelUser]) -> anyhow::Result<()> {
    if !matches!(remote.tls_mode(), 0 | 1) {
        bail!(
            "Xboard tls mode {} is not supported for VMess nodes",
            remote.tls_mode()
        );
    }
    if remote.reality_settings.is_configured() || remote.tls_settings.has_reality_key_material() {
        bail!("REALITY settings are not supported for VMess nodes");
    }
    if remote.tls_mode() == 0 && remote.tls_settings.is_configured() {
        bail!("Xboard tls_settings requires tls mode 1 for VMess nodes");
    }
    for user in users {
        ensure!(
            user.alter_id <= 0,
            "VMess alterId > 0 is not supported for user {}",
            user.id
        );
    }
    Ok(())
}

fn tls_config(remote: &NodeConfigResponse) -> anyhow::Result<EffectiveTlsConfig> {
    EffectiveTlsConfig::from_remote(remote)
}

async fn aerion_tls_identity(
    config: &EffectiveTlsConfig,
    protocol: &str,
) -> anyhow::Result<AerionTlsIdentity> {
    match &config.source {
        tls::TlsMaterialSource::Files {
            cert_path,
            key_path,
        } => Ok(AerionTlsIdentity {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            certificates: Vec::new(),
            key: None,
        }),
        tls::TlsMaterialSource::Acme {
            cert_path,
            key_path,
            config,
        } => {
            acme::ensure_certificate(config, cert_path, key_path)
                .await
                .context("ensure ACME certificate")?;
            Ok(AerionTlsIdentity {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                certificates: Vec::new(),
                key: None,
            })
        }
        tls::TlsMaterialSource::Inline { .. } | tls::TlsMaterialSource::SelfSigned { .. } => {
            let (cert_pem, key_pem) = tls::load_source_materials(&config.source).await?;
            Ok(AerionTlsIdentity {
                cert_path: PathBuf::new(),
                key_path: PathBuf::new(),
                certificates: vec![
                    String::from_utf8(cert_pem).with_context(|| {
                        format!("{protocol} certificate PEM is not valid UTF-8")
                    })?,
                ],
                key: Some(
                    String::from_utf8(key_pem).with_context(|| {
                        format!("{protocol} private key PEM is not valid UTF-8")
                    })?,
                ),
            })
        }
    }
}

fn reality_config(
    tls: &EffectiveTlsConfig,
    transport: &::aerion::vless_transport::VlessTransportConfig,
) -> anyhow::Result<::aerion::RealityServerConfig> {
    let Some(reality) = tls.reality.as_ref() else {
        bail!("VLESS REALITY config is missing");
    };
    Ok(::aerion::RealityServerConfig {
        server_name: reality.server_name.clone(),
        server_port: reality.server_port,
        server_names: reality.server_names.clone(),
        private_key: reality.private_key,
        short_ids: reality.short_ids.clone(),
        alpn_protocols: transport.alpn_protocols(),
    })
}

fn core_users(
    protocol: ProtocolKind,
    users: &[PanelUser],
) -> anyhow::Result<Vec<::aerion::core::CoreUser>> {
    let mut entries = Vec::new();
    for user in users {
        for credential in credentials_for_user(protocol, user)? {
            let mut entry = ::aerion::core::CoreUser::password(user.id.to_string(), credential);
            let rate = speed_limit_bytes_per_second(user.speed_limit);
            entry.upload_limit_bps = rate;
            entry.download_limit_bps = rate;
            entry.max_online_ips = u64::try_from(user.device_limit)
                .ok()
                .filter(|limit| *limit > 0);
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn credentials_for_server(
    protocol: ProtocolKind,
    users: &[PanelUser],
) -> anyhow::Result<Vec<String>> {
    let mut credentials = Vec::new();
    for user in users {
        credentials.extend(credentials_for_user(protocol, user)?);
    }
    Ok(credentials)
}

fn credentials_for_user(protocol: ProtocolKind, user: &PanelUser) -> anyhow::Result<Vec<String>> {
    let mut credentials = Vec::new();
    match protocol {
        ProtocolKind::Anytls | ProtocolKind::Vless | ProtocolKind::Vmess => {
            let uuid = user.uuid.trim();
            ensure!(
                !uuid.is_empty(),
                "{} user {} is missing uuid",
                protocol.as_str(),
                user.id
            );
            credentials.push(uuid.to_string());
        }
        ProtocolKind::Hysteria2 => {
            push_unique_credential(&mut credentials, user.password.trim());
            push_unique_credential(&mut credentials, user.uuid.trim());
            ensure!(
                !credentials.is_empty(),
                "HY2 user {} is missing password/uuid",
                user.id
            );
        }
        ProtocolKind::Mieru => {
            let identity = mieru_identity(user).ok_or_else(|| {
                anyhow::anyhow!("Mieru user {} is missing password/uuid", user.id)
            })?;
            credentials.push(identity.to_string());
        }
        ProtocolKind::Naive => {
            credentials.push(naive_credential(user)?);
        }
        ProtocolKind::Trojan => {
            let credential = trojan_password(user).ok_or_else(|| {
                anyhow::anyhow!("Trojan user {} is missing password/uuid", user.id)
            })?;
            credentials.push(credential.to_string());
        }
        ProtocolKind::Tuic => {
            let uuid = user.uuid.trim();
            ensure!(!uuid.is_empty(), "TUIC user {} is missing uuid", user.id);
            credentials.push(uuid.to_string());
        }
        ProtocolKind::Shadowsocks => bail!("Shadowsocks users are not mapped to Aerion"),
    }
    Ok(credentials)
}

fn push_unique_credential(credentials: &mut Vec<String>, value: &str) {
    if !value.is_empty() && !credentials.iter().any(|credential| credential == value) {
        credentials.push(value.to_string());
    }
}

fn split_primary(mut credentials: Vec<String>) -> anyhow::Result<(String, Vec<String>)> {
    ensure!(
        !credentials.is_empty(),
        "Aerion server requires at least one user credential"
    );
    let first = credentials.remove(0);
    Ok((first, credentials))
}

fn trojan_password(user: &PanelUser) -> Option<&str> {
    let password = user.password.trim();
    if password.is_empty() {
        let uuid = user.uuid.trim();
        (!uuid.is_empty()).then_some(uuid)
    } else {
        Some(password)
    }
}

fn mieru_identity(user: &PanelUser) -> Option<&str> {
    let uuid = user.uuid.trim();
    if uuid.is_empty() {
        let password = user.password.trim();
        (!password.is_empty()).then_some(password)
    } else {
        Some(uuid)
    }
}

fn naive_credential(user: &PanelUser) -> anyhow::Result<String> {
    let username = user.uuid.trim();
    let username = if username.is_empty() {
        user.id.to_string()
    } else {
        username.to_string()
    };
    let password = user.password.trim();
    let password = if password.is_empty() {
        user.uuid.trim()
    } else {
        password
    };
    ensure!(
        !password.is_empty(),
        "Naive user {} is missing password/uuid",
        user.id
    );
    Ok(format!("{username}:{password}"))
}

fn vless_transport(
    remote: &NodeConfigResponse,
) -> anyhow::Result<::aerion::vless_transport::VlessTransportConfig> {
    let object = remote.network_settings.as_ref().and_then(Value::as_object);
    let path = string_field(object, &["path"]);
    let host = string_field(object, &["host", "Host"]).or_else(|| header_value(object, "host"));
    let headers = headers(object);
    let network = remote.network.trim();
    let normalized = network.to_ascii_lowercase().replace(['-', '_'], "");
    match normalized.as_str() {
        "xhttp" | "splithttp" => ::aerion::vless_transport::VlessTransportConfig::xhttp(
            path,
            host,
            headers,
            string_field(object, &["mode"]),
        ),
        _ => {
            let service_name = string_field(object, &["serviceName", "service_name"]);
            let path = if normalized == "grpc" {
                service_name
            } else {
                path
            };
            ::aerion::vless_transport::VlessTransportConfig::from_network(
                network, path, host, headers,
            )
        }
    }
}

fn string_field(object: Option<&Map<String, Value>>, names: &[&str]) -> Option<String> {
    let object = object?;
    for name in names {
        if let Some(value) = object.get(*name).and_then(value_to_string) {
            return Some(value);
        }
    }
    None
}

fn headers(object: Option<&Map<String, Value>>) -> Vec<(String, String)> {
    let Some(headers) = object
        .and_then(|object| object.get("headers"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    headers
        .iter()
        .filter_map(|(key, value)| value_to_string(value).map(|value| (key.clone(), value)))
        .collect()
}

fn header_value(object: Option<&Map<String, Value>>, name: &str) -> Option<String> {
    headers(object)
        .into_iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_string()).filter(|text| !text.is_empty()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn listen_addr(remote: &NodeConfigResponse) -> anyhow::Result<SocketAddr> {
    let ip = effective_listen_ip(remote)
        .parse::<IpAddr>()
        .with_context(|| format!("parse listen_ip {}", effective_listen_ip(remote)))?;
    Ok(SocketAddr::new(ip, remote.server_port))
}

fn heartbeat_interval_secs(remote: &NodeConfigResponse) -> anyhow::Result<u64> {
    let heartbeat = remote.heartbeat.trim();
    if heartbeat.is_empty() {
        return Ok(::aerion::config::default_heartbeat_interval_secs());
    }
    heartbeat
        .parse::<u64>()
        .context("parse heartbeat interval seconds")
}

fn hysteria2_obfs(remote: &NodeConfigResponse) -> anyhow::Result<(Option<String>, Option<String>)> {
    let xboard_obfs = remote.is_obfs;
    let Some(obfs) = remote.obfs.as_ref() else {
        if xboard_obfs {
            let mut password = remote.obfs_password.trim();
            if password.is_empty() {
                password = remote.server_key.trim();
            }
            ensure!(
                !password.is_empty(),
                "HY2 salamander obfs password is required"
            );
            return Ok((Some("salamander".to_string()), Some(password.to_string())));
        }
        ensure!(
            remote.obfs_password.trim().is_empty(),
            "HY2 obfs password requires salamander obfs"
        );
        return Ok((None, None));
    };
    if !crate::panel::json_value_is_enabled(obfs) {
        ensure!(!xboard_obfs, "HY2 is_obfs requires salamander obfs");
        ensure!(
            remote.obfs_password.trim().is_empty(),
            "HY2 obfs password requires salamander obfs"
        );
        return Ok((None, None));
    }
    let obfs_type = match obfs {
        Value::String(text) => text.trim(),
        Value::Object(object) => object
            .get("type")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default(),
        _ => "",
    };
    ensure!(
        obfs_type.eq_ignore_ascii_case("salamander"),
        "HY2 obfs must be salamander"
    );
    let mut password = remote.obfs_password.trim();
    if password.is_empty() {
        password = remote.server_key.trim();
    }
    ensure!(
        !password.is_empty(),
        "HY2 salamander obfs password is required"
    );
    Ok((Some("salamander".to_string()), Some(password.to_string())))
}

fn hysteria2_udp_enabled(value: &str) -> bool {
    !is_disabled(value)
}

fn naive_quic_enabled(remote: &NodeConfigResponse) -> anyhow::Result<bool> {
    let network = remote.network.trim().to_ascii_lowercase();
    if matches!(network.as_str(), "quic" | "h3" | "http3") {
        return Ok(true);
    }
    if network.is_empty() || matches!(network.as_str(), "tcp" | "raw" | "http" | "https" | "h2") {
        return Ok(false);
    }
    bail!("unsupported Naive network {network}")
}

fn hysteria2_cc_rx(value: Option<&Value>, ignore_client_bandwidth: bool) -> anyhow::Result<String> {
    if ignore_client_bandwidth {
        return Ok("auto".to_string());
    }
    let Some(value) = value else {
        return Ok("0".to_string());
    };
    Ok(value_to_u64(value)?.saturating_mul(125_000).to_string())
}

fn mieru_transport(value: Option<&Value>) -> anyhow::Result<::aerion::MieruTransport> {
    if value.is_some_and(|value| !crate::panel::json_value_is_enabled(value)) {
        return Ok(::aerion::MieruTransport::Tcp);
    }
    match value {
        None | Some(Value::Null) => Ok(::aerion::MieruTransport::Tcp),
        Some(Value::String(text))
            if text.trim().is_empty() || text.trim().eq_ignore_ascii_case("tcp") =>
        {
            Ok(::aerion::MieruTransport::Tcp)
        }
        Some(Value::String(text)) if text.trim().eq_ignore_ascii_case("udp") => {
            Ok(::aerion::MieruTransport::Udp)
        }
        Some(Value::Object(object)) => match object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "tcp" => Ok(::aerion::MieruTransport::Tcp),
            "udp" => Ok(::aerion::MieruTransport::Udp),
            other => bail!("unsupported Mieru transport {other}"),
        },
        _ => bail!("unsupported Mieru transport"),
    }
}

fn mieru_traffic_pattern(
    remote: &NodeConfigResponse,
) -> anyhow::Result<Option<::aerion::MieruTrafficPattern>> {
    ::aerion::MieruTrafficPattern::parse_pair(
        Some(remote.traffic_pattern.trim()).filter(|value| !value.is_empty()),
        Some(remote.nonce_pattern.trim()).filter(|value| !value.is_empty()),
    )
    .context("parse Mieru traffic pattern")
}

fn value_to_u64(value: &Value) -> anyhow::Result<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .context("value must be a non-negative integer"),
        Value::String(text) => text.trim().parse::<u64>().context("parse decimal integer"),
        _ => bail!("value must be a number or decimal string"),
    }
}

fn configured_value(value: Option<&Value>) -> bool {
    value.is_some_and(crate::panel::json_value_is_enabled)
}

fn is_disabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "false" | "off" | "no" | "none" | "disabled"
    )
}

fn vless_tls_enabled(remote: &NodeConfigResponse) -> bool {
    remote.tls_mode() != 0 || remote.tls.is_none()
}

fn speed_limit_bytes_per_second(speed_limit: i64) -> Option<u64> {
    u64::try_from(speed_limit)
        .ok()
        .filter(|limit| *limit > 0)
        .map(|limit| limit.saturating_mul(125_000))
}

fn normalize_ip(ip: String) -> String {
    ip.trim_start_matches("::ffff:").to_string()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn builds_mieru_server_config() {
        let remote = NodeConfigResponse {
            listen_ip: "127.0.0.1".to_string(),
            server_port: 8964,
            network: "tcp".to_string(),
            ..Default::default()
        };
        let users = vec![PanelUser {
            id: 1001,
            uuid: "mieru-secret".to_string(),
            ..Default::default()
        }];

        let BuiltServerConfig::Mieru(config) =
            build_mieru_config(&remote, &users).expect("build Mieru config")
        else {
            panic!("expected Mieru config");
        };
        assert_eq!(config.listen, "127.0.0.1:8964".parse().unwrap());
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].username, "mieru-secret");
        assert_eq!(config.users[0].password, "mieru-secret");
        assert_eq!(config.transport, ::aerion::MieruTransport::Tcp);
    }

    #[test]
    fn builds_mieru_server_config_ignores_xboard_tls_and_cert() {
        let remote = NodeConfigResponse {
            listen_ip: "127.0.0.1".to_string(),
            server_port: 8964,
            network: "ws".to_string(),
            network_settings: Some(json!({ "path": "/ignored" })),
            tls: Some(json!(1)),
            tls_settings: crate::panel::NodeTlsSettings {
                server_name: "tls.example.com".to_string(),
                allow_insecure: true,
                ..Default::default()
            },
            reality_settings: crate::panel::NodeRealitySettings {
                server_name: "reality.example.com".to_string(),
                private_key: "ignored".to_string(),
                ..Default::default()
            },
            multiplex: Some(json!({ "enabled": true })),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "acme".to_string(),
                domain: "tls.example.com".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let users = vec![PanelUser {
            id: 1001,
            uuid: "mieru-secret".to_string(),
            ..Default::default()
        }];

        let BuiltServerConfig::Mieru(config) =
            build_mieru_config(&remote, &users).expect("build Mieru config")
        else {
            panic!("expected Mieru config");
        };
        assert_eq!(config.listen, "127.0.0.1:8964".parse().unwrap());
        assert_eq!(config.users[0].username, "mieru-secret");
    }

    #[tokio::test]
    async fn builds_naive_server_config() {
        let remote = NodeConfigResponse {
            listen_ip: "127.0.0.1".to_string(),
            server_port: 8443,
            network: "quic".to_string(),
            server_name: "naive.example.com".to_string(),
            congestion_control: "cubic".to_string(),
            udp_relay_mode: "native".to_string(),
            ..Default::default()
        };
        let users = vec![
            PanelUser {
                id: 1001,
                uuid: "alice".to_string(),
                password: "alice-pass".to_string(),
                ..Default::default()
            },
            PanelUser {
                id: 1002,
                uuid: "bob".to_string(),
                password: "bob-pass".to_string(),
                ..Default::default()
            },
        ];

        let BuiltServerConfig::Naive(config) = build_naive_config(&remote, &users)
            .await
            .expect("build Naive config")
        else {
            panic!("expected Naive config");
        };
        assert_eq!(config.listen, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(config.username, "alice");
        assert_eq!(config.password, "alice-pass");
        assert_eq!(config.users, vec!["bob:bob-pass"]);
        assert!(config.udp_over_tcp);
        assert!(config.tcp);
        assert!(config.quic);
        assert_eq!(config.quic_congestion_control, "cubic");
    }

    #[tokio::test]
    async fn builds_naive_server_config_from_uuid_only_user() {
        let remote = NodeConfigResponse {
            listen_ip: "127.0.0.1".to_string(),
            server_port: 8443,
            server_name: "naive.example.com".to_string(),
            ..Default::default()
        };
        let users = vec![PanelUser {
            id: 1001,
            uuid: "uuid-secret".to_string(),
            ..Default::default()
        }];

        let BuiltServerConfig::Naive(config) = build_naive_config(&remote, &users)
            .await
            .expect("build Naive config")
        else {
            panic!("expected Naive config");
        };
        assert_eq!(config.username, "uuid-secret");
        assert_eq!(config.password, "uuid-secret");
    }

    #[tokio::test]
    async fn builds_hysteria2_server_config_from_xboard_obfs_fields() {
        let remote = NodeConfigResponse {
            listen_ip: "127.0.0.1".to_string(),
            server_port: 8444,
            network: "udp".to_string(),
            server_name: "hy2.example.com".to_string(),
            version: Some(json!(2)),
            up_mbps: Some(json!(100)),
            server_key: "xboard-obfs-secret".to_string(),
            is_obfs: true,
            congestion_control: "reno".to_string(),
            udp_relay_mode: "native".to_string(),
            ..Default::default()
        };
        let users = vec![PanelUser {
            id: 1001,
            uuid: "uuid-secret".to_string(),
            password: "password-secret".to_string(),
            ..Default::default()
        }];

        let BuiltServerConfig::Hysteria2(config) = build_hysteria2_config(&remote, &users)
            .await
            .expect("build Hysteria2 config")
        else {
            panic!("expected Hysteria2 config");
        };
        assert_eq!(config.listen, "127.0.0.1:8444".parse().unwrap());
        assert_eq!(config.users, vec!["password-secret", "uuid-secret"]);
        assert_eq!(config.obfs.as_deref(), Some("salamander"));
        assert_eq!(config.obfs_password.as_deref(), Some("xboard-obfs-secret"));
        assert_eq!(config.upload_bandwidth, Some(100));
        assert_eq!(config.cc_rx, "12500000");
        assert_eq!(config.congestion_control, "reno");
        assert!(config.udp);
        assert_eq!(config.cert_path, PathBuf::new());
        assert!(config.key.is_some());
        assert_eq!(config.certificates.len(), 1);
    }

    #[test]
    fn trojan_accepts_websocket_transport() {
        let remote = NodeConfigResponse {
            network: "ws".to_string(),
            network_settings: Some(json!({
                "path": "trojan",
                "headers": {
                    "Host": "trojan.example.com"
                }
            })),
            ..Default::default()
        };

        validate_trojan_remote(&remote).expect("validate Trojan transport");
        let transport = vless_transport(&remote).expect("parse Trojan transport");
        assert_eq!(
            transport.kind,
            ::aerion::vless_transport::VlessTransportKind::WebSocket
        );
        assert_eq!(transport.path, "/trojan");
        assert_eq!(transport.host.as_deref(), Some("trojan.example.com"));
    }
}
