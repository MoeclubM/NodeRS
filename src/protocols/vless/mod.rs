mod codec;
mod vision;
mod xudp;

use anyhow::{Context, anyhow, bail, ensure};
use boring::ssl::NameType;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use self::codec::Command;
use super::shared::{
    EffectiveTlsConfig, bind_listeners, configure_tcp_stream, effective_listen_ip, grpc, http1,
    http2, httpupgrade, mux, routing, socksaddr::SocksAddr, tls, traffic::TrafficRecorder,
    transport, ws, xhttp,
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const COPY_BUFFER_LEN: usize = 64 * 1024;
const HTTP2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

enum TlsStream {
    Plain(http1::PrefixedIo<TcpStream>),
    Boring(tokio_boring::SslStream<http1::PrefixedIo<TcpStream>>),
    Reality(super::shared::reality_tls::RealityTlsStream),
}

impl TlsStream {
    fn fallback_local_addr(&self) -> anyhow::Result<SocketAddr> {
        match self {
            Self::Plain(stream) => stream
                .get_ref()
                .local_addr()
                .context("read VLESS fallback local address"),
            Self::Boring(stream) => stream
                .get_ref()
                .get_ref()
                .local_addr()
                .context("read VLESS fallback local address"),
            Self::Reality(stream) => Ok(stream.local_addr()),
        }
    }

    fn fallback_server_name(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Boring(stream) => stream.ssl().servername(NameType::HOST_NAME),
            Self::Reality(stream) => stream.server_name(),
        }
    }

    fn selected_alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Plain(_) => None,
            Self::Boring(stream) => stream.ssl().selected_alpn_protocol(),
            Self::Reality(stream) => stream.selected_alpn_protocol(),
        }
    }

    fn fallback_alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Plain(_) => None,
            Self::Boring(stream) => stream.ssl().selected_alpn_protocol(),
            Self::Reality(stream) => stream.fallback_alpn_protocol(),
        }
    }
}

impl Unpin for TlsStream {}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Boring(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Reality(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Boring(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Reality(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Boring(stream) => Pin::new(stream).poll_flush(cx),
            Self::Reality(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Boring(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Reality(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
struct RealityServerState {
    config: tls::RealityTlsConfig,
    cert_state: Arc<super::shared::reality::RealityCertificateState>,
    alpn_protocols: Vec<Vec<u8>>,
}

struct ObservedRealityTarget {
    stream: TcpStream,
    server_hello: super::shared::reality::ObservedServerHello,
}

struct RealityHandshakeProfile {
    cipher_suite: u16,
    key_share_group: u16,
}

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: Option<EffectiveTlsConfig>,
    transport: TransportMode,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    pub routing: routing::RoutingTable,
    pub fallbacks: FallbackConfig,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let transport = parse_transport_mode(remote)?;
        let mut tls = vless_tls_enabled(remote)
            .then(|| EffectiveTlsConfig::from_remote(remote))
            .transpose()?;
        if let Some(tls) = tls.as_mut() {
            if matches!(transport, TransportMode::Grpc(_)) && tls.alpn.is_empty() {
                tls.alpn = default_grpc_alpn();
            }
            if matches!(transport, TransportMode::H2(_)) && tls.alpn.is_empty() {
                tls.alpn = default_h2_alpn();
            }
            if matches!(transport, TransportMode::Xhttp(_)) && tls.alpn.is_empty() {
                tls.alpn = default_xhttp_alpn();
            }
        }
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls,
            transport,
            packet_encoding: parse_packet_encoding(remote)?,
            flow: parse_flow_value(remote.flow.trim(), "Xboard flow")?,
            routing: routing::RoutingTable::from_remote(
                &remote.routes,
                &remote.custom_outbounds,
                &remote.custom_routes,
            )
            .context("compile Xboard routing")?,
            fallbacks: FallbackConfig::from_remote(remote)?,
        })
    }
}

fn default_xhttp_alpn() -> Vec<String> {
    vec!["http/1.1".to_string(), "h2".to_string()]
}

#[derive(Debug, Clone, PartialEq)]
enum TransportMode {
    Tcp,
    Grpc(grpc::GrpcConfig),
    H2(http2::H2Config),
    Ws(ws::WsConfig),
    HttpUpgrade(httpupgrade::HttpUpgradeConfig),
    Xhttp(xhttp::XhttpConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PacketEncoding {
    #[default]
    None,
    Xudp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FlowMode {
    #[default]
    None,
    XtlsRprxVision,
}

type PathFallbacks = HashMap<String, FallbackTarget>;
type AlpnFallbacks = HashMap<String, PathFallbacks>;

#[derive(Debug, Clone, Default)]
pub struct FallbackConfig {
    by_name: HashMap<String, AlpnFallbacks>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct FallbackTarget {
    #[serde(default)]
    server: String,
    #[serde(
        alias = "serverPort",
        deserialize_with = "crate::panel::deserialize_u16_from_number_or_string"
    )]
    server_port: u16,
    #[serde(default)]
    xver: u8,
}

impl FallbackConfig {
    fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        let mut config = Self::default();

        if let Some(value) = remote.fallbacks.as_ref() {
            config.merge_xboard_fallbacks(value)?;
        }

        let default = match remote.fallback.as_ref() {
            Some(value) => Some(parse_fallback_target(value).context("decode VLESS fallback")?),
            None => None,
        };
        if let Some(default) = default {
            config.insert_entry(ParsedFallbackEntry {
                name: None,
                alpn: None,
                path: None,
                target: default,
            });
        }

        let by_alpn = match remote.fallback_for_alpn.as_ref() {
            Some(value) => parse_fallback_map(value).context("decode VLESS fallback_for_alpn")?,
            None => HashMap::new(),
        };
        for (alpn, target) in by_alpn {
            config.insert_entry(ParsedFallbackEntry {
                name: None,
                alpn: Some(alpn),
                path: None,
                target,
            });
        }

        config.finalize();

        Ok(config)
    }

    fn select<'a>(
        &'a self,
        server_name: Option<&str>,
        alpn: Option<&[u8]>,
        first_packet: &[u8],
    ) -> Option<&'a FallbackTarget> {
        let name = server_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let apfb = self
            .select_name(&name)
            .and_then(|matched| self.by_name.get(matched))?;
        let pfb = alpn
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
            .and_then(|value| apfb.get(value))
            .or_else(|| apfb.get(""))?;
        if (pfb.len() > 1 || !pfb.contains_key(""))
            && let Some(path) = detect_http_path(first_packet)
            && let Some(target) = pfb.get(path.as_str())
        {
            return Some(target);
        }
        pfb.get("")
    }

    fn merge_xboard_fallbacks(&mut self, value: &serde_json::Value) -> anyhow::Result<()> {
        let entries = value
            .as_array()
            .ok_or_else(|| anyhow!("Xboard VLESS fallbacks must be an array"))?;
        for entry in entries {
            self.insert_entry(parse_xboard_fallback_entry(entry)?);
        }
        Ok(())
    }

    fn insert_entry(&mut self, entry: ParsedFallbackEntry) {
        let name = entry.name.unwrap_or_default();
        let alpn = entry.alpn.unwrap_or_default();
        let path = entry.path.unwrap_or_default();
        self.by_name
            .entry(name)
            .or_default()
            .entry(alpn)
            .or_default()
            .insert(path, entry.target);
    }

    fn finalize(&mut self) {
        let default_name = self.by_name.get("").cloned();
        if let Some(default_name_entries) = default_name.as_ref() {
            let default_alpns = default_name_entries.keys().cloned().collect::<Vec<_>>();
            for (name, apfb) in &mut self.by_name {
                if name.is_empty() {
                    continue;
                }
                for alpn in &default_alpns {
                    apfb.entry(alpn.clone()).or_default();
                }
            }
        }

        for apfb in self.by_name.values_mut() {
            let default_paths = apfb.get("").cloned();
            if let Some(default_paths) = default_paths {
                for (alpn, pfb) in apfb.iter_mut() {
                    if alpn.is_empty() {
                        continue;
                    }
                    for (path, target) in &default_paths {
                        pfb.entry(path.clone()).or_insert_with(|| target.clone());
                    }
                }
            }
        }

        if let Some(default_name_entries) = default_name {
            for (name, apfb) in &mut self.by_name {
                if name.is_empty() {
                    continue;
                }
                for (alpn, default_paths) in &default_name_entries {
                    let pfb = apfb.entry(alpn.clone()).or_default();
                    for (path, target) in default_paths {
                        pfb.entry(path.clone()).or_insert_with(|| target.clone());
                    }
                }
            }
        }
    }

    fn select_name<'a>(&'a self, server_name: &str) -> Option<&'a str> {
        if self.by_name.is_empty() {
            return None;
        }
        if let Some((name, _)) = self.by_name.get_key_value(server_name) {
            return Some(name.as_str());
        }

        let mut matched = None;
        for name in self.by_name.keys() {
            if name.is_empty() {
                continue;
            }
            if !server_name.is_empty()
                && server_name.contains(name.as_str())
                && matched.is_none_or(|current: &str| name.len() > current.len())
            {
                matched = Some(name.as_str());
            }
        }
        matched.or_else(|| self.by_name.contains_key("").then_some(""))
    }
}

#[derive(Debug, Clone)]
struct ParsedFallbackEntry {
    name: Option<String>,
    alpn: Option<String>,
    path: Option<String>,
    target: FallbackTarget,
}

#[derive(Debug, Clone, Default)]
struct UserValidator {
    by_uuid: HashMap<[u8; 16], UserEntry>,
}

impl UserValidator {
    fn from_users(users: &[PanelUser]) -> anyhow::Result<Self> {
        let mut by_uuid = HashMap::new();
        for user in users {
            let uuid = parse_uuid(user.uuid.trim())
                .with_context(|| format!("decode VLESS uuid for user {}", user.id))?;
            ensure!(
                by_uuid
                    .insert(uuid, UserEntry::from_panel_user(user))
                    .is_none(),
                "duplicate VLESS credentials for user {}",
                user.id
            );
        }
        Ok(Self { by_uuid })
    }

    fn get(&self, uuid: &[u8; 16]) -> Option<UserEntry> {
        self.by_uuid.get(uuid).cloned()
    }
}

pub struct ServerController {
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    reality: Arc<RwLock<Option<RealityServerState>>>,
    tls_materials: AsyncMutex<Option<tls::LoadedTlsMaterials>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    transport: Arc<RwLock<TransportMode>>,
    packet_encoding: Arc<RwLock<PacketEncoding>>,
    flow: Arc<RwLock<FlowMode>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    fallbacks: Arc<RwLock<FallbackConfig>>,
    inner: Mutex<Option<RunningServer>>,
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    handle: JoinHandle<()>,
}

impl ServerController {
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            tls_config: Arc::new(RwLock::new(None)),
            reality: Arc::new(RwLock::new(None)),
            tls_materials: AsyncMutex::new(None),
            accounting,
            users: Arc::new(RwLock::new(UserValidator::default())),
            transport: Arc::new(RwLock::new(TransportMode::Tcp)),
            packet_encoding: Arc::new(RwLock::new(PacketEncoding::None)),
            flow: Arc::new(RwLock::new(FlowMode::None)),
            routing: Arc::new(RwLock::new(routing::RoutingTable::default())),
            fallbacks: Arc::new(RwLock::new(FallbackConfig::default())),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        let validator = UserValidator::from_users(users)?;
        self.accounting.replace_users(users);
        *self.users.write().expect("vless users lock poisoned") = validator;
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        *self
            .transport
            .write()
            .expect("vless transport lock poisoned") = config.transport;
        *self
            .packet_encoding
            .write()
            .expect("vless packet encoding lock poisoned") = config.packet_encoding;
        *self.flow.write().expect("vless flow lock poisoned") = config.flow;
        *self.routing.write().expect("vless routing lock poisoned") = config.routing;
        *self
            .fallbacks
            .write()
            .expect("vless fallback lock poisoned") = config.fallbacks;
        self.update_tls_config(config.tls.as_ref()).await?;

        let old = {
            let mut guard = self.inner.lock().expect("vless server controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip || running.server_port != config.server_port
            });
            if !should_restart {
                return Ok(());
            }
            guard.take()
        };

        if let Some(old) = old {
            old.handle.abort();
        }

        let listeners = bind_listeners(&config.listen_ip, config.server_port)?;
        let bind_addrs = listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();
        let tls_config = self.tls_config.clone();
        let reality = self.reality.clone();
        let accounting = self.accounting.clone();
        let users = self.users.clone();
        let transport = self.transport.clone();
        let packet_encoding = self.packet_encoding.clone();
        let flow = self.flow.clone();
        let routing = self.routing.clone();
        let fallbacks = self.fallbacks.clone();
        let handle = tokio::spawn(async move {
            info!(listen = ?bind_addrs, "VLESS listeners started");
            let mut accept_loops = JoinSet::new();
            for listener in listeners {
                let tls_config = tls_config.clone();
                let reality = reality.clone();
                let accounting = accounting.clone();
                let users = users.clone();
                let transport = transport.clone();
                let packet_encoding = packet_encoding.clone();
                let flow = flow.clone();
                let routing = routing.clone();
                let fallbacks = fallbacks.clone();
                accept_loops.spawn(async move {
                    accept_loop(
                        listener,
                        tls_config,
                        reality,
                        accounting,
                        users,
                        transport,
                        packet_encoding,
                        flow,
                        routing,
                        fallbacks,
                    )
                    .await;
                });
            }

            while let Some(result) = accept_loops.join_next().await {
                match result {
                    Ok(()) => warn!("VLESS accept loop exited unexpectedly"),
                    Err(error) if error.is_cancelled() => break,
                    Err(error) => error!(%error, "VLESS accept loop crashed"),
                }
            }
        });

        let mut guard = self.inner.lock().expect("vless server controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            handle,
        });
        Ok(())
    }

    pub async fn refresh_tls(&self) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let Some(tls_materials) = tls_materials.as_mut() else {
            return Ok(());
        };
        if let Some(reloaded) = tls::reload_if_changed(tls_materials).await? {
            *self
                .tls_config
                .write()
                .expect("vless tls config lock poisoned") = Some(reloaded);
            info!("VLESS TLS materials reloaded from disk");
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self.inner.lock().expect("vless server controller poisoned");
            guard.take()
        };

        if let Some(old) = old {
            old.handle.abort();
            info!(port = old.server_port, "VLESS listeners stopped");
        }
    }

    async fn update_tls_config(&self, tls: Option<&EffectiveTlsConfig>) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let Some(tls) = tls else {
            *self
                .tls_config
                .write()
                .expect("vless tls config lock poisoned") = None;
            *self.reality.write().expect("vless reality lock poisoned") = None;
            *tls_materials = None;
            return Ok(());
        };
        let reality = tls.reality.as_ref().map(|reality| tls::RealityTlsConfig {
            server_name: reality.server_name.clone(),
            server_port: reality.server_port,
            server_names: reality.server_names.clone(),
            private_key: reality.private_key,
            short_ids: reality.short_ids.clone(),
        });
        let should_reload = tls_materials.as_ref().is_none_or(|current| {
            !current.matches_source(&tls.source, tls.ech.as_ref(), reality.as_ref(), &tls.alpn)
        });
        if !should_reload {
            return Ok(());
        }

        if let Some(reality) = tls.reality.as_ref() {
            let short_id_hex = reality
                .short_ids
                .first()
                .map(hex::encode)
                .unwrap_or_default();
            let short_id_tail = &short_id_hex[short_id_hex.len().saturating_sub(4)..];
            info!(
                reality_server_names = %reality.server_names.join(","),
                reality_short_id_count = reality.short_ids.len(),
                reality_short_id_tail = %short_id_tail,
                "applying VLESS REALITY TLS config"
            );
        }

        let reloaded =
            tls::load_tls_materials(&tls.source, tls.ech.as_ref(), reality.as_ref(), &tls.alpn)
                .await
                .context("load VLESS TLS materials")?;
        let reality_state = match reality {
            Some(config) => Some(RealityServerState {
                config,
                cert_state: Arc::new(
                    super::shared::reality::build_certificate_state()
                        .context("build VLESS REALITY certificate state")?,
                ),
                alpn_protocols: tls::parse_alpn_protocols(&tls.alpn)
                    .context("parse VLESS REALITY ALPN protocols")?,
            }),
            None => None,
        };
        *self
            .tls_config
            .write()
            .expect("vless tls config lock poisoned") = Some(reloaded.acceptor());
        *self.reality.write().expect("vless reality lock poisoned") = reality_state;
        *tls_materials = Some(reloaded);
        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    reality: Arc<RwLock<Option<RealityServerState>>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    transport: Arc<RwLock<TransportMode>>,
    packet_encoding: Arc<RwLock<PacketEncoding>>,
    flow: Arc<RwLock<FlowMode>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    fallbacks: Arc<RwLock<FallbackConfig>>,
) {
    let listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "accept VLESS connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let acceptor = {
            let tls_config = tls_config
                .read()
                .expect("vless tls config lock poisoned")
                .clone();
            tls_config
        };
        let reality = reality.read().expect("vless reality lock poisoned").clone();
        let accounting = accounting.clone();
        let users = users.clone();
        let transport = transport.clone();
        let packet_encoding = packet_encoding.clone();
        let flow = flow.clone();
        let routing = routing.clone();
        let fallbacks = fallbacks.clone();
        tokio::spawn(async move {
            let tls_stream = if let Some(reality) = reality {
                match accept_reality_tls(stream, source, &reality).await {
                    Ok(Some(stream)) => stream,
                    Ok(None) => return,
                    Err(error) => {
                        warn!(
                            error = %error,
                            error_chain = %format_args!("{error:#}"),
                            %source,
                            "VLESS REALITY handshake failed"
                        );
                        return;
                    }
                }
            } else if let Some(acceptor) = acceptor {
                match timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    tokio_boring::accept(
                        acceptor.as_ref(),
                        http1::PrefixedIo::new(stream, Vec::new()),
                    ),
                )
                .await
                {
                    Ok(Ok(stream)) => TlsStream::Boring(stream),
                    Ok(Err(error)) => {
                        warn!(%error, %source, "VLESS TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        warn!(%source, "VLESS TLS handshake timed out");
                        return;
                    }
                }
            } else {
                TlsStream::Plain(http1::PrefixedIo::new(stream, Vec::new()))
            };
            let users = users.read().expect("vless users lock poisoned").clone();
            let transport = transport
                .read()
                .expect("vless transport lock poisoned")
                .clone();
            let packet_encoding = *packet_encoding
                .read()
                .expect("vless packet encoding lock poisoned");
            let flow = *flow.read().expect("vless flow lock poisoned");
            let routing = routing.read().expect("vless routing lock poisoned").clone();
            let fallbacks = fallbacks
                .read()
                .expect("vless fallback lock poisoned")
                .clone();
            let result = match transport {
                TransportMode::Tcp => {
                    serve_connection(
                        tls_stream,
                        source,
                        accounting,
                        users,
                        packet_encoding,
                        flow,
                        routing,
                        fallbacks,
                    )
                    .await
                }
                TransportMode::Grpc(config) => {
                    serve_grpc_connection(
                        tls_stream,
                        source,
                        accounting,
                        users,
                        packet_encoding,
                        flow,
                        routing,
                        config,
                    )
                    .await
                }
                TransportMode::H2(config) => {
                    serve_h2_connection(
                        tls_stream,
                        source,
                        accounting,
                        users,
                        packet_encoding,
                        flow,
                        routing,
                        config,
                    )
                    .await
                }
                TransportMode::Ws(config) => {
                    serve_ws_connection(
                        tls_stream,
                        source,
                        accounting,
                        users,
                        packet_encoding,
                        flow,
                        routing,
                        config,
                    )
                    .await
                }
                TransportMode::HttpUpgrade(config) => {
                    serve_httpupgrade_connection(
                        tls_stream,
                        source,
                        accounting,
                        users,
                        packet_encoding,
                        flow,
                        routing,
                        config,
                    )
                    .await
                }
                TransportMode::Xhttp(config) => {
                    serve_xhttp_connection(
                        tls_stream,
                        source,
                        accounting,
                        users,
                        packet_encoding,
                        flow,
                        routing,
                        config,
                    )
                    .await
                }
            };
            if let Err(error) = result {
                warn!(%error, %source, "VLESS session terminated with error");
            }
        });
    }
}

async fn accept_reality_tls(
    mut stream: TcpStream,
    source: SocketAddr,
    reality: &RealityServerState,
) -> anyhow::Result<Option<TlsStream>> {
    let client_hello = timeout(
        TLS_HANDSHAKE_TIMEOUT,
        super::shared::reality::read_client_hello(&mut stream),
    )
    .await
    .map_err(|_| anyhow!("REALITY ClientHello timed out"))??;

    let authenticated =
        match super::shared::reality::authenticate_client_hello(&client_hello, &reality.config) {
            Ok(authenticated) => authenticated,
            Err(error) => {
                warn!(%error, %source, "VLESS REALITY ClientHello rejected; forwarding to target");
                proxy_reality_fallback(stream, reality, client_hello.prefix).await?;
                return Ok(None);
            }
        };

    let observed_target = match observe_reality_target(&client_hello.prefix, reality).await {
        Ok(observed) => observed,
        Err(error) => {
            warn!(
                %error,
                %source,
                "VLESS REALITY target handshake observation failed; forwarding to target"
            );
            proxy_reality_fallback(stream, reality, client_hello.prefix).await?;
            return Ok(None);
        }
    };

    let handshake_profile = match reality_handshake_profile(&observed_target.server_hello) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(
                %error,
                %source,
                "VLESS REALITY target handshake profile is unsupported; forwarding to target"
            );
            proxy_observed_reality_fallback(stream, observed_target, Vec::new()).await?;
            return Ok(None);
        }
    };

    let client_details = super::shared::reality::client_hello_details(&client_hello)
        .context("parse REALITY ClientHello details")?;

    let tls_stream = match super::shared::reality_tls::accept(
        stream,
        &client_hello,
        &client_details,
        &authenticated,
        &reality.cert_state,
        super::shared::reality_tls::RealityTlsProfile {
            cipher_suite: handshake_profile.cipher_suite,
            key_share_group: handshake_profile.key_share_group,
        },
        Some(&observed_target.server_hello),
        &reality.alpn_protocols,
        TLS_HANDSHAKE_TIMEOUT,
    )
    .await
    {
        Ok(stream) => TlsStream::Reality(stream),
        Err(error) => {
            let sent_server_flight = error.sent_server_flight();
            let (stream, error) = error.into_parts();
            if !sent_server_flight {
                warn!(
                    error = %error,
                    error_chain = %format_args!("{error:#}"),
                    %source,
                    "VLESS REALITY TLS handshake failed before server flight; forwarding to target"
                );
                proxy_observed_reality_fallback(stream, observed_target, Vec::new()).await?;
                return Ok(None);
            }
            warn!(
                error = %error,
                error_chain = %format_args!("{error:#}"),
                %source,
                "VLESS REALITY TLS handshake failed after server flight"
            );
            return Err(error.context("VLESS REALITY TLS handshake failed after server flight"));
        }
    };
    Ok(Some(tls_stream))
}

fn reality_handshake_profile(
    server_hello: &super::shared::reality::ObservedServerHello,
) -> anyhow::Result<RealityHandshakeProfile> {
    let Some(_curves_list) = server_hello.curves_list() else {
        bail!(
            "unsupported REALITY target key share group 0x{:04x}",
            server_hello.key_share_group
        );
    };
    ensure!(
        matches!(server_hello.cipher_suite, 0x1301 | 0x1302 | 0x1303),
        "unsupported REALITY target cipher suite 0x{:04x}",
        server_hello.cipher_suite
    );

    Ok(RealityHandshakeProfile {
        cipher_suite: server_hello.cipher_suite,
        key_share_group: server_hello.key_share_group,
    })
}

async fn observe_reality_target(
    client_hello_prefix: &[u8],
    reality: &RealityServerState,
) -> anyhow::Result<ObservedRealityTarget> {
    let mut target = timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TcpStream::connect((
            reality.config.server_name.as_str(),
            reality.config.server_port,
        )),
    )
    .await
    .map_err(|_| anyhow!("connect REALITY target timed out"))?
    .with_context(|| {
        format!(
            "connect REALITY target {}:{}",
            reality.config.server_name, reality.config.server_port
        )
    })?;
    configure_tcp_stream(&target);
    target
        .write_all(client_hello_prefix)
        .await
        .context("write REALITY target ClientHello")?;

    let observed = timeout(
        TLS_HANDSHAKE_TIMEOUT,
        super::shared::reality::read_server_hello(&mut target),
    )
    .await
    .map_err(|_| anyhow!("read REALITY target ServerHello timed out"))??;

    Ok(ObservedRealityTarget {
        stream: target,
        server_hello: observed,
    })
}

async fn proxy_observed_reality_fallback(
    stream: TcpStream,
    observed_target: ObservedRealityTarget,
    consumed_after_client_hello: Vec<u8>,
) -> anyhow::Result<()> {
    let control = SessionControl::new();
    let (mut client_reader, mut client_writer) = split(stream);
    let (mut target_reader, mut target_writer) = split(observed_target.stream);
    if !observed_target.server_hello.prefix.is_empty() {
        client_writer
            .write_all(&observed_target.server_hello.prefix)
            .await
            .context("write observed REALITY target ServerHello")?;
    }
    if !consumed_after_client_hello.is_empty() {
        target_writer
            .write_all(&consumed_after_client_hello)
            .await
            .context("write observed REALITY fallback client flight")?;
    }

    let client_to_target = copy_with_traffic(
        &mut client_reader,
        &mut target_writer,
        control.clone(),
        None,
    );
    let target_to_client = copy_with_traffic(&mut target_reader, &mut client_writer, control, None);
    let _ = tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

async fn proxy_reality_fallback(
    stream: TcpStream,
    reality: &RealityServerState,
    consumed: Vec<u8>,
) -> anyhow::Result<()> {
    let fallback = timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TcpStream::connect((
            reality.config.server_name.as_str(),
            reality.config.server_port,
        )),
    )
    .await
    .map_err(|_| anyhow!("connect REALITY fallback target timed out"))?
    .with_context(|| {
        format!(
            "connect REALITY fallback {}:{}",
            reality.config.server_name, reality.config.server_port
        )
    })?;
    configure_tcp_stream(&fallback);
    let control = SessionControl::new();
    let (mut client_reader, mut client_writer) = split(stream);
    let (mut fallback_reader, mut fallback_writer) = split(fallback);
    if !consumed.is_empty() {
        fallback_writer
            .write_all(&consumed)
            .await
            .context("write REALITY fallback client hello")?;
    }

    let client_to_fallback = copy_with_traffic(
        &mut client_reader,
        &mut fallback_writer,
        control.clone(),
        None,
    );
    let fallback_to_client =
        copy_with_traffic(&mut fallback_reader, &mut client_writer, control, None);
    let _ = tokio::try_join!(client_to_fallback, fallback_to_client)?;
    Ok(())
}

struct FallbackContext {
    local_addr: SocketAddr,
    server_name: Option<String>,
    alpn: Option<Vec<u8>>,
    first_packet: Vec<u8>,
}

async fn prefetch_first_packet<S>(stream: &mut S) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; 8192];
    match tokio::time::timeout(REQUEST_HEADER_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(0)) => Ok(Vec::new()),
        Ok(Ok(read)) => {
            buffer.truncate(read);
            Ok(buffer)
        }
        Ok(Err(error)) => Err(error).context("read VLESS fallback preface"),
        Err(_) => Ok(Vec::new()),
    }
}

async fn prefetch_prefixed_stream<S>(
    mut stream: S,
) -> anyhow::Result<(Vec<u8>, http1::PrefixedIo<S>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first_packet = prefetch_first_packet(&mut stream).await?;
    let replay = first_packet.clone();
    Ok((first_packet, http1::PrefixedIo::new(stream, replay)))
}

async fn prepare_fallback_stream(
    stream: TlsStream,
) -> anyhow::Result<(FallbackContext, http1::PrefixedIo<TlsStream>)> {
    let local_addr = stream.fallback_local_addr()?;
    let server_name = stream.fallback_server_name().map(str::to_string);
    let alpn = stream.fallback_alpn_protocol().map(|value| value.to_vec());
    let (first_packet, stream) = prefetch_prefixed_stream(stream).await?;
    Ok((
        FallbackContext {
            local_addr,
            server_name,
            alpn,
            first_packet,
        },
        stream,
    ))
}

fn detect_http_path(first_packet: &[u8]) -> Option<String> {
    if first_packet.len() < 18 || first_packet.get(4).copied() == Some(b'*') {
        return None;
    }
    for index in 4..=8.min(first_packet.len().saturating_sub(1)) {
        if first_packet[index] == b'/' && first_packet[index - 1] == b' ' {
            let search_end = first_packet.len().min(64);
            for end in (index + 1)..search_end {
                match first_packet[end] {
                    b'\r' | b'\n' => break,
                    b'?' | b' ' => {
                        return Some(String::from_utf8_lossy(&first_packet[index..end]).into());
                    }
                    _ => {}
                }
            }
            break;
        }
    }
    None
}

fn normalize_proxy_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(value) => value
            .ip()
            .to_ipv4()
            .map(|ip| SocketAddr::new(std::net::IpAddr::V4(ip), value.port()))
            .unwrap_or(SocketAddr::V6(value)),
        other => other,
    }
}

fn encode_proxy_header(source: SocketAddr, local: SocketAddr, xver: u8) -> anyhow::Result<Vec<u8>> {
    let source = normalize_proxy_addr(source);
    let local = normalize_proxy_addr(local);
    match xver {
        1 => Ok(match (source.ip(), local.ip()) {
            (std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(local_ip)) => format!(
                "PROXY TCP4 {source_ip} {local_ip} {} {}\r\n",
                source.port(),
                local.port()
            )
            .into_bytes(),
            (std::net::IpAddr::V6(source_ip), std::net::IpAddr::V6(local_ip)) => format!(
                "PROXY TCP6 {source_ip} {local_ip} {} {}\r\n",
                source.port(),
                local.port()
            )
            .into_bytes(),
            _ => b"PROXY UNKNOWN\r\n".to_vec(),
        }),
        2 => {
            let mut header = Vec::with_capacity(28);
            header.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0AQUIT\x0A");
            match (source.ip(), local.ip()) {
                (std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(local_ip)) => {
                    header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&local_ip.octets());
                }
                (std::net::IpAddr::V6(source_ip), std::net::IpAddr::V6(local_ip)) => {
                    header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&local_ip.octets());
                }
                _ => {
                    header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                    return Ok(header);
                }
            }
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&local.port().to_be_bytes());
            Ok(header)
        }
        other => bail!("unsupported VLESS fallback xver {other}"),
    }
}

async fn serve_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    fallbacks: FallbackConfig,
) -> anyhow::Result<()> {
    let (fallback, mut stream) = prepare_fallback_stream(stream).await?;
    if !fallback.first_packet.is_empty() && fallback.first_packet.len() < 18 {
        if let Some(target) = fallbacks.select(
            fallback.server_name.as_deref(),
            fallback.alpn.as_deref(),
            &fallback.first_packet,
        ) {
            proxy_fallback(stream, source, fallback.local_addr, target, Vec::new()).await?;
            return Ok(());
        }
    }
    let mut consumed = Vec::with_capacity(64);
    let request = match timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut consumed),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            if let Some(target) = fallbacks.select(
                fallback.server_name.as_deref(),
                fallback.alpn.as_deref(),
                &fallback.first_packet,
            ) {
                proxy_fallback(stream, source, fallback.local_addr, target, consumed).await?;
                return Ok(());
            }
            return Err(error);
        }
        Err(_) => {
            if let Some(target) = fallbacks.select(
                fallback.server_name.as_deref(),
                fallback.alpn.as_deref(),
                &fallback.first_packet,
            ) {
                proxy_fallback(stream, source, fallback.local_addr, target, consumed).await?;
                return Ok(());
            }
            return Err(anyhow!("VLESS request header timed out"));
        }
    };
    validate_request_addons(&request, flow)?;

    let user = match users.get(&request.user) {
        Some(user) => user,
        None => {
            if let Some(target) = fallbacks.select(
                fallback.server_name.as_deref(),
                fallback.alpn.as_deref(),
                &fallback.first_packet,
            ) {
                proxy_fallback(stream, source, fallback.local_addr, target, consumed).await?;
                return Ok(());
            }
            bail!("unknown VLESS user")
        }
    };

    let lease = accounting.open_session(&user, source)?;
    serve_authenticated_connection(
        stream,
        accounting,
        lease,
        user,
        request,
        packet_encoding,
        flow,
        routing,
    )
    .await
}

async fn serve_grpc_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: grpc::GrpcConfig,
) -> anyhow::Result<()> {
    let on_stream: Arc<dyn Fn(grpc::GrpcStream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let routing = routing.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_grpc_stream(
                stream,
                source,
                accounting,
                users,
                packet_encoding,
                flow,
                routing,
            )
            .await
            {
                warn!(%error, %source, "VLESS gRPC session terminated with error");
            }
        });
    });
    grpc::serve_h2(stream, config, on_stream).await
}

async fn serve_grpc_stream(
    mut stream: grpc::GrpcStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request, flow)?;
    let user = users
        .get(&request.user)
        .ok_or_else(|| anyhow!("unknown VLESS user"))?;
    let lease = accounting.open_session(&user, source)?;
    serve_authenticated_connection(
        stream,
        accounting,
        lease,
        user,
        request,
        packet_encoding,
        flow,
        routing,
    )
    .await
}

async fn serve_h2_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: http2::H2Config,
) -> anyhow::Result<()> {
    let on_stream: Arc<dyn Fn(http2::H2Stream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let routing = routing.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_h2_stream(
                stream,
                source,
                accounting,
                users,
                packet_encoding,
                flow,
                routing,
            )
            .await
            {
                warn!(%error, %source, "VLESS HTTP/2 session terminated with error");
            }
        });
    });
    http2::serve_h2(stream, config, on_stream).await
}

async fn serve_h2_stream(
    mut stream: http2::H2Stream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request, flow)?;
    let user = users
        .get(&request.user)
        .ok_or_else(|| anyhow!("unknown VLESS user"))?;
    let lease = accounting.open_session(&user, source)?;
    serve_authenticated_connection(
        stream,
        accounting,
        lease,
        user,
        request,
        packet_encoding,
        flow,
        routing,
    )
    .await
}

async fn serve_ws_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: ws::WsConfig,
) -> anyhow::Result<()> {
    let Some(mut stream) = ws::accept(stream, &config).await? else {
        return Ok(());
    };
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request, flow)?;
    let user = users
        .get(&request.user)
        .ok_or_else(|| anyhow!("unknown VLESS user"))?;
    let lease = accounting.open_session(&user, source)?;
    serve_authenticated_connection(
        stream,
        accounting,
        lease,
        user,
        request,
        packet_encoding,
        flow,
        routing,
    )
    .await
}

async fn serve_httpupgrade_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: httpupgrade::HttpUpgradeConfig,
) -> anyhow::Result<()> {
    let Some(mut stream) = httpupgrade::accept(stream, &config).await? else {
        return Ok(());
    };
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request, flow)?;
    let user = users
        .get(&request.user)
        .ok_or_else(|| anyhow!("unknown VLESS user"))?;
    let lease = accounting.open_session(&user, source)?;
    serve_authenticated_connection(
        stream,
        accounting,
        lease,
        user,
        request,
        packet_encoding,
        flow,
        routing,
    )
    .await
}

async fn serve_xhttp_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()> {
    let mut stream = http1::PrefixedIo::new(stream, Vec::new()).capture_inner_reads();
    let is_h2 = if stream.get_ref().selected_alpn_protocol() == Some(b"h2") {
        true
    } else {
        timeout(
            REQUEST_HEADER_TIMEOUT,
            sniff_http2_connection_preface(&mut stream),
        )
        .await
        .map_err(|_| anyhow!("XHTTP connection preface timed out"))??
    };
    let (stream, prefetched) = stream.into_parts();
    let stream = http1::PrefixedIo::new(stream, prefetched);
    if is_h2 {
        return serve_xhttp_h2_connection(
            stream,
            source,
            accounting,
            users,
            packet_encoding,
            flow,
            routing,
            config,
        )
        .await;
    }

    serve_xhttp_http1_connection(
        stream,
        source,
        accounting,
        users,
        packet_encoding,
        flow,
        routing,
        config,
    )
    .await
}

async fn serve_xhttp_http1_connection(
    mut stream: http1::PrefixedIo<TlsStream>,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()> {
    loop {
        let wrapped = xhttp::accept_prefixed(stream, &config).await?;
        match wrapped {
            xhttp::AcceptResult::Stream(stream) => {
                return serve_xhttp_stream(
                    stream,
                    source,
                    accounting,
                    users,
                    packet_encoding,
                    flow,
                    routing,
                )
                .await;
            }
            xhttp::AcceptResult::Responded(xhttp::ResponseState::Continue(next_stream)) => {
                stream = next_stream;
            }
            xhttp::AcceptResult::Responded(xhttp::ResponseState::Closed) => return Ok(()),
        }
    }
}

async fn serve_xhttp_h2_connection<S>(
    stream: S,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let on_stream: Arc<dyn Fn(xhttp::XhttpStream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let routing = routing.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_xhttp_stream(
                stream,
                source,
                accounting,
                users,
                packet_encoding,
                flow,
                routing,
            )
            .await
            {
                warn!(%error, %source, "VLESS XHTTP h2 session terminated with error");
            }
        });
    });
    xhttp::serve_h2(stream, config, on_stream).await
}

async fn sniff_http2_connection_preface<S>(
    stream: &mut http1::PrefixedIo<S>,
) -> anyhow::Result<bool>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = [0u8; HTTP2_CONNECTION_PREFACE.len()];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = stream
            .read(&mut bytes[offset..])
            .await
            .context("read XHTTP connection preface")?;
        if read == 0 {
            return Ok(false);
        }
        offset += read;
        if bytes[..offset] != HTTP2_CONNECTION_PREFACE[..offset] {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn serve_xhttp_stream(
    mut stream: xhttp::XhttpStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request, flow)?;
    let user = users
        .get(&request.user)
        .ok_or_else(|| anyhow!("unknown VLESS user"))?;
    let lease = accounting.open_session(&user, source)?;
    serve_authenticated_connection(
        stream,
        accounting,
        lease,
        user,
        request,
        packet_encoding,
        flow,
        routing,
    )
    .await
}

async fn serve_authenticated_connection<S>(
    stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    request: codec::Request,
    packet_encoding: PacketEncoding,
    flow: FlowMode,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match request.command {
        Command::Tcp => {
            serve_connect(
                stream,
                accounting,
                lease,
                user,
                request.user,
                flow,
                request.destination,
                routing,
            )
            .await
        }
        Command::Udp => {
            if packet_encoding == PacketEncoding::Xudp {
                serve_xudp(stream, accounting, lease, user, routing).await
            } else {
                serve_udp(
                    stream,
                    accounting,
                    lease,
                    user,
                    request.destination,
                    routing,
                )
                .await
            }
        }
        Command::Mux => {
            ensure!(
                request.destination
                    == SocksAddr::Domain(
                        codec::XUDP_MUX_DESTINATION.to_string(),
                        codec::XUDP_MUX_PORT
                    ),
                "unsupported VLESS mux destination {}",
                request.destination
            );
            serve_mux(stream, accounting, lease, user, routing).await
        }
    }
}

async fn serve_connect<S>(
    stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    request_user: [u8; 16],
    flow: FlowMode,
    destination: SocksAddr,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let remote = transport::connect_tcp_destination(&destination, &routing)
        .await
        .with_context(|| format!("connect VLESS destination {destination}"))?;
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);
    let (mut client_reader, mut client_writer) = split(stream);
    let (mut remote_reader, mut remote_writer) = split(remote);

    if flow == FlowMode::XtlsRprxVision {
        let mut vision_reader = vision::VisionReader::new(client_reader, request_user);
        let client_to_remote = copy_with_traffic(
            &mut vision_reader,
            &mut remote_writer,
            control.clone(),
            Some(upload),
        );
        let remote_to_client = copy_with_response_header(
            &mut remote_reader,
            &mut client_writer,
            control,
            download,
            flow,
            request_user,
        );
        let _ = tokio::try_join!(client_to_remote, remote_to_client)?;
    } else {
        let client_to_remote = copy_with_traffic(
            &mut client_reader,
            &mut remote_writer,
            control.clone(),
            Some(upload),
        );
        let remote_to_client = copy_with_response_header(
            &mut remote_reader,
            &mut client_writer,
            control,
            download,
            flow,
            request_user,
        );
        let _ = tokio::try_join!(client_to_remote, remote_to_client)?;
    }
    Ok(())
}

async fn copy_with_response_header<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
    flow: FlowMode,
    request_user: [u8; 16],
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![
        0u8;
        if flow == FlowMode::XtlsRprxVision {
            u16::MAX as usize
        } else {
            COPY_BUFFER_LEN
        }
    ];
    let mut total = 0u64;
    let read = tokio::select! {
        _ = control.cancelled() => return Ok(total),
        read = reader.read(&mut buffer) => match read {
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Err(error) => return Err(error).context("read proxied VLESS chunk"),
        },
    };
    if read == 0 {
        match writer.write_all(&codec::RESPONSE_HEADER).await {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(total);
            }
            Err(error) => return Err(error).context("write VLESS response header"),
        }
        let _ = writer.shutdown().await;
        return Ok(total);
    }

    traffic.limit(read as u64, &control).await;
    if control.is_cancelled() {
        return Ok(total);
    }
    tokio::select! {
        _ = control.cancelled() => return Ok(total),
        result = write_response_header_and_chunk(writer, flow, request_user, &buffer[..read]) => match result {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) => return Ok(total),
            Err(error) => return Err(error).context("write proxied VLESS chunk"),
        },
    }
    let transferred = read as u64;
    total += transferred;
    traffic.record(transferred);

    let remaining = copy_with_traffic(reader, writer, control, Some(traffic)).await?;
    Ok(total + remaining)
}

fn encode_response_header(
    flow: FlowMode,
    request_user: [u8; 16],
    chunk: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(codec::RESPONSE_HEADER.len() + chunk.len() + 21);
    response.extend_from_slice(&codec::RESPONSE_HEADER);
    if flow == FlowMode::XtlsRprxVision {
        response.extend_from_slice(&vision::encode_end_frame(&request_user, chunk)?);
    } else {
        response.extend_from_slice(chunk);
    }
    Ok(response)
}

async fn write_response_header_and_chunk<W>(
    writer: &mut W,
    flow: FlowMode,
    request_user: [u8; 16],
    chunk: &[u8],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if flow == FlowMode::XtlsRprxVision {
        let response = encode_response_header(flow, request_user, chunk)?;
        writer.write_all(&response).await?;
        return Ok(());
    }

    if writer.is_write_vectored() {
        let mut header_offset = 0usize;
        let mut chunk_offset = 0usize;
        while header_offset < codec::RESPONSE_HEADER.len() || chunk_offset < chunk.len() {
            let mut slices = [IoSlice::new(&[]), IoSlice::new(&[])];
            let mut count = 0usize;
            if header_offset < codec::RESPONSE_HEADER.len() {
                slices[count] = IoSlice::new(&codec::RESPONSE_HEADER[header_offset..]);
                count += 1;
            }
            if chunk_offset < chunk.len() {
                slices[count] = IoSlice::new(&chunk[chunk_offset..]);
                count += 1;
            }
            let written = writer.write_vectored(&slices[..count]).await?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            let header_remaining = codec::RESPONSE_HEADER.len() - header_offset;
            if written <= header_remaining {
                header_offset += written;
            } else {
                header_offset = codec::RESPONSE_HEADER.len();
                chunk_offset += written - header_remaining;
            }
        }
    } else {
        let mut buffer = Vec::with_capacity(codec::RESPONSE_HEADER.len() + chunk.len());
        buffer.extend_from_slice(&codec::RESPONSE_HEADER);
        buffer.extend_from_slice(chunk);
        writer.write_all(&buffer).await?;
    }
    Ok(())
}

async fn serve_udp<S>(
    stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    destination: SocksAddr,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = transport::resolve_destination(&destination, &routing, "udp")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no UDP addresses resolved for {destination}"))?;
    let socket = transport::bind_udp_socket().await?;
    let target = transport::normalize_udp_target(&socket, target);
    socket
        .connect(target)
        .await
        .with_context(|| format!("connect VLESS UDP target {target}"))?;

    let socket = Arc::new(socket);
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);
    let (reader, mut writer) = split(stream);
    codec::write_response_header(&mut writer).await?;
    let select_control = control.clone();

    let mut client_task = tokio::spawn({
        let socket = socket.clone();
        let control = control.clone();
        async move { relay_client_to_udp(reader, socket, control, upload).await }
    });
    let mut server_task =
        tokio::spawn(async move { relay_udp_to_client(writer, socket, control, download).await });

    tokio::select! {
        _ = select_control.cancelled() => {
            client_task.abort();
            server_task.abort();
            Ok(())
        }
        result = &mut client_task => {
            server_task.abort();
            flatten_join(result)
        }
        result = &mut server_task => {
            client_task.abort();
            flatten_join(result)
        }
    }
}

async fn serve_xudp<S>(
    mut stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    codec::write_response_header(&mut stream).await?;
    xudp::relay(
        stream,
        routing,
        lease.control(),
        TrafficRecorder::upload(accounting.clone(), user.id),
        TrafficRecorder::download(accounting, user.id),
    )
    .await
}

async fn serve_mux<S>(
    mut stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    codec::write_response_header(&mut stream).await?;
    mux::relay(
        stream,
        routing,
        lease.control(),
        TrafficRecorder::upload(accounting.clone(), user.id),
        TrafficRecorder::download(accounting, user.id),
    )
    .await
}

async fn proxy_fallback<S>(
    stream: S,
    source: SocketAddr,
    local: SocketAddr,
    target: &FallbackTarget,
    consumed: Vec<u8>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fallback = TcpStream::connect((target.server.as_str(), target.server_port))
        .await
        .with_context(|| {
            format!(
                "connect VLESS fallback {}:{}",
                target.server, target.server_port
            )
        })?;
    configure_tcp_stream(&fallback);
    let control = SessionControl::new();
    let (mut client_reader, mut client_writer) = split(stream);
    let (mut fallback_reader, mut fallback_writer) = split(fallback);
    if target.xver != 0 {
        let header = encode_proxy_header(source, local, target.xver)?;
        fallback_writer
            .write_all(&header)
            .await
            .context("write VLESS fallback proxy protocol header")?;
    }
    if !consumed.is_empty() {
        fallback_writer
            .write_all(&consumed)
            .await
            .context("write VLESS fallback preface")?;
    }

    let client_to_fallback = copy_with_traffic(
        &mut client_reader,
        &mut fallback_writer,
        control.clone(),
        None,
    );
    let fallback_to_client =
        copy_with_traffic(&mut fallback_reader, &mut client_writer, control, None);
    let _ = tokio::try_join!(client_to_fallback, fallback_to_client)?;
    Ok(())
}

async fn relay_client_to_udp<R>(
    mut reader: ReadHalf<R>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let frame = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            frame = codec::read_udp_frame(&mut reader) => frame?,
        };
        let Some(frame) = frame else {
            return Ok(());
        };

        traffic.limit(frame.wire_len as u64, &control).await;
        if control.is_cancelled() {
            return Ok(());
        }
        let sent = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            sent = socket.send(&frame.payload) => sent.context("send VLESS UDP payload")?,
        };
        ensure!(
            sent == frame.payload.len(),
            "short VLESS UDP send: expected {}, wrote {}",
            frame.payload.len(),
            sent
        );
        traffic.record(frame.wire_len as u64);
    }
}

async fn relay_udp_to_client<W>(
    mut writer: WriteHalf<W>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let payload_len = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = socket.recv(&mut buffer) => read.context("receive VLESS UDP payload")?,
        };
        let encoded = codec::encode_udp_frame(&buffer[..payload_len])?;
        traffic.limit(encoded.len() as u64, &control).await;
        if control.is_cancelled() {
            return Ok(());
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&encoded) => result.context("write VLESS UDP response")?,
        }
        traffic.record(encoded.len() as u64);
    }
}

async fn copy_with_traffic<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    traffic: Option<TrafficRecorder>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    let mut total = 0u64;
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer) => match read {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    let _ = writer.shutdown().await;
                    return Ok(total);
                }
                Err(error) => return Err(error).context("read proxied VLESS chunk"),
            },
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        if let Some(traffic) = traffic.as_ref() {
            traffic.limit(read as u64, &control).await;
            if control.is_cancelled() {
                return Ok(total);
            }
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => match result {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(total);
                }
                Err(error) => return Err(error).context("write proxied VLESS chunk"),
            },
        }
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
    }
}

fn flatten_join(result: Result<anyhow::Result<()>, tokio::task::JoinError>) -> anyhow::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error).context("join VLESS UDP relay task"),
    }
}

fn parse_transport_mode(remote: &NodeConfigResponse) -> anyhow::Result<TransportMode> {
    let network = remote.network.trim();
    if network.is_empty() || network.eq_ignore_ascii_case("tcp") {
        ensure!(
            remote
                .network_settings
                .as_ref()
                .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
            "Xboard networkSettings is only supported for VLESS grpc/ws/httpupgrade/xhttp nodes"
        );
        return Ok(TransportMode::Tcp);
    }
    if network.eq_ignore_ascii_case("grpc") {
        return Ok(TransportMode::Grpc(
            grpc::GrpcConfig::from_network_settings(remote.network_settings.as_ref())?,
        ));
    }
    if network.eq_ignore_ascii_case("h2") || network.eq_ignore_ascii_case("http") {
        return Ok(TransportMode::H2(http2::H2Config::from_network_settings(
            remote.network_settings.as_ref(),
        )?));
    }
    if network.eq_ignore_ascii_case("ws") {
        return Ok(TransportMode::Ws(ws::WsConfig::from_network_settings(
            remote.network_settings.as_ref(),
        )?));
    }
    if network.eq_ignore_ascii_case("httpupgrade") {
        return Ok(TransportMode::HttpUpgrade(
            httpupgrade::HttpUpgradeConfig::from_network_settings(
                remote.network_settings.as_ref(),
            )?,
        ));
    }
    if network.eq_ignore_ascii_case("xhttp") || network.eq_ignore_ascii_case("splithttp") {
        return Ok(TransportMode::Xhttp(
            xhttp::XhttpConfig::from_network_settings(remote.network_settings.as_ref())?,
        ));
    }
    bail!(
        "Xboard network must be tcp, grpc, h2, ws, httpupgrade, xhttp or splithttp for VLESS nodes"
    );
}

fn parse_packet_encoding(remote: &NodeConfigResponse) -> anyhow::Result<PacketEncoding> {
    let packet_encoding = remote.packet_encoding.trim();
    if packet_encoding.is_empty() || packet_encoding.eq_ignore_ascii_case("none") {
        return Ok(PacketEncoding::None);
    }
    if packet_encoding.eq_ignore_ascii_case("xudp") {
        return Ok(PacketEncoding::Xudp);
    }
    bail!("unsupported VLESS packet_encoding {packet_encoding}");
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    let transport_mode = parse_transport_mode(remote)?;
    parse_packet_encoding(remote)?;
    let flow = parse_flow_value(remote.flow.trim(), "Xboard flow")?;
    if remote.tls.is_some() && !matches!(remote.tls_mode(), 0 | 1 | 2) {
        bail!(
            "Xboard tls mode {} is not supported by NodeRS VLESS server yet",
            remote.tls_mode()
        );
    }
    if remote.tls_mode() != 2
        && (remote.reality_settings.is_configured()
            || remote.tls_settings.has_reality_key_material())
    {
        bail!("REALITY settings require tls mode 2 for VLESS nodes");
    }
    if let Some(transport) = remote.transport.as_ref() {
        validate_transport_field(transport, &transport_mode)?;
    }
    let decryption = remote.decryption.trim();
    if !decryption.is_empty() && !decryption.eq_ignore_ascii_case("none") {
        bail!("Xboard decryption must be none for VLESS nodes");
    }
    ensure!(
        flow != FlowMode::XtlsRprxVision || matches!(transport_mode, TransportMode::Tcp),
        "Xboard flow xtls-rprx-vision currently only supports VLESS tcp transport"
    );
    Ok(())
}

fn vless_tls_enabled(remote: &NodeConfigResponse) -> bool {
    remote.tls_mode() != 0 || remote.tls.is_none()
}

fn validate_transport_field(
    value: &serde_json::Value,
    transport_mode: &TransportMode,
) -> anyhow::Result<()> {
    if !crate::panel::json_value_is_enabled(value) {
        return Ok(());
    }

    let expected: &[&str] = match transport_mode {
        TransportMode::Tcp => &["tcp"],
        TransportMode::Grpc(_) => &["grpc"],
        TransportMode::H2(_) => &["h2", "http"],
        TransportMode::Ws(_) => &["ws"],
        TransportMode::HttpUpgrade(_) => &["httpupgrade"],
        TransportMode::Xhttp(_) => &["xhttp", "splithttp"],
    };

    let transport_type = match value {
        serde_json::Value::String(text) => text.trim(),
        serde_json::Value::Object(object) => object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .unwrap_or_default(),
        _ => {
            bail!("Xboard transport must be a string or object when provided");
        }
    };

    if expected
        .iter()
        .any(|expected| transport_type.eq_ignore_ascii_case(expected))
    {
        return Ok(());
    }

    bail!("Xboard transport is not supported by NodeRS VLESS server yet");
}

fn parse_fallback_map(
    value: &serde_json::Value,
) -> anyhow::Result<HashMap<String, FallbackTarget>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("VLESS fallback_for_alpn must be an object"))?;
    let mut targets = HashMap::new();
    for (alpn, value) in object {
        let key = alpn.trim().to_ascii_lowercase();
        ensure!(
            !key.is_empty(),
            "VLESS fallback_for_alpn contains empty ALPN"
        );
        ensure!(
            targets
                .insert(key.clone(), parse_fallback_target(value)?)
                .is_none(),
            "duplicate VLESS fallback_for_alpn entry {key}"
        );
    }
    Ok(targets)
}

fn parse_fallback_target(value: &serde_json::Value) -> anyhow::Result<FallbackTarget> {
    if let Some(object) = value.as_object()
        && let Some(dest) = object.get("dest")
    {
        let mut target = parse_xboard_fallback_dest(dest)?;
        target.xver = object
            .get("xver")
            .map(parse_u8_json)
            .transpose()?
            .unwrap_or(0);
        ensure!(target.xver <= 2, "VLESS fallback xver must be 0, 1 or 2");
        return Ok(target);
    }

    let target: FallbackTarget =
        serde_json::from_value(value.clone()).context("parse VLESS fallback target")?;
    ensure!(
        !target.server.trim().is_empty() && target.server_port > 0,
        "VLESS fallback target requires server and server_port"
    );
    ensure!(target.xver <= 2, "VLESS fallback xver must be 0, 1 or 2");
    Ok(target)
}

fn parse_xboard_fallback_entry(value: &serde_json::Value) -> anyhow::Result<ParsedFallbackEntry> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Xboard VLESS fallback entry must be an object"))?;

    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let path = object
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    ensure!(
        path.is_empty() || path.starts_with('/'),
        "Xboard VLESS fallback path must start with /"
    );

    let xver = object
        .get("xver")
        .map(parse_u8_json)
        .transpose()?
        .unwrap_or(0);
    ensure!(xver <= 2, "Xboard VLESS fallback xver must be 0, 1 or 2");

    let fallback_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    ensure!(
        fallback_type.is_empty() || fallback_type.eq_ignore_ascii_case("tcp"),
        "Xboard VLESS fallback type is not supported yet"
    );

    let dest = object
        .get("dest")
        .ok_or_else(|| anyhow!("Xboard VLESS fallback entry requires dest"))?;
    let mut target = parse_xboard_fallback_dest(dest)?;
    target.xver = xver;

    let alpn = object
        .get("alpn")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    Ok(ParsedFallbackEntry {
        name: (!name.is_empty()).then_some(name),
        alpn,
        path: (!path.is_empty()).then_some(path.to_string()),
        target,
    })
}

fn parse_u8_json(value: &serde_json::Value) -> anyhow::Result<u8> {
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| anyhow!("expected u8 number, got {value}")),
        serde_json::Value::String(text) => {
            text.trim().parse::<u8>().context("parse u8 string value")
        }
        _ => bail!("expected u8 number or decimal string, got {value}"),
    }
}

fn parse_xboard_fallback_dest(value: &serde_json::Value) -> anyhow::Result<FallbackTarget> {
    match value {
        serde_json::Value::Number(number) => {
            let port = number
                .as_u64()
                .ok_or_else(|| anyhow!("Xboard VLESS fallback dest must be a TCP port"))?;
            let server_port =
                u16::try_from(port).context("Xboard VLESS fallback port does not fit u16")?;
            ensure!(
                server_port > 0,
                "Xboard VLESS fallback port must be non-zero"
            );
            Ok(FallbackTarget {
                server: "127.0.0.1".to_string(),
                server_port,
                xver: 0,
            })
        }
        serde_json::Value::String(text) => {
            let compact = text.trim();
            ensure!(
                !compact.is_empty() && !compact.starts_with('/') && !compact.starts_with('@'),
                "Xboard VLESS fallback dest must be tcp host:port or port"
            );
            if compact.chars().all(|ch| ch.is_ascii_digit()) {
                let server_port = compact
                    .parse::<u16>()
                    .context("parse Xboard VLESS fallback port")?;
                ensure!(
                    server_port > 0,
                    "Xboard VLESS fallback port must be non-zero"
                );
                return Ok(FallbackTarget {
                    server: "127.0.0.1".to_string(),
                    server_port,
                    xver: 0,
                });
            }

            let (server, port) = compact
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("Xboard VLESS fallback dest must be tcp host:port"))?;
            ensure!(
                !server.trim().is_empty(),
                "Xboard VLESS fallback host is required"
            );
            let server_port = port
                .trim()
                .parse::<u16>()
                .context("parse Xboard VLESS fallback port")?;
            ensure!(
                server_port > 0,
                "Xboard VLESS fallback port must be non-zero"
            );
            Ok(FallbackTarget {
                server: server.trim().to_string(),
                server_port,
                xver: 0,
            })
        }
        _ => bail!("Xboard VLESS fallback dest must be a string or number"),
    }
}

fn parse_uuid(value: &str) -> anyhow::Result<[u8; 16]> {
    let compact = value
        .trim()
        .chars()
        .filter(|ch| *ch != '-')
        .collect::<String>();
    ensure!(!compact.is_empty(), "VLESS uuid is required");
    ensure!(
        compact.len() == 32,
        "VLESS uuid must contain 32 hexadecimal characters"
    );
    let mut uuid = [0u8; 16];
    hex::decode_to_slice(compact.as_bytes(), &mut uuid).context("decode VLESS uuid")?;
    Ok(uuid)
}

fn validate_request_addons(request: &codec::Request, allowed_flow: FlowMode) -> anyhow::Result<()> {
    ensure!(
        request.addons.seed.is_empty(),
        "VLESS addons seed is not supported by NodeRS VLESS server yet"
    );
    let request_flow = parse_flow_value(request.addons.flow.trim(), "VLESS addons flow")?;
    ensure!(
        request_flow == allowed_flow,
        "VLESS addons flow does not match configured Xboard flow"
    );
    ensure!(
        request_flow != FlowMode::XtlsRprxVision || request.command == Command::Tcp,
        "VLESS xtls-rprx-vision flow currently only supports TCP requests"
    );
    Ok(())
}

fn parse_flow_value(value: &str, field: &str) -> anyhow::Result<FlowMode> {
    if value.is_empty() {
        return Ok(FlowMode::None);
    }
    if value == FLOW_XTLS_RPRX_VISION {
        return Ok(FlowMode::XtlsRprxVision);
    }
    bail!("unsupported {field}: {value}")
}

fn default_grpc_alpn() -> Vec<String> {
    vec!["h2".to_string()]
}

fn default_h2_alpn() -> Vec<String> {
    vec!["h2".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::{CertConfig, NodeRealitySettings};

    const REALITY_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "vless".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            server_name: "node.example.com".to_string(),
            decryption: "none".to_string(),
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
    fn validator_accepts_canonical_uuid() {
        let validator = UserValidator::from_users(&[PanelUser {
            id: 1,
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".to_string(),
            ..Default::default()
        }])
        .expect("validator");

        let uuid = parse_uuid("bf000d23-0752-40b4-affe-68f7707a9661").expect("uuid");
        assert_eq!(validator.get(&uuid).map(|user| user.id), Some(1));
    }

    #[test]
    fn validator_rejects_invalid_uuid_string() {
        let error = UserValidator::from_users(&[PanelUser {
            id: 1,
            uuid: "not-a-uuid".to_string(),
            ..Default::default()
        }])
        .expect_err("invalid uuid should be rejected");
        assert!(error.to_string().contains("uuid"));
    }

    #[test]
    fn fallback_selection_uses_default_when_alpn_does_not_match() {
        let config = FallbackConfig {
            by_name: HashMap::from([(
                String::new(),
                HashMap::from([
                    (
                        String::new(),
                        HashMap::from([(
                            String::new(),
                            FallbackTarget {
                                server: "127.0.0.1".to_string(),
                                server_port: 80,
                                xver: 0,
                            },
                        )]),
                    ),
                    (
                        "h2".to_string(),
                        HashMap::from([(
                            String::new(),
                            FallbackTarget {
                                server: "127.0.0.1".to_string(),
                                server_port: 443,
                                xver: 0,
                            },
                        )]),
                    ),
                ]),
            )]),
        };

        assert_eq!(
            config
                .select(None, Some(b"h2"), b"GET / HTTP/1.1\r\n\r\n")
                .map(|target| target.server_port),
            Some(443)
        );
        assert_eq!(
            config
                .select(None, Some(b"http/1.1"), b"GET / HTTP/1.1\r\n\r\n")
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn fallback_selection_prefers_matching_server_name() {
        let config = FallbackConfig {
            by_name: HashMap::from([
                (
                    String::new(),
                    HashMap::from([(
                        String::new(),
                        HashMap::from([(
                            String::new(),
                            FallbackTarget {
                                server: "127.0.0.1".to_string(),
                                server_port: 80,
                                xver: 0,
                            },
                        )]),
                    )]),
                ),
                (
                    "example.com".to_string(),
                    HashMap::from([
                        (
                            String::new(),
                            HashMap::from([(
                                String::new(),
                                FallbackTarget {
                                    server: "127.0.0.1".to_string(),
                                    server_port: 8080,
                                    xver: 0,
                                },
                            )]),
                        ),
                        (
                            "h2".to_string(),
                            HashMap::from([(
                                String::new(),
                                FallbackTarget {
                                    server: "127.0.0.1".to_string(),
                                    server_port: 8443,
                                    xver: 0,
                                },
                            )]),
                        ),
                    ]),
                ),
            ]),
        };

        assert_eq!(
            config
                .select(
                    Some("api.example.com"),
                    Some(b"http/1.1"),
                    b"GET / HTTP/1.1\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(8080)
        );
        assert_eq!(
            config
                .select(
                    Some("api.example.com"),
                    Some(b"h2"),
                    b"GET / HTTP/1.1\r\n\r\n"
                )
                .map(|target| target.server_port),
            Some(8443)
        );
        assert_eq!(
            config
                .select(
                    Some("other.example.net"),
                    Some(b"http/1.1"),
                    b"GET / HTTP/1.1\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn fallback_selection_inherits_default_name_alpn_and_path_layers() {
        let config = FallbackConfig::from_remote(&NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "dest": 80 },
                { "alpn": "h2", "dest": 443 },
                { "path": "/ws", "dest": 8080 },
                { "name": "example.com", "dest": 8443 }
            ])),
            ..base_remote()
        })
        .expect("fallback config");

        assert_eq!(
            config
                .select(
                    Some("api.example.com"),
                    Some(b"http/1.1"),
                    b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(8443)
        );
        assert_eq!(
            config
                .select(
                    Some("api.example.com"),
                    Some(b"h2"),
                    b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(8443)
        );
        assert_eq!(
            config
                .select(
                    Some("api.example.com"),
                    Some(b"http/1.1"),
                    b"GET /ws HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(8080)
        );
    }

    #[test]
    fn fallback_selection_rejects_unmatched_alpn_without_default() {
        let config = FallbackConfig::from_remote(&NodeConfigResponse {
            fallback_for_alpn: Some(serde_json::json!({
                "h2": {
                    "server": "127.0.0.1",
                    "server_port": 443
                }
            })),
            ..base_remote()
        })
        .expect("fallback config");

        assert!(
            config
                .select(None, Some(b"http/1.1"), b"GET / HTTP/1.1\r\n\r\n")
                .is_none()
        );
    }

    #[test]
    fn fallback_for_alpn_keys_are_case_insensitive() {
        let remote = NodeConfigResponse {
            fallback_for_alpn: Some(serde_json::json!({
                "H2": {
                    "server": "127.0.0.1",
                    "server_port": 8443,
                }
            })),
            ..base_remote()
        };

        let config = FallbackConfig::from_remote(&remote).expect("fallback config");
        assert_eq!(
            config
                .select(None, Some(b"h2"), b"GET / HTTP/1.1\r\n\r\n")
                .map(|target| target.server_port),
            Some(8443)
        );
    }

    #[test]
    fn parses_fallback_xver() {
        let target = parse_fallback_target(&serde_json::json!({
            "server": "127.0.0.1",
            "server_port": 8080,
            "xver": 2
        }))
        .expect("parse fallback");

        assert_eq!(target.xver, 2);
    }

    #[test]
    fn parses_xray_style_fallback_dest() {
        let target = parse_fallback_target(&serde_json::json!({
            "dest": "127.0.0.1:8080",
            "xver": "1"
        }))
        .expect("parse fallback dest");

        assert_eq!(target.server, "127.0.0.1");
        assert_eq!(target.server_port, 8080);
        assert_eq!(target.xver, 1);
    }

    #[test]
    fn parses_fallback_string_port() {
        let target = parse_fallback_target(&serde_json::json!({
            "server": "127.0.0.1",
            "server_port": "8080"
        }))
        .expect("parse fallback");

        assert_eq!(target.server_port, 8080);

        let target = parse_fallback_target(&serde_json::json!({
            "server": "127.0.0.1",
            "serverPort": "8081"
        }))
        .expect("parse fallback camel port");

        assert_eq!(target.server_port, 8081);
    }

    #[test]
    fn accepts_none_decryption() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).expect("config");
        assert_eq!(config.server_port, 443);
    }

    #[test]
    fn rejects_non_none_decryption() {
        let remote = NodeConfigResponse {
            decryption: "aes-128-gcm".to_string(),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("decryption");
        assert!(error.to_string().contains("decryption"));
    }

    #[test]
    fn accepts_xudp_packet_encoding() {
        let remote = NodeConfigResponse {
            packet_encoding: "xudp".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("packet encoding");
        assert_eq!(config.packet_encoding, PacketEncoding::Xudp);

        let remote = NodeConfigResponse {
            packet_encoding: "none".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("packet encoding none");
        assert_eq!(config.packet_encoding, PacketEncoding::None);
    }

    #[test]
    fn rejects_unknown_packet_encoding() {
        let remote = NodeConfigResponse {
            packet_encoding: "packetaddr".to_string(),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("packet encoding");
        assert!(error.to_string().contains("packet_encoding"));
    }

    #[test]
    fn accepts_xboard_disabled_tls_mode() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(0)),
            cert_config: None,
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(config.tls.is_none());
        assert_eq!(config.server_port, 443);
    }

    #[test]
    fn accepts_xboard_multiplex_but_rejects_unknown_tls_mode() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(1)),
            multiplex: Some(serde_json::json!({
                "enabled": true,
                "protocol": "yamux"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(config.tls.is_some());
        assert_eq!(config.server_port, 443);

        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(3)),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("tls mode");
        assert!(error.to_string().contains("tls mode"));
    }

    #[test]
    fn accepts_reality_tls_mode() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            reality_settings: NodeRealitySettings {
                server_name: "reality.example.com".to_string(),
                public_key: REALITY_KEY_B64.to_string(),
                private_key: REALITY_KEY_B64.to_string(),
                short_id: "a1b2".to_string(),
                ..Default::default()
            },
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("reality config");
        let reality = config
            .tls
            .expect("tls config")
            .reality
            .expect("reality config");
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(
            reality.server_names,
            vec!["reality.example.com".to_string()]
        );
        assert_eq!(reality.short_ids, vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]]);
    }

    #[test]
    fn accepts_reality_with_websocket_transport() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            network: "ws".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/ws"
            })),
            reality_settings: NodeRealitySettings {
                server_name: "reality.example.com".to_string(),
                private_key: REALITY_KEY_B64.to_string(),
                short_id: "a1b2".to_string(),
                ..Default::default()
            },
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("REALITY ws transport");
        assert!(matches!(config.transport, TransportMode::Ws(_)));
        assert!(config.tls.expect("tls config").reality.is_some());
    }

    #[test]
    fn accepts_reality_with_xhttp_transport() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            network: "xhttp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "stream-one"
            })),
            reality_settings: NodeRealitySettings {
                server_name: "reality.example.com".to_string(),
                private_key: REALITY_KEY_B64.to_string(),
                short_id: "a1b2".to_string(),
                ..Default::default()
            },
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("REALITY xhttp transport");
        assert!(matches!(config.transport, TransportMode::Xhttp(_)));
        assert_eq!(
            config.tls.expect("tls config").alpn,
            vec!["http/1.1".to_string(), "h2".to_string()]
        );
    }

    #[test]
    fn parses_xboard_vless_xhttp_reality_config() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "network": "xhttp",
            "networkSettings": {
                "path": "/xhttp",
                "host": "cdn.example.com",
                "mode": "stream-one"
            },
            "tls": 2,
            "flow": "",
            "decryption": null,
            "tls_settings": {
                "server_name": "reality.example.com",
                "server_port": "8443",
                "public_key": REALITY_KEY_B64,
                "private_key": REALITY_KEY_B64,
                "short_id": "a1b2",
                "allow_insecure": false
            },
            "multiplex": null
        }))
        .expect("parse Xboard VLESS XHTTP REALITY config");

        let config = EffectiveNodeConfig::from_remote(&remote).expect("effective config");
        assert_eq!(config.server_port, 443);
        assert!(matches!(config.transport, TransportMode::Xhttp(_)));
        let reality = config
            .tls
            .expect("tls config")
            .reality
            .expect("reality config");
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(reality.server_port, 8443);
        assert_eq!(reality.short_ids, vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]]);
    }

    #[test]
    fn accepts_xhttp_network_settings() {
        let remote = NodeConfigResponse {
            network: "xhttp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "stream-one"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Xhttp(_)));
        assert_eq!(
            config.tls.expect("tls config").alpn,
            vec!["http/1.1".to_string(), "h2".to_string()]
        );
    }

    #[test]
    fn accepts_grpc_network_settings() {
        let remote = NodeConfigResponse {
            network: "grpc".to_string(),
            network_settings: Some(serde_json::json!({
                "serviceName": "TunService"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Grpc(_)));
        assert_eq!(config.tls.expect("tls config").alpn, vec!["h2".to_string()]);
    }

    #[test]
    fn accepts_h2_network_settings() {
        let remote = NodeConfigResponse {
            network: "h2".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/h2",
                "host": "cdn.example.com"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::H2(_)));
        assert_eq!(config.tls.expect("tls config").alpn, vec!["h2".to_string()]);
    }

    #[test]
    fn accepts_splithttp_as_xhttp_transport_alias() {
        let remote = NodeConfigResponse {
            network: "splithttp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "stream-one"
            })),
            transport: Some(serde_json::json!({
                "type": "splithttp"
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Xhttp(_)));
    }

    #[test]
    fn preserves_explicit_alpn_for_xhttp() {
        let remote = NodeConfigResponse {
            network: "xhttp".to_string(),
            alpn: vec!["http/1.1".to_string()],
            network_settings: Some(serde_json::json!({
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "stream-one"
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(
            config.tls.expect("tls config").alpn,
            vec!["http/1.1".to_string()]
        );
    }

    #[tokio::test]
    async fn sniff_http2_connection_preface_accepts_exact_preface() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut stream = http1::PrefixedIo::new(server, Vec::new()).capture_inner_reads();
        let write = tokio::spawn(async move {
            client
                .write_all(HTTP2_CONNECTION_PREFACE)
                .await
                .expect("write h2 preface");
        });

        let is_h2 = sniff_http2_connection_preface(&mut stream)
            .await
            .expect("sniff http2 preface");
        let (_stream, captured) = stream.into_parts();
        write.await.expect("join write");

        assert!(is_h2);
        assert_eq!(captured, HTTP2_CONNECTION_PREFACE);
    }

    #[tokio::test]
    async fn sniff_http2_connection_preface_rejects_http1_request_and_preserves_prefix() {
        let request = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (mut client, server) = tokio::io::duplex(4096);
        let mut stream = http1::PrefixedIo::new(server, Vec::new()).capture_inner_reads();
        let write = tokio::spawn(async move {
            client
                .write_all(request)
                .await
                .expect("write http1 request");
        });

        let is_h2 = sniff_http2_connection_preface(&mut stream)
            .await
            .expect("sniff http1 preface");
        let (stream, captured) = stream.into_parts();
        let mut stream = http1::PrefixedIo::new(stream, captured);
        let parsed = http1::read_request_head(&mut stream)
            .await
            .expect("parse preserved http1 request");
        write.await.expect("join write");

        assert!(!is_h2);
        assert_eq!(parsed.request.method, "GET");
        assert_eq!(parsed.request.path, "/x");
        assert_eq!(parsed.request.host, "example.com");
    }

    #[tokio::test]
    async fn prefetched_vless_tcp_prefix_is_replayed_to_request_reader() {
        let mut request = Vec::new();
        request.push(codec::VERSION);
        request.extend_from_slice(&[0x11; 16]);
        request.push(0);
        request.push(0x01);
        request.extend_from_slice(&443u16.to_be_bytes());
        request.push(0x02);
        request.push(11);
        request.extend_from_slice(b"example.com");

        let (mut client, server) = tokio::io::duplex(4096);
        let write = tokio::spawn(async move {
            client
                .write_all(&request)
                .await
                .expect("write VLESS request");
        });

        let (first_packet, mut stream) = prefetch_prefixed_stream(server)
            .await
            .expect("prepare prefixed stream");
        let mut consumed = Vec::new();
        let request = codec::read_request(&mut stream, &mut consumed)
            .await
            .expect("read replayed VLESS request");
        write.await.expect("join write");

        assert_eq!(first_packet, consumed);
        assert_eq!(request.command, Command::Tcp);
        assert_eq!(
            request.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
    }

    #[tokio::test]
    async fn writes_response_header_with_first_payload() {
        let (mut reader, mut writer) = tokio::io::duplex(4096);
        let write = tokio::spawn(async move {
            write_response_header_and_chunk(&mut writer, FlowMode::None, [0; 16], b"pong")
                .await
                .expect("write response header and payload");
        });

        let mut output = [0u8; 6];
        reader
            .read_exact(&mut output)
            .await
            .expect("read combined response");
        write.await.expect("join write");

        assert_eq!(&output, &[0, 0, b'p', b'o', b'n', b'g']);
    }

    #[test]
    fn validates_runtime_vless_flow_addons() {
        let request = codec::Request {
            user: [0u8; 16],
            addons: codec::Addons {
                flow: "xtls-rprx-vision".to_string(),
                seed: Vec::new(),
            },
            command: Command::Tcp,
            destination: SocksAddr::Domain("example.com".to_string(), 443),
        };

        validate_request_addons(&request, FlowMode::XtlsRprxVision).expect("matching flow");
        let error = validate_request_addons(&request, FlowMode::None)
            .expect_err("mismatched flow should be rejected");
        assert!(error.to_string().contains("flow"));

        let request = codec::Request {
            addons: codec::Addons {
                flow: String::new(),
                seed: vec![1, 2, 3],
            },
            ..request
        };
        let error =
            validate_request_addons(&request, FlowMode::None).expect_err("seed should be rejected");
        assert!(error.to_string().contains("addons seed"));
    }

    #[test]
    fn rejects_vless_vision_for_non_tcp_request() {
        let request = codec::Request {
            user: [0u8; 16],
            addons: codec::Addons {
                flow: "xtls-rprx-vision".to_string(),
                seed: Vec::new(),
            },
            command: Command::Udp,
            destination: SocksAddr::Domain("example.com".to_string(), 443),
        };

        let error = validate_request_addons(&request, FlowMode::XtlsRprxVision)
            .expect_err("Vision UDP should be rejected");
        assert!(error.to_string().contains("TCP"));
    }

    #[test]
    fn parses_xboard_vless_vision_flow_for_tcp_only() {
        let remote = NodeConfigResponse {
            flow: "xtls-rprx-vision".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("vision config");
        assert_eq!(config.flow, FlowMode::XtlsRprxVision);

        let remote = NodeConfigResponse {
            flow: "xtls-rprx-vision".to_string(),
            network: "xhttp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "stream-one"
            })),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("non-tcp vision");
        assert!(error.to_string().contains("tcp transport"));
    }

    #[test]
    fn rejects_enabled_transport_without_type() {
        let remote = NodeConfigResponse {
            transport: Some(serde_json::json!({
                "enabled": true
            })),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("transport");
        assert!(error.to_string().contains("transport"));
    }

    #[test]
    fn encodes_vless_vision_response_header_and_first_payload() {
        let user = [7u8; 16];
        let response = encode_response_header(FlowMode::XtlsRprxVision, user, b"pong")
            .expect("encode vision response");

        assert_eq!(&response[..2], &codec::RESPONSE_HEADER);
        assert_eq!(&response[2..18], &user);
        assert_eq!(response[18], 1);
        assert_eq!(&response[19..21], &4u16.to_be_bytes());
        assert_eq!(&response[21..23], &0u16.to_be_bytes());
        assert_eq!(&response[23..], b"pong");
    }

    #[test]
    fn parses_xboard_fallbacks_subset() {
        let remote = NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "dest": 80 },
                { "name": "example.com", "alpn": "h2", "dest": "127.0.0.1:8443" }
            ])),
            ..base_remote()
        };

        let config = FallbackConfig::from_remote(&remote).expect("fallback config");
        assert_eq!(
            config
                .select(
                    Some("sub.example.com"),
                    Some(b"h2"),
                    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(8443)
        );
        assert_eq!(
            config
                .select(
                    Some("other.example.net"),
                    Some(b"http/1.1"),
                    b"GET / HTTP/1.1\r\nHost: other.example.net\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn parses_xboard_fallbacks_with_path_name_and_xver() {
        let remote = NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "dest": 80 },
                { "name": "example.com", "alpn": "h2", "path": "/ws", "dest": "127.0.0.1:8443", "xver": 1 }
            ])),
            ..base_remote()
        };

        let config = FallbackConfig::from_remote(&remote).expect("fallback config");
        let target = config
            .select(
                Some("api.example.com"),
                Some(b"h2"),
                b"GET /ws?ed=2048 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .expect("path-specific fallback");
        assert_eq!(target.server, "127.0.0.1");
        assert_eq!(target.server_port, 8443);
        assert_eq!(target.xver, 1);

        assert_eq!(
            config
                .select(
                    Some("other.example.com"),
                    Some(b"http/1.1"),
                    b"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn fallback_selection_uses_default_path_when_http_path_misses() {
        let config = FallbackConfig::from_remote(&NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "dest": 80 },
                { "path": "/ws", "dest": 8080 }
            ])),
            ..base_remote()
        })
        .expect("fallback config");

        assert_eq!(
            config
                .select(
                    None,
                    None,
                    b"GET /other HTTP/1.1\r\nHost: example.com\r\n\r\n",
                )
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn rejects_xboard_fallback_path_without_leading_slash() {
        let remote = NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "path": "ws", "dest": 80 }
            ])),
            ..base_remote()
        };

        let error = FallbackConfig::from_remote(&remote).expect_err("unsupported fallback path");
        assert!(error.to_string().contains("must start with /"));
    }

    #[test]
    fn encodes_proxy_protocol_headers() {
        let v1 = encode_proxy_header(
            SocketAddr::from(([1, 2, 3, 4], 1234)),
            SocketAddr::from(([5, 6, 7, 8], 443)),
            1,
        )
        .expect("v1");
        assert_eq!(v1, b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n");

        let v2 = encode_proxy_header(
            SocketAddr::from(([1, 2, 3, 4], 1234)),
            SocketAddr::from(([5, 6, 7, 8], 443)),
            2,
        )
        .expect("v2");
        assert_eq!(
            &v2[..16],
            b"\x0D\x0A\x0D\x0A\x00\x0D\x0AQUIT\x0A\x21\x11\x00\x0C"
        );
        assert_eq!(&v2[16..20], &[1, 2, 3, 4]);
        assert_eq!(&v2[20..24], &[5, 6, 7, 8]);
        assert_eq!(&v2[24..26], &1234u16.to_be_bytes());
        assert_eq!(&v2[26..28], &443u16.to_be_bytes());
    }

    #[test]
    fn detects_http_path_from_first_packet() {
        assert_eq!(
            detect_http_path(b"GET /ws?ed=2048 HTTP/1.1\r\nHost: example.com\r\n\r\n").as_deref(),
            Some("/ws")
        );
        assert_eq!(
            detect_http_path(b"POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n").as_deref(),
            Some("/api")
        );
        assert!(detect_http_path(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").is_none());
    }

    #[test]
    fn accepts_websocket_network_settings() {
        let remote = NodeConfigResponse {
            network: "ws".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/ws",
                "headers": {
                    "Host": "cdn.example.com"
                }
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Ws(_)));
    }

    #[test]
    fn accepts_httpupgrade_network_settings() {
        let remote = NodeConfigResponse {
            network: "httpupgrade".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/upgrade",
                "host": "cdn.example.com"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::HttpUpgrade(_)));
    }

    #[test]
    fn accepts_disabled_tcp_network_settings_from_xboard() {
        let remote = NodeConfigResponse {
            network: "tcp".to_string(),
            network_settings: Some(serde_json::json!({
                "enabled": false,
                "headers": {}
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Tcp));
    }

    #[test]
    fn accepts_transport_type_matching_selected_network() {
        let remote = NodeConfigResponse {
            network: "xhttp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "stream-one"
            })),
            transport: Some(serde_json::json!({
                "type": "xhttp"
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Xhttp(_)));
    }
}
