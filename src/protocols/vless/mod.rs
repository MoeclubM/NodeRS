mod codec;
mod grpc;
mod http1;
mod httpupgrade;
mod mux;
mod ws;
mod xhttp;
mod xudp;

use anyhow::{Context, anyhow, bail, ensure};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use self::codec::Command;
use super::anytls::{
    EffectiveTlsConfig, bind_listeners, configure_tcp_stream, effective_listen_ip, routing,
    socksaddr::SocksAddr, tls, traffic::TrafficRecorder, transport,
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const COPY_BUFFER_LEN: usize = 64 * 1024;

type TlsStream = tokio_boring::SslStream<TcpStream>;

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: EffectiveTlsConfig,
    transport: TransportMode,
    packet_encoding: PacketEncoding,
    pub routing: routing::RoutingTable,
    pub fallbacks: FallbackConfig,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let transport = parse_transport_mode(remote)?;
        let mut tls = EffectiveTlsConfig::from_remote(remote)?;
        if matches!(transport, TransportMode::Grpc(_)) && tls.alpn.is_empty() {
            tls.alpn = default_grpc_alpn();
        }
        if matches!(transport, TransportMode::Xhttp(_)) && tls.alpn.is_empty() {
            tls.alpn = default_xhttp_alpn();
        }
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls,
            transport,
            packet_encoding: parse_packet_encoding(remote)?,
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

#[derive(Debug, Clone, Default)]
pub struct FallbackConfig {
    default: Option<FallbackTarget>,
    by_alpn: HashMap<String, FallbackTarget>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct FallbackTarget {
    #[serde(default)]
    server: String,
    #[serde(deserialize_with = "crate::panel::deserialize_u16_from_number_or_string")]
    server_port: u16,
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
            config.default = Some(default);
        }

        let by_alpn = match remote.fallback_for_alpn.as_ref() {
            Some(value) => parse_fallback_map(value).context("decode VLESS fallback_for_alpn")?,
            None => HashMap::new(),
        };
        config.by_alpn.extend(by_alpn);

        Ok(config)
    }

    fn select<'a>(&'a self, alpn: Option<&[u8]>) -> Option<&'a FallbackTarget> {
        alpn.and_then(|value| std::str::from_utf8(value).ok())
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
            .and_then(|value| self.by_alpn.get(value))
            .or(self.default.as_ref())
    }

    fn merge_xboard_fallbacks(&mut self, value: &serde_json::Value) -> anyhow::Result<()> {
        let entries = value
            .as_array()
            .ok_or_else(|| anyhow!("Xboard VLESS fallbacks must be an array"))?;
        for entry in entries {
            let entry = parse_xboard_fallback_entry(entry)?;
            if let Some(alpn) = entry.alpn {
                self.by_alpn.insert(alpn.to_ascii_lowercase(), entry.target);
            } else {
                self.default = Some(entry.target);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ParsedFallbackEntry {
    alpn: Option<String>,
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
    tls_materials: AsyncMutex<Option<tls::LoadedTlsMaterials>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    transport: Arc<RwLock<TransportMode>>,
    packet_encoding: Arc<RwLock<PacketEncoding>>,
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
            tls_materials: AsyncMutex::new(None),
            accounting,
            users: Arc::new(RwLock::new(UserValidator::default())),
            transport: Arc::new(RwLock::new(TransportMode::Tcp)),
            packet_encoding: Arc::new(RwLock::new(PacketEncoding::None)),
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
        *self.routing.write().expect("vless routing lock poisoned") = config.routing;
        *self
            .fallbacks
            .write()
            .expect("vless fallback lock poisoned") = config.fallbacks;
        self.update_tls_config(&config.tls).await?;

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
        let accounting = self.accounting.clone();
        let users = self.users.clone();
        let transport = self.transport.clone();
        let packet_encoding = self.packet_encoding.clone();
        let routing = self.routing.clone();
        let fallbacks = self.fallbacks.clone();
        let handle = tokio::spawn(async move {
            info!(listen = ?bind_addrs, "VLESS listeners started");
            let mut accept_loops = JoinSet::new();
            for listener in listeners {
                let tls_config = tls_config.clone();
                let accounting = accounting.clone();
                let users = users.clone();
                let transport = transport.clone();
                let packet_encoding = packet_encoding.clone();
                let routing = routing.clone();
                let fallbacks = fallbacks.clone();
                accept_loops.spawn(async move {
                    accept_loop(
                        listener,
                        tls_config,
                        accounting,
                        users,
                        transport,
                        packet_encoding,
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

    async fn update_tls_config(&self, tls: &EffectiveTlsConfig) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let reality = tls.reality.as_ref().map(|reality| tls::RealityTlsConfig {
            server_name: reality.server_name.clone(),
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
                reality_server_name = %reality.server_name,
                reality_short_id_count = reality.short_ids.len(),
                reality_short_id_tail = %short_id_tail,
                "applying VLESS REALITY TLS config"
            );
        }

        let reloaded =
            tls::load_tls_materials(&tls.source, tls.ech.as_ref(), reality.as_ref(), &tls.alpn)
                .await
                .context("load VLESS TLS materials")?;
        *self
            .tls_config
            .write()
            .expect("vless tls config lock poisoned") = Some(reloaded.acceptor());
        *tls_materials = Some(reloaded);
        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    transport: Arc<RwLock<TransportMode>>,
    packet_encoding: Arc<RwLock<PacketEncoding>>,
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
            let Some(tls_config) = tls_config else {
                warn!(listen = %listen, "VLESS TLS config is not ready; dropping connection");
                continue;
            };
            tls_config
        };
        let accounting = accounting.clone();
        let users = users.clone();
        let transport = transport.clone();
        let packet_encoding = packet_encoding.clone();
        let routing = routing.clone();
        let fallbacks = fallbacks.clone();
        tokio::spawn(async move {
            let tls_stream = match timeout(
                TLS_HANDSHAKE_TIMEOUT,
                tokio_boring::accept(acceptor.as_ref(), stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    warn!(%error, %source, "VLESS TLS handshake failed");
                    return;
                }
                Err(_) => {
                    warn!(%source, "VLESS TLS handshake timed out");
                    return;
                }
            };
            let users = users.read().expect("vless users lock poisoned").clone();
            let transport = transport
                .read()
                .expect("vless transport lock poisoned")
                .clone();
            let packet_encoding = *packet_encoding
                .read()
                .expect("vless packet encoding lock poisoned");
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

async fn serve_connection(
    mut stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    routing: routing::RoutingTable,
    fallbacks: FallbackConfig,
) -> anyhow::Result<()> {
    let negotiated_alpn = stream
        .ssl()
        .selected_alpn_protocol()
        .map(|value| value.to_vec());
    let mut consumed = Vec::with_capacity(64);
    let request = match timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut consumed),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            if let Some(target) = fallbacks.select(negotiated_alpn.as_deref()) {
                proxy_fallback(stream, target, consumed).await?;
                return Ok(());
            }
            return Err(error);
        }
        Err(_) => {
            if let Some(target) = fallbacks.select(negotiated_alpn.as_deref()) {
                proxy_fallback(stream, target, consumed).await?;
                return Ok(());
            }
            return Err(anyhow!("VLESS request header timed out"));
        }
    };
    if let Err(error) = validate_request_addons(&request) {
        if let Some(target) = fallbacks.select(negotiated_alpn.as_deref()) {
            proxy_fallback(stream, target, consumed).await?;
            return Ok(());
        }
        return Err(error);
    }

    let user = match users.get(&request.user) {
        Some(user) => user,
        None => {
            if let Some(target) = fallbacks.select(negotiated_alpn.as_deref()) {
                proxy_fallback(stream, target, consumed).await?;
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
    routing: routing::RoutingTable,
    config: grpc::GrpcConfig,
) -> anyhow::Result<()> {
    let on_stream: Arc<dyn Fn(grpc::GrpcStream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let routing = routing.clone();
        tokio::spawn(async move {
            if let Err(error) =
                serve_grpc_stream(stream, source, accounting, users, packet_encoding, routing).await
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
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request)?;
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
    validate_request_addons(&request)?;
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
    validate_request_addons(&request)?;
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
    routing: routing::RoutingTable,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()> {
    let negotiated_alpn = stream
        .ssl()
        .selected_alpn_protocol()
        .map(|value| value.to_vec());
    if negotiated_alpn.as_deref() == Some(b"h2") {
        return serve_xhttp_h2_connection(
            stream,
            source,
            accounting,
            users,
            packet_encoding,
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
        routing,
        config,
    )
    .await
}

async fn serve_xhttp_http1_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    routing: routing::RoutingTable,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()> {
    let mut stream = http1::PrefixedIo::new(stream, Vec::new());
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

async fn serve_xhttp_h2_connection(
    stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    routing: routing::RoutingTable,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()> {
    let on_stream: Arc<dyn Fn(xhttp::XhttpStream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let routing = routing.clone();
        tokio::spawn(async move {
            if let Err(error) =
                serve_xhttp_stream(stream, source, accounting, users, packet_encoding, routing)
                    .await
            {
                warn!(%error, %source, "VLESS XHTTP h2 session terminated with error");
            }
        });
    });
    xhttp::serve_h2(stream, config, on_stream).await
}

async fn serve_xhttp_stream(
    mut stream: xhttp::XhttpStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    packet_encoding: PacketEncoding,
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let request = timeout(
        REQUEST_HEADER_TIMEOUT,
        codec::read_request(&mut stream, &mut Vec::new()),
    )
    .await
    .map_err(|_| anyhow!("VLESS request header timed out"))??;
    validate_request_addons(&request)?;
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
    codec::write_response_header(&mut client_writer).await?;
    let (mut remote_reader, mut remote_writer) = split(remote);

    let client_to_remote = copy_with_traffic(
        &mut client_reader,
        &mut remote_writer,
        control.clone(),
        Some(upload),
    );
    let remote_to_client = copy_with_traffic(
        &mut remote_reader,
        &mut client_writer,
        control,
        Some(download),
    );
    let _ = tokio::try_join!(client_to_remote, remote_to_client)?;
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

async fn proxy_fallback(
    stream: TlsStream,
    target: &FallbackTarget,
    consumed: Vec<u8>,
) -> anyhow::Result<()> {
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
                .is_none_or(|value| !json_value_effectively_enabled(value)),
            "Xboard networkSettings is only supported for VLESS grpc/ws/httpupgrade/xhttp nodes"
        );
        return Ok(TransportMode::Tcp);
    }
    if network.eq_ignore_ascii_case("grpc") {
        return Ok(TransportMode::Grpc(
            grpc::GrpcConfig::from_network_settings(remote.network_settings.as_ref())?,
        ));
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
    if network.eq_ignore_ascii_case("xhttp") {
        return Ok(TransportMode::Xhttp(
            xhttp::XhttpConfig::from_network_settings(remote.network_settings.as_ref())?,
        ));
    }
    bail!("Xboard network must be tcp, grpc, ws, httpupgrade or xhttp for VLESS nodes");
}

fn parse_packet_encoding(remote: &NodeConfigResponse) -> anyhow::Result<PacketEncoding> {
    let packet_encoding = remote.packet_encoding.trim();
    if packet_encoding.is_empty() {
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
    if remote.tls.is_some() && !matches!(remote.tls_mode(), 1 | 2) {
        bail!(
            "Xboard tls mode {} is not supported by NodeRS VLESS server yet",
            remote.tls_mode()
        );
    }
    if remote.multiplex_enabled() {
        bail!("Xboard multiplex is not supported by NodeRS VLESS server yet");
    }
    if let Some(transport) = remote.transport.as_ref() {
        validate_transport_field(transport, &transport_mode)?;
    }
    let decryption = remote.decryption.trim();
    if !decryption.is_empty() && !decryption.eq_ignore_ascii_case("none") {
        bail!("Xboard decryption must be none for VLESS nodes");
    }
    validate_flow_value(remote.flow.trim(), "Xboard flow")?;
    Ok(())
}

fn validate_transport_field(
    value: &serde_json::Value,
    transport_mode: &TransportMode,
) -> anyhow::Result<()> {
    if !json_value_effectively_enabled(value) {
        return Ok(());
    }

    let expected = match transport_mode {
        TransportMode::Tcp => "tcp",
        TransportMode::Grpc(_) => "grpc",
        TransportMode::Ws(_) => "ws",
        TransportMode::HttpUpgrade(_) => "httpupgrade",
        TransportMode::Xhttp(_) => "xhttp",
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

    if transport_type.is_empty() || transport_type.eq_ignore_ascii_case(expected) {
        return Ok(());
    }

    bail!("Xboard transport is not supported by NodeRS VLESS server yet");
}

fn json_value_effectively_enabled(value: &serde_json::Value) -> bool {
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
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(object) => object
            .get("enabled")
            .map(json_value_effectively_enabled)
            .unwrap_or(!object.is_empty()),
    }
}

fn parse_fallback_map(
    value: &serde_json::Value,
) -> anyhow::Result<HashMap<String, FallbackTarget>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("VLESS fallback_for_alpn must be an object"))?;
    let mut targets = HashMap::new();
    for (alpn, value) in object {
        let key = alpn.trim();
        ensure!(
            !key.is_empty(),
            "VLESS fallback_for_alpn contains empty ALPN"
        );
        ensure!(
            targets
                .insert(key.to_string(), parse_fallback_target(value)?)
                .is_none(),
            "duplicate VLESS fallback_for_alpn entry {key}"
        );
    }
    Ok(targets)
}

fn parse_fallback_target(value: &serde_json::Value) -> anyhow::Result<FallbackTarget> {
    let target: FallbackTarget =
        serde_json::from_value(value.clone()).context("parse VLESS fallback target")?;
    ensure!(
        !target.server.trim().is_empty() && target.server_port > 0,
        "VLESS fallback target requires server and server_port"
    );
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
        .trim();
    ensure!(
        name.is_empty(),
        "Xboard VLESS fallback name is not supported yet"
    );

    let path = object
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    ensure!(
        path.is_empty(),
        "Xboard VLESS fallback path is not supported yet"
    );

    let xver = object
        .get("xver")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    ensure!(xver == 0, "Xboard VLESS fallback xver is not supported yet");

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
    let target = parse_xboard_fallback_dest(dest)?;

    let alpn = object
        .get("alpn")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    Ok(ParsedFallbackEntry { alpn, target })
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

fn validate_request_addons(request: &codec::Request) -> anyhow::Result<()> {
    ensure!(
        request.addons.seed.is_empty(),
        "VLESS addons seed is not supported by NodeRS VLESS server yet"
    );
    validate_flow_value(request.addons.flow.trim(), "VLESS addons flow")?;
    Ok(())
}

fn validate_flow_value(value: &str, field: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    bail!("{field} is not supported by NodeRS VLESS server yet")
}

fn default_grpc_alpn() -> Vec<String> {
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
            default: Some(FallbackTarget {
                server: "127.0.0.1".to_string(),
                server_port: 80,
            }),
            by_alpn: HashMap::from([(
                "h2".to_string(),
                FallbackTarget {
                    server: "127.0.0.1".to_string(),
                    server_port: 443,
                },
            )]),
        };

        assert_eq!(
            config.select(Some(b"h2")).map(|target| target.server_port),
            Some(443)
        );
        assert_eq!(
            config
                .select(Some(b"http/1.1"))
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn parses_fallback_string_port() {
        let target = parse_fallback_target(&serde_json::json!({
            "server": "127.0.0.1",
            "server_port": "8080"
        }))
        .expect("parse fallback");

        assert_eq!(target.server_port, 8080);
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
    fn accepts_disabled_multiplex_but_rejects_non_tls_mode() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(1)),
            multiplex: Some(serde_json::json!({
                "enabled": false,
                "protocol": "yamux"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
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
        let reality = config.tls.reality.expect("reality config");
        assert_eq!(reality.server_name, "reality.example.com");
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
            config.tls.alpn,
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
        assert_eq!(config.tls.alpn, vec!["h2".to_string()]);
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
        assert_eq!(config.tls.alpn, vec!["http/1.1".to_string()]);
    }

    #[test]
    fn still_rejects_runtime_vless_flow_addons() {
        let request = codec::Request {
            user: [0u8; 16],
            addons: codec::Addons {
                flow: "xtls-rprx-vision".to_string(),
                seed: Vec::new(),
            },
            command: Command::Tcp,
            destination: SocksAddr::Domain("example.com".to_string(), 443),
        };

        let error = validate_request_addons(&request).expect_err("flow should be rejected");
        assert!(error.to_string().contains("addons flow"));

        let request = codec::Request {
            addons: codec::Addons {
                flow: String::new(),
                seed: vec![1, 2, 3],
            },
            ..request
        };
        let error = validate_request_addons(&request).expect_err("seed should be rejected");
        assert!(error.to_string().contains("addons seed"));
    }

    #[test]
    fn parses_xboard_fallbacks_subset() {
        let remote = NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "dest": 80 },
                { "alpn": "h2", "dest": "127.0.0.1:8443" }
            ])),
            ..base_remote()
        };

        let config = FallbackConfig::from_remote(&remote).expect("fallback config");
        assert_eq!(
            config.select(Some(b"h2")).map(|target| target.server_port),
            Some(8443)
        );
        assert_eq!(
            config
                .select(Some(b"http/1.1"))
                .map(|target| target.server_port),
            Some(80)
        );
    }

    #[test]
    fn rejects_xboard_fallbacks_with_unsupported_path() {
        let remote = NodeConfigResponse {
            fallbacks: Some(serde_json::json!([
                { "path": "/ws", "dest": 80 }
            ])),
            ..base_remote()
        };

        let error = FallbackConfig::from_remote(&remote).expect_err("unsupported fallback path");
        assert!(error.to_string().contains("fallback path"));
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
