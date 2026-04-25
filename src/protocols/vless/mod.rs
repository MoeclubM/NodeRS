mod codec;
mod http1;
mod httpupgrade;
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
    vec!["h2".to_string(), "http/1.1".to_string()]
}

#[derive(Debug, Clone, PartialEq)]
enum TransportMode {
    Tcp,
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
    server_port: u16,
}

impl FallbackConfig {
    fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        let default = match remote.fallback.as_ref() {
            Some(value) => Some(parse_fallback_target(value).context("decode VLESS fallback")?),
            None => None,
        };

        let by_alpn = match remote.fallback_for_alpn.as_ref() {
            Some(value) => parse_fallback_map(value).context("decode VLESS fallback_for_alpn")?,
            None => HashMap::new(),
        };

        Ok(Self { default, by_alpn })
    }

    fn select<'a>(&'a self, alpn: Option<&[u8]>) -> Option<&'a FallbackTarget> {
        if !self.by_alpn.is_empty() {
            return alpn
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| self.by_alpn.get(value));
        }
        self.default.as_ref()
    }
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
        let should_reload = tls_materials.as_ref().is_none_or(|current| {
            !current.matches_source(&tls.source, tls.ech.as_ref(), &tls.alpn)
        });
        if !should_reload {
            return Ok(());
        }

        let reloaded = tls::load_tls_materials(&tls.source, tls.ech.as_ref(), &tls.alpn)
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
        Err(_) => return Err(anyhow!("VLESS request header timed out")),
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
        Command::Mux => {
            ensure!(
                packet_encoding == PacketEncoding::Xudp,
                "VLESS mux is only supported for packet_encoding xudp"
            );
            ensure!(
                request.destination
                    == SocksAddr::Domain(
                        codec::XUDP_MUX_DESTINATION.to_string(),
                        codec::XUDP_MUX_PORT
                    ),
                "unsupported VLESS mux destination {}",
                request.destination
            );
            serve_xudp(stream, accounting, lease, user, routing).await
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
            read = reader.read(&mut buffer) => read.context("read proxied VLESS chunk")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => result.context("write proxied VLESS chunk")?,
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
            remote.network_settings.is_none(),
            "Xboard networkSettings is only supported for VLESS ws/httpupgrade/xhttp nodes"
        );
        return Ok(TransportMode::Tcp);
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
    bail!("Xboard network must be tcp, ws, httpupgrade or xhttp for VLESS nodes");
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
    parse_transport_mode(remote)?;
    parse_packet_encoding(remote)?;
    if remote.tls.is_some() && remote.tls_mode() != 1 {
        bail!(
            "Xboard tls mode {} is not supported by NodeRS VLESS server yet",
            remote.tls_mode()
        );
    }
    if remote.transport.is_some() {
        bail!("Xboard transport is not supported by NodeRS VLESS server yet");
    }
    if remote.multiplex_enabled() {
        bail!("Xboard multiplex is not supported by NodeRS VLESS server yet");
    }
    if remote.fallbacks.is_some() {
        bail!("Xboard fallbacks is not supported by NodeRS VLESS server yet");
    }
    let decryption = remote.decryption.trim();
    if !decryption.is_empty() && !decryption.eq_ignore_ascii_case("none") {
        bail!("Xboard decryption must be none for VLESS nodes");
    }
    if !remote.flow.trim().is_empty() {
        bail!("Xboard flow is not supported by NodeRS VLESS server yet");
    }
    Ok(())
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
    ensure!(
        request.addons.flow.trim().is_empty(),
        "VLESS addons flow is not supported by NodeRS VLESS server yet"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::CertConfig;

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
    fn fallback_selection_prefers_alpn_map_over_default() {
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
        assert!(config.select(Some(b"http/1.1")).is_none());
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
            tls: Some(serde_json::json!(2)),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("tls mode");
        assert!(error.to_string().contains("tls mode"));
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
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
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
    fn rejects_runtime_vless_addons_until_flow_support_lands() {
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
}
