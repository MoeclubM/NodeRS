use anyhow::{Context, anyhow, bail, ensure};
use bytes::Bytes;
use quinn::{Endpoint, VarInt};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser, RouteConfig};

use super::shared::{
    EffectiveTlsConfig, effective_listen_ip, routing::RoutingTable, socksaddr::SocksAddr, tls,
    traffic::TrafficRecorder, transport,
};

const H3_ALPN: &str = "h3";
const AUTH_PATH: &str = "/auth";
const AUTH_HOST: &str = "hysteria";
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HY2_TCP_REQUEST_ID: u64 = 0x401;
const COPY_BUFFER_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: EffectiveTlsConfig,
    pub cc_rx: String,
    pub udp_enabled: bool,
    pub routes: Vec<RouteConfig>,
    pub custom_outbounds: Vec<serde_json::Value>,
    pub custom_routes: Vec<serde_json::Value>,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let mut tls = EffectiveTlsConfig::from_remote(remote)?;
        tls.alpn = vec![H3_ALPN.to_string()];
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls,
            cc_rx: hy2_cc_rx(remote.down_mbps.as_ref(), remote.ignore_client_bandwidth)?,
            udp_enabled: hy2_udp_enabled(&remote.udp_relay_mode),
            routes: remote.routes.clone(),
            custom_outbounds: remote.custom_outbounds.clone(),
            custom_routes: remote.custom_routes.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct UserValidator {
    by_auth: FxHashMap<String, UserEntry>,
}

impl UserValidator {
    fn from_users(users: &[PanelUser]) -> anyhow::Result<Self> {
        let mut by_auth = FxHashMap::default();
        for user in users {
            let entry = UserEntry::from_panel_user(user);
            for auth in [user.password.trim(), user.uuid.trim()] {
                if auth.is_empty() {
                    continue;
                }
                ensure!(
                    by_auth.insert(auth.to_string(), entry.clone()).is_none(),
                    "duplicate HY2 auth credential for user {}",
                    user.id
                );
            }
        }
        ensure!(!by_auth.is_empty(), "HY2 users require password or uuid");
        Ok(Self { by_auth })
    }

    fn get(&self, auth: &str) -> Option<UserEntry> {
        self.by_auth.get(auth).cloned()
    }
}

pub struct ServerController {
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    inner: Mutex<Option<RunningServer>>,
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    endpoint: Endpoint,
    handle: JoinHandle<()>,
}

impl ServerController {
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            accounting,
            users: Arc::new(RwLock::new(UserValidator::default())),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        let validator = UserValidator::from_users(users)?;
        self.accounting.replace_users(users);
        *self.users.write().expect("hy2 users lock poisoned") = validator;
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        let old = {
            let mut guard = self.inner.lock().expect("hy2 server controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip || running.server_port != config.server_port
            });
            if !should_restart {
                return Ok(());
            }
            guard.take()
        };

        if let Some(old) = old {
            old.endpoint.close(VarInt::from_u32(0), b"server restart");
            old.handle.abort();
        }

        let endpoint = build_endpoint(&config).await?;
        let local_addr = endpoint.local_addr().context("read HY2 local address")?;
        let users = self.users.clone();
        let accounting = self.accounting.clone();
        let cc_rx = config.cc_rx.clone();
        let udp_enabled = config.udp_enabled;
        let routing = RoutingTable::from_remote(
            &config.routes,
            &config.custom_outbounds,
            &config.custom_routes,
        )
        .context("compile HY2 routing")?;
        let accept_endpoint = endpoint.clone();
        let handle = tokio::spawn(async move {
            info!(listen = %local_addr, "HY2 endpoint started");
            let mut connections = JoinSet::new();
            while let Some(incoming) = accept_endpoint.accept().await {
                let users = users.clone();
                let accounting = accounting.clone();
                let routing = routing.clone();
                let cc_rx = cc_rx.clone();
                connections.spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            if let Err(error) = handle_connection(
                                connection,
                                accounting,
                                users,
                                routing,
                                cc_rx,
                                udp_enabled,
                            )
                            .await
                            {
                                warn!(%error, "HY2 connection terminated with error");
                            }
                        }
                        Err(error) => warn!(%error, "HY2 QUIC handshake failed"),
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    error!(%error, "HY2 connection task crashed");
                }
            }
        });

        let mut guard = self.inner.lock().expect("hy2 server controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            endpoint,
            handle,
        });
        Ok(())
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self.inner.lock().expect("hy2 server controller poisoned");
            guard.take()
        };
        if let Some(old) = old {
            old.endpoint.close(VarInt::from_u32(0), b"server shutdown");
            old.handle.abort();
            info!(port = old.server_port, "HY2 endpoint stopped");
        }
    }
}

async fn build_endpoint(config: &EffectiveNodeConfig) -> anyhow::Result<Endpoint> {
    let rustls_config = tls::load_rustls_server_config(&config.tls.source, &[H3_ALPN.to_string()])
        .await
        .context("load HY2 TLS materials")?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .context("build HY2 QUIC TLS config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    server_config.transport_config(Arc::new(transport_config));
    let listen_ip = config.listen_ip.trim();
    let bind_addr: SocketAddr = format!("{listen_ip}:{}", config.server_port)
        .parse()
        .with_context(|| {
            format!(
                "parse HY2 listen address {listen_ip}:{}",
                config.server_port
            )
        })?;
    Endpoint::server(server_config, bind_addr).context("bind HY2 UDP endpoint")
}

async fn handle_connection(
    connection: quinn::Connection,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    routing: RoutingTable,
    cc_rx: String,
    udp_enabled: bool,
) -> anyhow::Result<()> {
    let Some(user) = authenticate_connection(&connection, users, cc_rx, udp_enabled).await? else {
        return Ok(());
    };
    if udp_enabled {
        let sessions = Arc::new(AsyncMutex::new(FxHashMap::default()));
        tokio::spawn(handle_udp_datagrams(
            connection.clone(),
            sessions,
            routing.clone(),
            accounting.clone(),
            user.clone(),
        ));
    }

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(error) => return Err(error).context("accept HY2 TCP stream"),
        };
        let accounting = accounting.clone();
        let routing = routing.clone();
        let user = user.clone();
        let remote = connection.remote_address();
        tokio::spawn(async move {
            if let Err(error) =
                handle_tcp_stream(send, recv, remote, accounting, user, routing).await
            {
                warn!(%error, "HY2 TCP stream failed");
            }
        });
    }
}

async fn authenticate_connection(
    connection: &quinn::Connection,
    users: Arc<RwLock<UserValidator>>,
    cc_rx: String,
    udp_enabled: bool,
) -> anyhow::Result<Option<UserEntry>> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3 = h3::server::builder()
        .build(h3_connection)
        .await
        .context("initialize HY2 HTTP/3 server")?;
    let resolver = tokio::time::timeout(AUTH_TIMEOUT, h3.accept())
        .await
        .context("HY2 auth request timed out")?
        .context("accept HY2 HTTP/3 request")?
        .ok_or_else(|| anyhow!("HY2 connection closed before auth"))?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .context("resolve HY2 auth request")?;

    if !is_auth_request(&request) {
        send_h3_status(&mut stream, 404).await?;
        return Ok(None);
    }

    let auth = request
        .headers()
        .get("Hysteria-Auth")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim();
    let user = users.read().expect("hy2 users lock poisoned").get(auth);
    let Some(user) = user else {
        send_h3_status(&mut stream, 404).await?;
        return Ok(None);
    };

    let response = http::Response::builder()
        .status(http::StatusCode::from_u16(233).context("build HY2 status code")?)
        .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
        .header("Hysteria-CC-RX", cc_rx)
        .header("Hysteria-Padding", "")
        .body(())
        .context("build HY2 auth response")?;
    stream
        .send_response(response)
        .await
        .context("send HY2 auth response")?;
    stream.finish().await.context("finish HY2 auth stream")?;
    Ok(Some(user))
}

fn is_auth_request(request: &http::Request<()>) -> bool {
    request.method() == http::Method::POST
        && request.uri().path() == AUTH_PATH
        && request
            .uri()
            .authority()
            .map(|authority| authority.as_str().eq_ignore_ascii_case(AUTH_HOST))
            .unwrap_or(false)
}

async fn send_h3_status<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: u16,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let response = http::Response::builder()
        .status(status)
        .body(())
        .with_context(|| format!("build HY2 HTTP/3 {status} response"))?;
    stream
        .send_response(response)
        .await
        .with_context(|| format!("send HY2 HTTP/3 {status} response"))?;
    stream
        .finish()
        .await
        .with_context(|| format!("finish HY2 HTTP/3 {status} response"))?;
    Ok(())
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    user: UserEntry,
    routing: RoutingTable,
) -> anyhow::Result<()> {
    let destination = match read_tcp_request(&mut recv).await {
        Ok(destination) => destination,
        Err(error) => {
            write_tcp_response(&mut send, 1, &error.to_string()).await?;
            let _ = send.finish();
            return Err(error);
        }
    };
    let remote = match transport::connect_tcp_destination(&destination, &routing).await {
        Ok(remote) => remote,
        Err(error) => {
            write_tcp_response(&mut send, 1, &error.to_string()).await?;
            let _ = send.finish();
            return Err(error).with_context(|| format!("connect HY2 destination {destination}"));
        }
    };
    write_tcp_response(&mut send, 0, "").await?;
    let lease = accounting.open_session(&user, source)?;
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let client_to_remote =
        copy_with_traffic(&mut recv, &mut remote_writer, control.clone(), upload);
    let remote_to_client = copy_with_traffic(&mut remote_reader, &mut send, control, download);
    let _ = tokio::try_join!(client_to_remote, remote_to_client)?;
    let _ = send.finish();
    Ok(())
}

type UdpSessions = Arc<AsyncMutex<FxHashMap<u32, Arc<UdpSession>>>>;

struct UdpSession {
    socket: Arc<UdpSocket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpMessage {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: String,
    payload: Vec<u8>,
}

async fn handle_udp_datagrams(
    connection: quinn::Connection,
    sessions: UdpSessions,
    routing: RoutingTable,
    accounting: Arc<Accounting>,
    user: UserEntry,
) {
    loop {
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(error) => {
                debug_connection_closed_as_udp_end(error);
                return;
            }
        };
        let upload = datagram.len() as u64;
        let message = match decode_udp_message(&datagram) {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "invalid HY2 UDP datagram");
                continue;
            }
        };
        if message.fragment_count != 1 || message.fragment_id != 0 {
            warn!(
                session_id = message.session_id,
                packet_id = message.packet_id,
                fragment_id = message.fragment_id,
                fragment_count = message.fragment_count,
                "HY2 UDP fragmentation is not implemented yet; dropping fragmented packet"
            );
            continue;
        }
        let destination = match parse_host_port(&message.address) {
            Ok(destination) => destination,
            Err(error) => {
                warn!(%error, address = %message.address, "resolve HY2 UDP target failed");
                continue;
            }
        };
        let target = match transport::resolve_destination(&destination, &routing, "udp").await {
            Ok(mut targets) => match targets.pop() {
                Some(target) => target,
                None => {
                    warn!(address = %message.address, "HY2 UDP target did not resolve");
                    continue;
                }
            },
            Err(error) => {
                warn!(%error, address = %message.address, "resolve HY2 UDP target failed");
                continue;
            }
        };
        let session = match get_or_create_udp_session(
            message.session_id,
            &connection,
            &sessions,
            accounting.clone(),
            user.clone(),
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                warn!(%error, session_id = message.session_id, "create HY2 UDP session failed");
                continue;
            }
        };
        let target = transport::normalize_udp_target(&session.socket, target);
        if let Err(error) = session.socket.send_to(&message.payload, target).await {
            warn!(%error, target = %target, "send HY2 UDP payload failed");
            continue;
        }
        TrafficRecorder::upload(accounting.clone(), user.id).record(upload);
    }
}

fn debug_connection_closed_as_udp_end(error: quinn::ConnectionError) {
    match error {
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::ConnectionClosed(_) => {}
        error => warn!(%error, "HY2 UDP datagram receiver stopped"),
    }
}

async fn get_or_create_udp_session(
    session_id: u32,
    connection: &quinn::Connection,
    sessions: &UdpSessions,
    accounting: Arc<Accounting>,
    user: UserEntry,
) -> anyhow::Result<Arc<UdpSession>> {
    if let Some(session) = sessions.lock().await.get(&session_id).cloned() {
        return Ok(session);
    }
    let socket = Arc::new(transport::bind_udp_socket().await?);
    let session = Arc::new(UdpSession {
        socket: socket.clone(),
    });
    sessions.lock().await.insert(session_id, session.clone());
    let connection = connection.clone();
    let download = TrafficRecorder::download(accounting, user.id);
    tokio::spawn(async move {
        if let Err(error) = relay_udp_responses(session_id, socket, connection, download).await {
            warn!(%error, session_id, "HY2 UDP response relay failed");
        }
    });
    Ok(session)
}

async fn relay_udp_responses(
    session_id: u32,
    socket: Arc<UdpSocket>,
    connection: quinn::Connection,
    traffic: TrafficRecorder,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (read, source) = tokio::select! {
            closed = connection.closed() => {
                debug_connection_closed_as_udp_end(closed);
                return Ok(());
            }
            result = socket.recv_from(&mut buffer) => result.context("receive HY2 UDP response")?,
        };
        let message = UdpMessage {
            session_id,
            packet_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            address: source.to_string(),
            payload: buffer[..read].to_vec(),
        };
        let encoded = encode_udp_message(&message)?;
        match connection.send_datagram(Bytes::from(encoded.clone())) {
            Ok(()) => traffic.record(encoded.len() as u64),
            Err(error) => return Err(error).context("send HY2 UDP datagram"),
        }
    }
}

async fn read_tcp_request<R>(reader: &mut R) -> anyhow::Result<SocksAddr>
where
    R: AsyncRead + Unpin,
{
    let request_id = read_varint(reader).await?;
    ensure!(
        request_id == HY2_TCP_REQUEST_ID,
        "unsupported HY2 request id {request_id:#x}"
    );
    let address_len = read_varint(reader).await?;
    ensure!(address_len <= 2048, "HY2 address is too long");
    let mut address = vec![0u8; address_len as usize];
    reader
        .read_exact(&mut address)
        .await
        .context("read HY2 target address")?;
    let padding_len = read_varint(reader).await?;
    discard_exact(reader, padding_len as usize).await?;
    parse_host_port(std::str::from_utf8(&address).context("decode HY2 target address")?)
}

async fn write_tcp_response<W>(writer: &mut W, status: u8, message: &str) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut response = Vec::with_capacity(1 + message.len() + 2);
    response.push(status);
    encode_varint(message.len() as u64, &mut response)?;
    response.extend_from_slice(message.as_bytes());
    encode_varint(0, &mut response)?;
    writer
        .write_all(&response)
        .await
        .context("write HY2 TCP response")
}

async fn copy_with_traffic<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
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
            read = reader.read(&mut buffer) => read.context("read HY2 proxied chunk")?,
        };
        if read == 0 {
            writer.shutdown().await.ok();
            return Ok(total);
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => result.context("write HY2 proxied chunk")?,
        }
        total += read as u64;
        traffic.record(read as u64);
    }
}

async fn read_varint<R>(reader: &mut R) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let first = reader.read_u8().await.context("read HY2 varint")?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(reader.read_u8().await.context("read HY2 varint")?);
    }
    Ok(value)
}

fn encode_varint(value: u64, output: &mut Vec<u8>) -> anyhow::Result<()> {
    if value < (1 << 6) {
        output.push(value as u8);
    } else if value < (1 << 14) {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else if value < (1 << 62) {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        bail!("HY2 varint value is too large: {value}");
    }
    Ok(())
}

fn decode_udp_message(mut bytes: &[u8]) -> anyhow::Result<UdpMessage> {
    ensure!(bytes.len() >= 8, "HY2 UDP datagram is too short");
    let session_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let packet_id = u16::from_be_bytes([bytes[4], bytes[5]]);
    let fragment_id = bytes[6];
    let fragment_count = bytes[7];
    bytes = &bytes[8..];
    let address_len = read_varint_from_slice(&mut bytes)?;
    ensure!(address_len <= 2048, "HY2 UDP address is too long");
    ensure!(
        bytes.len() >= address_len as usize,
        "HY2 UDP address is truncated"
    );
    let (address, payload) = bytes.split_at(address_len as usize);
    Ok(UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address: std::str::from_utf8(address)
            .context("decode HY2 UDP address")?
            .to_string(),
        payload: payload.to_vec(),
    })
}

fn encode_udp_message(message: &UdpMessage) -> anyhow::Result<Vec<u8>> {
    let address = message.address.as_bytes();
    let mut encoded = Vec::with_capacity(8 + address.len() + message.payload.len() + 8);
    encoded.extend_from_slice(&message.session_id.to_be_bytes());
    encoded.extend_from_slice(&message.packet_id.to_be_bytes());
    encoded.push(message.fragment_id);
    encoded.push(message.fragment_count);
    encode_varint(address.len() as u64, &mut encoded)?;
    encoded.extend_from_slice(address);
    encoded.extend_from_slice(&message.payload);
    Ok(encoded)
}

fn read_varint_from_slice(bytes: &mut &[u8]) -> anyhow::Result<u64> {
    ensure!(!bytes.is_empty(), "HY2 varint is truncated");
    let first = bytes[0];
    let len = 1usize << (first >> 6);
    ensure!(bytes.len() >= len, "HY2 varint is truncated");
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    *bytes = &bytes[len..];
    Ok(value)
}

async fn discard_exact<R>(reader: &mut R, length: usize) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut remaining = length;
    let mut buffer = [0u8; 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        reader
            .read_exact(&mut buffer[..take])
            .await
            .context("discard HY2 padding")?;
        remaining -= take;
    }
    Ok(())
}

fn parse_host_port(value: &str) -> anyhow::Result<SocksAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(SocksAddr::Ip(addr));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("HY2 target address must be host:port"))?;
    let port = port
        .trim()
        .parse::<u16>()
        .context("parse HY2 target port")?;
    ensure!(!host.trim().is_empty(), "HY2 target host is required");
    match host.trim().parse::<IpAddr>() {
        Ok(ip) => Ok(SocksAddr::Ip(SocketAddr::new(ip, port))),
        Err(_) => Ok(SocksAddr::Domain(host.trim().to_string(), port)),
    }
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if remote.tls_mode() == 2
        || remote.reality_settings.is_configured()
        || remote.tls_settings.has_reality_key_material()
    {
        bail!("HY2 does not support REALITY TLS mode");
    }
    let network = remote.network.trim();
    ensure!(
        network.is_empty()
            || network.eq_ignore_ascii_case("udp")
            || network.eq_ignore_ascii_case("quic")
            || network.eq_ignore_ascii_case("hysteria2")
            || network.eq_ignore_ascii_case("hy2"),
        "HY2 network must be empty, udp, quic, hysteria2 or hy2"
    );
    if remote
        .obfs
        .as_ref()
        .is_some_and(crate::panel::json_value_is_enabled)
        || !remote.obfs_password.trim().is_empty()
    {
        bail!("HY2 salamander obfs is not implemented yet");
    }
    if remote.udp_over_stream {
        bail!("HY2 udp_over_stream is not supported by the HY2 protocol datagram relay");
    }
    if remote.multiplex_enabled() {
        bail!("HY2 multiplex is not a server-side setting");
    }
    Ok(())
}

fn is_disabled_udp_relay_mode(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "false" | "off" | "no" | "none" | "disabled"
    )
}

fn hy2_udp_enabled(value: &str) -> bool {
    !is_disabled_udp_relay_mode(value)
}

fn hy2_cc_rx(
    value: Option<&serde_json::Value>,
    ignore_client_bandwidth: bool,
) -> anyhow::Result<String> {
    if ignore_client_bandwidth {
        return Ok("auto".to_string());
    }
    let Some(mbps) = value.map(value_to_u64).transpose()? else {
        return Ok("0".to_string());
    };
    Ok(mbps.saturating_mul(125_000).to_string())
}

fn value_to_u64(value: &serde_json::Value) -> anyhow::Result<u64> {
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| anyhow!("HY2 bandwidth must be a non-negative integer")),
        serde_json::Value::String(text) => {
            text.trim().parse::<u64>().context("parse HY2 bandwidth")
        }
        _ => bail!("HY2 bandwidth must be a number or decimal string"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::CertConfig;

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "hysteria2".to_string(),
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
    fn parses_hy2_remote_config() {
        let remote = NodeConfigResponse {
            down_mbps: Some(serde_json::json!(100)),
            udp_relay_mode: "native".to_string(),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.cc_rx, "12500000");
        assert_eq!(config.tls.alpn, vec!["h3".to_string()]);
        assert!(config.udp_enabled);
    }

    #[test]
    fn hy2_ignore_client_bandwidth_uses_auto_cc_rx() {
        let remote = NodeConfigResponse {
            down_mbps: Some(serde_json::json!(100)),
            ignore_client_bandwidth: true,
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.cc_rx, "auto");
    }

    #[test]
    fn rejects_hy2_obfs_until_salamander_is_supported() {
        let remote = NodeConfigResponse {
            obfs: Some(serde_json::json!("salamander")),
            obfs_password: "secret".to_string(),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("obfs");
        assert!(error.to_string().contains("salamander obfs"));
    }

    #[test]
    fn encodes_and_decodes_hy2_varints() {
        let values = [0, 63, 64, 16_383, 16_384, 1_073_741_823];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        for value in values {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).expect("encode");
            let decoded = runtime
                .block_on(async { read_varint(&mut encoded.as_slice()).await })
                .expect("decode");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn encodes_and_decodes_hy2_udp_messages() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 9,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:53".to_string(),
            payload: b"hello".to_vec(),
        };

        let encoded = encode_udp_message(&message).expect("encode");
        let decoded = decode_udp_message(&encoded).expect("decode");

        assert_eq!(decoded, message);
    }

    #[test]
    fn parses_hy2_host_port_targets() {
        assert_eq!(
            parse_host_port("example.com:443").expect("domain"),
            SocksAddr::Domain("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:53").expect("ip"),
            SocksAddr::Ip("127.0.0.1:53".parse().expect("addr"))
        );
    }

    #[test]
    fn validates_hy2_users_from_password_or_uuid() {
        let validator = UserValidator::from_users(&[PanelUser {
            id: 1,
            uuid: "uuid-auth".to_string(),
            password: "pass-auth".to_string(),
            ..Default::default()
        }])
        .expect("validator");

        assert_eq!(validator.get("uuid-auth").map(|user| user.id), Some(1));
        assert_eq!(validator.get("pass-auth").map(|user| user.id), Some(1));
    }
}
