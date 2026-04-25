use anyhow::{Context, anyhow, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use super::anytls::{
    EffectiveTlsConfig, bind_listeners, configure_tcp_stream, effective_listen_ip, routing,
    socksaddr::SocksAddr, tls, traffic::TrafficRecorder, transport,
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const COPY_BUFFER_LEN: usize = 64 * 1024;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const CRLF: [u8; 2] = *b"\r\n";
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TROJAN_AUTH_HEX_LEN: usize = 56;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

type TlsStream = tokio_boring::SslStream<TcpStream>;

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: EffectiveTlsConfig,
    pub routing: routing::RoutingTable,
    pub fallbacks: FallbackConfig,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls: EffectiveTlsConfig::from_remote(remote)?,
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
            Some(value) => Some(parse_fallback_target(value).context("decode Trojan fallback")?),
            None => None,
        };

        let by_alpn = match remote.fallback_for_alpn.as_ref() {
            Some(value) => parse_fallback_map(value).context("decode Trojan fallback_for_alpn")?,
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

#[derive(Clone, Default)]
struct UserValidator {
    by_auth: HashMap<[u8; TROJAN_AUTH_HEX_LEN], UserEntry>,
}

impl UserValidator {
    fn from_users(users: &[PanelUser]) -> anyhow::Result<Self> {
        let mut by_auth = HashMap::new();
        for user in users {
            let password = effective_password(user)
                .ok_or_else(|| anyhow!("Trojan user {} is missing password/uuid", user.id))?;
            let auth = trojan_auth(password);
            ensure!(
                by_auth
                    .insert(auth, UserEntry::from_panel_user(user))
                    .is_none(),
                "duplicate Trojan credentials for user {}",
                user.id
            );
        }
        Ok(Self { by_auth })
    }

    fn get(&self, auth: &[u8; TROJAN_AUTH_HEX_LEN]) -> Option<UserEntry> {
        self.by_auth.get(auth).cloned()
    }
}

pub struct ServerController {
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    tls_materials: AsyncMutex<Option<tls::LoadedTlsMaterials>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
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
            routing: Arc::new(RwLock::new(routing::RoutingTable::default())),
            fallbacks: Arc::new(RwLock::new(FallbackConfig::default())),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        let validator = UserValidator::from_users(users)?;
        self.accounting.replace_users(users);
        *self.users.write().expect("trojan users lock poisoned") = validator;
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        *self.routing.write().expect("trojan routing lock poisoned") = config.routing;
        *self
            .fallbacks
            .write()
            .expect("trojan fallback lock poisoned") = config.fallbacks;
        self.update_tls_config(&config.tls).await?;

        let old = {
            let mut guard = self
                .inner
                .lock()
                .expect("trojan server controller poisoned");
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
        let routing = self.routing.clone();
        let fallbacks = self.fallbacks.clone();
        let handle = tokio::spawn(async move {
            info!(listen = ?bind_addrs, "Trojan listeners started");
            let mut accept_loops = JoinSet::new();
            for listener in listeners {
                let tls_config = tls_config.clone();
                let accounting = accounting.clone();
                let users = users.clone();
                let routing = routing.clone();
                let fallbacks = fallbacks.clone();
                accept_loops.spawn(async move {
                    accept_loop(listener, tls_config, accounting, users, routing, fallbacks).await;
                });
            }

            while let Some(result) = accept_loops.join_next().await {
                match result {
                    Ok(()) => warn!("Trojan accept loop exited unexpectedly"),
                    Err(error) if error.is_cancelled() => break,
                    Err(error) => error!(%error, "Trojan accept loop crashed"),
                }
            }
        });

        let mut guard = self
            .inner
            .lock()
            .expect("trojan server controller poisoned");
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
                .expect("trojan tls config lock poisoned") = Some(reloaded);
            info!("Trojan TLS materials reloaded from disk");
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self
                .inner
                .lock()
                .expect("trojan server controller poisoned");
            guard.take()
        };
        if let Some(old) = old {
            old.handle.abort();
            info!(port = old.server_port, "Trojan listeners stopped");
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
            .context("load Trojan TLS materials")?;
        *self
            .tls_config
            .write()
            .expect("trojan tls config lock poisoned") = Some(reloaded.acceptor());
        *tls_materials = Some(reloaded);
        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
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
                error!(%error, listen = %listen, "accept Trojan connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let acceptor = {
            let tls_config = tls_config
                .read()
                .expect("trojan tls config lock poisoned")
                .clone();
            let Some(tls_config) = tls_config else {
                warn!(listen = %listen, "Trojan TLS config is not ready; dropping connection");
                continue;
            };
            tls_config
        };
        let accounting = accounting.clone();
        let users = users.clone();
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
                    warn!(%error, %source, "Trojan TLS handshake failed");
                    return;
                }
                Err(_) => {
                    warn!(%source, "Trojan TLS handshake timed out");
                    return;
                }
            };
            let users = users.read().expect("trojan users lock poisoned").clone();
            let routing = routing
                .read()
                .expect("trojan routing lock poisoned")
                .clone();
            let fallbacks = fallbacks
                .read()
                .expect("trojan fallback lock poisoned")
                .clone();
            if let Err(error) =
                serve_connection(tls_stream, source, accounting, users, routing, fallbacks).await
            {
                warn!(%error, %source, "Trojan session terminated with error");
            }
        });
    }
}

async fn serve_connection(
    mut stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    routing: routing::RoutingTable,
    fallbacks: FallbackConfig,
) -> anyhow::Result<()> {
    let negotiated_alpn = stream
        .ssl()
        .selected_alpn_protocol()
        .map(|value| value.to_vec());
    let mut consumed = Vec::with_capacity(128);
    let handshake = timeout(
        AUTHENTICATION_TIMEOUT,
        read_handshake(&mut stream, &users, &mut consumed),
    )
    .await;

    let (user, command) = match handshake {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            if let Some(target) = fallbacks.select(negotiated_alpn.as_deref()) {
                proxy_fallback(stream, target, consumed).await?;
                return Ok(());
            }
            return Err(error);
        }
        Err(_) => {
            return Err(anyhow!("Trojan authentication timed out"));
        }
    };

    let lease = accounting.open_session(&user, source)?;
    match command {
        TrojanCommand::Connect(destination) => {
            serve_connect(stream, accounting, lease, user, destination, routing).await
        }
        TrojanCommand::UdpAssociate(destination) => {
            serve_udp_associate(stream, accounting, lease, user, destination, routing).await
        }
    }
}

async fn serve_connect(
    stream: TlsStream,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    destination: SocksAddr,
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let remote = transport::connect_tcp_destination(&destination, &routing)
        .await
        .with_context(|| format!("connect Trojan destination {destination}"))?;
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);
    let (mut client_reader, mut client_writer) = split(stream);
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

async fn serve_udp_associate(
    stream: TlsStream,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    _destination: SocksAddr,
    routing: routing::RoutingTable,
) -> anyhow::Result<()> {
    let socket = Arc::new(transport::bind_udp_socket().await?);
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);
    let (reader, writer) = split(stream);
    let select_control = control.clone();

    let mut client_task = tokio::spawn({
        let socket = socket.clone();
        let control = control.clone();
        let routing = routing.clone();
        async move { relay_client_to_udp(reader, socket, control, routing, upload).await }
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

async fn proxy_fallback(
    stream: TlsStream,
    target: &FallbackTarget,
    consumed: Vec<u8>,
) -> anyhow::Result<()> {
    let fallback = TcpStream::connect((target.server.as_str(), target.server_port))
        .await
        .with_context(|| {
            format!(
                "connect Trojan fallback {}:{}",
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
            .context("write Trojan fallback preface")?;
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

async fn relay_client_to_udp(
    mut reader: ReadHalf<TlsStream>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    routing: routing::RoutingTable,
    traffic: TrafficRecorder,
) -> anyhow::Result<()> {
    let mut destination_cache = HashMap::new();
    loop {
        let packet = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            packet = read_udp_packet(&mut reader) => packet?,
        };
        let Some(packet) = packet else {
            return Ok(());
        };

        let target =
            resolve_udp_target(&packet.destination, &routing, &mut destination_cache).await?;
        let target = transport::normalize_udp_target(&socket, target);
        let sent = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            sent = socket.send_to(&packet.payload, target) => sent.with_context(|| format!("send Trojan UDP payload to {target}"))?,
        };
        if sent != packet.payload.len() {
            bail!(
                "short Trojan UDP send: expected {}, wrote {}",
                packet.payload.len(),
                sent
            );
        }
        traffic.record(packet.wire_len as u64);
    }
}

async fn relay_udp_to_client(
    mut writer: WriteHalf<TlsStream>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (payload_len, source) = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = socket.recv_from(&mut buffer) => read.context("receive Trojan UDP payload")?,
        };
        let encoded = encode_udp_packet(
            &SocksAddr::Ip(transport::normalize_udp_source(source)),
            &buffer[..payload_len],
        )?;
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&encoded) => result.context("write Trojan UDP response")?,
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
            read = reader.read(&mut buffer) => read.context("read Trojan proxied chunk")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => result.context("write Trojan proxied chunk")?,
        }
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
    }
}

#[derive(Debug)]
enum TrojanCommand {
    Connect(SocksAddr),
    UdpAssociate(SocksAddr),
}

#[derive(Debug)]
struct TrojanUdpPacket {
    destination: SocksAddr,
    payload: Vec<u8>,
    wire_len: usize,
}

async fn read_handshake(
    stream: &mut TlsStream,
    users: &UserValidator,
    consumed: &mut Vec<u8>,
) -> anyhow::Result<(UserEntry, TrojanCommand)> {
    let auth = read_auth_token(stream, consumed).await?;
    let user = users
        .get(&auth)
        .ok_or_else(|| anyhow!("unknown Trojan user"))?;
    let command = read_request(stream, consumed).await?;
    Ok((user, command))
}

async fn read_auth_token<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
) -> anyhow::Result<[u8; TROJAN_AUTH_HEX_LEN]>
where
    R: AsyncRead + Unpin,
{
    let mut auth = [0u8; TROJAN_AUTH_HEX_LEN];
    read_exact_recorded(reader, &mut auth, consumed, "read Trojan auth token").await?;
    ensure_crlf(reader, consumed, "read Trojan auth delimiter").await?;
    Ok(auth)
}

async fn read_request<R>(reader: &mut R, consumed: &mut Vec<u8>) -> anyhow::Result<TrojanCommand>
where
    R: AsyncRead + Unpin,
{
    let cmd = read_u8_recorded(reader, consumed, "read Trojan command").await?;
    let destination = read_socks_addr_recorded(reader, consumed).await?;
    ensure_crlf(reader, consumed, "read Trojan request delimiter").await?;

    match cmd {
        CMD_CONNECT => Ok(TrojanCommand::Connect(destination)),
        CMD_UDP_ASSOCIATE => Ok(TrojanCommand::UdpAssociate(destination)),
        other => bail!("unsupported Trojan command {other:#x}"),
    }
}

async fn resolve_udp_target(
    destination: &SocksAddr,
    routing: &routing::RoutingTable,
    cache: &mut HashMap<String, SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    let cache_key = destination.to_string();
    if let Some(target) = cache.get(&cache_key) {
        return Ok(*target);
    }

    let target = transport::resolve_destination(destination, routing, "udp")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no UDP addresses resolved for {destination}"))?;
    cache.insert(cache_key, target);
    Ok(target)
}

async fn read_udp_packet<R>(reader: &mut R) -> anyhow::Result<Option<TrojanUdpPacket>>
where
    R: AsyncRead + Unpin,
{
    let Some((destination, addr_len)) = read_udp_destination(reader).await? else {
        return Ok(None);
    };
    let length = read_u16(reader, "read Trojan UDP payload length").await?;
    ensure_crlf_plain(reader, "read Trojan UDP delimiter").await?;
    let mut payload = vec![0u8; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .context("read Trojan UDP payload")?;
    Ok(Some(TrojanUdpPacket {
        destination,
        payload,
        wire_len: addr_len + 2 + CRLF.len() + length as usize,
    }))
}

async fn read_udp_destination<R>(reader: &mut R) -> anyhow::Result<Option<(SocksAddr, usize)>>
where
    R: AsyncRead + Unpin,
{
    let atyp = match reader.read_u8().await {
        Ok(atyp) => atyp,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read Trojan UDP address type"),
    };

    let destination = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .context("read Trojan UDP IPv4 address")?;
            let port = read_u16(reader, "read Trojan UDP IPv4 port").await?;
            (
                SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)),
                1 + 4 + 2,
            )
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .context("read Trojan UDP IPv6 address")?;
            let port = read_u16(reader, "read Trojan UDP IPv6 port").await?;
            (
                SocksAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                1 + 16 + 2,
            )
        }
        ATYP_DOMAIN => {
            let length = reader
                .read_u8()
                .await
                .context("read Trojan UDP domain length")?;
            let mut domain = vec![0u8; length as usize];
            reader
                .read_exact(&mut domain)
                .await
                .context("read Trojan UDP domain")?;
            let port = read_u16(reader, "read Trojan UDP domain port").await?;
            (
                SocksAddr::Domain(
                    String::from_utf8(domain).context("decode Trojan UDP domain")?,
                    port,
                ),
                1 + 1 + length as usize + 2,
            )
        }
        other => bail!("unsupported Trojan UDP address type {other:#x}"),
    };
    Ok(Some(destination))
}

async fn read_u16<R>(reader: &mut R, context: &str) -> anyhow::Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    reader
        .read_exact(&mut bytes)
        .await
        .with_context(|| context.to_string())?;
    Ok(u16::from_be_bytes(bytes))
}

async fn ensure_crlf_plain<R>(reader: &mut R, context: &str) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut delimiter = [0u8; 2];
    reader
        .read_exact(&mut delimiter)
        .await
        .with_context(|| context.to_string())?;
    ensure!(delimiter == CRLF, "Trojan delimiter must be CRLF");
    Ok(())
}

fn encode_udp_packet(source: &SocksAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        bail!("Trojan UDP payload too large: {}", payload.len());
    }

    let mut encoded = Vec::with_capacity(address_wire_len(source) + 2 + CRLF.len() + payload.len());
    write_socks_addr(&mut encoded, source)?;
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&CRLF);
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn write_socks_addr(buffer: &mut Vec<u8>, destination: &SocksAddr) -> anyhow::Result<()> {
    match destination {
        SocksAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buffer.push(ATYP_IPV4);
                buffer.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buffer.push(ATYP_IPV6);
                buffer.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain(host, _) => {
            let host = host.as_bytes();
            if host.len() > u8::MAX as usize {
                bail!("Trojan domain too long: {}", host.len());
            }
            buffer.push(ATYP_DOMAIN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host);
        }
    }

    let port = match destination {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn address_wire_len(destination: &SocksAddr) -> usize {
    match destination {
        SocksAddr::Ip(addr) if addr.is_ipv4() => 1 + 4 + 2,
        SocksAddr::Ip(_) => 1 + 16 + 2,
        SocksAddr::Domain(host, _) => 1 + 1 + host.len() + 2,
    }
}

fn flatten_join(result: Result<anyhow::Result<()>, tokio::task::JoinError>) -> anyhow::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error).context("join Trojan UDP relay task"),
    }
}

async fn read_socks_addr_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
) -> anyhow::Result<SocksAddr>
where
    R: AsyncRead + Unpin,
{
    let atyp = read_u8_recorded(reader, consumed, "read Trojan address type").await?;
    match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            read_exact_recorded(reader, &mut octets, consumed, "read Trojan IPv4 address").await?;
            let port = read_u16_recorded(reader, consumed, "read Trojan IPv4 port").await?;
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            read_exact_recorded(reader, &mut octets, consumed, "read Trojan IPv6 address").await?;
            let port = read_u16_recorded(reader, consumed, "read Trojan IPv6 port").await?;
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let length = read_u8_recorded(reader, consumed, "read Trojan domain length").await?;
            let mut domain = vec![0u8; length as usize];
            read_exact_recorded(reader, &mut domain, consumed, "read Trojan domain").await?;
            let port = read_u16_recorded(reader, consumed, "read Trojan domain port").await?;
            Ok(SocksAddr::Domain(
                String::from_utf8(domain).context("decode Trojan domain")?,
                port,
            ))
        }
        other => bail!("unsupported Trojan address type {other:#x}"),
    }
}

async fn ensure_crlf<R>(reader: &mut R, consumed: &mut Vec<u8>, context: &str) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut delimiter = [0u8; 2];
    read_exact_recorded(reader, &mut delimiter, consumed, context).await?;
    ensure!(delimiter == CRLF, "Trojan delimiter must be CRLF");
    Ok(())
}

async fn read_u8_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
    context: &str,
) -> anyhow::Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    read_exact_recorded(reader, &mut byte, consumed, context).await?;
    Ok(byte[0])
}

async fn read_u16_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
    context: &str,
) -> anyhow::Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    read_exact_recorded(reader, &mut bytes, consumed, context).await?;
    Ok(u16::from_be_bytes(bytes))
}

async fn read_exact_recorded<R>(
    reader: &mut R,
    buffer: &mut [u8],
    consumed: &mut Vec<u8>,
    context: &str,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    reader
        .read_exact(buffer)
        .await
        .with_context(|| context.to_string())?;
    consumed.extend_from_slice(buffer);
    Ok(())
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !remote.network.trim().is_empty() && !remote.network.eq_ignore_ascii_case("tcp") {
        anyhow::bail!("Xboard network must be tcp for Trojan nodes");
    }
    if remote.tls.is_some() && remote.tls_mode() != 1 {
        anyhow::bail!(
            "Xboard tls mode {} is not supported by NodeRS Trojan server yet",
            remote.tls_mode()
        );
    }
    if remote.network_settings.is_some() {
        anyhow::bail!("Xboard networkSettings is not supported by NodeRS Trojan server yet");
    }
    if remote.transport.is_some() {
        anyhow::bail!("Xboard transport is not supported by NodeRS Trojan server yet");
    }
    if remote.multiplex_enabled() {
        anyhow::bail!("Xboard multiplex is not supported by NodeRS Trojan server yet");
    }
    if remote.fallbacks.is_some() {
        anyhow::bail!("Xboard fallbacks is not supported by NodeRS Trojan server yet");
    }
    Ok(())
}

fn parse_fallback_map(
    value: &serde_json::Value,
) -> anyhow::Result<HashMap<String, FallbackTarget>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Trojan fallback_for_alpn must be an object"))?;
    let mut targets = HashMap::new();
    for (alpn, value) in object {
        let key = alpn.trim();
        ensure!(
            !key.is_empty(),
            "Trojan fallback_for_alpn contains empty ALPN"
        );
        ensure!(
            targets
                .insert(key.to_string(), parse_fallback_target(value)?)
                .is_none(),
            "duplicate Trojan fallback_for_alpn entry {key}"
        );
    }
    Ok(targets)
}

fn parse_fallback_target(value: &serde_json::Value) -> anyhow::Result<FallbackTarget> {
    let target: FallbackTarget =
        serde_json::from_value(value.clone()).context("parse Trojan fallback target")?;
    ensure!(
        !target.server.trim().is_empty() && target.server_port > 0,
        "Trojan fallback target requires server and server_port"
    );
    Ok(target)
}

fn effective_password(user: &PanelUser) -> Option<&str> {
    let password = user.password.trim();
    if !password.is_empty() {
        return Some(password);
    }
    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return Some(uuid);
    }
    None
}

fn trojan_auth(password: &str) -> [u8; TROJAN_AUTH_HEX_LEN] {
    let digest = Sha224::digest(password.as_bytes());
    let mut auth = [0u8; TROJAN_AUTH_HEX_LEN];
    for (index, byte) in digest.iter().enumerate() {
        auth[index * 2] = HEX_LOWER[(byte >> 4) as usize];
        auth[index * 2 + 1] = HEX_LOWER[(byte & 0x0f) as usize];
    }
    auth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::CertConfig;

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "trojan".to_string(),
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
    fn trojan_auth_uses_lower_hex_sha224() {
        let auth = trojan_auth("password");
        assert_eq!(
            std::str::from_utf8(&auth).expect("utf8 auth"),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn validator_uses_password_override_before_uuid() {
        let validator = UserValidator::from_users(&[PanelUser {
            id: 7,
            uuid: "uuid-secret".to_string(),
            password: "real-password".to_string(),
            ..Default::default()
        }])
        .expect("validator");

        assert!(validator.get(&trojan_auth("real-password")).is_some());
        assert!(validator.get(&trojan_auth("uuid-secret")).is_none());
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

    #[tokio::test]
    async fn reads_trojan_connect_request() {
        let mut bytes = &b"\x01\x03\x0bexample.com\x01\xbb\r\n"[..];
        let command = read_request(&mut bytes, &mut Vec::new())
            .await
            .expect("parse request");
        match command {
            TrojanCommand::Connect(SocksAddr::Domain(host, port)) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected Trojan connect request"),
        }
    }

    #[tokio::test]
    async fn reads_trojan_udp_associate_request() {
        let mut bytes = &b"\x03\x01\x7f\x00\x00\x01\x005\r\n"[..];
        let command = read_request(&mut bytes, &mut Vec::new())
            .await
            .expect("parse request");
        match command {
            TrojanCommand::UdpAssociate(SocksAddr::Ip(destination)) => {
                assert_eq!(destination, SocketAddr::from(([127, 0, 0, 1], 53)));
            }
            _ => panic!("expected Trojan UDP associate request"),
        }
    }

    #[tokio::test]
    async fn reads_trojan_udp_packet() {
        let mut bytes = &b"\x03\x0bexample.com\x01\xbb\x00\x05\r\nhello"[..];
        let packet = read_udp_packet(&mut bytes)
            .await
            .expect("read packet")
            .expect("packet exists");
        assert_eq!(
            packet.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
        assert_eq!(packet.payload, b"hello");
        assert_eq!(packet.wire_len, 1 + 1 + 11 + 2 + 2 + 2 + 5);
    }

    #[test]
    fn encodes_trojan_udp_packet() {
        let encoded =
            encode_udp_packet(&SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 53))), b"abc")
                .expect("encode packet");
        assert_eq!(encoded, b"\x01\x01\x02\x03\x04\x005\x00\x03\r\nabc");
    }

    #[test]
    fn rejects_unsupported_transport_extensions() {
        let remote = NodeConfigResponse {
            transport: Some(serde_json::json!({
                "type": "ws"
            })),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("transport");
        assert!(error.to_string().contains("transport"));
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
}
