use anyhow::{Context, anyhow, bail, ensure};
use boring::ssl::NameType;
use serde::Deserialize;
use sha2::{Digest, Sha224};
use std::collections::{HashMap, HashSet};
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
    #[serde(deserialize_with = "crate::panel::deserialize_u16_from_number_or_string")]
    server_port: u16,
    #[serde(default)]
    xver: u8,
}

#[derive(Debug, Clone)]
struct ParsedFallbackEntry {
    name: Option<String>,
    alpn: Option<String>,
    path: Option<String>,
    target: FallbackTarget,
}

impl FallbackConfig {
    fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        let mut config = Self::default();

        if let Some(value) = remote.fallbacks.as_ref() {
            config.merge_xboard_fallbacks(value)?;
        }

        let default = match remote.fallback.as_ref() {
            Some(value) => Some(parse_fallback_target(value).context("decode Trojan fallback")?),
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
            Some(value) => parse_fallback_map(value).context("decode Trojan fallback_for_alpn")?,
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
            .ok_or_else(|| anyhow!("Xboard Trojan fallbacks must be an array"))?;
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
    panel_users: Arc<RwLock<Vec<PanelUser>>>,
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
            panel_users: Arc::new(RwLock::new(Vec::new())),
            users: Arc::new(RwLock::new(UserValidator::default())),
            routing: Arc::new(RwLock::new(routing::RoutingTable::default())),
            fallbacks: Arc::new(RwLock::new(FallbackConfig::default())),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        let validator = UserValidator::from_users(users)?;
        let previous = self
            .panel_users
            .read()
            .expect("trojan panel users lock poisoned")
            .iter()
            .map(|user| (user.id, effective_password(user).map(str::to_string)))
            .collect::<HashMap<_, _>>();
        let rotated_ids = users
            .iter()
            .filter_map(|user| {
                let current = effective_password(user).map(str::to_string);
                previous
                    .get(&user.id)
                    .filter(|previous| **previous != current)
                    .map(|_| user.id)
            })
            .collect::<HashSet<_>>();
        *self
            .panel_users
            .write()
            .expect("trojan panel users lock poisoned") = users.to_vec();
        *self.users.write().expect("trojan users lock poisoned") = validator;
        self.accounting.replace_users(users);
        self.accounting.cancel_sessions_for_ids(&rotated_ids);
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
            !current.matches_source(&tls.source, tls.ech.as_ref(), None, &tls.alpn)
        });
        if !should_reload {
            return Ok(());
        }

        let reloaded = tls::load_tls_materials(&tls.source, tls.ech.as_ref(), None, &tls.alpn)
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
    let server_name = stream
        .ssl()
        .servername(NameType::HOST_NAME)
        .map(str::to_string);
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
            if let Some(target) = fallbacks.select(
                server_name.as_deref(),
                negotiated_alpn.as_deref(),
                &consumed,
            ) {
                proxy_fallback(stream, source, target, consumed).await?;
                return Ok(());
            }
            return Err(error);
        }
        Err(_) => {
            if let Some(target) = fallbacks.select(
                server_name.as_deref(),
                negotiated_alpn.as_deref(),
                &consumed,
            ) {
                proxy_fallback(stream, source, target, consumed).await?;
                return Ok(());
            }
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
    source: SocketAddr,
    target: &FallbackTarget,
    consumed: Vec<u8>,
) -> anyhow::Result<()> {
    let local = stream
        .get_ref()
        .local_addr()
        .context("read Trojan fallback local address")?;
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
    if target.xver != 0 {
        let header = encode_proxy_header(source, local, target.xver)?;
        fallback_writer
            .write_all(&header)
            .await
            .context("write Trojan fallback proxy protocol header")?;
    }
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
                Err(error) => return Err(error).context("read Trojan proxied chunk"),
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
                Err(error) => return Err(error).context("write Trojan proxied chunk"),
            },
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
    let mut read_total = 0;
    while read_total < buffer.len() {
        let read = reader
            .read(&mut buffer[read_total..])
            .await
            .with_context(|| context.to_string())?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                .with_context(|| context.to_string());
        }
        consumed.extend_from_slice(&buffer[read_total..read_total + read]);
        read_total += read;
    }
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
    if remote
        .network_settings
        .as_ref()
        .is_some_and(json_value_effectively_enabled)
    {
        anyhow::bail!("Xboard networkSettings is not supported by NodeRS Trojan server yet");
    }
    if let Some(transport) = remote.transport.as_ref() {
        validate_transport_field(transport)?;
    }
    if remote.multiplex_enabled() {
        anyhow::bail!("Xboard multiplex is not supported by NodeRS Trojan server yet");
    }
    Ok(())
}

fn validate_transport_field(value: &serde_json::Value) -> anyhow::Result<()> {
    let Some(object) = value.as_object() else {
        bail!("Xboard transport must be an object when provided");
    };
    let transport_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if transport_type.is_empty() || transport_type.eq_ignore_ascii_case("tcp") {
        return Ok(());
    }
    bail!("Xboard transport is not supported by NodeRS Trojan server yet")
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
        serde_json::Value::Array(items) => items.iter().any(json_value_effectively_enabled),
        serde_json::Value::Object(object) => object.values().any(json_value_effectively_enabled),
    }
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
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), value.port()))
            .unwrap_or(SocketAddr::V6(value)),
        other => other,
    }
}

fn encode_proxy_header(source: SocketAddr, local: SocketAddr, xver: u8) -> anyhow::Result<Vec<u8>> {
    let source = normalize_proxy_addr(source);
    let local = normalize_proxy_addr(local);
    match xver {
        1 => Ok(match (source.ip(), local.ip()) {
            (IpAddr::V4(source_ip), IpAddr::V4(local_ip)) => format!(
                "PROXY TCP4 {source_ip} {local_ip} {} {}\r\n",
                source.port(),
                local.port()
            )
            .into_bytes(),
            (IpAddr::V6(source_ip), IpAddr::V6(local_ip)) => format!(
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
                (IpAddr::V4(source_ip), IpAddr::V4(local_ip)) => {
                    header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&local_ip.octets());
                }
                (IpAddr::V6(source_ip), IpAddr::V6(local_ip)) => {
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
        other => bail!("unsupported Trojan fallback xver {other}"),
    }
}

fn parse_fallback_map(
    value: &serde_json::Value,
) -> anyhow::Result<HashMap<String, FallbackTarget>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Trojan fallback_for_alpn must be an object"))?;
    let mut targets = HashMap::new();
    for (alpn, value) in object {
        let key = alpn.trim().to_ascii_lowercase();
        ensure!(
            !key.is_empty(),
            "Trojan fallback_for_alpn contains empty ALPN"
        );
        ensure!(
            targets
                .insert(key.clone(), parse_fallback_target(value)?)
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
    ensure!(target.xver <= 2, "Trojan fallback xver must be 0, 1 or 2");
    Ok(target)
}

fn parse_xboard_fallback_entry(value: &serde_json::Value) -> anyhow::Result<ParsedFallbackEntry> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Xboard Trojan fallback entry must be an object"))?;

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
        "Xboard Trojan fallback path must start with /"
    );

    let xver = object
        .get("xver")
        .map(parse_u8_json)
        .transpose()?
        .unwrap_or(0);
    ensure!(xver <= 2, "Xboard Trojan fallback xver must be 0, 1 or 2");

    let fallback_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    ensure!(
        fallback_type.is_empty() || fallback_type.eq_ignore_ascii_case("tcp"),
        "Xboard Trojan fallback type is not supported yet"
    );

    let dest = object
        .get("dest")
        .ok_or_else(|| anyhow!("Xboard Trojan fallback entry requires dest"))?;
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
                .ok_or_else(|| anyhow!("Xboard Trojan fallback dest must be a TCP port"))?;
            let server_port =
                u16::try_from(port).context("Xboard Trojan fallback port does not fit u16")?;
            ensure!(
                server_port > 0,
                "Xboard Trojan fallback port must be non-zero"
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
                "Xboard Trojan fallback dest must be tcp host:port or port"
            );
            if compact.chars().all(|ch| ch.is_ascii_digit()) {
                let server_port = compact
                    .parse::<u16>()
                    .context("parse Xboard Trojan fallback port")?;
                ensure!(
                    server_port > 0,
                    "Xboard Trojan fallback port must be non-zero"
                );
                return Ok(FallbackTarget {
                    server: "127.0.0.1".to_string(),
                    server_port,
                    xver: 0,
                });
            }

            let (server, port) = compact
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("Xboard Trojan fallback dest must be tcp host:port"))?;
            ensure!(
                !server.trim().is_empty(),
                "Xboard Trojan fallback host is required"
            );
            let server_port = port
                .trim()
                .parse::<u16>()
                .context("parse Xboard Trojan fallback port")?;
            ensure!(
                server_port > 0,
                "Xboard Trojan fallback port must be non-zero"
            );
            Ok(FallbackTarget {
                server: server.trim().to_string(),
                server_port,
                xver: 0,
            })
        }
        _ => bail!("Xboard Trojan fallback dest must be a string or number"),
    }
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
        let config = FallbackConfig::from_remote(&NodeConfigResponse {
            fallback: Some(serde_json::json!({
                "server": "127.0.0.1",
                "server_port": 80
            })),
            fallback_for_alpn: Some(serde_json::json!({
                "h2": {
                    "server": "127.0.0.1",
                    "server_port": 443
                }
            })),
            ..base_remote()
        })
        .expect("fallback config");

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
    fn parses_fallback_string_port() {
        let target = parse_fallback_target(&serde_json::json!({
            "server": "127.0.0.1",
            "server_port": "8080"
        }))
        .expect("parse fallback");

        assert_eq!(target.server, "127.0.0.1");
        assert_eq!(target.server_port, 8080);
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
            config
                .select(None, Some(b"h2"), b"GET / HTTP/1.1\r\n\r\n")
                .map(|target| target.server_port),
            Some(8443)
        );
        assert_eq!(
            config
                .select(None, Some(b"http/1.1"), b"GET / HTTP/1.1\r\n\r\n")
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
                    b"GET /other HTTP/1.1\r\nHost: example.com\r\n\r\n"
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
    fn accepts_disabled_network_settings_and_tcp_transport_field() {
        let remote = NodeConfigResponse {
            network_settings: Some(serde_json::json!({
                "ws": false,
                "headers": {},
                "path": ""
            })),
            transport: Some(serde_json::json!({
                "type": "tcp"
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.server_port, 443);
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
    fn replace_users_cancels_active_session_when_password_rotates() {
        let accounting = Accounting::new();
        let controller = ServerController::new(accounting.clone());
        controller
            .replace_users(&[PanelUser {
                id: 1,
                uuid: "stable-uuid".to_string(),
                password: "old-password".to_string(),
                ..Default::default()
            }])
            .expect("initial users");

        let user = controller
            .users
            .read()
            .expect("trojan users lock poisoned")
            .get(&trojan_auth("old-password"))
            .expect("user exists");
        let lease = accounting
            .open_session(&user, "1.1.1.1:1234".parse().expect("socket addr"))
            .expect("session should open");
        let control = lease.control();

        controller
            .replace_users(&[PanelUser {
                id: 1,
                uuid: "stable-uuid".to_string(),
                password: "new-password".to_string(),
                ..Default::default()
            }])
            .expect("rotated users");

        assert!(control.is_cancelled());
    }
}
