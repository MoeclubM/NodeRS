mod codec;
mod crypto;
mod traffic_pattern;

use anyhow::{Context, anyhow, bail, ensure};
use rand::RngExt;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use self::codec::{Metadata, ProtocolType, SocksCommand};
use super::shared::{
    bind_listeners, bind_udp_sockets, configure_tcp_stream, effective_listen_ip, routing,
    socksaddr::SocksAddr, traffic::TrafficRecorder, transport,
};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_RETRANSMIT_INTERVAL: Duration = Duration::from_secs(1);
const COPY_BUFFER_LEN: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    transport: UnderlayTransport,
    pub traffic_pattern: traffic_pattern::TrafficPatternConfig,
    pub routing: routing::RoutingTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnderlayTransport {
    Tcp,
    Udp,
}

pub struct ServerController {
    accounting: Arc<Accounting>,
    panel_users: Arc<RwLock<Vec<PanelUser>>>,
    users: Arc<RwLock<UserValidator>>,
    traffic_pattern: Arc<RwLock<traffic_pattern::TrafficPatternConfig>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    replay: Arc<ReplayCache>,
    inner: Mutex<Option<RunningServer>>,
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    transport: UnderlayTransport,
    handles: Vec<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct UserCredential {
    user: UserEntry,
    name: String,
    hashed_password: [u8; 32],
}

#[derive(Clone, Default)]
struct UserValidator {
    users: Vec<UserCredential>,
}

struct ReplayCache {
    entries: Mutex<HashMap<[u8; 16], Instant>>,
}

struct ConnectionWriter {
    stream: WriteHalf<TcpStream>,
    cipher: crypto::CipherState,
    traffic_pattern: traffic_pattern::TrafficPattern,
}

struct SessionState {
    id: u32,
    writer: Arc<AsyncMutex<ConnectionWriter>>,
    control: Arc<SessionControl>,
    upload: TrafficRecorder,
    download: TrafficRecorder,
    _lease: SessionLease,
    request_buffer: AsyncMutex<Vec<u8>>,
    remote_writer: AsyncMutex<Option<WriteHalf<TcpStream>>>,
    next_send_seq: AtomicU32,
    closed: AtomicBool,
}

struct PacketSessionState {
    id: u32,
    source: Mutex<SocketAddr>,
    socket: Arc<UdpSocket>,
    key: [u8; crypto::KEY_LEN],
    user: UserCredential,
    nonce_pattern: traffic_pattern::NoncePatternState,
    control: Arc<SessionControl>,
    upload: TrafficRecorder,
    download: TrafficRecorder,
    _lease: SessionLease,
    request_buffer: AsyncMutex<Vec<u8>>,
    remote_writer: AsyncMutex<Option<WriteHalf<TcpStream>>>,
    next_send_seq: AtomicU32,
    next_recv_seq: AtomicU32,
    recv_buffer: AsyncMutex<BTreeMap<u32, Vec<u8>>>,
    sent_packets: AsyncMutex<BTreeMap<u32, SentPacket>>,
    last_seen: AtomicI64,
    closed: AtomicBool,
}

#[derive(Clone)]
struct SentPacket {
    bytes: Vec<u8>,
}

struct DecodedPacket {
    metadata: Metadata,
    payload: Vec<u8>,
    user: UserCredential,
    key: [u8; crypto::KEY_LEN],
    nonce_prefix: [u8; 16],
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            transport: parse_transport(remote.transport.as_ref())?,
            traffic_pattern: traffic_pattern::TrafficPatternConfig::decode(&remote.traffic_pattern)
                .context("decode Mieru traffic_pattern")?,
            routing: routing::RoutingTable::from_remote(
                &remote.routes,
                &remote.custom_outbounds,
                &remote.custom_routes,
            )
            .context("compile Xboard routing")?,
        })
    }
}

impl ServerController {
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            accounting,
            panel_users: Arc::new(RwLock::new(Vec::new())),
            users: Arc::new(RwLock::new(UserValidator::default())),
            traffic_pattern: Arc::new(
                RwLock::new(traffic_pattern::TrafficPatternConfig::default()),
            ),
            routing: Arc::new(RwLock::new(routing::RoutingTable::default())),
            replay: Arc::new(ReplayCache::default()),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        *self
            .panel_users
            .write()
            .expect("mieru panel users lock poisoned") = users.to_vec();
        self.accounting.replace_users(users);
        *self.users.write().expect("mieru users lock poisoned") = UserValidator::from_users(users)?;
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        let users = self
            .panel_users
            .read()
            .expect("mieru panel users lock poisoned")
            .clone();
        *self.users.write().expect("mieru users lock poisoned") =
            UserValidator::from_users(&users)?;
        *self
            .traffic_pattern
            .write()
            .expect("mieru traffic pattern lock poisoned") = config.traffic_pattern;
        *self.routing.write().expect("mieru routing lock poisoned") = config.routing;

        let old = {
            let mut guard = self.inner.lock().expect("mieru controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip
                    || running.server_port != config.server_port
                    || running.transport != config.transport
            });
            if !should_restart {
                return Ok(());
            }
            guard.take()
        };

        if let Some(old) = old {
            for handle in old.handles {
                handle.abort();
            }
        }

        let mut handles = Vec::new();
        let mut bind_addrs = Vec::new();

        match config.transport {
            UnderlayTransport::Tcp => {
                let listeners = bind_listeners(&config.listen_ip, config.server_port)?;
                bind_addrs.extend(
                    listeners
                        .iter()
                        .filter_map(|listener| listener.local_addr().ok())
                        .map(|addr| format!("tcp://{addr}")),
                );
                for listener in listeners {
                    let accounting = self.accounting.clone();
                    let users = self.users.clone();
                    let traffic_pattern = self.traffic_pattern.clone();
                    let routing = self.routing.clone();
                    let replay = self.replay.clone();
                    handles.push(tokio::spawn(async move {
                        accept_loop(
                            listener,
                            accounting,
                            users,
                            traffic_pattern,
                            routing,
                            replay,
                        )
                        .await;
                    }));
                }
            }
            UnderlayTransport::Udp => {
                let sockets = bind_udp_sockets(&config.listen_ip, config.server_port)?;
                bind_addrs.extend(
                    sockets
                        .iter()
                        .filter_map(|socket| socket.local_addr().ok())
                        .map(|addr| format!("udp://{addr}")),
                );
                for socket in sockets {
                    let socket = Arc::new(socket);
                    let accounting = self.accounting.clone();
                    let users = self.users.clone();
                    let traffic_pattern = self.traffic_pattern.clone();
                    let routing = self.routing.clone();
                    let replay = self.replay.clone();
                    let sessions = Arc::new(AsyncMutex::new(
                        HashMap::<u32, Arc<PacketSessionState>>::new(),
                    ));
                    handles.push(tokio::spawn(async move {
                        packet_loop(
                            socket,
                            accounting,
                            users,
                            traffic_pattern,
                            routing,
                            replay,
                            sessions,
                        )
                        .await;
                    }));
                }
            }
        }

        info!(listen = ?bind_addrs, "Mieru listeners started");
        let mut guard = self.inner.lock().expect("mieru controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            transport: config.transport,
            handles,
        });
        Ok(())
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self.inner.lock().expect("mieru controller poisoned");
            guard.take()
        };
        if let Some(old) = old {
            for handle in old.handles {
                handle.abort();
            }
            info!(port = old.server_port, "Mieru listeners stopped");
        }
    }
}

impl UserValidator {
    fn from_users(users: &[PanelUser]) -> anyhow::Result<Self> {
        let mut seen = HashSet::new();
        let users = users
            .iter()
            .map(UserCredential::from_panel_user)
            .collect::<Result<Vec<_>, _>>()?;
        for user in &users {
            ensure!(
                seen.insert(user.hashed_password),
                "duplicate Mieru credentials for user {}",
                user.user.id
            );
        }
        Ok(Self { users })
    }
}

impl UserCredential {
    fn from_panel_user(user: &PanelUser) -> anyhow::Result<Self> {
        let name = effective_identity(user)
            .ok_or_else(|| anyhow!("Mieru user {} is missing password/uuid", user.id))?;
        Ok(Self {
            user: UserEntry::from_panel_user(user),
            name: name.to_string(),
            hashed_password: crypto::hash_password(name, name),
        })
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl ReplayCache {
    fn remember(&self, prefix: [u8; 16]) -> bool {
        let now = Instant::now();
        let mut guard = self.entries.lock().expect("mieru replay cache poisoned");
        guard.retain(|_, seen| now.duration_since(*seen) <= crypto::REPLAY_WINDOW);
        if guard.contains_key(&prefix) {
            return true;
        }
        guard.insert(prefix, now);
        false
    }
}

async fn accept_loop(
    listener: TcpListener,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    traffic_pattern: Arc<RwLock<traffic_pattern::TrafficPatternConfig>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    replay: Arc<ReplayCache>,
) {
    let listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "accept Mieru TCP connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let accounting = accounting.clone();
        let users = users.clone();
        let traffic_pattern = traffic_pattern.clone();
        let routing = routing.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            let users = users.read().expect("mieru users lock poisoned").clone();
            let traffic_pattern = traffic_pattern
                .read()
                .expect("mieru traffic pattern lock poisoned")
                .clone();
            let routing = routing.read().expect("mieru routing lock poisoned").clone();
            if let Err(error) = serve_underlay_connection(
                stream,
                source,
                accounting,
                users,
                traffic_pattern,
                routing,
                replay,
            )
            .await
            {
                warn!(%error, %source, "Mieru TCP underlay terminated with error");
            }
        });
    }
}

async fn serve_underlay_connection(
    stream: TcpStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: UserValidator,
    traffic_pattern: traffic_pattern::TrafficPatternConfig,
    routing: routing::RoutingTable,
    replay: Arc<ReplayCache>,
) -> anyhow::Result<()> {
    let (mut reader, writer) = split(stream);
    let (credential, key, mut recv_cipher, first_metadata) = match timeout(
        AUTHENTICATION_TIMEOUT,
        authenticate_connection(
            &mut reader,
            &users,
            &replay,
            traffic_pattern.effective().nonce.clone(),
        ),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => bail!("Mieru authentication timed out"),
    };
    let writer = Arc::new(AsyncMutex::new(ConnectionWriter {
        stream: writer,
        cipher: crypto::CipherState::new(
            key,
            Some(credential.name.clone()),
            traffic_pattern.effective().nonce.clone(),
        ),
        traffic_pattern: traffic_pattern.effective().clone(),
    }));
    let sessions = Arc::new(AsyncMutex::new(HashMap::<u32, Arc<SessionState>>::new()));

    let first_payload =
        read_segment_payload(&mut reader, &mut recv_cipher, &first_metadata).await?;
    handle_metadata(
        first_metadata,
        first_payload,
        source,
        credential.clone(),
        accounting.clone(),
        routing.clone(),
        writer.clone(),
        sessions.clone(),
    )
    .await?;

    loop {
        let metadata = match read_metadata(&mut reader, &mut recv_cipher).await {
            Ok(metadata) => metadata,
            Err(error) if is_clean_eof(&error) => break,
            Err(error) => return Err(error),
        };
        let payload = read_segment_payload(&mut reader, &mut recv_cipher, &metadata).await?;
        handle_metadata(
            metadata,
            payload,
            source,
            credential.clone(),
            accounting.clone(),
            routing.clone(),
            writer.clone(),
            sessions.clone(),
        )
        .await?;
    }

    cancel_all_sessions(&sessions).await;
    Ok(())
}

async fn authenticate_connection<R>(
    reader: &mut R,
    users: &UserValidator,
    replay: &ReplayCache,
    nonce_pattern: traffic_pattern::NoncePattern,
) -> anyhow::Result<(UserCredential, [u8; 32], crypto::CipherState, Metadata)>
where
    R: AsyncRead + Unpin,
{
    let mut frame = vec![0u8; crypto::NONCE_LEN + codec::METADATA_LEN + crypto::TAG_LEN];
    reader
        .read_exact(&mut frame)
        .await
        .context("read Mieru initial frame")?;

    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&frame[..crypto::NONCE_LEN]);
    let mut candidates = users
        .users
        .iter()
        .filter(|user| crypto::user_hint_matches(&user.name, &nonce))
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = users.users.clone();
    }

    for user in candidates {
        for key in crypto::derive_keys(&user.hashed_password, std::time::SystemTime::now())? {
            let Ok((nonce, plaintext)) = crypto::decrypt_first_frame(key, &frame) else {
                continue;
            };
            let metadata = match codec::decode_metadata(&plaintext) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let mut replay_key = [0u8; 16];
            replay_key.copy_from_slice(&nonce[..16]);
            ensure!(
                !replay.remember(replay_key),
                "replayed Mieru TCP session detected"
            );
            return Ok((
                user,
                key,
                crypto::CipherState::from_received(key, nonce, None, nonce_pattern.clone()),
                metadata,
            ));
        }
    }

    bail!("failed to match Mieru user")
}

async fn read_metadata<R>(
    reader: &mut R,
    cipher: &mut crypto::CipherState,
) -> anyhow::Result<Metadata>
where
    R: AsyncRead + Unpin,
{
    let frame_len = codec::METADATA_LEN
        + crypto::TAG_LEN
        + if cipher.expects_nonce() {
            crypto::NONCE_LEN
        } else {
            0
        };
    let mut frame = vec![0u8; frame_len];
    match reader.read_exact(&mut frame).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(error).context("Mieru underlay EOF");
        }
        Err(error) => return Err(error).context("read Mieru metadata"),
    }
    let plaintext = cipher.decrypt(&frame).context("decrypt Mieru metadata")?;
    codec::decode_metadata(&plaintext)
}

async fn read_segment_payload<R>(
    reader: &mut R,
    cipher: &mut crypto::CipherState,
    metadata: &Metadata,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let (prefix_len, payload_len, suffix_len) = match metadata {
        Metadata::Session(value) => (
            0usize,
            usize::from(value.payload_len),
            usize::from(value.suffix_len),
        ),
        Metadata::Data(value) => (
            usize::from(value.prefix_len),
            usize::from(value.payload_len),
            usize::from(value.suffix_len),
        ),
    };

    if prefix_len > 0 {
        discard_bytes(reader, prefix_len, "read Mieru prefix padding").await?;
    }

    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        let mut encrypted = vec![0u8; payload_len + crypto::TAG_LEN];
        reader
            .read_exact(&mut encrypted)
            .await
            .with_context(|| format!("read Mieru payload of {payload_len} bytes"))?;
        cipher
            .decrypt(&encrypted)
            .context("decrypt Mieru payload")?
    };

    if suffix_len > 0 {
        discard_bytes(reader, suffix_len, "read Mieru suffix padding").await?;
    }

    Ok(payload)
}

async fn discard_bytes<R>(reader: &mut R, len: usize, context: &str) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .await
        .with_context(|| context.to_string())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_metadata(
    metadata: Metadata,
    payload: Vec<u8>,
    source: SocketAddr,
    credential: UserCredential,
    accounting: Arc<Accounting>,
    routing: routing::RoutingTable,
    writer: Arc<AsyncMutex<ConnectionWriter>>,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<SessionState>>>>,
) -> anyhow::Result<()> {
    match metadata {
        Metadata::Session(value) => match value.protocol {
            ProtocolType::OpenSessionRequest => {
                ensure!(value.session_id != 0, "Mieru session id 0 is reserved");
                let lease = accounting.open_session(&credential.user, source)?;
                let control = lease.control();
                let session = Arc::new(SessionState {
                    id: value.session_id,
                    writer: writer.clone(),
                    control,
                    upload: TrafficRecorder::upload(accounting.clone(), credential.user.id),
                    download: TrafficRecorder::download(accounting, credential.user.id),
                    _lease: lease,
                    request_buffer: AsyncMutex::new(Vec::new()),
                    remote_writer: AsyncMutex::new(None),
                    next_send_seq: AtomicU32::new(0),
                    closed: AtomicBool::new(false),
                });
                {
                    let mut guard = sessions.lock().await;
                    ensure!(
                        guard.insert(value.session_id, session.clone()).is_none(),
                        "duplicate Mieru session id {}",
                        value.session_id
                    );
                }
                write_session_segment(
                    &writer,
                    ProtocolType::OpenSessionResponse,
                    value.session_id,
                    session.next_send_seq.fetch_add(1, Ordering::SeqCst),
                    value.status_code,
                    &[],
                )
                .await?;
                if !payload.is_empty() {
                    handle_session_payload(session, payload, routing, sessions).await?;
                }
            }
            ProtocolType::CloseSessionRequest => {
                close_session(
                    &sessions,
                    value.session_id,
                    Some((ProtocolType::CloseSessionResponse, value.status_code)),
                )
                .await;
            }
            ProtocolType::CloseSessionResponse => {
                close_session(&sessions, value.session_id, None).await;
            }
            ProtocolType::OpenSessionResponse => {
                bail!("unexpected Mieru openSessionResponse from client");
            }
            _ => bail!("invalid Mieru session protocol {}", value.protocol as u8),
        },
        Metadata::Data(value) => match value.protocol {
            ProtocolType::DataClientToServer => {
                let session = {
                    let guard = sessions.lock().await;
                    guard.get(&value.session_id).cloned()
                };
                if let Some(session) = session {
                    handle_session_payload(session, payload, routing, sessions).await?;
                }
            }
            ProtocolType::AckClientToServer => {}
            ProtocolType::DataServerToClient | ProtocolType::AckServerToClient => {
                bail!(
                    "unexpected Mieru server-bound data protocol {}",
                    value.protocol as u8
                );
            }
            _ => bail!("invalid Mieru data protocol {}", value.protocol as u8),
        },
    }
    Ok(())
}

async fn handle_session_payload(
    session: Arc<SessionState>,
    payload: Vec<u8>,
    routing: routing::RoutingTable,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<SessionState>>>>,
) -> anyhow::Result<()> {
    if payload.is_empty() || session.control.is_cancelled() {
        return Ok(());
    }

    if session.remote_writer.lock().await.is_some() {
        session
            .upload
            .limit(payload.len() as u64, &session.control)
            .await;
        if session.control.is_cancelled() {
            return Ok(());
        }
        let mut guard = session.remote_writer.lock().await;
        if let Some(remote) = guard.as_mut() {
            tokio::select! {
                _ = session.control.cancelled() => return Ok(()),
                result = remote.write_all(&payload) => result.context("write Mieru proxied upload")?,
            }
            session.upload.record(payload.len() as u64);
        }
        return Ok(());
    }

    let request = {
        let mut buffer = session.request_buffer.lock().await;
        buffer.extend_from_slice(&payload);
        match codec::parse_socks5_request(&buffer)? {
            Some(request) => {
                let consumed_len = request.consumed_len;
                let request = (request, buffer[consumed_len..].to_vec());
                buffer.clear();
                request
            }
            None => return Ok(()),
        }
    };
    let (request, remaining) = request;

    match request.command {
        SocksCommand::Connect => {
            let remote = match transport::connect_tcp_destination(&request.destination, &routing)
                .await
            {
                Ok(remote) => remote,
                Err(error) => {
                    let bind = SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0)));
                    let response =
                        codec::encode_socks5_response(codec::SOCKS_REPLY_HOST_UNREACHABLE, &bind)?;
                    write_data_segment(
                        &session.writer,
                        session.id,
                        session.next_send_seq.fetch_add(1, Ordering::SeqCst),
                        &response,
                    )
                    .await?;
                    close_session(
                        &sessions,
                        session.id,
                        Some((ProtocolType::CloseSessionRequest, 0)),
                    )
                    .await;
                    return Err(error).context("connect Mieru destination");
                }
            };
            let bind = remote
                .local_addr()
                .map(SocksAddr::Ip)
                .unwrap_or_else(|_| SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))));
            let response = codec::encode_socks5_response(codec::SOCKS_REPLY_SUCCESS, &bind)?;
            write_data_segment(
                &session.writer,
                session.id,
                session.next_send_seq.fetch_add(1, Ordering::SeqCst),
                &response,
            )
            .await?;

            let (mut remote_reader, mut remote_writer) = split(remote);
            if !remaining.is_empty() {
                session
                    .upload
                    .limit(remaining.len() as u64, &session.control)
                    .await;
                if session.control.is_cancelled() {
                    return Ok(());
                }
                remote_writer
                    .write_all(&remaining)
                    .await
                    .context("write initial Mieru payload to remote")?;
                session.upload.record(remaining.len() as u64);
            }
            *session.remote_writer.lock().await = Some(remote_writer);

            tokio::spawn(async move {
                if let Err(error) =
                    relay_remote_to_session(session.clone(), &mut remote_reader).await
                {
                    warn!(%error, session_id = session.id, "Mieru remote relay terminated with error");
                }
                close_session(
                    &sessions,
                    session.id,
                    Some((ProtocolType::CloseSessionRequest, 0)),
                )
                .await;
            });
        }
        SocksCommand::UdpAssociate => {
            let bind = SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0)));
            let response =
                codec::encode_socks5_response(codec::SOCKS_REPLY_COMMAND_NOT_SUPPORTED, &bind)?;
            write_data_segment(
                &session.writer,
                session.id,
                session.next_send_seq.fetch_add(1, Ordering::SeqCst),
                &response,
            )
            .await?;
            close_session(
                &sessions,
                session.id,
                Some((ProtocolType::CloseSessionRequest, 0)),
            )
            .await;
        }
    }

    Ok(())
}

async fn packet_loop(
    socket: Arc<UdpSocket>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    traffic_pattern: Arc<RwLock<traffic_pattern::TrafficPatternConfig>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    replay: Arc<ReplayCache>,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) {
    let listen = socket
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut buffer = vec![0u8; 1500];
    loop {
        let (size, source) = match socket.recv_from(&mut buffer).await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "receive Mieru UDP packet failed");
                continue;
            }
        };
        let source = transport::normalize_udp_source(source);
        let users = users.read().expect("mieru users lock poisoned").clone();
        let traffic_pattern = traffic_pattern
            .read()
            .expect("mieru traffic pattern lock poisoned")
            .clone();
        let routing = routing.read().expect("mieru routing lock poisoned").clone();
        if let Err(error) = handle_packet(
            socket.clone(),
            source,
            &buffer[..size],
            accounting.clone(),
            users,
            traffic_pattern,
            routing,
            replay.clone(),
            sessions.clone(),
        )
        .await
        {
            warn!(%error, %source, "Mieru UDP packet handling failed");
        }
        cleanup_packet_sessions(&sessions).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_packet(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    packet: &[u8],
    accounting: Arc<Accounting>,
    users: UserValidator,
    traffic_pattern: traffic_pattern::TrafficPatternConfig,
    routing: routing::RoutingTable,
    replay: Arc<ReplayCache>,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) -> anyhow::Result<()> {
    let decoded = decode_packet(packet, &users)?;
    if matches!(decoded.metadata, Metadata::Session(_)) && replay.remember(decoded.nonce_prefix) {
        bail!("replayed Mieru UDP session packet detected");
    }

    match decoded.metadata {
        Metadata::Session(metadata) => match metadata.protocol {
            ProtocolType::OpenSessionRequest => {
                ensure!(metadata.session_id != 0, "Mieru session id 0 is reserved");
                let session = get_or_create_packet_session(
                    metadata.session_id,
                    source,
                    socket,
                    accounting,
                    decoded.user,
                    decoded.key,
                    traffic_pattern.effective().nonce.clone(),
                    sessions.clone(),
                )
                .await?;
                update_packet_session_source(&session, source);
                handle_packet_open_session(session, metadata, decoded.payload, routing, sessions)
                    .await?;
            }
            ProtocolType::CloseSessionRequest | ProtocolType::CloseSessionResponse => {
                close_packet_session(&sessions, metadata.session_id).await;
            }
            ProtocolType::OpenSessionResponse => bail!("unexpected Mieru UDP openSessionResponse"),
            _ => bail!(
                "invalid Mieru UDP session protocol {}",
                metadata.protocol as u8
            ),
        },
        Metadata::Data(metadata) => match metadata.protocol {
            ProtocolType::DataClientToServer | ProtocolType::AckClientToServer => {
                let session = {
                    let guard = sessions.lock().await;
                    guard.get(&metadata.session_id).cloned()
                }
                .ok_or_else(|| {
                    anyhow!(
                        "Mieru UDP session {} is not registered",
                        metadata.session_id
                    )
                })?;
                update_packet_session_source(&session, source);
                ack_packet_segments(&session, metadata.unack_seq).await;
                session.last_seen.store(now_micros(), Ordering::SeqCst);
                if metadata.protocol == ProtocolType::DataClientToServer {
                    enqueue_packet_payload(session, metadata, decoded.payload, routing, sessions)
                        .await?;
                }
            }
            ProtocolType::DataServerToClient | ProtocolType::AckServerToClient => {
                bail!(
                    "unexpected Mieru UDP server-bound data protocol {}",
                    metadata.protocol as u8
                )
            }
            _ => bail!(
                "invalid Mieru UDP data protocol {}",
                metadata.protocol as u8
            ),
        },
    }
    Ok(())
}

fn decode_packet(packet: &[u8], users: &UserValidator) -> anyhow::Result<DecodedPacket> {
    ensure!(
        packet.len() >= crypto::NONCE_LEN + codec::METADATA_LEN + crypto::TAG_LEN,
        "Mieru UDP packet is too short"
    );
    let metadata_end = crypto::NONCE_LEN + codec::METADATA_LEN + crypto::TAG_LEN;
    let encrypted_metadata = &packet[..metadata_end];
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&encrypted_metadata[..crypto::NONCE_LEN]);
    let mut nonce_prefix = [0u8; 16];
    nonce_prefix.copy_from_slice(&nonce[..16]);

    let mut candidates = users
        .users
        .iter()
        .filter(|user| crypto::user_hint_matches(&user.name, &nonce))
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = users.users.clone();
    }

    for user in candidates {
        for key in crypto::derive_keys(&user.hashed_password, std::time::SystemTime::now())? {
            let Ok((_, metadata_bytes)) = crypto::decrypt_first_frame(key, encrypted_metadata)
            else {
                continue;
            };
            let Ok(metadata) = codec::decode_metadata(&metadata_bytes) else {
                continue;
            };
            let payload = decrypt_packet_payload(&metadata, key, &nonce, &packet[metadata_end..])?;
            return Ok(DecodedPacket {
                metadata,
                payload,
                user,
                key,
                nonce_prefix,
            });
        }
    }

    bail!("failed to match Mieru UDP user")
}

fn decrypt_packet_payload(
    metadata: &Metadata,
    key: [u8; crypto::KEY_LEN],
    nonce: &[u8; crypto::NONCE_LEN],
    remaining: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (prefix_len, payload_len, suffix_len) = match metadata {
        Metadata::Session(value) => (
            0usize,
            usize::from(value.payload_len),
            usize::from(value.suffix_len),
        ),
        Metadata::Data(value) => (
            usize::from(value.prefix_len),
            usize::from(value.payload_len),
            usize::from(value.suffix_len),
        ),
    };
    ensure!(
        remaining.len() >= prefix_len,
        "truncated Mieru UDP prefix padding"
    );
    if payload_len == 0 {
        ensure!(
            remaining.len() == prefix_len + suffix_len,
            "Mieru UDP padding length mismatch"
        );
        return Ok(Vec::new());
    }

    let payload_start = prefix_len;
    let payload_end = payload_start + payload_len + crypto::TAG_LEN;
    ensure!(
        remaining.len() >= payload_end,
        "truncated Mieru UDP payload"
    );
    ensure!(
        remaining.len() == payload_end + suffix_len,
        "Mieru UDP padding length mismatch"
    );
    crypto::decrypt_packet_payload(key, nonce, &remaining[payload_start..payload_end])
}

#[allow(clippy::too_many_arguments)]
async fn get_or_create_packet_session(
    session_id: u32,
    source: SocketAddr,
    socket: Arc<UdpSocket>,
    accounting: Arc<Accounting>,
    user: UserCredential,
    key: [u8; crypto::KEY_LEN],
    nonce_pattern: traffic_pattern::NoncePattern,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) -> anyhow::Result<Arc<PacketSessionState>> {
    let mut guard = sessions.lock().await;
    if let Some(session) = guard.get(&session_id) {
        return Ok(session.clone());
    }

    let lease = accounting.open_session(&user.user, source)?;
    let session = Arc::new(PacketSessionState {
        id: session_id,
        source: Mutex::new(source),
        socket,
        key,
        user: user.clone(),
        nonce_pattern: traffic_pattern::NoncePatternState::new(nonce_pattern),
        control: lease.control(),
        upload: TrafficRecorder::upload(accounting.clone(), user.user.id),
        download: TrafficRecorder::download(accounting, user.user.id),
        _lease: lease,
        request_buffer: AsyncMutex::new(Vec::new()),
        remote_writer: AsyncMutex::new(None),
        next_send_seq: AtomicU32::new(0),
        next_recv_seq: AtomicU32::new(0),
        recv_buffer: AsyncMutex::new(BTreeMap::new()),
        sent_packets: AsyncMutex::new(BTreeMap::new()),
        last_seen: AtomicI64::new(now_micros()),
        closed: AtomicBool::new(false),
    });
    guard.insert(session_id, session.clone());
    tokio::spawn(retransmit_packet_segments(session.clone()));
    Ok(session)
}

fn update_packet_session_source(session: &PacketSessionState, source: SocketAddr) {
    *session
        .source
        .lock()
        .expect("mieru UDP source lock poisoned") = source;
}

async fn handle_packet_open_session(
    session: Arc<PacketSessionState>,
    metadata: codec::SessionMetadata,
    payload: Vec<u8>,
    routing: routing::RoutingTable,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) -> anyhow::Result<()> {
    let response_seq = session.next_send_seq.fetch_add(1, Ordering::SeqCst);
    send_packet_session_segment(
        &session,
        ProtocolType::OpenSessionResponse,
        response_seq,
        0,
        &[],
    )
    .await?;
    session
        .next_recv_seq
        .store(metadata.seq + 1, Ordering::SeqCst);
    if !payload.is_empty() {
        handle_packet_session_payload(session, payload, routing, sessions).await?;
    }
    Ok(())
}

async fn enqueue_packet_payload(
    session: Arc<PacketSessionState>,
    metadata: codec::DataMetadata,
    payload: Vec<u8>,
    routing: routing::RoutingTable,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) -> anyhow::Result<()> {
    {
        let mut recv = session.recv_buffer.lock().await;
        recv.insert(metadata.seq, payload);
    }
    loop {
        let next = session.next_recv_seq.load(Ordering::SeqCst);
        let Some(payload) = session.recv_buffer.lock().await.remove(&next) else {
            break;
        };
        session.next_recv_seq.store(next + 1, Ordering::SeqCst);
        handle_packet_session_payload(session.clone(), payload, routing.clone(), sessions.clone())
            .await?;
    }
    send_packet_ack(&session, ProtocolType::AckServerToClient).await
}

async fn handle_packet_session_payload(
    session: Arc<PacketSessionState>,
    payload: Vec<u8>,
    routing: routing::RoutingTable,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) -> anyhow::Result<()> {
    if payload.is_empty() || session.control.is_cancelled() {
        return Ok(());
    }

    if session.remote_writer.lock().await.is_some() {
        session
            .upload
            .limit(payload.len() as u64, &session.control)
            .await;
        if session.control.is_cancelled() {
            return Ok(());
        }
        let mut guard = session.remote_writer.lock().await;
        if let Some(remote) = guard.as_mut() {
            tokio::select! {
                _ = session.control.cancelled() => return Ok(()),
                result = remote.write_all(&payload) => result.context("write Mieru UDP proxied upload")?,
            }
            session.upload.record(payload.len() as u64);
        }
        return Ok(());
    }

    let request = {
        let mut buffer = session.request_buffer.lock().await;
        buffer.extend_from_slice(&payload);
        match codec::parse_socks5_request(&buffer)? {
            Some(request) => {
                let consumed_len = request.consumed_len;
                let request = (request, buffer[consumed_len..].to_vec());
                buffer.clear();
                request
            }
            None => return Ok(()),
        }
    };
    let (request, remaining) = request;
    match request.command {
        SocksCommand::Connect => {
            open_packet_tcp_session(session, request, remaining, routing, sessions).await
        }
        SocksCommand::UdpAssociate => {
            write_packet_socks_response(
                &session,
                codec::SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))),
            )
            .await?;
            close_packet_session(&sessions, session.id).await;
            Ok(())
        }
    }
}

async fn open_packet_tcp_session(
    session: Arc<PacketSessionState>,
    request: codec::SocksRequest,
    remaining: Vec<u8>,
    routing: routing::RoutingTable,
    sessions: Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) -> anyhow::Result<()> {
    let remote = match transport::connect_tcp_destination(&request.destination, &routing).await {
        Ok(remote) => remote,
        Err(error) => {
            write_packet_socks_response(
                &session,
                codec::SOCKS_REPLY_HOST_UNREACHABLE,
                SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))),
            )
            .await?;
            close_packet_session(&sessions, session.id).await;
            return Err(error).context("connect Mieru UDP TCP destination");
        }
    };
    let bind = remote
        .local_addr()
        .map(SocksAddr::Ip)
        .unwrap_or_else(|_| SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0))));
    write_packet_socks_response(&session, codec::SOCKS_REPLY_SUCCESS, bind).await?;
    let (mut remote_reader, mut remote_writer) = split(remote);
    if !remaining.is_empty() {
        session
            .upload
            .limit(remaining.len() as u64, &session.control)
            .await;
        if session.control.is_cancelled() {
            return Ok(());
        }
        remote_writer
            .write_all(&remaining)
            .await
            .context("write initial Mieru UDP TCP payload")?;
        session.upload.record(remaining.len() as u64);
    }
    *session.remote_writer.lock().await = Some(remote_writer);
    tokio::spawn(async move {
        if let Err(error) =
            relay_remote_to_packet_session(session.clone(), &mut remote_reader).await
        {
            warn!(%error, session_id = session.id, "Mieru UDP TCP relay terminated with error");
        }
        close_packet_session(&sessions, session.id).await;
    });
    Ok(())
}

async fn relay_remote_to_packet_session(
    session: Arc<PacketSessionState>,
    remote_reader: &mut ReadHalf<TcpStream>,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let read = tokio::select! {
            _ = session.control.cancelled() => return Ok(()),
            read = remote_reader.read(&mut buffer) => read.context("read Mieru UDP proxied download")?,
        };
        if read == 0 {
            return Ok(());
        }
        session.download.limit(read as u64, &session.control).await;
        if session.control.is_cancelled() {
            return Ok(());
        }
        session.download.record(read as u64);
        write_packet_data(&session, &buffer[..read]).await?;
    }
}

async fn write_packet_socks_response(
    session: &PacketSessionState,
    reply: u8,
    bind: SocksAddr,
) -> anyhow::Result<()> {
    let response = codec::encode_socks5_response(reply, &bind)?;
    write_packet_data(session, &response).await
}

async fn write_packet_data(session: &PacketSessionState, payload: &[u8]) -> anyhow::Result<()> {
    let seq = session.next_send_seq.fetch_add(1, Ordering::SeqCst);
    send_packet_data_segment(session, ProtocolType::DataServerToClient, seq, payload).await
}

async fn send_packet_ack(
    session: &PacketSessionState,
    protocol: ProtocolType,
) -> anyhow::Result<()> {
    let seq = session
        .next_send_seq
        .load(Ordering::SeqCst)
        .saturating_sub(1);
    send_packet_data_segment(session, protocol, seq, &[]).await
}

async fn send_packet_session_segment(
    session: &PacketSessionState,
    protocol: ProtocolType,
    seq: u32,
    status_code: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
    let metadata =
        codec::encode_session_metadata(protocol, session.id, seq, status_code, payload.len())?;
    let packet = encode_packet(session, &metadata, payload)?;
    let source = *session
        .source
        .lock()
        .expect("mieru UDP source lock poisoned");
    send_packet_to_source(session, &packet, source).await?;
    session
        .sent_packets
        .lock()
        .await
        .insert(seq, SentPacket { bytes: packet });
    Ok(())
}

async fn send_packet_data_segment(
    session: &PacketSessionState,
    protocol: ProtocolType,
    seq: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    let metadata = codec::encode_data_metadata_full(
        protocol,
        session.id,
        seq,
        session.next_recv_seq.load(Ordering::SeqCst),
        1024,
        0,
        0,
        payload.len(),
        0,
    )?;
    let packet = encode_packet(session, &metadata, payload)?;
    let source = *session
        .source
        .lock()
        .expect("mieru UDP source lock poisoned");
    send_packet_to_source(session, &packet, source).await?;
    if matches!(protocol, ProtocolType::DataServerToClient) {
        session
            .sent_packets
            .lock()
            .await
            .insert(seq, SentPacket { bytes: packet });
    }
    Ok(())
}

fn encode_packet(
    session: &PacketSessionState,
    metadata: &[u8; codec::METADATA_LEN],
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (mut packet, nonce) = crypto::encrypt_packet_metadata(
        session.key,
        &session.user.name,
        &session.nonce_pattern,
        metadata,
    )?;
    if !payload.is_empty() {
        packet.extend_from_slice(&crypto::encrypt_packet_payload(
            session.key,
            &nonce,
            payload,
        )?);
    }
    Ok(packet)
}

async fn send_packet_to_source(
    session: &PacketSessionState,
    packet: &[u8],
    source: SocketAddr,
) -> anyhow::Result<()> {
    let target = transport::normalize_udp_target(&session.socket, source);
    let sent = session
        .socket
        .send_to(packet, target)
        .await
        .with_context(|| format!("send Mieru UDP packet to {target}"))?;
    ensure!(
        sent == packet.len(),
        "short Mieru UDP packet send: expected {}, wrote {}",
        packet.len(),
        sent
    );
    Ok(())
}

async fn retransmit_packet_segments(session: Arc<PacketSessionState>) {
    loop {
        tokio::time::sleep(UDP_RETRANSMIT_INTERVAL).await;
        if session.control.is_cancelled() || session.closed.load(Ordering::SeqCst) {
            return;
        }
        let packets = session
            .sent_packets
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let source = *session
            .source
            .lock()
            .expect("mieru UDP source lock poisoned");
        for packet in packets {
            if let Err(error) = send_packet_to_source(&session, &packet.bytes, source).await {
                warn!(%error, session_id = session.id, "retransmit Mieru UDP packet failed");
                return;
            }
        }
    }
}

async fn ack_packet_segments(session: &PacketSessionState, unack_seq: u32) {
    let mut sent = session.sent_packets.lock().await;
    let acknowledged = sent
        .keys()
        .copied()
        .filter(|seq| *seq < unack_seq)
        .collect::<Vec<_>>();
    for seq in acknowledged {
        sent.remove(&seq);
    }
}

async fn close_packet_session(
    sessions: &Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
    session_id: u32,
) {
    let session = sessions.lock().await.remove(&session_id);
    if let Some(session) = session {
        session.closed.store(true, Ordering::SeqCst);
        session.control.cancel();
        let _ = session.remote_writer.lock().await.take();
    }
}

async fn cleanup_packet_sessions(
    sessions: &Arc<AsyncMutex<HashMap<u32, Arc<PacketSessionState>>>>,
) {
    let deadline = now_micros() - UDP_SESSION_IDLE_TIMEOUT.as_micros() as i64;
    let stale = {
        let guard = sessions.lock().await;
        guard
            .iter()
            .filter_map(|(id, session)| {
                (session.last_seen.load(Ordering::SeqCst) < deadline).then_some(*id)
            })
            .collect::<Vec<_>>()
    };
    for id in stale {
        close_packet_session(sessions, id).await;
    }
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

async fn relay_remote_to_session(
    session: Arc<SessionState>,
    remote_reader: &mut ReadHalf<TcpStream>,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let read = tokio::select! {
            _ = session.control.cancelled() => return Ok(()),
            read = remote_reader.read(&mut buffer) => read.context("read Mieru proxied download")?,
        };
        if read == 0 {
            return Ok(());
        }
        session.download.limit(read as u64, &session.control).await;
        if session.control.is_cancelled() {
            return Ok(());
        }
        session.download.record(read as u64);
        write_data_segment(
            &session.writer,
            session.id,
            session.next_send_seq.fetch_add(1, Ordering::SeqCst),
            &buffer[..read],
        )
        .await?;
    }
}

async fn write_session_segment(
    writer: &Arc<AsyncMutex<ConnectionWriter>>,
    protocol: ProtocolType,
    session_id: u32,
    seq: u32,
    status_code: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
    let metadata =
        codec::encode_session_metadata(protocol, session_id, seq, status_code, payload.len())?;
    write_segment(writer, &metadata, payload).await
}

async fn write_data_segment(
    writer: &Arc<AsyncMutex<ConnectionWriter>>,
    session_id: u32,
    seq: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    let metadata = codec::encode_data_metadata(
        ProtocolType::DataServerToClient,
        session_id,
        seq,
        payload.len(),
    )?;
    write_segment(writer, &metadata, payload).await
}

async fn write_segment(
    writer: &Arc<AsyncMutex<ConnectionWriter>>,
    metadata: &[u8; codec::METADATA_LEN],
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut writer = writer.lock().await;
    let traffic_pattern = writer.traffic_pattern.clone();
    let encoded_metadata = writer.cipher.encrypt(metadata)?;
    write_with_possible_fragment(
        &mut writer.stream,
        &traffic_pattern,
        &encoded_metadata,
        "write Mieru metadata",
    )
    .await?;
    if !payload.is_empty() {
        let encoded_payload = writer.cipher.encrypt(payload)?;
        write_with_possible_fragment(
            &mut writer.stream,
            &traffic_pattern,
            &encoded_payload,
            "write Mieru payload",
        )
        .await?;
    }
    Ok(())
}

async fn write_with_possible_fragment(
    stream: &mut WriteHalf<TcpStream>,
    traffic_pattern: &traffic_pattern::TrafficPattern,
    bytes: &[u8],
    context: &str,
) -> anyhow::Result<()> {
    if !traffic_pattern.tcp_fragment.enable || bytes.is_empty() {
        stream
            .write_all(bytes)
            .await
            .with_context(|| context.to_string())?;
        return Ok(());
    }

    let total_len = bytes.len();
    let min_len = (total_len as f64).sqrt() as usize + 1;
    let max_len = min_len.max(total_len / 2);
    let mut sent = 0usize;
    while sent < total_len {
        let remaining = total_len - sent;
        let chunk_len = if min_len >= max_len {
            remaining.min(max_len.max(1))
        } else {
            rand::rng().random_range(min_len..=max_len).min(remaining)
        };
        stream
            .write_all(&bytes[sent..sent + chunk_len])
            .await
            .with_context(|| context.to_string())?;
        sent += chunk_len;
        if sent < total_len && traffic_pattern.tcp_fragment.max_sleep_ms > 0 {
            let sleep_ms = rand::rng().random_range(0..=traffic_pattern.tcp_fragment.max_sleep_ms);
            tokio::time::sleep(Duration::from_millis(u64::from(sleep_ms))).await;
        }
    }
    Ok(())
}

async fn close_session(
    sessions: &Arc<AsyncMutex<HashMap<u32, Arc<SessionState>>>>,
    session_id: u32,
    response: Option<(ProtocolType, u8)>,
) {
    let session = {
        let mut guard = sessions.lock().await;
        guard.remove(&session_id)
    };
    let Some(session) = session else {
        return;
    };
    if session.closed.swap(true, Ordering::SeqCst) {
        return;
    }
    session.control.cancel();
    let _ = session.remote_writer.lock().await.take();
    if let Some((protocol, status_code)) = response {
        let seq = session.next_send_seq.fetch_add(1, Ordering::SeqCst);
        if let Err(error) =
            write_session_segment(&session.writer, protocol, session.id, seq, status_code, &[])
                .await
        {
            warn!(%error, session_id = session.id, "write Mieru close segment failed");
        }
    }
}

async fn cancel_all_sessions(sessions: &Arc<AsyncMutex<HashMap<u32, Arc<SessionState>>>>) {
    let values = {
        let mut guard = sessions.lock().await;
        guard
            .drain()
            .map(|(_, session)| session)
            .collect::<Vec<_>>()
    };
    for session in values {
        session.control.cancel();
        let _ = session.remote_writer.lock().await.take();
    }
}

fn parse_transport(value: Option<&Value>) -> anyhow::Result<UnderlayTransport> {
    if value.is_some_and(|value| !crate::panel::json_value_is_enabled(value)) {
        return Ok(UnderlayTransport::Tcp);
    }

    match value {
        None | Some(Value::Null) => Ok(UnderlayTransport::Tcp),
        Some(Value::String(text))
            if text.trim().is_empty() || text.trim().eq_ignore_ascii_case("tcp") =>
        {
            Ok(UnderlayTransport::Tcp)
        }
        Some(Value::Object(object))
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("tcp")) =>
        {
            Ok(UnderlayTransport::Tcp)
        }
        Some(Value::String(text)) if text.trim().eq_ignore_ascii_case("udp") => {
            Ok(UnderlayTransport::Udp)
        }
        Some(Value::Object(object))
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("udp")) =>
        {
            Ok(UnderlayTransport::Udp)
        }
        _ => bail!("Xboard Mieru transport is not supported by NodeRS yet"),
    }
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !remote.network.trim().is_empty() && !remote.network.eq_ignore_ascii_case("tcp") {
        bail!("Xboard network must be tcp for Mieru nodes");
    }
    if remote
        .network_settings
        .as_ref()
        .is_some_and(crate::panel::json_value_is_enabled)
    {
        bail!("Xboard networkSettings is not supported by NodeRS Mieru server yet");
    }
    parse_transport(remote.transport.as_ref())?;
    if remote.tls.is_some()
        || remote.tls_settings.is_configured()
        || remote.tls_settings.has_reality_key_material()
        || remote.reality_settings.is_configured()
        || remote.cert_config.is_some()
    {
        bail!("Xboard tls is not supported by NodeRS Mieru server");
    }
    if !remote.packet_encoding.trim().is_empty()
        || !remote.flow.trim().is_empty()
        || !remote.decryption.trim().is_empty()
    {
        bail!("unsupported Mieru extension fields in Xboard config");
    }
    Ok(())
}

fn effective_identity(user: &PanelUser) -> Option<&str> {
    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return Some(uuid);
    }
    let password = user.password.trim();
    if !password.is_empty() {
        return Some(password);
    }
    None
}

fn is_clean_eof(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "mieru".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 8964,
            transport: Some(Value::String("TCP".to_string())),
            ..Default::default()
        }
    }

    fn build_client_open_frame(
        user: &UserCredential,
        session_id: u32,
        payload: &[u8],
    ) -> anyhow::Result<([u8; 32], Vec<u8>)> {
        let key = crypto::derive_keys(&user.hashed_password, std::time::SystemTime::now())?[1];
        let mut cipher = crypto::CipherState::new(
            key,
            Some(user.name.clone()),
            traffic_pattern::NoncePattern::default(),
        );
        Ok((
            key,
            encrypt_client_open_frame(&mut cipher, session_id, payload)?,
        ))
    }

    fn encrypt_client_open_frame(
        cipher: &mut crypto::CipherState,
        session_id: u32,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let metadata = codec::encode_session_metadata(
            ProtocolType::OpenSessionRequest,
            session_id,
            0,
            0,
            payload.len(),
        )?;
        let mut frame = cipher.encrypt(&metadata)?;
        if !payload.is_empty() {
            frame.extend_from_slice(&cipher.encrypt(payload)?);
        }
        Ok(frame)
    }

    async fn read_client_segment(
        reader: &mut ReadHalf<TcpStream>,
        cipher: &mut crypto::CipherState,
    ) -> anyhow::Result<(Metadata, Vec<u8>)> {
        let metadata = read_metadata(reader, cipher).await?;
        let payload = read_segment_payload(reader, cipher, &metadata).await?;
        Ok((metadata, payload))
    }

    #[test]
    fn accepts_tcp_and_udp_transport() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).expect("config");
        assert_eq!(config.server_port, 8964);
        assert_eq!(config.transport, UnderlayTransport::Tcp);

        let remote = NodeConfigResponse {
            transport: Some(Value::String("UDP".to_string())),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("udp config");
        assert_eq!(config.transport, UnderlayTransport::Udp);
    }

    #[test]
    fn decodes_udp_packet_payload_and_empty_ack() {
        let user = UserCredential::from_panel_user(&PanelUser {
            id: 7,
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".to_string(),
            ..Default::default()
        })
        .expect("user");
        let validator = UserValidator {
            users: vec![user.clone()],
        };
        let key = crypto::derive_keys(&user.hashed_password, std::time::SystemTime::now())
            .expect("keys")[1];
        let nonce_pattern = traffic_pattern::NoncePatternState::new(Default::default());

        let metadata = codec::encode_data_metadata_full(
            ProtocolType::DataClientToServer,
            11,
            3,
            2,
            1024,
            0,
            0,
            4,
            0,
        )
        .expect("metadata");
        let (mut packet, nonce) =
            crypto::encrypt_packet_metadata(key, &user.name, &nonce_pattern, &metadata)
                .expect("metadata encrypt");
        packet.extend_from_slice(
            &crypto::encrypt_packet_payload(key, &nonce, b"ping").expect("payload encrypt"),
        );
        let decoded = decode_packet(&packet, &validator).expect("decode data packet");
        assert_eq!(decoded.payload, b"ping");
        let Metadata::Data(data) = decoded.metadata else {
            panic!("expected data metadata");
        };
        assert_eq!(data.protocol, ProtocolType::DataClientToServer);
        assert_eq!(data.session_id, 11);
        assert_eq!(data.seq, 3);
        assert_eq!(data.unack_seq, 2);

        let metadata = codec::encode_data_metadata_full(
            ProtocolType::AckClientToServer,
            11,
            3,
            5,
            1024,
            0,
            0,
            0,
            0,
        )
        .expect("ack metadata");
        let (packet, _) =
            crypto::encrypt_packet_metadata(key, &user.name, &nonce_pattern, &metadata)
                .expect("ack metadata encrypt");
        let decoded = decode_packet(&packet, &validator).expect("decode ack packet");
        assert!(decoded.payload.is_empty());
        let Metadata::Data(data) = decoded.metadata else {
            panic!("expected ack metadata");
        };
        assert_eq!(data.protocol, ProtocolType::AckClientToServer);
        assert_eq!(data.unack_seq, 5);
    }

    #[test]
    fn user_validator_uses_uuid_before_password() {
        let validator = UserValidator::from_users(&[PanelUser {
            id: 1,
            uuid: "uuid-secret".to_string(),
            password: "real-secret".to_string(),
            ..Default::default()
        }])
        .expect("validator");
        assert_eq!(validator.users[0].name, "uuid-secret");
    }

    #[test]
    fn accepts_xboard_mieru_traffic_pattern() {
        let remote = NodeConfigResponse {
            traffic_pattern: base64::engine::general_purpose::STANDARD
                .encode(traffic_pattern::build_pattern_bytes_for_test()),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(config.traffic_pattern.effective().tcp_fragment.enable);
        assert_eq!(
            config.traffic_pattern.effective().nonce.kind,
            traffic_pattern::NoncePatternKind::PrintableSubset
        );
    }

    #[test]
    fn accepts_disabled_network_settings_and_transport_object() {
        let remote = NodeConfigResponse {
            network_settings: Some(serde_json::json!({
                "enabled": false,
                "header": { "type": "none" }
            })),
            transport: Some(serde_json::json!({
                "enabled": false,
                "type": "udp"
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.server_port, 8964);
    }

    #[test]
    fn accepts_xboard_multiplex_for_mieru() {
        let remote = NodeConfigResponse {
            multiplex: Some(serde_json::json!({
                "enabled": true,
                "protocol": "mieru"
            })),
            ..base_remote()
        };

        EffectiveNodeConfig::from_remote(&remote).expect("config");
    }

    #[tokio::test]
    async fn serves_connect_session_over_mieru_tcp() {
        let user = UserCredential::from_panel_user(&PanelUser {
            id: 7,
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".to_string(),
            ..Default::default()
        })
        .expect("user");

        let target = TcpListener::bind("127.0.0.1:0").await.expect("target bind");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("target accept");
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.expect("target read");
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").await.expect("target write");
        });

        let server = TcpListener::bind("127.0.0.1:0").await.expect("server bind");
        let server_addr = server.local_addr().expect("server addr");
        let accounting = Accounting::new();
        let replay = Arc::new(ReplayCache::default());
        let server_user = user.clone();
        let server_task = tokio::spawn(async move {
            let (stream, source) = server.accept().await.expect("server accept");
            serve_underlay_connection(
                stream,
                source,
                accounting,
                UserValidator {
                    users: vec![server_user],
                },
                traffic_pattern::TrafficPatternConfig::default(),
                routing::RoutingTable::default(),
                replay,
            )
            .await
            .expect("serve underlay");
        });

        let client = TcpStream::connect(server_addr)
            .await
            .expect("client connect");
        let (mut client_reader, mut client_writer) = split(client);
        let request = [
            codec::SOCKS_VERSION,
            0x01,
            0,
            0x01,
            127,
            0,
            0,
            1,
            (target_addr.port() >> 8) as u8,
            target_addr.port() as u8,
            b'p',
            b'i',
            b'n',
            b'g',
        ];
        let (key, frame) = build_client_open_frame(&user, 1, &request).expect("frame");
        client_writer.write_all(&frame).await.expect("client write");

        let mut client_recv =
            crypto::CipherState::new(key, None, traffic_pattern::NoncePattern::default());
        let (metadata, payload) = read_client_segment(&mut client_reader, &mut client_recv)
            .await
            .expect("open response");
        let Metadata::Session(open) = metadata else {
            panic!("expected session metadata");
        };
        assert_eq!(open.protocol, ProtocolType::OpenSessionResponse);
        assert!(payload.is_empty());

        let (metadata, payload) = read_client_segment(&mut client_reader, &mut client_recv)
            .await
            .expect("socks response");
        let Metadata::Data(data) = metadata else {
            panic!("expected data metadata");
        };
        assert_eq!(data.protocol, ProtocolType::DataServerToClient);
        assert_eq!(
            payload[..2],
            [codec::SOCKS_VERSION, codec::SOCKS_REPLY_SUCCESS]
        );

        let (_, payload) = read_client_segment(&mut client_reader, &mut client_recv)
            .await
            .expect("remote payload");
        assert_eq!(payload, b"pong");

        client_writer.shutdown().await.expect("client shutdown");
        let _ = target_task.await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn serves_multiple_sessions_over_one_mieru_tcp_underlay() {
        let user = UserCredential::from_panel_user(&PanelUser {
            id: 7,
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".to_string(),
            ..Default::default()
        })
        .expect("user");

        let target = TcpListener::bind("127.0.0.1:0").await.expect("target bind");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            for expected in [b"one".as_slice(), b"two".as_slice()] {
                let (mut stream, _) = target.accept().await.expect("target accept");
                let mut buffer = vec![0u8; expected.len()];
                stream.read_exact(&mut buffer).await.expect("target read");
                assert_eq!(buffer, expected);
                stream.write_all(expected).await.expect("target write");
            }
        });

        let server = TcpListener::bind("127.0.0.1:0").await.expect("server bind");
        let server_addr = server.local_addr().expect("server addr");
        let accounting = Accounting::new();
        let replay = Arc::new(ReplayCache::default());
        let server_user = user.clone();
        let server_task = tokio::spawn(async move {
            let (stream, source) = server.accept().await.expect("server accept");
            serve_underlay_connection(
                stream,
                source,
                accounting,
                UserValidator {
                    users: vec![server_user],
                },
                traffic_pattern::TrafficPatternConfig::default(),
                routing::RoutingTable::default(),
                replay,
            )
            .await
            .expect("serve underlay");
        });

        let client = TcpStream::connect(server_addr)
            .await
            .expect("client connect");
        let (mut client_reader, mut client_writer) = split(client);
        let request1 = socks_connect_request(target_addr, b"one");
        let request2 = socks_connect_request(target_addr, b"two");
        let key = crypto::derive_keys(&user.hashed_password, std::time::SystemTime::now())
            .expect("keys")[1];
        let mut client_send = crypto::CipherState::new(
            key,
            Some(user.name.clone()),
            traffic_pattern::NoncePattern::default(),
        );
        let frame1 = encrypt_client_open_frame(&mut client_send, 1, &request1).expect("frame1");
        let frame2 = encrypt_client_open_frame(&mut client_send, 2, &request2).expect("frame2");
        client_writer
            .write_all(&frame1)
            .await
            .expect("write frame1");
        client_writer
            .write_all(&frame2)
            .await
            .expect("write frame2");

        let mut client_recv =
            crypto::CipherState::new(key, None, traffic_pattern::NoncePattern::default());
        let mut seen = HashMap::<u32, Vec<Vec<u8>>>::new();
        while !seen
            .get(&1)
            .is_some_and(|payloads| payloads.iter().any(|payload| payload == b"one"))
            || !seen
                .get(&2)
                .is_some_and(|payloads| payloads.iter().any(|payload| payload == b"two"))
        {
            let (metadata, payload) = timeout(
                Duration::from_secs(2),
                read_client_segment(&mut client_reader, &mut client_recv),
            )
            .await
            .expect("client segment timeout")
            .expect("client segment");
            let session_id = match metadata {
                Metadata::Session(value) => value.session_id,
                Metadata::Data(value) => value.session_id,
            };
            seen.entry(session_id).or_default().push(payload);
        }

        assert!(
            seen.get(&1)
                .is_some_and(|payloads| payloads.iter().any(|payload| payload == b"one"))
        );
        assert!(
            seen.get(&2)
                .is_some_and(|payloads| payloads.iter().any(|payload| payload == b"two"))
        );

        client_writer.shutdown().await.expect("client shutdown");
        let _ = target_task.await;
        let _ = server_task.await;
    }

    fn socks_connect_request(target_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut request = vec![codec::SOCKS_VERSION, 0x01, 0, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        request.extend_from_slice(payload);
        request
    }
}
