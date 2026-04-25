mod codec;
mod crypto;

use anyhow::{Context, anyhow, bail, ensure};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use self::codec::{Metadata, ProtocolType, SocksCommand};
use super::anytls::{
    bind_listeners, configure_tcp_stream, effective_listen_ip, routing, socksaddr::SocksAddr,
    traffic::TrafficRecorder, transport,
};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const COPY_BUFFER_LEN: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub routing: routing::RoutingTable,
}

pub struct ServerController {
    accounting: Arc<Accounting>,
    panel_users: Arc<RwLock<Vec<PanelUser>>>,
    users: Arc<RwLock<UserValidator>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    replay: Arc<ReplayCache>,
    inner: Mutex<Option<RunningServer>>,
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
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

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
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
        *self.routing.write().expect("mieru routing lock poisoned") = config.routing;

        let old = {
            let mut guard = self.inner.lock().expect("mieru controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip || running.server_port != config.server_port
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

        let listeners = bind_listeners(&config.listen_ip, config.server_port)?;
        let bind_addrs = listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .map(|addr| format!("tcp://{addr}"))
            .collect::<Vec<_>>();

        let mut handles = Vec::new();
        for listener in listeners {
            let accounting = self.accounting.clone();
            let users = self.users.clone();
            let routing = self.routing.clone();
            let replay = self.replay.clone();
            handles.push(tokio::spawn(async move {
                accept_loop(listener, accounting, users, routing, replay).await;
            }));
        }

        info!(listen = ?bind_addrs, "Mieru listeners started");
        let mut guard = self.inner.lock().expect("mieru controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
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
        let routing = routing.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            let users = users.read().expect("mieru users lock poisoned").clone();
            let routing = routing.read().expect("mieru routing lock poisoned").clone();
            if let Err(error) =
                serve_underlay_connection(stream, source, accounting, users, routing, replay).await
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
    routing: routing::RoutingTable,
    replay: Arc<ReplayCache>,
) -> anyhow::Result<()> {
    let (mut reader, writer) = split(stream);
    let (credential, key, mut recv_cipher, first_metadata) = match timeout(
        AUTHENTICATION_TIMEOUT,
        authenticate_connection(&mut reader, &users, &replay),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => bail!("Mieru authentication timed out"),
    };
    let writer = Arc::new(AsyncMutex::new(ConnectionWriter {
        stream: writer,
        cipher: crypto::CipherState::new(key, Some(credential.name.clone())),
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
                crypto::CipherState::from_received(key, nonce, None),
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

    {
        let mut guard = session.remote_writer.lock().await;
        if let Some(remote) = guard.as_mut() {
            tokio::select! {
                _ = session.control.cancelled() => return Ok(()),
                result = remote.write_all(&payload) => result.context("write Mieru proxied upload")?,
            }
            session.upload.record(payload.len() as u64);
            return Ok(());
        }
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
    let encoded_metadata = writer.cipher.encrypt(metadata)?;
    writer
        .stream
        .write_all(&encoded_metadata)
        .await
        .context("write Mieru metadata")?;
    if !payload.is_empty() {
        let encoded_payload = writer.cipher.encrypt(payload)?;
        writer
            .stream
            .write_all(&encoded_payload)
            .await
            .context("write Mieru payload")?;
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

fn parse_transport(value: Option<&Value>) -> anyhow::Result<()> {
    match value {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(text))
            if text.trim().is_empty() || text.trim().eq_ignore_ascii_case("tcp") =>
        {
            Ok(())
        }
        Some(Value::Object(object))
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("tcp")) =>
        {
            Ok(())
        }
        Some(Value::String(text)) if text.trim().eq_ignore_ascii_case("udp") => {
            bail!("Xboard Mieru UDP transport is not supported by NodeRS yet")
        }
        Some(Value::Object(object))
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("udp")) =>
        {
            bail!("Xboard Mieru UDP transport is not supported by NodeRS yet")
        }
        _ => bail!("Xboard Mieru transport is not supported by NodeRS yet"),
    }
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !remote.network.trim().is_empty() && !remote.network.eq_ignore_ascii_case("tcp") {
        bail!("Xboard network must be tcp for Mieru nodes");
    }
    if remote.network_settings.is_some() {
        bail!("Xboard networkSettings is not supported by NodeRS Mieru server yet");
    }
    parse_transport(remote.transport.as_ref())?;
    if !remote.traffic_pattern.trim().is_empty() {
        bail!("Xboard traffic_pattern is not supported by NodeRS Mieru server yet");
    }
    if remote.multiplex_enabled() {
        bail!("Xboard multiplex is not supported by NodeRS Mieru server yet");
    }
    if remote.tls.is_some() || remote.tls_settings.is_configured() || remote.cert_config.is_some() {
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

fn is_clean_eof(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut cipher = crypto::CipherState::new(key, Some(user.name.clone()));
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
        Ok((key, frame))
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
    fn accepts_tcp_transport_and_rejects_udp_transport() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).expect("config");
        assert_eq!(config.server_port, 8964);

        let remote = NodeConfigResponse {
            transport: Some(Value::String("UDP".to_string())),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("udp transport");
        assert!(error.to_string().contains("UDP"));
    }

    #[test]
    fn user_validator_uses_password_before_uuid() {
        let validator = UserValidator::from_users(&[PanelUser {
            id: 1,
            uuid: "uuid-secret".to_string(),
            password: "real-secret".to_string(),
            ..Default::default()
        }])
        .expect("validator");
        assert_eq!(validator.users[0].name, "real-secret");
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

        let mut client_recv = crypto::CipherState::new(key, None);
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
}
