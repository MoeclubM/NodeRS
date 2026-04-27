mod codec;
mod crypto;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use self::codec::{Command, Request};
use self::crypto::{
    BodyReader, BodyWriter, SecurityType, auth_id_is_fresh, cmd_key, decode_auth_id,
    encode_response_header, parse_uuid,
};
use super::anytls::{
    EffectiveTlsConfig, bind_listeners, configure_tcp_stream, effective_listen_ip, routing, tls,
    traffic::TrafficRecorder, transport,
};

const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_ID_SKEW: Duration = Duration::from_secs(120);
const COPY_BUFFER_LEN: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: Option<EffectiveTlsConfig>,
    pub security: SecurityType,
    pub global_padding: bool,
    pub authenticated_length: bool,
    pub routing: routing::RoutingTable,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let security = SecurityType::from_remote(&remote.cipher)?;
        if security.normalized() == SecurityType::None
            && remote.global_padding
            && !remote.authenticated_length
        {
            bail!("VMess global_padding requires authenticated_length when security is none/zero");
        }
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls: (remote.tls_mode() == 1)
                .then(|| EffectiveTlsConfig::from_remote(remote))
                .transpose()?,
            security,
            global_padding: remote.global_padding,
            authenticated_length: remote.authenticated_length,
            routing: routing::RoutingTable::from_remote(
                &remote.routes,
                &remote.custom_outbounds,
                &remote.custom_routes,
            )
            .context("compile Xboard routing")?,
        })
    }

    #[cfg(test)]
    fn expected_request_options(&self, command: Command) -> crypto::RequestOptions {
        let mut options = crypto::RequestOptions::default();
        match self.security.normalized() {
            SecurityType::None => {
                if self.authenticated_length {
                    options.set_chunk_stream();
                    options.set_authenticated_length();
                    if self.global_padding {
                        options.set_global_padding();
                    }
                } else if matches!(command, Command::Udp) {
                    options.set_chunk_stream();
                }
            }
            SecurityType::Aes128Gcm | SecurityType::ChaCha20Poly1305 => {
                options.set_chunk_stream();
                options.set_chunk_masking();
                if self.global_padding {
                    options.set_global_padding();
                }
                if self.authenticated_length {
                    options.set_authenticated_length();
                }
            }
            SecurityType::Zero => unreachable!("zero security is normalized to none"),
        }
        options
    }

    fn validate_request(&self, request: &Request) -> anyhow::Result<()> {
        ensure!(
            !matches!(request.command, Command::Udp) || request.options.chunk_stream(),
            "VMess UDP packet transfer requires chunk stream"
        );
        request.request_body_config()?;
        request.response_body_config()?;
        Ok(())
    }
}

struct VmessUser {
    user: UserEntry,
    cmd_key: [u8; 16],
}

#[derive(Default)]
struct UserValidator {
    users: Vec<VmessUser>,
    recent_auth_ids: Mutex<HashMap<[u8; 16], Instant>>,
    recent_sessions: Mutex<HashMap<(i64, [u8; 16], [u8; 16]), Instant>>,
}

impl UserValidator {
    fn from_users(users: &[PanelUser]) -> anyhow::Result<Self> {
        let mut entries = Vec::with_capacity(users.len());
        for user in users {
            ensure!(
                user.alter_id <= 0,
                "VMess alterId > 0 is not supported for user {}",
                user.id
            );
            let uuid = parse_uuid(user.uuid.trim())
                .with_context(|| format!("decode VMess uuid for user {}", user.id))?;
            entries.push(VmessUser {
                user: UserEntry::from_panel_user(user),
                cmd_key: cmd_key(&uuid),
            });
        }
        Ok(Self {
            users: entries,
            recent_auth_ids: Mutex::new(HashMap::new()),
            recent_sessions: Mutex::new(HashMap::new()),
        })
    }

    fn match_auth_id(&self, auth_id: &[u8; 16], now: Instant) -> anyhow::Result<&VmessUser> {
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let skew_secs = AUTH_ID_SKEW.as_secs() as i64;

        let mut matched = None;
        for candidate in &self.users {
            let Ok(decoded) = decode_auth_id(&candidate.cmd_key, auth_id) else {
                continue;
            };
            if !auth_id_is_fresh(&decoded, unix_now, skew_secs) {
                continue;
            }
            matched = Some(candidate);
            break;
        }

        let candidate = matched.ok_or_else(|| anyhow!("unknown VMess user or stale auth id"))?;
        let mut recent = self
            .recent_auth_ids
            .lock()
            .expect("vmess auth id replay lock poisoned");
        recent.retain(|_, ts| now.duration_since(*ts) <= AUTH_ID_SKEW);
        if recent.insert(*auth_id, now).is_some() {
            bail!("replayed VMess auth id");
        }
        Ok(candidate)
    }

    fn register_session(
        &self,
        user_id: i64,
        key: [u8; 16],
        iv: [u8; 16],
        now: Instant,
    ) -> anyhow::Result<()> {
        let mut sessions = self
            .recent_sessions
            .lock()
            .expect("vmess session replay lock poisoned");
        sessions.retain(|_, ts| now.duration_since(*ts) <= AUTH_ID_SKEW);
        let session = (user_id, key, iv);
        if sessions.insert(session, now).is_some() {
            bail!("duplicated VMess request session id");
        }
        Ok(())
    }
}

pub struct ServerController {
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    tls_materials: AsyncMutex<Option<tls::LoadedTlsMaterials>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: Arc<RwLock<Option<EffectiveNodeConfig>>>,
    inner: Mutex<Option<RunningServer>>,
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    handles: Vec<JoinHandle<()>>,
}

impl ServerController {
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            tls_config: Arc::new(RwLock::new(None)),
            tls_materials: AsyncMutex::new(None),
            accounting,
            users: Arc::new(RwLock::new(UserValidator::default())),
            runtime: Arc::new(RwLock::new(None)),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        let validator = UserValidator::from_users(users)?;
        self.accounting.replace_users(users);
        *self.users.write().expect("vmess users lock poisoned") = validator;
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        self.update_tls_config(config.tls.as_ref()).await?;
        *self.runtime.write().expect("vmess runtime lock poisoned") = Some(config.clone());

        let old = {
            let mut guard = self.inner.lock().expect("vmess server controller poisoned");
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
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();
        let tls_config = self.tls_config.clone();
        let accounting = self.accounting.clone();
        let users = self.users.clone();
        let runtime = self.runtime.clone();
        info!(listen = ?bind_addrs, "VMess listeners started");
        let mut handles = Vec::new();
        for listener in listeners {
            let tls_config = tls_config.clone();
            let accounting = accounting.clone();
            let users = users.clone();
            let runtime = runtime.clone();
            handles.push(tokio::spawn(async move {
                accept_loop(listener, tls_config, accounting, users, runtime).await;
            }));
        }

        let mut guard = self.inner.lock().expect("vmess server controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            handles,
        });
        Ok(())
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let Some(tls_materials) = tls_materials.as_mut() else {
            return Ok(());
        };
        if let Some(reloaded) = tls::reload_if_changed(tls_materials).await? {
            *self
                .tls_config
                .write()
                .expect("vmess tls config lock poisoned") = Some(reloaded);
            info!("VMess TLS materials reloaded from disk");
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self.inner.lock().expect("vmess server controller poisoned");
            guard.take()
        };
        if let Some(old) = old {
            for handle in old.handles {
                handle.abort();
            }
            info!(port = old.server_port, "VMess listeners stopped");
        }
    }

    async fn update_tls_config(&self, tls: Option<&EffectiveTlsConfig>) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let Some(tls) = tls else {
            *self
                .tls_config
                .write()
                .expect("vmess tls config lock poisoned") = None;
            *tls_materials = None;
            return Ok(());
        };

        let should_reload = tls_materials.as_ref().is_none_or(|current| {
            !current.matches_source(&tls.source, tls.ech.as_ref(), None, &tls.alpn)
        });
        if !should_reload {
            return Ok(());
        }

        let reloaded = tls::load_tls_materials(&tls.source, tls.ech.as_ref(), None, &tls.alpn)
            .await
            .context("load VMess TLS materials")?;
        *self
            .tls_config
            .write()
            .expect("vmess tls config lock poisoned") = Some(reloaded.acceptor());
        *tls_materials = Some(reloaded);
        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: Arc<RwLock<Option<EffectiveNodeConfig>>>,
) {
    let listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "accept VMess connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let accounting = accounting.clone();
        let users = users.clone();
        let runtime = runtime.clone();
        let tls_config = tls_config.clone();
        tokio::spawn(async move {
            let runtime = match runtime.read().expect("vmess runtime lock poisoned").clone() {
                Some(runtime) => runtime,
                None => {
                    warn!(%source, "VMess runtime config is not ready; dropping connection");
                    return;
                }
            };
            let acceptor = tls_config
                .read()
                .expect("vmess tls config lock poisoned")
                .clone();
            let result = if let Some(acceptor) = acceptor {
                match timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    tokio_boring::accept(acceptor.as_ref(), stream),
                )
                .await
                {
                    Ok(Ok(stream)) => {
                        serve_connection(stream, source, accounting, users, runtime).await
                    }
                    Ok(Err(error)) => Err(error).context("VMess TLS handshake failed"),
                    Err(_) => Err(anyhow!("VMess TLS handshake timed out")),
                }
            } else {
                serve_connection(stream, source, accounting, users, runtime).await
            };
            if let Err(error) = result {
                warn!(%error, %source, "VMess session terminated with error");
            }
        });
    }
}

async fn serve_connection<S>(
    mut stream: S,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: EffectiveNodeConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut auth_id = [0u8; 16];
    timeout(REQUEST_HEADER_TIMEOUT, stream.read_exact(&mut auth_id))
        .await
        .context("VMess auth id timed out")?
        .context("read VMess auth id")?;

    let now = Instant::now();
    let user = {
        let validator = users.read().expect("vmess users lock poisoned");
        let matched = validator.match_auth_id(&auth_id, now)?;
        (matched.user.clone(), matched.cmd_key)
    };
    let header = timeout(
        REQUEST_HEADER_TIMEOUT,
        crypto::open_vmess_aead_header(&mut stream, &user.1, &auth_id),
    )
    .await
    .context("VMess AEAD header timed out")??;
    let request = codec::parse_request_header(&header)?;
    runtime.validate_request(&request)?;
    {
        let validator = users.read().expect("vmess users lock poisoned");
        validator.register_session(
            user.0.id,
            request.request_body_key,
            request.request_body_iv,
            now,
        )?;
    }
    let lease = accounting.open_session(&user.0, source)?;
    match request.command {
        Command::Tcp => {
            serve_connect(stream, accounting, lease, user.0, request, runtime.routing).await
        }
        Command::Udp => {
            serve_udp(stream, accounting, lease, user.0, request, runtime.routing).await
        }
    }
}

async fn serve_connect<S>(
    stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    request: Request,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let remote = transport::connect_tcp_destination(&request.destination, &routing)
        .await
        .with_context(|| format!("connect VMess destination {}", request.destination))?;
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);

    let response_header = encode_response_header(
        request.response_header,
        &request.request_body_key,
        &request.request_body_iv,
    )?;

    let (client_read_half, mut client_write_half) = split(stream);
    client_write_half
        .write_all(&response_header)
        .await
        .context("write VMess response header")?;
    let client_reader = BodyReader::new(client_read_half, request.request_body_config()?)?;
    let client_writer = BodyWriter::new(client_write_half, request.response_body_config()?)?;

    let (remote_reader, remote_writer) = split(remote);
    let mut client_to_remote = tokio::spawn(relay_client_to_tcp(
        client_reader,
        remote_writer,
        control.clone(),
        upload,
    ));
    let mut remote_to_client = tokio::spawn(relay_tcp_to_client(
        remote_reader,
        client_writer,
        control.clone(),
        download,
    ));

    tokio::select! {
        _ = control.cancelled() => {
            client_to_remote.abort();
            remote_to_client.abort();
            Ok(())
        }
        result = &mut client_to_remote => {
            control.cancel();
            remote_to_client.abort();
            flatten_join(result, "join VMess uplink relay")
        }
        result = &mut remote_to_client => {
            control.cancel();
            client_to_remote.abort();
            flatten_join(result, "join VMess downlink relay")
        }
    }
}

async fn serve_udp<S>(
    stream: S,
    accounting: Arc<Accounting>,
    lease: SessionLease,
    user: UserEntry,
    request: Request,
    routing: routing::RoutingTable,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = transport::resolve_destination(&request.destination, &routing, "udp")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no UDP addresses resolved for {}", request.destination))?;
    let socket = transport::bind_udp_socket().await?;
    let target = transport::normalize_udp_target(&socket, target);
    socket
        .connect(target)
        .await
        .with_context(|| format!("connect VMess UDP target {target}"))?;

    let response_header = encode_response_header(
        request.response_header,
        &request.request_body_key,
        &request.request_body_iv,
    )?;

    let socket = Arc::new(socket);
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);

    let (client_read_half, mut client_write_half) = split(stream);
    client_write_half
        .write_all(&response_header)
        .await
        .context("write VMess UDP response header")?;
    let client_reader = BodyReader::new(client_read_half, request.request_body_config()?)?;
    let client_writer = BodyWriter::new(client_write_half, request.response_body_config()?)?;

    let mut client_task = tokio::spawn(relay_client_to_udp(
        client_reader,
        socket.clone(),
        control.clone(),
        upload,
    ));
    let mut server_task = tokio::spawn(relay_udp_to_client(
        client_writer,
        socket,
        control.clone(),
        download,
    ));

    tokio::select! {
        _ = control.cancelled() => {
            client_task.abort();
            server_task.abort();
            Ok(())
        }
        result = &mut client_task => {
            control.cancel();
            server_task.abort();
            flatten_join(result, "join VMess UDP uplink relay")
        }
        result = &mut server_task => {
            control.cancel();
            client_task.abort();
            flatten_join(result, "join VMess UDP downlink relay")
        }
    }
}

async fn relay_client_to_tcp<R>(
    mut reader: BodyReader<R>,
    mut writer: WriteHalf<TcpStream>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read_plain(&mut buffer) => match read {
                Ok(read) => read,
                Err(error) if is_broken_pipe(&error) =>
                {
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
                Err(error) => return Err(error),
            },
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&buffer[..read]) => match result {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) => return Ok(()),
                Err(error) => return Err(error).context("write proxied VMess TCP chunk"),
            },
        }
        traffic.record(read as u64);
    }
}

async fn relay_tcp_to_client<W>(
    mut reader: ReadHalf<TcpStream>,
    mut writer: BodyWriter<W>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => match read {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    writer.finish().await?;
                    return Ok(());
                }
                Err(error) => return Err(error).context("read proxied VMess TCP chunk"),
            },
        };
        if read == 0 {
            writer.finish().await?;
            return Ok(());
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all_plain(&buffer[..read]) => result?,
        }
        traffic.record(read as u64);
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            error.kind() == std::io::ErrorKind::BrokenPipe
                || error.kind() == std::io::ErrorKind::ConnectionReset
        })
    })
}

async fn relay_client_to_udp<R>(
    mut reader: BodyReader<R>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            frame = reader.read_packet() => frame?,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let sent = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            sent = socket.send(&frame) => sent.context("send VMess UDP payload")?,
        };
        ensure!(
            sent == frame.len(),
            "short VMess UDP send: expected {}, wrote {}",
            frame.len(),
            sent
        );
        traffic.record(frame.len() as u64);
    }
}

async fn relay_udp_to_client<W>(
    mut writer: BodyWriter<W>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let payload_len = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = socket.recv(&mut buffer) => read.context("receive VMess UDP payload")?,
        };
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_packet_plain(&buffer[..payload_len]) => result?,
        }
        traffic.record(payload_len as u64);
    }
}

fn flatten_join(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    context: &str,
) -> anyhow::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error).context(context.to_string()),
    }
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !remote.network.trim().is_empty() && !remote.network.eq_ignore_ascii_case("tcp") {
        bail!("Xboard network must be tcp for VMess nodes");
    }
    if remote
        .network_settings
        .as_ref()
        .is_some_and(json_has_meaningful_config)
    {
        bail!("Xboard networkSettings is not supported by NodeRS VMess server yet");
    }
    if remote
        .transport
        .as_ref()
        .is_some_and(json_has_meaningful_config)
    {
        bail!("Xboard transport is not supported by NodeRS VMess server yet");
    }
    if remote.multiplex_enabled() {
        bail!("Xboard multiplex is not supported by NodeRS VMess server yet");
    }
    if !matches!(remote.tls_mode(), 0 | 1) {
        bail!(
            "Xboard tls mode {} is not supported by NodeRS VMess server yet",
            remote.tls_mode()
        );
    }
    if remote.tls_mode() == 0
        && (remote.tls_settings.is_configured() || remote.tls_settings.has_reality_key_material())
    {
        bail!("Xboard tls_settings requires tls mode 1 for VMess nodes");
    }
    let packet_encoding = remote.packet_encoding.trim();
    if !packet_encoding.is_empty() && !packet_encoding.eq_ignore_ascii_case("none") {
        bail!("Xboard packet_encoding is not supported by NodeRS VMess server yet");
    }
    if !remote.flow.trim().is_empty() {
        bail!("Xboard flow is not supported by NodeRS VMess server");
    }
    if !remote.decryption.trim().is_empty() && !remote.decryption.eq_ignore_ascii_case("none") {
        bail!("Xboard decryption is not supported for VMess nodes");
    }
    Ok(())
}

fn json_has_meaningful_config(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(number) => {
            number.as_i64().is_some_and(|value| value != 0)
                || number.as_u64().is_some_and(|value| value != 0)
                || number.as_f64().is_some_and(|value| value != 0.0)
        }
        serde_json::Value::String(value) => !value.trim().is_empty(),
        serde_json::Value::Array(values) => values.iter().any(json_has_meaningful_config),
        serde_json::Value::Object(values) => values.values().any(json_has_meaningful_config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::CertConfig;
    use crate::protocols::anytls::socksaddr::SocksAddr;

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "vmess".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 10086,
            cipher: "aes-128-gcm".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn aes_config_derives_expected_options() {
        let remote = NodeConfigResponse {
            global_padding: true,
            authenticated_length: true,
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).unwrap();
        let options = config.expected_request_options(Command::Tcp);
        assert_eq!(options.bits(), 0x1d);
    }

    #[test]
    fn none_udp_defaults_to_chunk_stream() {
        let remote = NodeConfigResponse {
            cipher: "none".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).unwrap();
        assert_eq!(config.expected_request_options(Command::Tcp).bits(), 0x00);
        assert_eq!(config.expected_request_options(Command::Udp).bits(), 0x01);
    }

    #[test]
    fn rejects_unsupported_tls_mode() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).unwrap_err();
        assert!(error.to_string().contains("tls mode"));
    }

    #[test]
    fn accepts_outer_tls_mode_one() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(1)),
            tls_settings: crate::panel::NodeTlsSettings {
                server_name: "node.example.com".to_string(),
                ..Default::default()
            },
            cert_config: Some(CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(config.tls.is_some());
    }

    #[test]
    fn accepts_explicit_tls_zero_and_disabled_multiplex() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(0)),
            multiplex: Some(serde_json::json!({
                "enabled": false,
                "protocol": "yamux"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.server_port, 10086);
    }

    #[test]
    fn accepts_empty_xboard_network_settings_for_tcp() {
        let remote = NodeConfigResponse {
            network: "tcp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "",
                "host": "",
                "headers": null,
                "serviceName": "",
                "header": null
            })),
            ..base_remote()
        };
        EffectiveNodeConfig::from_remote(&remote).expect("config");
    }

    #[test]
    fn rejects_meaningful_xboard_network_settings() {
        let remote = NodeConfigResponse {
            network: "tcp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/ws"
            })),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network settings");
        assert!(error.to_string().contains("networkSettings"));
    }

    #[test]
    fn validates_client_wire_options_not_panel_cipher_template() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).unwrap();
        let request = Request {
            command: Command::Tcp,
            destination: SocksAddr::Domain("example.com".to_string(), 443),
            response_header: 0x7f,
            options: crypto::RequestOptions::default(),
            security: SecurityType::None,
            request_body_iv: [0x11; 16],
            request_body_key: [0x22; 16],
        };
        config.validate_request(&request).expect("request");
    }

    #[test]
    fn rejects_udp_without_chunk_stream() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).unwrap();
        let request = Request {
            command: Command::Udp,
            destination: SocksAddr::Domain("example.com".to_string(), 53),
            response_header: 0x7f,
            options: crypto::RequestOptions::default(),
            security: SecurityType::None,
            request_body_iv: [0x11; 16],
            request_body_key: [0x22; 16],
        };
        let error = config.validate_request(&request).expect_err("chunk stream");
        assert!(error.to_string().contains("chunk stream"));
    }

    #[test]
    fn rejects_invalid_body_options_before_proxying() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).unwrap();
        let request = Request {
            command: Command::Tcp,
            destination: SocksAddr::Domain("example.com".to_string(), 443),
            response_header: 0x7f,
            options: crypto::RequestOptions::default(),
            security: SecurityType::Aes128Gcm,
            request_body_iv: [0x11; 16],
            request_body_key: [0x22; 16],
        };
        let error = config.validate_request(&request).expect_err("body options");
        assert!(error.to_string().contains("requires chunk stream"));
    }

    #[test]
    fn rejects_alter_id_users() {
        let users = vec![PanelUser {
            id: 1,
            uuid: "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string(),
            password: String::new(),
            alter_id: 1,
            speed_limit: 0,
            device_limit: 0,
        }];
        assert!(UserValidator::from_users(&users).is_err());
    }
}
