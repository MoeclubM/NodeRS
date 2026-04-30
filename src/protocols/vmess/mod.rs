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
use super::shared::{
    EffectiveTlsConfig, bind_listeners, configure_tcp_stream, effective_listen_ip, grpc, http1,
    httpupgrade, mux, routing, tls, traffic::TrafficRecorder, transport, ws, xhttp,
};

const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_ID_SKEW: Duration = Duration::from_secs(120);
const COPY_BUFFER_LEN: usize = 64 * 1024;
const HTTP2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: Option<EffectiveTlsConfig>,
    transport: TransportMode,
    #[cfg(test)]
    pub security: SecurityType,
    #[cfg(test)]
    pub global_padding: bool,
    #[cfg(test)]
    pub authenticated_length: bool,
    pub routing: routing::RoutingTable,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let transport = parse_transport_mode(remote)?;
        let mut tls = (remote.tls_mode() == 1)
            .then(|| EffectiveTlsConfig::from_remote(remote))
            .transpose()?;
        if let Some(tls) = tls.as_mut() {
            if matches!(transport, TransportMode::Grpc(_)) && tls.alpn.is_empty() {
                tls.alpn = default_grpc_alpn();
            }
            if matches!(transport, TransportMode::Xhttp(_)) && tls.alpn.is_empty() {
                tls.alpn = default_xhttp_alpn();
            }
        }
        #[cfg(test)]
        let security = SecurityType::from_remote(&remote.cipher)?;
        #[cfg(not(test))]
        SecurityType::from_remote(&remote.cipher)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls,
            transport,
            #[cfg(test)]
            security,
            #[cfg(test)]
            global_padding: remote.global_padding,
            #[cfg(test)]
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
                if matches!(command, Command::Udp) {
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

#[derive(Debug, Clone, PartialEq)]
enum TransportMode {
    Tcp,
    Grpc(grpc::GrpcConfig),
    Ws(ws::WsConfig),
    HttpUpgrade(httpupgrade::HttpUpgradeConfig),
    Xhttp(xhttp::XhttpConfig),
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
                        serve_transport(stream, source, accounting, users, runtime).await
                    }
                    Ok(Err(error)) => Err(error).context("VMess TLS handshake failed"),
                    Err(_) => Err(anyhow!("VMess TLS handshake timed out")),
                }
            } else {
                serve_transport(stream, source, accounting, users, runtime).await
            };
            if let Err(error) = result {
                warn!(%error, %source, "VMess session terminated with error");
            }
        });
    }
}

async fn serve_transport<S>(
    stream: S,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: EffectiveNodeConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match runtime.transport.clone() {
        TransportMode::Tcp => serve_connection(stream, source, accounting, users, runtime).await,
        TransportMode::Grpc(config) => {
            serve_grpc_transport(stream, source, accounting, users, runtime, config).await
        }
        TransportMode::Ws(config) => {
            let Some(stream) = ws::accept(stream, &config).await? else {
                return Ok(());
            };
            serve_connection(stream, source, accounting, users, runtime).await
        }
        TransportMode::HttpUpgrade(config) => {
            let Some(stream) = httpupgrade::accept(stream, &config).await? else {
                return Ok(());
            };
            serve_connection(stream, source, accounting, users, runtime).await
        }
        TransportMode::Xhttp(config) => {
            serve_xhttp_transport(stream, source, accounting, users, runtime, config).await
        }
    }
}

async fn serve_grpc_transport<S>(
    stream: S,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: EffectiveNodeConfig,
    config: grpc::GrpcConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let on_stream: Arc<dyn Fn(grpc::GrpcStream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, source, accounting, users, runtime).await {
                warn!(%error, %source, "VMess gRPC session terminated with error");
            }
        });
    });
    grpc::serve_h2(stream, config, on_stream).await
}

async fn serve_xhttp_transport<S>(
    stream: S,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: EffectiveNodeConfig,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = http1::PrefixedIo::new(stream, Vec::new()).capture_inner_reads();
    let is_h2 = timeout(
        REQUEST_HEADER_TIMEOUT,
        sniff_http2_connection_preface(&mut stream),
    )
    .await
    .map_err(|_| anyhow!("XHTTP connection preface timed out"))??;
    let (stream, prefetched) = stream.into_parts();
    let stream = http1::PrefixedIo::new(stream, prefetched);
    if is_h2 {
        return serve_xhttp_h2_transport(stream, source, accounting, users, runtime, config).await;
    }

    serve_xhttp_http1_transport(stream, source, accounting, users, runtime, config).await
}

async fn serve_xhttp_http1_transport<S>(
    mut stream: http1::PrefixedIo<S>,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: EffectiveNodeConfig,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let wrapped = xhttp::accept_prefixed(stream, &config).await?;
        match wrapped {
            xhttp::AcceptResult::Stream(stream) => {
                return serve_connection(stream, source, accounting, users, runtime).await;
            }
            xhttp::AcceptResult::Responded(xhttp::ResponseState::Continue(next_stream)) => {
                stream = next_stream;
            }
            xhttp::AcceptResult::Responded(xhttp::ResponseState::Closed) => return Ok(()),
        }
    }
}

async fn serve_xhttp_h2_transport<S>(
    stream: S,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    runtime: EffectiveNodeConfig,
    config: xhttp::XhttpConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let on_stream: Arc<dyn Fn(xhttp::XhttpStream) + Send + Sync> = Arc::new(move |stream| {
        let accounting = accounting.clone();
        let users = users.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, source, accounting, users, runtime).await {
                warn!(%error, %source, "VMess XHTTP h2 session terminated with error");
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
        Command::Mux => {
            serve_mux(stream, accounting, lease, user.0, request, runtime.routing).await
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

async fn serve_mux<S>(
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
    let response_header = encode_response_header(
        request.response_header,
        &request.request_body_key,
        &request.request_body_iv,
    )?;

    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), user.id);
    let download = TrafficRecorder::download(accounting, user.id);

    let (client_read_half, mut client_write_half) = split(stream);
    client_write_half
        .write_all(&response_header)
        .await
        .context("write VMess mux response header")?;
    let client_reader = BodyReader::new(client_read_half, request.request_body_config()?)?;
    let client_writer = BodyWriter::new(client_write_half, request.response_body_config()?)?;
    let (client_plain, mux_plain) = tokio::io::duplex(COPY_BUFFER_LEN);
    let (plain_reader, plain_writer) = split(client_plain);

    let mut client_to_mux = tokio::spawn(relay_body_to_plain(
        client_reader,
        plain_writer,
        control.clone(),
    ));
    let mut mux_to_client = tokio::spawn(relay_plain_to_body(
        plain_reader,
        client_writer,
        control.clone(),
    ));
    let mut mux_task = tokio::spawn(mux::relay(
        mux_plain,
        routing,
        control.clone(),
        upload,
        download,
    ));

    tokio::select! {
        _ = control.cancelled() => {
            client_to_mux.abort();
            mux_to_client.abort();
            mux_task.abort();
            Ok(())
        }
        result = &mut client_to_mux => {
            control.cancel();
            mux_to_client.abort();
            mux_task.abort();
            flatten_join(result, "join VMess mux uplink bridge")
        }
        result = &mut mux_to_client => {
            control.cancel();
            client_to_mux.abort();
            mux_task.abort();
            flatten_join(result, "join VMess mux downlink bridge")
        }
        result = &mut mux_task => {
            control.cancel();
            client_to_mux.abort();
            mux_to_client.abort();
            flatten_join(result, "join VMess mux relay")
        }
    }
}

async fn relay_body_to_plain<R, W>(
    mut reader: BodyReader<R>,
    mut writer: W,
    control: Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read_plain(&mut buffer) => match read {
                Ok(read) => read,
                Err(error) if is_broken_pipe(&error) => {
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
            result = writer.write_all(&buffer[..read]) => result.context("write VMess mux plaintext")?,
        }
    }
}

async fn relay_plain_to_body<R, W>(
    mut reader: R,
    mut writer: BodyWriter<W>,
    control: Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER_LEN];
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => read.context("read VMess mux plaintext")?,
        };
        if read == 0 {
            writer.finish().await?;
            return Ok(());
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all_plain(&buffer[..read]) => result?,
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
    parse_transport_mode(remote)?;
    if remote
        .transport
        .as_ref()
        .is_some_and(crate::panel::json_value_is_enabled)
    {
        bail!("Xboard transport is not supported by NodeRS VMess server yet");
    }
    if !matches!(remote.tls_mode(), 0 | 1) {
        bail!(
            "Xboard tls mode {} is not supported by NodeRS VMess server yet",
            remote.tls_mode()
        );
    }
    if remote.reality_settings.is_configured() || remote.tls_settings.has_reality_key_material() {
        bail!("REALITY settings are not supported for VMess nodes");
    }
    if remote.tls_mode() == 0 && remote.tls_settings.is_configured() {
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

fn parse_transport_mode(remote: &NodeConfigResponse) -> anyhow::Result<TransportMode> {
    let network = remote.network.trim();
    if network.is_empty() || network.eq_ignore_ascii_case("tcp") {
        ensure!(
            remote
                .network_settings
                .as_ref()
                .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
            "Xboard networkSettings is only supported for VMess grpc/ws/httpupgrade/xhttp nodes"
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
    bail!("Xboard network must be tcp, grpc, ws, httpupgrade or xhttp for VMess nodes");
}

fn default_grpc_alpn() -> Vec<String> {
    vec!["h2".to_string()]
}

fn default_xhttp_alpn() -> Vec<String> {
    vec!["http/1.1".to_string(), "h2".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::CertConfig;
    use crate::protocols::shared::socksaddr::SocksAddr;
    use tokio::io::duplex;

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
    fn rejects_reality_settings() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(1)),
            tls_settings: crate::panel::NodeTlsSettings {
                private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ..Default::default()
            },
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).unwrap_err();
        assert!(error.to_string().contains("REALITY"));
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
    fn accepts_enabled_vmess_multiplex_config() {
        let remote = NodeConfigResponse {
            multiplex: Some(serde_json::json!({
                "enabled": true,
                "protocol": "mux"
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
    fn accepts_xboard_websocket_transport() {
        let remote = NodeConfigResponse {
            network: "ws".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/vmess",
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
    fn accepts_xboard_grpc_transport() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(1)),
            cert_config: Some(CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            network: "grpc".to_string(),
            network_settings: Some(serde_json::json!({
                "serviceName": "GunService"
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.transport, TransportMode::Grpc(_)));
        assert_eq!(config.tls.expect("tls config").alpn, vec!["h2".to_string()]);
    }

    #[test]
    fn accepts_xboard_httpupgrade_transport() {
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
    fn accepts_xboard_xhttp_transport() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(1)),
            cert_config: Some(CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
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
    fn rejects_meaningful_xboard_network_settings_for_tcp() {
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
    fn rejects_unsupported_xboard_network() {
        let remote = NodeConfigResponse {
            network: "h2".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/h2",
                "host": "cdn.example.com"
            })),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network");
        assert!(error.to_string().contains("network"));
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

    #[tokio::test]
    async fn bridges_vmess_mux_body_to_plain_stream() {
        let mut options = crypto::RequestOptions::default();
        options.set_chunk_stream();
        let config = crypto::BodyConfig::new(
            SecurityType::None,
            options,
            [0x11; 16],
            [0x22; 16],
            [0x11; 16],
            [0x22; 16],
        )
        .expect("body config");
        let (client_io, server_io) = duplex(4096);
        let (plain_reader, plain_writer) = duplex(4096);

        let write = tokio::spawn(async move {
            let mut writer = BodyWriter::new(client_io, config).expect("writer");
            writer
                .write_all_plain(b"mux-bytes")
                .await
                .expect("write body");
            writer.finish().await.expect("finish body");
        });
        let bridge = tokio::spawn(async move {
            let reader = BodyReader::new(server_io, config).expect("reader");
            relay_body_to_plain(reader, plain_writer, SessionControl::new())
                .await
                .expect("bridge body to plain");
        });

        let mut output = Vec::new();
        let mut plain_reader = plain_reader;
        plain_reader
            .read_to_end(&mut output)
            .await
            .expect("read plain");
        write.await.expect("join writer");
        bridge.await.expect("join bridge");
        assert_eq!(output, b"mux-bytes");
    }

    #[tokio::test]
    async fn bridges_plain_stream_to_vmess_mux_body() {
        let mut options = crypto::RequestOptions::default();
        options.set_chunk_stream();
        let config = crypto::BodyConfig::new(
            SecurityType::None,
            options,
            [0x11; 16],
            [0x22; 16],
            [0x11; 16],
            [0x22; 16],
        )
        .expect("body config");
        let (plain_writer, plain_reader) = duplex(4096);
        let (server_io, client_io) = duplex(4096);

        let write = tokio::spawn(async move {
            let mut plain_writer = plain_writer;
            plain_writer
                .write_all(b"mux-response")
                .await
                .expect("write plain");
        });
        let bridge = tokio::spawn(async move {
            let writer = BodyWriter::new(server_io, config).expect("writer");
            relay_plain_to_body(plain_reader, writer, SessionControl::new())
                .await
                .expect("bridge plain to body");
        });

        let mut reader = BodyReader::new(client_io, config).expect("reader");
        let mut output = Vec::new();
        let mut buffer = [0u8; 64];
        loop {
            let read = reader.read_plain(&mut buffer).await.expect("read body");
            if read == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read]);
        }
        write.await.expect("join writer");
        bridge.await.expect("join bridge");
        assert_eq!(output, b"mux-response");
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
