use anyhow::{Context, anyhow, bail, ensure};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use bytes::{Buf, Bytes};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, IdleTimeout, UdpPoller, VarInt};
use rustc_hash::FxHashMap;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser, RouteConfig};

use super::shared::{
    EffectiveTlsConfig, effective_listen_ip, routing::RoutingTable, socksaddr::SocksAddr, tls,
    traffic::TrafficRecorder, transport,
};

const H3_ALPN: &str = "h3";
const AUTH_PATH: &str = "/auth";
const AUTH_HOST: &str = "hysteria";
const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HY2_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const HY2_CONN_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const HY2_MAX_INCOMING_STREAMS: u32 = 1024;
const HY2_DATAGRAM_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const HY2_TCP_REQUEST_ID: u64 = 0x401;
const COPY_BUFFER_LEN: usize = 64 * 1024;
const MAX_ADDRESS_LEN: u64 = 2048;
const MAX_PADDING_LEN: u64 = 4096;
const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;
const SALAMANDER_MIN_PASSWORD_LEN: usize = 4;
const UDP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub tls: EffectiveTlsConfig,
    pub cc_rx: String,
    congestion_control: Hy2CongestionControl,
    auth_timeout: Duration,
    pub udp_enabled: bool,
    obfs: Option<SalamanderConfig>,
    masquerade: MasqueradeConfig,
    pub routes: Vec<RouteConfig>,
    pub custom_outbounds: Vec<serde_json::Value>,
    pub custom_routes: Vec<serde_json::Value>,
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let mut tls = EffectiveTlsConfig::from_remote(remote)?;
        tls.alpn = hy2_alpn(remote)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            tls,
            cc_rx: hy2_cc_rx(remote.up_mbps.as_ref(), remote.ignore_client_bandwidth)?,
            congestion_control: parse_hy2_congestion_control(&remote.congestion_control)?,
            auth_timeout: parse_hy2_duration(
                &remote.auth_timeout,
                DEFAULT_AUTH_TIMEOUT,
                "auth_timeout",
            )?,
            udp_enabled: hy2_udp_enabled(&remote.udp_relay_mode),
            obfs: parse_hy2_obfs(remote)?,
            masquerade: parse_hy2_masquerade(remote.masquerade.as_ref())?,
            routes: remote.routes.clone(),
            custom_outbounds: remote.custom_outbounds.clone(),
            custom_routes: remote.custom_routes.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hy2CongestionControl {
    Bbr,
    Reno,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MasqueradeConfig {
    NotFound,
    File {
        dir: PathBuf,
    },
    Proxy {
        url: String,
        rewrite_host: bool,
        x_forwarded: bool,
        insecure: bool,
    },
    String {
        content: Vec<u8>,
        headers: Vec<(String, String)>,
        status_code: u16,
    },
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
    tls: EffectiveTlsConfig,
    cc_rx: String,
    congestion_control: Hy2CongestionControl,
    auth_timeout: Duration,
    udp_enabled: bool,
    obfs: Option<SalamanderConfig>,
    masquerade: MasqueradeConfig,
    endpoint: Endpoint,
    handle: JoinHandle<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SalamanderConfig {
    password: Vec<u8>,
}

impl SalamanderConfig {
    fn new(password: &str) -> anyhow::Result<Self> {
        let password = password.as_bytes().to_vec();
        ensure!(
            password.len() >= SALAMANDER_MIN_PASSWORD_LEN,
            "HY2 salamander obfs password must be at least {SALAMANDER_MIN_PASSWORD_LEN} bytes"
        );
        Ok(Self { password })
    }
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    io: UdpSocket,
    password: Vec<u8>,
    recv_buffer: Mutex<Vec<u8>>,
}

impl SalamanderUdpSocket {
    fn new(socket: std::net::UdpSocket, config: SalamanderConfig) -> io::Result<Self> {
        Ok(Self {
            io: UdpSocket::from_std(socket)?,
            password: config.password,
            recv_buffer: Mutex::new(Vec::new()),
        })
    }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderUdpPoller {
            socket: self,
            future: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        boring::rand::rand_bytes(&mut salt)
            .map_err(|error| io::Error::other(format!("generate HY2 salamander salt: {error}")))?;
        let mut packet = vec![0u8; SALAMANDER_SALT_LEN + transmit.contents.len()];
        packet[..SALAMANDER_SALT_LEN].copy_from_slice(&salt);
        salamander_xor(
            &self.password,
            &salt,
            transmit.contents,
            &mut packet[SALAMANDER_SALT_LEN..],
        );
        let written = self.io.try_send_to(&packet, transmit.destination)?;
        if written == packet.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write full HY2 salamander packet",
            ))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let mut buffer = self
                .recv_buffer
                .lock()
                .expect("hy2 salamander recv buffer poisoned");
            buffer.resize(bufs[0].len() + SALAMANDER_SALT_LEN, 0);
            match self.io.try_recv_from(&mut buffer) {
                Ok((read, addr)) => {
                    if read <= SALAMANDER_SALT_LEN {
                        continue;
                    }
                    let mut salt = [0u8; SALAMANDER_SALT_LEN];
                    salt.copy_from_slice(&buffer[..SALAMANDER_SALT_LEN]);
                    let output_len = read - SALAMANDER_SALT_LEN;
                    salamander_xor(
                        &self.password,
                        &salt,
                        &buffer[SALAMANDER_SALT_LEN..read],
                        &mut bufs[0][..output_len],
                    );
                    meta[0] = RecvMeta {
                        addr,
                        len: output_len,
                        stride: output_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
type Hy2H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;

struct SalamanderUdpPoller {
    socket: Arc<SalamanderUdpSocket>,
    future: Option<IoFuture>,
}

impl fmt::Debug for SalamanderUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderUdpPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for SalamanderUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.future.is_none() {
            let socket = this.socket.clone();
            this.future = Some(Box::pin(async move { socket.io.writable().await }));
        }
        let result = this
            .future
            .as_mut()
            .expect("HY2 writable future set")
            .as_mut()
            .poll(cx);
        if result.is_ready() {
            this.future = None;
        }
        result
    }
}

fn salamander_xor(
    password: &[u8],
    salt: &[u8; SALAMANDER_SALT_LEN],
    input: &[u8],
    output: &mut [u8],
) {
    debug_assert_eq!(input.len(), output.len());
    let key = salamander_key(password, salt);
    for (index, (plain, cipher)) in output.iter_mut().zip(input).enumerate() {
        *plain = *cipher ^ key[index % SALAMANDER_KEY_LEN];
    }
}

fn salamander_key(password: &[u8], salt: &[u8; SALAMANDER_SALT_LEN]) -> [u8; SALAMANDER_KEY_LEN] {
    let mut key = [0u8; SALAMANDER_KEY_LEN];
    let mut hasher = Blake2bVar::new(SALAMANDER_KEY_LEN).expect("valid BLAKE2b output length");
    hasher.update(password);
    hasher.update(salt);
    hasher
        .finalize_variable(&mut key)
        .expect("valid BLAKE2b output buffer length");
    key
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
                running.listen_ip != config.listen_ip
                    || running.server_port != config.server_port
                    || running.tls != config.tls
                    || running.cc_rx != config.cc_rx
                    || running.congestion_control != config.congestion_control
                    || running.auth_timeout != config.auth_timeout
                    || running.udp_enabled != config.udp_enabled
                    || running.obfs != config.obfs
                    || running.masquerade != config.masquerade
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
        let auth_timeout = config.auth_timeout;
        let udp_enabled = config.udp_enabled;
        let masquerade = config.masquerade.clone();
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
                let masquerade = masquerade.clone();
                connections.spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            if let Err(error) = handle_connection(
                                connection,
                                accounting,
                                users,
                                routing,
                                cc_rx,
                                auth_timeout,
                                udp_enabled,
                                masquerade,
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
            tls: config.tls,
            cc_rx: config.cc_rx,
            congestion_control: config.congestion_control,
            auth_timeout: config.auth_timeout,
            udp_enabled: config.udp_enabled,
            obfs: config.obfs,
            masquerade: config.masquerade,
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
    let rustls_config = tls::load_rustls_server_config(&config.tls.source, &config.tls.alpn)
        .await
        .context("load HY2 TLS materials")?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .context("build HY2 QUIC TLS config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport_config = quinn::TransportConfig::default();
    configure_hy2_transport(&mut transport_config, config.congestion_control)?;
    server_config.transport_config(Arc::new(transport_config));
    let bind_addr = hy2_bind_addr(&config.listen_ip, config.server_port)?;
    if let Some(obfs) = config.obfs.clone() {
        let socket = std::net::UdpSocket::bind(bind_addr).context("bind HY2 UDP endpoint")?;
        socket
            .set_nonblocking(true)
            .context("set HY2 UDP endpoint nonblocking")?;
        let socket = SalamanderUdpSocket::new(socket, obfs)?;
        return Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
        .context("bind HY2 salamander UDP endpoint");
    }
    Endpoint::server(server_config, bind_addr).context("bind HY2 UDP endpoint")
}

fn configure_hy2_transport(
    transport_config: &mut quinn::TransportConfig,
    congestion_control: Hy2CongestionControl,
) -> anyhow::Result<()> {
    let idle_timeout =
        IdleTimeout::try_from(DEFAULT_QUIC_IDLE_TIMEOUT).context("build HY2 QUIC idle timeout")?;
    transport_config
        .max_concurrent_bidi_streams(VarInt::from_u32(HY2_MAX_INCOMING_STREAMS))
        .stream_receive_window(VarInt::from_u32(HY2_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(HY2_CONN_RECEIVE_WINDOW))
        .send_window(u64::from(HY2_CONN_RECEIVE_WINDOW))
        .max_idle_timeout(Some(idle_timeout))
        .datagram_receive_buffer_size(Some(HY2_DATAGRAM_BUFFER_SIZE))
        .datagram_send_buffer_size(HY2_DATAGRAM_BUFFER_SIZE)
        .congestion_controller_factory(match congestion_control {
            Hy2CongestionControl::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            Hy2CongestionControl::Reno => Arc::new(quinn::congestion::NewRenoConfig::default()),
        });
    Ok(())
}

fn hy2_bind_addr(listen_ip: &str, server_port: u16) -> anyhow::Result<SocketAddr> {
    let listen_ip = listen_ip.trim();
    format!("{listen_ip}:{server_port}")
        .parse()
        .with_context(|| format!("parse HY2 listen address {listen_ip}:{server_port}"))
}

async fn handle_connection(
    connection: quinn::Connection,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    routing: RoutingTable,
    cc_rx: String,
    auth_timeout: Duration,
    udp_enabled: bool,
    masquerade: MasqueradeConfig,
) -> anyhow::Result<()> {
    let Some((user, lease, _h3_connection)) = authenticate_connection(
        &connection,
        accounting.clone(),
        users,
        cc_rx,
        auth_timeout,
        udp_enabled,
        masquerade,
    )
    .await?
    else {
        return Ok(());
    };
    // The h3 server connection sends H3_NO_ERROR from Drop. Keep it alive for the
    // whole proxy connection so clients can open HY2 TCP streams after /auth.
    let control = lease.control();
    if udp_enabled {
        let sessions = Arc::new(AsyncMutex::new(FxHashMap::default()));
        let fragments = Arc::new(AsyncMutex::new(FxHashMap::default()));
        tokio::spawn(handle_udp_datagrams(
            connection.clone(),
            sessions,
            fragments,
            routing.clone(),
            accounting.clone(),
            user.clone(),
            control.clone(),
        ));
    }

    loop {
        let (send, recv) = match tokio::select! {
            _ = control.cancelled() => {
                connection.close(VarInt::from_u32(0), b"session cancelled");
                return Ok(());
            }
            stream = connection.accept_bi() => stream
        } {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(error) => return Err(error).context("accept HY2 TCP stream"),
        };
        let accounting = accounting.clone();
        let routing = routing.clone();
        let user = user.clone();
        let control = control.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_tcp_stream(send, recv, accounting, user, routing, control).await
            {
                warn!(%error, "HY2 TCP stream failed");
            }
        });
    }
}

async fn authenticate_connection(
    connection: &quinn::Connection,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<UserValidator>>,
    cc_rx: String,
    auth_timeout: Duration,
    udp_enabled: bool,
    masquerade: MasqueradeConfig,
) -> anyhow::Result<Option<(UserEntry, SessionLease, Hy2H3Connection)>> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3 = h3::server::builder()
        .build(h3_connection)
        .await
        .context("initialize HY2 HTTP/3 server")?;
    let timeout = tokio::time::sleep(auth_timeout);
    tokio::pin!(timeout);
    loop {
        let resolver = tokio::select! {
            _ = &mut timeout => return Err(anyhow!("HY2 auth request timed out")),
            resolver = h3.accept() => resolver
                .context("accept HY2 HTTP/3 request")?
                .ok_or_else(|| anyhow!("HY2 connection closed before auth"))?,
        };
        let (request, mut stream) = resolver
            .resolve_request()
            .await
            .context("resolve HY2 HTTP/3 request")?;

        if !is_auth_request(&request) {
            send_masquerade_response(
                &masquerade,
                &request,
                &mut stream,
                connection.remote_address(),
            )
            .await?;
            continue;
        }

        let auth = request
            .headers()
            .get("Hysteria-Auth")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .trim();
        let user = users.read().expect("hy2 users lock poisoned").get(auth);
        let Some(user) = user else {
            send_masquerade_response(
                &masquerade,
                &request,
                &mut stream,
                connection.remote_address(),
            )
            .await?;
            continue;
        };
        let lease = accounting.open_session(&user, connection.remote_address())?;

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
        return Ok(Some((user, lease, h3)));
    }
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

async fn send_masquerade_response<S>(
    config: &MasqueradeConfig,
    request: &http::Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    remote_addr: SocketAddr,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    match config {
        MasqueradeConfig::NotFound => send_h3_status(stream, 404).await,
        MasqueradeConfig::String {
            content,
            headers,
            status_code,
        } => send_h3_body(stream, *status_code, headers, content.clone()).await,
        MasqueradeConfig::File { dir } => send_file_masquerade(dir, request, stream).await,
        MasqueradeConfig::Proxy {
            url,
            rewrite_host,
            x_forwarded,
            insecure,
        } => {
            send_proxy_masquerade(
                url,
                *rewrite_host,
                *x_forwarded,
                *insecure,
                request,
                stream,
                remote_addr,
            )
            .await
        }
    }
}

async fn send_h3_body<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: u16,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut response = http::Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    let response = response
        .body(())
        .with_context(|| format!("build HY2 HTTP/3 {status} response"))?;
    stream
        .send_response(response)
        .await
        .with_context(|| format!("send HY2 HTTP/3 {status} response"))?;
    if !body.is_empty() {
        stream
            .send_data(Bytes::from(body))
            .await
            .context("send HY2 HTTP/3 response body")?;
    }
    stream
        .finish()
        .await
        .with_context(|| format!("finish HY2 HTTP/3 {status} response"))?;
    Ok(())
}

async fn send_file_masquerade<S>(
    dir: &Path,
    request: &http::Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let path = masquerade_file_path(dir, request.uri().path())?;
    let path = match tokio::fs::metadata(&path).await {
        Ok(metadata) if metadata.is_dir() => path.join("index.html"),
        Ok(metadata) if metadata.is_file() => path,
        Ok(_) => return send_h3_status(stream, 404).await,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return send_h3_status(stream, 404).await;
        }
        Err(error) => return Err(error).context("read HY2 masquerade file metadata"),
    };
    let body = match tokio::fs::read(&path).await {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return send_h3_status(stream, 404).await;
        }
        Err(error) => return Err(error).context("read HY2 masquerade file"),
    };
    send_h3_body(stream, 200, &[], body).await
}

async fn send_proxy_masquerade<S>(
    url: &str,
    rewrite_host: bool,
    x_forwarded: bool,
    insecure: bool,
    request: &http::Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    remote_addr: SocketAddr,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let target = masquerade_proxy_url(url, request.uri())?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .context("receive HY2 masquerade request body")?
    {
        while chunk.has_remaining() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
    }

    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder
        .build()
        .context("build HY2 masquerade proxy client")?;
    let mut proxied = client.request(request.method().clone(), target);
    for (name, value) in request.headers() {
        if !is_hop_by_hop_header(name) {
            proxied = proxied.header(name, value.clone());
        }
    }
    if !rewrite_host && let Some(authority) = request.uri().authority() {
        proxied = proxied.header(http::header::HOST, authority.as_str());
    }
    if x_forwarded {
        proxied = proxied
            .header("x-forwarded-for", remote_addr.ip().to_string())
            .header("x-forwarded-proto", "https");
        if let Some(authority) = request.uri().authority() {
            proxied = proxied.header("x-forwarded-host", authority.as_str());
        }
    }

    let response = proxied
        .body(body)
        .send()
        .await
        .context("proxy HY2 masquerade request")?;
    let status = response.status();
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        if !is_hop_by_hop_header(name) {
            headers.push((
                name.as_str().to_string(),
                value
                    .to_str()
                    .context("decode HY2 masquerade proxy response header")?
                    .to_string(),
            ));
        }
    }
    let body = response
        .bytes()
        .await
        .context("read HY2 masquerade proxy response")?
        .to_vec();
    send_h3_body(stream, status.as_u16(), &headers, body).await
}

fn is_hop_by_hop_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn masquerade_proxy_url(base_url: &str, uri: &http::Uri) -> anyhow::Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(base_url).context("parse HY2 masquerade proxy url")?;
    let mut path = url.path().trim_end_matches('/').to_string();
    let request_path = uri.path();
    if request_path == "/" {
        if path.is_empty() {
            path.push('/');
        }
    } else {
        path.push('/');
        path.push_str(request_path.trim_start_matches('/'));
    }
    url.set_path(&path);
    let query = match (url.query(), uri.query()) {
        (Some(base), Some(request)) if !base.is_empty() && !request.is_empty() => {
            Some(format!("{base}&{request}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(request)) if !request.is_empty() => Some(request.to_string()),
        _ => None,
    };
    url.set_query(query.as_deref());
    Ok(url)
}

fn masquerade_file_path(root: &Path, request_path: &str) -> anyhow::Result<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(request_path.trim_start_matches('/'))
        .decode_utf8()
        .context("decode HY2 masquerade file path")?;
    let mut path = root.to_path_buf();
    for component in Path::new(decoded.as_ref()).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("HY2 masquerade file path escapes root")
            }
        }
    }
    Ok(path)
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    accounting: Arc<Accounting>,
    user: UserEntry,
    routing: RoutingTable,
    control: Arc<SessionControl>,
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
type UdpFragments = Arc<AsyncMutex<FxHashMap<(u32, u16), UdpFragmentBuffer>>>;

struct UdpSession {
    socket: Arc<UdpSocket>,
    last_seen: Arc<Mutex<Instant>>,
    response_handle: Mutex<JoinHandle<()>>,
}

struct UdpFragmentBuffer {
    address: String,
    created_at: Instant,
    fragments: Vec<Option<Vec<u8>>>,
}

impl UdpSession {
    fn touch(&self) {
        *self
            .last_seen
            .lock()
            .expect("HY2 UDP session time poisoned") = Instant::now();
    }

    fn is_idle(&self, now: Instant) -> bool {
        now.saturating_duration_since(
            *self
                .last_seen
                .lock()
                .expect("HY2 UDP session time poisoned"),
        ) >= UDP_SESSION_IDLE_TIMEOUT
    }

    fn abort_response_relay(&self) {
        self.response_handle
            .lock()
            .expect("HY2 UDP response handle poisoned")
            .abort();
    }
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
    fragments: UdpFragments,
    routing: RoutingTable,
    accounting: Arc<Accounting>,
    user: UserEntry,
    control: Arc<SessionControl>,
) {
    let upload_traffic = TrafficRecorder::upload(accounting.clone(), user.id);
    let mut cleanup = tokio::time::interval(UDP_FRAGMENT_TIMEOUT);
    loop {
        let datagram = match tokio::select! {
            _ = control.cancelled() => return,
            _ = cleanup.tick() => {
                cleanup_udp_state(&sessions, &fragments).await;
                continue;
            }
            datagram = connection.read_datagram() => datagram,
        } {
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
        let message = match reassemble_udp_message(message, &fragments).await {
            Ok(Some(message)) => {
                upload_traffic.limit(upload, &control).await;
                if control.is_cancelled() {
                    return;
                }
                upload_traffic.record(upload);
                message
            }
            Ok(None) => {
                upload_traffic.limit(upload, &control).await;
                if control.is_cancelled() {
                    return;
                }
                upload_traffic.record(upload);
                continue;
            }
            Err(error) => {
                warn!(%error, "invalid HY2 UDP fragment");
                continue;
            }
        };
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
            control.clone(),
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
    }
}

async fn reassemble_udp_message(
    message: UdpMessage,
    fragments: &UdpFragments,
) -> anyhow::Result<Option<UdpMessage>> {
    ensure!(
        message.fragment_count > 0,
        "HY2 UDP fragment_count must be positive"
    );
    if message.fragment_count == 1 {
        return Ok(Some(message));
    }
    ensure!(
        message.fragment_id < message.fragment_count,
        "HY2 UDP fragment_id must be less than fragment_count"
    );

    let key = (message.session_id, message.packet_id);
    let mut guard = fragments.lock().await;
    let entry = guard.entry(key).or_insert_with(|| UdpFragmentBuffer {
        address: message.address.clone(),
        created_at: Instant::now(),
        fragments: vec![None; usize::from(message.fragment_count)],
    });
    ensure!(
        entry.fragments.len() == usize::from(message.fragment_count),
        "HY2 UDP fragment_count changed for packet"
    );
    ensure!(
        entry.address == message.address,
        "HY2 UDP fragment address changed for packet"
    );
    let index = usize::from(message.fragment_id);
    entry.fragments[index] = Some(message.payload);
    if entry.fragments.iter().any(Option::is_none) {
        return Ok(None);
    }

    let entry = guard.remove(&key).expect("HY2 fragment buffer exists");
    let mut payload = Vec::new();
    for fragment in entry.fragments {
        payload.extend(fragment.expect("HY2 fragment present"));
    }
    Ok(Some(UdpMessage {
        session_id: key.0,
        packet_id: key.1,
        fragment_id: 0,
        fragment_count: 1,
        address: entry.address,
        payload,
    }))
}

async fn cleanup_udp_state(sessions: &UdpSessions, fragments: &UdpFragments) {
    cleanup_udp_fragments(fragments).await;
    cleanup_udp_sessions(sessions).await;
}

async fn cleanup_udp_fragments(fragments: &UdpFragments) {
    let now = Instant::now();
    fragments.lock().await.retain(|_, buffer| {
        now.saturating_duration_since(buffer.created_at) < UDP_FRAGMENT_TIMEOUT
    });
}

async fn cleanup_udp_sessions(sessions: &UdpSessions) {
    let now = Instant::now();
    let expired = {
        let mut guard = sessions.lock().await;
        let session_ids = guard
            .iter()
            .filter_map(|(session_id, session)| session.is_idle(now).then_some(*session_id))
            .collect::<Vec<_>>();
        session_ids
            .into_iter()
            .filter_map(|session_id| guard.remove(&session_id))
            .collect::<Vec<_>>()
    };
    for session in expired {
        session.abort_response_relay();
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
    control: Arc<SessionControl>,
) -> anyhow::Result<Arc<UdpSession>> {
    if let Some(session) = sessions.lock().await.get(&session_id).cloned() {
        session.touch();
        return Ok(session);
    }
    let socket = Arc::new(transport::bind_udp_socket().await?);
    let connection = connection.clone();
    let download = TrafficRecorder::download(accounting, user.id);
    let last_seen = Arc::new(Mutex::new(Instant::now()));
    let response_last_seen = last_seen.clone();
    let response_socket = socket.clone();
    let response_handle = tokio::spawn(async move {
        if let Err(error) = relay_udp_responses(
            session_id,
            response_socket,
            connection,
            control,
            download,
            response_last_seen,
        )
        .await
        {
            warn!(%error, session_id, "HY2 UDP response relay failed");
        }
    });
    let session = Arc::new(UdpSession {
        socket: socket.clone(),
        last_seen,
        response_handle: Mutex::new(response_handle),
    });
    sessions.lock().await.insert(session_id, session.clone());
    Ok(session)
}

async fn relay_udp_responses(
    session_id: u32,
    socket: Arc<UdpSocket>,
    connection: quinn::Connection,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
    last_seen: Arc<Mutex<Instant>>,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (read, source) = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            closed = connection.closed() => {
                debug_connection_closed_as_udp_end(closed);
                return Ok(());
            }
            result = socket.recv_from(&mut buffer) => result.context("receive HY2 UDP response")?,
        };
        *last_seen.lock().expect("HY2 UDP session time poisoned") = Instant::now();
        let messages = encode_udp_response_messages(
            session_id,
            next_udp_packet_id(),
            source.to_string(),
            &buffer[..read],
            connection.max_datagram_size(),
        )?;
        for message in messages {
            let encoded = encode_udp_message(&message)?;
            traffic.limit(encoded.len() as u64, &control).await;
            if control.is_cancelled() {
                return Ok(());
            }
            match connection.send_datagram(Bytes::from(encoded.clone())) {
                Ok(()) => traffic.record(encoded.len() as u64),
                Err(error) => return Err(error).context("send HY2 UDP datagram"),
            }
        }
    }
}

fn encode_udp_response_messages(
    session_id: u32,
    packet_id: u16,
    address: String,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<UdpMessage>> {
    let max_datagram_size = max_datagram_size.unwrap_or(usize::MAX);
    let header_len = encoded_udp_header_len(&address)?;
    if header_len + payload.len() <= max_datagram_size {
        return Ok(vec![UdpMessage {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address,
            payload: payload.to_vec(),
        }]);
    }
    ensure!(
        header_len < max_datagram_size,
        "HY2 UDP datagram header exceeds peer limit"
    );
    let fragment_payload_len = max_datagram_size - header_len;
    ensure!(
        fragment_payload_len > 0,
        "HY2 UDP fragment payload limit is zero"
    );
    let fragment_count = payload.len().div_ceil(fragment_payload_len);
    ensure!(
        fragment_count <= u8::MAX as usize,
        "HY2 UDP packet requires too many fragments"
    );
    let mut messages = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(fragment_payload_len).enumerate() {
        messages.push(UdpMessage {
            session_id,
            packet_id,
            fragment_id: index as u8,
            fragment_count: fragment_count as u8,
            address: address.clone(),
            payload: chunk.to_vec(),
        });
    }
    Ok(messages)
}

fn encoded_udp_header_len(address: &str) -> anyhow::Result<usize> {
    let mut varint = Vec::new();
    encode_varint(address.len() as u64, &mut varint)?;
    Ok(8 + varint.len() + address.len())
}

fn next_udp_packet_id() -> u16 {
    static NEXT_PACKET_ID: AtomicU16 = AtomicU16::new(0);
    NEXT_PACKET_ID.fetch_add(1, Ordering::Relaxed)
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
    ensure!(address_len > 0, "HY2 address is required");
    ensure!(address_len <= MAX_ADDRESS_LEN, "HY2 address is too long");
    let mut address = vec![0u8; address_len as usize];
    reader
        .read_exact(&mut address)
        .await
        .context("read HY2 target address")?;
    let padding_len = read_varint(reader).await?;
    ensure!(padding_len <= MAX_PADDING_LEN, "HY2 padding is too long");
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
        traffic.limit(read as u64, &control).await;
        if control.is_cancelled() {
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
    ensure!(address_len > 0, "HY2 UDP address is required");
    ensure!(
        address_len <= MAX_ADDRESS_LEN,
        "HY2 UDP address is too long"
    );
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

fn hy2_alpn(remote: &NodeConfigResponse) -> anyhow::Result<Vec<String>> {
    for protocol in &remote.alpn {
        ensure!(
            protocol.eq_ignore_ascii_case(H3_ALPN),
            "HY2 alpn only supports h3"
        );
    }
    Ok(vec![H3_ALPN.to_string()])
}

fn parse_hy2_congestion_control(value: &str) -> anyhow::Result<Hy2CongestionControl> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "bbr" => Ok(Hy2CongestionControl::Bbr),
        "reno" => Ok(Hy2CongestionControl::Reno),
        other => bail!("unsupported HY2 congestion_control {other}"),
    }
}

fn parse_hy2_duration(value: &str, default: Duration, field: &str) -> anyhow::Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(default);
    }
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let number = value[..split]
        .parse::<u64>()
        .with_context(|| format!("parse HY2 {field}"))?;
    let duration = match &value[split..] {
        "" | "s" => Duration::from_secs(number),
        "ms" => Duration::from_millis(number),
        "m" => Duration::from_secs(number.saturating_mul(60)),
        "h" => Duration::from_secs(number.saturating_mul(3600)),
        unit => bail!("unsupported HY2 {field} unit {unit}"),
    };
    ensure!(duration > Duration::ZERO, "HY2 {field} must be positive");
    Ok(duration)
}

fn parse_hy2_masquerade(value: Option<&serde_json::Value>) -> anyhow::Result<MasqueradeConfig> {
    let Some(value) = value else {
        return Ok(MasqueradeConfig::NotFound);
    };
    match value {
        serde_json::Value::Null => Ok(MasqueradeConfig::NotFound),
        serde_json::Value::String(kind) if kind.trim().is_empty() || kind.trim() == "404" => {
            Ok(MasqueradeConfig::NotFound)
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("404")
                .trim()
                .to_ascii_lowercase();
            match kind.as_str() {
                "" | "404" => Ok(MasqueradeConfig::NotFound),
                "file" => {
                    let file = object.get("file").and_then(serde_json::Value::as_object);
                    let dir = file
                        .and_then(|file| file.get("dir"))
                        .or_else(|| object.get("dir"))
                        .and_then(serde_json::Value::as_str)
                        .context("HY2 masquerade.file.dir is required")?;
                    Ok(MasqueradeConfig::File {
                        dir: PathBuf::from(dir),
                    })
                }
                "proxy" => {
                    let proxy = object.get("proxy").and_then(serde_json::Value::as_object);
                    let url = proxy
                        .and_then(|proxy| proxy.get("url"))
                        .or_else(|| object.get("url"))
                        .and_then(serde_json::Value::as_str)
                        .context("HY2 masquerade.proxy.url is required")?;
                    let parsed =
                        reqwest::Url::parse(url).context("parse HY2 masquerade proxy url")?;
                    ensure!(
                        matches!(parsed.scheme(), "http" | "https"),
                        "HY2 masquerade proxy url must use http or https"
                    );
                    Ok(MasqueradeConfig::Proxy {
                        url: url.to_string(),
                        rewrite_host: json_bool(
                            proxy
                                .and_then(|proxy| proxy.get("rewriteHost"))
                                .or_else(|| object.get("rewriteHost")),
                        ),
                        x_forwarded: json_bool(
                            proxy
                                .and_then(|proxy| proxy.get("xForwarded"))
                                .or_else(|| object.get("xForwarded")),
                        ),
                        insecure: json_bool(
                            proxy
                                .and_then(|proxy| proxy.get("insecure"))
                                .or_else(|| object.get("insecure")),
                        ),
                    })
                }
                "string" => {
                    let string = object.get("string").and_then(serde_json::Value::as_object);
                    let content = string
                        .and_then(|string| string.get("content"))
                        .or_else(|| object.get("content"))
                        .and_then(serde_json::Value::as_str)
                        .context("HY2 masquerade.string.content is required")?;
                    let status_code = string
                        .and_then(|string| string.get("statusCode"))
                        .or_else(|| object.get("statusCode"))
                        .map(parse_hy2_status_code)
                        .transpose()?
                        .unwrap_or(200);
                    ensure!(
                        status_code != 233,
                        "HY2 masquerade.string.statusCode cannot be 233"
                    );
                    let headers = parse_masquerade_headers(
                        string
                            .and_then(|string| string.get("headers"))
                            .or_else(|| object.get("headers")),
                    )?;
                    Ok(MasqueradeConfig::String {
                        content: content.as_bytes().to_vec(),
                        headers,
                        status_code,
                    })
                }
                other => bail!("unsupported HY2 masquerade type {other}"),
            }
        }
        _ => bail!("HY2 masquerade must be an object"),
    }
}

fn parse_hy2_status_code(value: &serde_json::Value) -> anyhow::Result<u16> {
    let status = value_to_u64(value)?;
    ensure!(
        (200..=599).contains(&status),
        "HY2 masquerade status code must be 200-599"
    );
    Ok(status as u16)
}

fn parse_masquerade_headers(
    value: Option<&serde_json::Value>,
) -> anyhow::Result<Vec<(String, String)>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let serde_json::Value::Object(object) = value else {
        bail!("HY2 masquerade.string.headers must be an object");
    };
    object
        .iter()
        .map(|(name, value)| {
            let value = value
                .as_str()
                .context("HY2 masquerade.string.headers values must be strings")?;
            Ok((name.clone(), value.to_string()))
        })
        .collect()
}

fn json_bool(value: Option<&serde_json::Value>) -> bool {
    value.and_then(serde_json::Value::as_bool).unwrap_or(false)
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if let Some(version) = &remote.version {
        let version = match version {
            serde_json::Value::Number(number) => number
                .as_u64()
                .ok_or_else(|| anyhow!("HY2 version must be a non-negative integer"))?,
            serde_json::Value::String(text) => {
                text.trim().parse::<u64>().context("parse HY2 version")?
            }
            _ => bail!("HY2 version must be a number or decimal string"),
        };
        ensure!(version == 2, "HY2 only supports hysteria version 2");
    }
    if remote.tls_mode() == 2
        || remote.reality_settings.is_configured()
        || remote.tls_settings.has_reality_key_material()
    {
        bail!("HY2 does not support REALITY TLS mode");
    }
    if remote.tls_settings.ech.is_enabled() {
        bail!(
            "HY2 QUIC TLS does not support Xboard tls_settings.ech with the current rustls backend"
        );
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

fn parse_hy2_obfs(remote: &NodeConfigResponse) -> anyhow::Result<Option<SalamanderConfig>> {
    let Some(obfs) = remote.obfs.as_ref() else {
        ensure!(
            remote.obfs_password.trim().is_empty(),
            "HY2 obfs password requires salamander obfs"
        );
        return Ok(None);
    };
    if !crate::panel::json_value_is_enabled(obfs) {
        ensure!(
            remote.obfs_password.trim().is_empty(),
            "HY2 obfs password requires salamander obfs"
        );
        return Ok(None);
    }

    let obfs_type = hy2_obfs_type(obfs).unwrap_or_default();
    ensure!(
        obfs_type.eq_ignore_ascii_case("salamander"),
        "HY2 obfs must be salamander"
    );
    let password = remote.obfs_password.trim();
    ensure!(
        !password.is_empty(),
        "HY2 salamander obfs password is required"
    );
    Ok(Some(SalamanderConfig::new(password)?))
}

fn hy2_obfs_type(value: &serde_json::Value) -> Option<&str> {
    match value {
        serde_json::Value::String(text) => Some(text.trim()),
        serde_json::Value::Object(object) => object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::trim),
        _ => None,
    }
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
    use crate::panel::{CertConfig, NodeEchSettings, NodeTlsSettings};

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
            version: Some(serde_json::json!(2)),
            up_mbps: Some(serde_json::json!(100)),
            down_mbps: Some(serde_json::json!(300)),
            udp_relay_mode: "native".to_string(),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.cc_rx, "12500000");
        assert_eq!(config.tls.alpn, vec!["h3".to_string()]);
        assert_eq!(config.congestion_control, Hy2CongestionControl::Bbr);
        assert_eq!(config.auth_timeout, DEFAULT_AUTH_TIMEOUT);
        assert_eq!(config.masquerade, MasqueradeConfig::NotFound);
        assert!(config.udp_enabled);
    }

    #[test]
    fn parses_hy2_congestion_timeout_and_masquerade() {
        let remote = NodeConfigResponse {
            congestion_control: "reno".to_string(),
            auth_timeout: "3s".to_string(),
            masquerade: Some(serde_json::json!({
                "type": "string",
                "content": "hello",
                "headers": {
                    "content-type": "text/plain"
                },
                "statusCode": 418
            })),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.congestion_control, Hy2CongestionControl::Reno);
        assert_eq!(config.auth_timeout, Duration::from_secs(3));
        assert_eq!(
            config.masquerade,
            MasqueradeConfig::String {
                content: b"hello".to_vec(),
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                status_code: 418,
            }
        );
    }

    #[test]
    fn rejects_unsupported_hy2_congestion_control() {
        let remote = NodeConfigResponse {
            congestion_control: "cubic".to_string(),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("congestion");
        assert!(error.to_string().contains("congestion_control"));
    }

    #[test]
    fn rejects_non_h3_hy2_alpn() {
        let remote = NodeConfigResponse {
            alpn: vec!["h2".to_string()],
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("alpn");
        assert!(error.to_string().contains("alpn"));
    }

    #[test]
    fn rejects_hy2_ech_until_quic_backend_supports_it() {
        let remote = NodeConfigResponse {
            tls_settings: NodeTlsSettings {
                ech: NodeEchSettings {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("ech");
        assert!(error.to_string().contains("tls_settings.ech"));
    }

    #[test]
    fn parses_hy2_proxy_masquerade_from_xboard_shape() {
        let config = parse_hy2_masquerade(Some(&serde_json::json!({
            "type": "proxy",
            "url": "https://example.com/base",
            "rewriteHost": true,
            "xForwarded": true,
            "insecure": true
        })))
        .expect("masquerade");

        assert_eq!(
            config,
            MasqueradeConfig::Proxy {
                url: "https://example.com/base".to_string(),
                rewrite_host: true,
                x_forwarded: true,
                insecure: true,
            }
        );
    }

    #[test]
    fn builds_hy2_proxy_masquerade_target_url() {
        let uri: http::Uri = "https://hysteria.example/path?q=1".parse().expect("uri");
        let url = masquerade_proxy_url("https://example.com/base?token=2", &uri).expect("url");

        assert_eq!(url.as_str(), "https://example.com/base/path?token=2&q=1");
    }

    #[test]
    fn rejects_hy2_file_masquerade_path_escape() {
        let error =
            masquerade_file_path(Path::new("/var/www"), "/../secret").expect_err("path escape");

        assert!(error.to_string().contains("escapes root"));
    }

    #[test]
    fn hy2_cc_rx_uses_server_receive_bandwidth() {
        let remote = NodeConfigResponse {
            up_mbps: Some(serde_json::json!(40)),
            down_mbps: Some(serde_json::json!(200)),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(config.cc_rx, "5000000");
    }

    #[test]
    fn rejects_hysteria_v1_config() {
        let remote = NodeConfigResponse {
            version: Some(serde_json::json!(1)),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("version");
        assert!(error.to_string().contains("version 2"));
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
    fn parses_hy2_salamander_obfs() {
        let remote = NodeConfigResponse {
            obfs: Some(serde_json::json!({ "type": "salamander" })),
            obfs_password: "secret".to_string(),
            ..base_remote()
        };

        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert_eq!(
            config.obfs,
            Some(SalamanderConfig {
                password: b"secret".to_vec()
            })
        );
    }

    #[test]
    fn rejects_hy2_salamander_short_password() {
        let remote = NodeConfigResponse {
            obfs: Some(serde_json::json!("salamander")),
            obfs_password: "abc".to_string(),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("password");
        assert!(error.to_string().contains("at least 4 bytes"));
    }

    #[test]
    fn hy2_salamander_xor_roundtrips() {
        let salt = [7u8; SALAMANDER_SALT_LEN];
        let payload = b"hello hysteria";
        let mut encrypted = vec![0u8; payload.len()];
        let mut decrypted = vec![0u8; payload.len()];

        salamander_xor(b"secret", &salt, payload, &mut encrypted);
        assert_ne!(encrypted, payload);
        salamander_xor(b"secret", &salt, &encrypted, &mut decrypted);

        assert_eq!(decrypted, payload);
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
    fn rejects_oversized_hy2_tcp_padding() {
        let mut request = Vec::new();
        encode_varint(HY2_TCP_REQUEST_ID, &mut request).expect("request id");
        encode_varint(15, &mut request).expect("address len");
        request.extend_from_slice(b"example.com:443");
        encode_varint(MAX_PADDING_LEN + 1, &mut request).expect("padding len");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let error = runtime
            .block_on(async { read_tcp_request(&mut request.as_slice()).await })
            .expect_err("padding");

        assert!(error.to_string().contains("padding"));
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
    fn reassembles_hy2_udp_fragments() {
        let fragments = Arc::new(AsyncMutex::new(FxHashMap::default()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let result = runtime
            .block_on(async {
                let first = reassemble_udp_message(
                    UdpMessage {
                        session_id: 7,
                        packet_id: 9,
                        fragment_id: 0,
                        fragment_count: 2,
                        address: "example.com:53".to_string(),
                        payload: b"hel".to_vec(),
                    },
                    &fragments,
                )
                .await?;
                assert!(first.is_none());
                reassemble_udp_message(
                    UdpMessage {
                        session_id: 7,
                        packet_id: 9,
                        fragment_id: 1,
                        fragment_count: 2,
                        address: "example.com:53".to_string(),
                        payload: b"lo".to_vec(),
                    },
                    &fragments,
                )
                .await
            })
            .expect("reassemble")
            .expect("complete message");

        assert_eq!(result.fragment_count, 1);
        assert_eq!(result.payload, b"hello");
    }

    #[test]
    fn accepts_unfragmented_hy2_udp_with_nonzero_fragment_id() {
        let fragments = Arc::new(AsyncMutex::new(FxHashMap::default()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let result = runtime
            .block_on(async {
                reassemble_udp_message(
                    UdpMessage {
                        session_id: 7,
                        packet_id: 9,
                        fragment_id: 3,
                        fragment_count: 1,
                        address: "example.com:53".to_string(),
                        payload: b"hello".to_vec(),
                    },
                    &fragments,
                )
                .await
            })
            .expect("unfragmented packet")
            .expect("message");

        assert_eq!(result.fragment_id, 3);
        assert_eq!(result.payload, b"hello");
    }

    #[test]
    fn cleans_expired_hy2_udp_fragments() {
        let fragments = Arc::new(AsyncMutex::new(FxHashMap::default()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            fragments.lock().await.insert(
                (7, 9),
                UdpFragmentBuffer {
                    address: "example.com:53".to_string(),
                    created_at: Instant::now() - UDP_FRAGMENT_TIMEOUT - Duration::from_secs(1),
                    fragments: vec![Some(b"hel".to_vec()), None],
                },
            );

            cleanup_udp_fragments(&fragments).await;

            assert!(fragments.lock().await.is_empty());
        });
    }

    #[test]
    fn cleans_idle_hy2_udp_sessions() {
        let sessions = Arc::new(AsyncMutex::new(FxHashMap::default()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("socket"));
            let session = Arc::new(UdpSession {
                socket,
                last_seen: Arc::new(Mutex::new(
                    Instant::now() - UDP_SESSION_IDLE_TIMEOUT - Duration::from_secs(1),
                )),
                response_handle: Mutex::new(tokio::spawn(async {
                    std::future::pending::<()>().await;
                })),
            });
            sessions.lock().await.insert(7, session);

            cleanup_udp_sessions(&sessions).await;

            assert!(sessions.lock().await.is_empty());
        });
    }

    #[test]
    fn fragments_hy2_udp_responses_to_peer_datagram_size() {
        let address = "example.com:53".to_string();
        let header_len = encoded_udp_header_len(&address).expect("header len");
        let payload: Vec<u8> = (0..25).collect();

        let messages =
            encode_udp_response_messages(7, 9, address.clone(), &payload, Some(header_len + 10))
                .expect("fragments");

        assert_eq!(messages.len(), 3);
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(message.session_id, 7);
            assert_eq!(message.packet_id, 9);
            assert_eq!(message.fragment_id, index as u8);
            assert_eq!(message.fragment_count, 3);
            assert_eq!(message.address, address);
            assert!(encode_udp_message(message).expect("encode").len() <= header_len + 10);
        }
        let combined: Vec<u8> = messages
            .iter()
            .flat_map(|message| message.payload.iter().copied())
            .collect();
        assert_eq!(combined, payload);
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
