mod aead2022;
mod crypto;

use anyhow::{Context, anyhow, bail, ensure};
use futures_util::StreamExt;
use rand::RngExt;
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Child;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::panel::{NodeConfigResponse, PanelUser};

use self::crypto::{Method, UserCredential, decode_udp_packet, encode_udp_packet};
use super::shared::{
    bind_listeners, bind_udp_sockets, configure_tcp_stream, effective_listen_ip, routing,
    socksaddr::SocksAddr, traffic::TrafficRecorder, transport,
};

const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const COPY_BUFFER_LEN: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub method: Method,
    pub server_key: String,
    pub networks: EnabledNetworks,
    pub plugin: Option<PluginConfig>,
    pub multiplex: MultiplexConfig,
    pub routing: routing::RoutingTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnabledNetworks {
    tcp: bool,
    udp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginConfig {
    command: String,
    opts: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiplexConfig {
    enabled: bool,
    protocol: SingMuxProtocol,
    padding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SingMuxProtocol {
    Yamux,
}

pub struct ServerController {
    accounting: Arc<Accounting>,
    panel_users: Arc<RwLock<Vec<PanelUser>>>,
    users: Arc<RwLock<Vec<UserCredential>>>,
    method: Arc<RwLock<Option<Method>>>,
    server_key: Arc<RwLock<String>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    tcp_replay: Arc<aead2022::TcpReplayCache>,
    inner: Mutex<Option<RunningServer>>,
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    method: Method,
    networks: EnabledNetworks,
    plugin: Option<PluginConfig>,
    multiplex: MultiplexConfig,
    handles: Vec<JoinHandle<()>>,
    plugin_processes: Vec<Child>,
}

struct UdpSession {
    _lease: SessionLease,
    outbound: Arc<UdpSocket>,
    credential: UserCredential,
    client_addr: Arc<Mutex<SocketAddr>>,
    aead2022: Option<Mutex<aead2022::UdpSession>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum UdpSessionKey {
    Legacy { client: SocketAddr, uid: i64 },
    Aead2022 { session_id: u64, uid: i64 },
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let method = parse_method(remote)?;
        let networks = parse_networks(&remote.network, &method)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            method,
            server_key: remote.server_key.trim().to_string(),
            networks,
            plugin: parse_plugin(remote)?,
            multiplex: parse_multiplex(remote)?,
            routing: routing::RoutingTable::from_remote(
                &remote.routes,
                &remote.custom_outbounds,
                &remote.custom_routes,
            )
            .context("compile Xboard routing")?,
        })
    }
}

impl EnabledNetworks {
    fn any(self) -> bool {
        self.tcp || self.udp
    }
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: SingMuxProtocol::Yamux,
            padding: false,
        }
    }
}

impl ServerController {
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            accounting,
            panel_users: Arc::new(RwLock::new(Vec::new())),
            users: Arc::new(RwLock::new(Vec::new())),
            method: Arc::new(RwLock::new(None)),
            server_key: Arc::new(RwLock::new(String::new())),
            routing: Arc::new(RwLock::new(routing::RoutingTable::default())),
            tcp_replay: Arc::new(aead2022::TcpReplayCache::default()),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        *self
            .panel_users
            .write()
            .expect("shadowsocks panel users lock poisoned") = users.to_vec();
        self.accounting.replace_users(users);

        let method = self
            .method
            .read()
            .expect("shadowsocks method lock poisoned")
            .clone();
        if let Some(method) = method {
            let server_key = self
                .server_key
                .read()
                .expect("shadowsocks server key lock poisoned")
                .clone();
            let credentials = build_users(&method, &server_key, users)?;
            *self.users.write().expect("shadowsocks users lock poisoned") = credentials;
        }
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        let panel_users = self
            .panel_users
            .read()
            .expect("shadowsocks panel users lock poisoned")
            .clone();
        let credentials = build_users(&config.method, &config.server_key, &panel_users)?;
        *self.users.write().expect("shadowsocks users lock poisoned") = credentials;
        *self
            .method
            .write()
            .expect("shadowsocks method lock poisoned") = Some(config.method.clone());
        *self
            .server_key
            .write()
            .expect("shadowsocks server key lock poisoned") = config.server_key;
        *self
            .routing
            .write()
            .expect("shadowsocks routing lock poisoned") = config.routing;

        let old = {
            let mut guard = self.inner.lock().expect("shadowsocks controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip
                    || running.server_port != config.server_port
                    || running.method != config.method
                    || running.networks != config.networks
                    || running.plugin != config.plugin
                    || running.multiplex != config.multiplex
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
            stop_plugin_processes(old.plugin_processes).await;
        }

        let mut handles = Vec::new();
        let mut bind_addrs = Vec::new();
        let mut plugin_processes = Vec::new();
        let tcp_listen_ip;
        let tcp_port;
        if config.plugin.is_some() {
            tcp_listen_ip = loopback_listen_ip(&config.listen_ip).to_string();
            tcp_port = reserve_loopback_port(&tcp_listen_ip)?;
            let plugin = config.plugin.as_ref().expect("plugin checked");
            plugin_processes = start_plugin_processes(
                plugin,
                &config.listen_ip,
                config.server_port,
                &tcp_listen_ip,
                tcp_port,
            )?;
        } else {
            tcp_listen_ip = config.listen_ip.clone();
            tcp_port = config.server_port;
        }

        if config.networks.tcp {
            let listeners = bind_listeners(&tcp_listen_ip, tcp_port)?;
            bind_addrs.extend(
                listeners
                    .iter()
                    .filter_map(|listener| listener.local_addr().ok())
                    .map(|addr| format!("tcp://{addr}")),
            );
            for listener in listeners {
                let accounting = self.accounting.clone();
                let users = self.users.clone();
                let routing = self.routing.clone();
                let tcp_replay = self.tcp_replay.clone();
                let multiplex = config.multiplex;
                handles.push(tokio::spawn(async move {
                    accept_tcp_loop(listener, accounting, users, routing, tcp_replay, multiplex)
                        .await;
                }));
            }
        }

        if config.networks.udp {
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
                let routing = self.routing.clone();
                let sessions = Arc::new(AsyncMutex::new(
                    HashMap::<UdpSessionKey, Arc<UdpSession>>::new(),
                ));
                handles.push(tokio::spawn(async move {
                    run_udp_server(socket, accounting, users, routing, sessions).await;
                }));
            }
        }

        ensure!(
            config.networks.any(),
            "Shadowsocks node has no enabled network"
        );
        info!(listen = ?bind_addrs, method = ?config.method, "Shadowsocks listeners started");

        let mut guard = self.inner.lock().expect("shadowsocks controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            method: config.method,
            networks: config.networks,
            plugin: config.plugin,
            multiplex: config.multiplex,
            handles,
            plugin_processes,
        });
        Ok(())
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self.inner.lock().expect("shadowsocks controller poisoned");
            guard.take()
        };
        if let Some(old) = old {
            for handle in old.handles {
                handle.abort();
            }
            stop_plugin_processes(old.plugin_processes).await;
            info!(port = old.server_port, "Shadowsocks listeners stopped");
        }
    }
}

async fn accept_tcp_loop(
    listener: TcpListener,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<Vec<UserCredential>>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    tcp_replay: Arc<aead2022::TcpReplayCache>,
    multiplex: MultiplexConfig,
) {
    let listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "accept Shadowsocks TCP connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let accounting = accounting.clone();
        let users = users.clone();
        let routing = routing.clone();
        let tcp_replay = tcp_replay.clone();
        tokio::spawn(async move {
            let users = users
                .read()
                .expect("shadowsocks users lock poisoned")
                .clone();
            let routing = routing
                .read()
                .expect("shadowsocks routing lock poisoned")
                .clone();
            if let Err(error) = serve_tcp_connection(
                stream, source, accounting, users, routing, tcp_replay, multiplex,
            )
            .await
            {
                warn!(%error, %source, "Shadowsocks TCP session terminated with error");
            }
        });
    }
}

async fn serve_tcp_connection(
    stream: TcpStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    users: Vec<UserCredential>,
    routing: routing::RoutingTable,
    tcp_replay: Arc<aead2022::TcpReplayCache>,
    multiplex: MultiplexConfig,
) -> anyhow::Result<()> {
    let (reader, writer) = split(stream);
    enum AcceptedReader<R> {
        Legacy(crypto::AcceptedTcpReader<R>),
        Aead2022(aead2022::AcceptedTcpReader<R>, aead2022::TcpResponseContext),
    }

    let accepted = match users.first().map(|user| user.method.clone()) {
        Some(Method::Aead2022(_)) => match timeout(
            TCP_HANDSHAKE_TIMEOUT,
            aead2022::AcceptedTcpReader::accept(reader, &users, &tcp_replay),
        )
        .await
        {
            Ok(result) => {
                let accepted = result?;
                let response_context = accepted.response_context();
                AcceptedReader::Aead2022(accepted, response_context)
            }
            Err(_) => bail!("Shadowsocks TCP authentication timed out"),
        },
        _ => match timeout(
            TCP_HANDSHAKE_TIMEOUT,
            crypto::AcceptedTcpReader::accept(reader, &users),
        )
        .await
        {
            Ok(result) => AcceptedReader::Legacy(result?),
            Err(_) => bail!("Shadowsocks TCP authentication timed out"),
        },
    };
    let credential = match &accepted {
        AcceptedReader::Legacy(accepted) => accepted.credential().clone(),
        AcceptedReader::Aead2022(accepted, _) => accepted.credential().clone(),
    };
    let response_context = match &accepted {
        AcceptedReader::Aead2022(_, response_context) => Some(response_context.clone()),
        AcceptedReader::Legacy(_) => None,
    };
    let lease = accounting.open_session(&credential.user, source)?;
    let control = lease.control();
    let upload = TrafficRecorder::upload(accounting.clone(), credential.user.id);
    let download = TrafficRecorder::download(accounting, credential.user.id);

    let (mut client_plain_reader, client_plain_writer) = tokio::io::duplex(COPY_BUFFER_LEN);
    let (server_plain_reader, mut server_plain_writer) = tokio::io::duplex(COPY_BUFFER_LEN);

    let decrypt_task = match accepted {
        AcceptedReader::Legacy(accepted) => tokio::spawn({
            let control = control.clone();
            async move { accepted.pump_to_plain(client_plain_writer, control).await }
        }),
        AcceptedReader::Aead2022(accepted, _) => tokio::spawn({
            let control = control.clone();
            async move { accepted.pump_to_plain(client_plain_writer, control).await }
        }),
    };
    let encrypt_task = match &credential.method {
        Method::Aead2022(_) => {
            let control = control.clone();
            let credential = credential.clone();
            let response_context = response_context
                .clone()
                .expect("Shadowsocks 2022 response context missing");
            tokio::spawn(async move {
                aead2022::pump_plain_to_tcp(
                    &credential,
                    &response_context,
                    server_plain_reader,
                    writer,
                    control,
                )
                .await
            })
        }
        _ => tokio::spawn({
            let control = control.clone();
            let credential = credential.clone();
            async move {
                crypto::pump_plain_to_tcp(&credential, server_plain_reader, writer, control).await
            }
        }),
    };

    let destination = match SocksAddr::read_from(&mut client_plain_reader).await {
        Ok(destination) => destination,
        Err(error) => {
            control.cancel();
            decrypt_task.abort();
            encrypt_task.abort();
            let _ = decrypt_task.await;
            let _ = encrypt_task.await;
            return Err(error).context("read Shadowsocks destination");
        }
    };

    if is_sing_mux_destination(&destination) {
        ensure!(
            multiplex.enabled,
            "Shadowsocks multiplex is not enabled for this node"
        );
        handle_sing_mux_connection(
            client_plain_reader,
            server_plain_writer,
            routing,
            control.clone(),
            upload,
            download,
            multiplex,
        )
        .await?;
        flatten_join(decrypt_task.await, "join Shadowsocks decrypt task")?;
        flatten_join(encrypt_task.await, "join Shadowsocks encrypt task")?;
        return Ok(());
    }

    let remote = transport::connect_tcp_destination(&destination, &routing)
        .await
        .with_context(|| format!("connect Shadowsocks destination {destination}"))?;
    let (mut remote_reader, mut remote_writer) = split(remote);

    let proxy_result = tokio::try_join!(
        copy_with_traffic(
            &mut client_plain_reader,
            &mut remote_writer,
            control.clone(),
            Some(upload),
        ),
        copy_with_traffic(
            &mut remote_reader,
            &mut server_plain_writer,
            control.clone(),
            Some(download),
        )
    );

    if let Err(error) = proxy_result {
        control.cancel();
        decrypt_task.abort();
        encrypt_task.abort();
        let _ = decrypt_task.await;
        let _ = encrypt_task.await;
        return Err(error);
    }

    drop(server_plain_writer);
    flatten_join(decrypt_task.await, "join Shadowsocks decrypt task")?;
    flatten_join(encrypt_task.await, "join Shadowsocks encrypt task")?;
    Ok(())
}

async fn run_udp_server(
    socket: Arc<UdpSocket>,
    accounting: Arc<Accounting>,
    users: Arc<RwLock<Vec<UserCredential>>>,
    routing: Arc<RwLock<routing::RoutingTable>>,
    sessions: Arc<AsyncMutex<HashMap<UdpSessionKey, Arc<UdpSession>>>>,
) {
    let listen = socket
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut buffer = vec![0u8; u16::MAX as usize + 512];
    loop {
        let (size, source) = match socket.recv_from(&mut buffer).await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "receive Shadowsocks UDP packet failed");
                continue;
            }
        };
        let source = transport::normalize_udp_source(source);
        let users = users
            .read()
            .expect("shadowsocks users lock poisoned")
            .clone();
        let routing = routing
            .read()
            .expect("shadowsocks routing lock poisoned")
            .clone();
        if let Err(error) = handle_udp_request(
            socket.clone(),
            source,
            &buffer[..size],
            accounting.clone(),
            users,
            routing,
            sessions.clone(),
        )
        .await
        {
            warn!(%error, %source, "Shadowsocks UDP packet handling failed");
        }
    }
}

async fn handle_udp_request(
    inbound_socket: Arc<UdpSocket>,
    source: SocketAddr,
    packet: &[u8],
    accounting: Arc<Accounting>,
    users: Vec<UserCredential>,
    routing: routing::RoutingTable,
    sessions: Arc<AsyncMutex<HashMap<UdpSessionKey, Arc<UdpSession>>>>,
) -> anyhow::Result<()> {
    let method = users
        .first()
        .map(|user| user.method.clone())
        .ok_or_else(|| anyhow!("no Shadowsocks users configured"))?;

    let (credential, destination, payload, wire_len, session) = match method {
        Method::Aead2022(_) => {
            let identified = aead2022::identify_udp_request(packet, &users)
                .context("identify Shadowsocks 2022 UDP packet")?;
            let session = get_or_create_udp_session(
                inbound_socket.clone(),
                source,
                &identified.credential,
                accounting.clone(),
                sessions,
                UdpSessionKey::Aead2022 {
                    session_id: identified.client_session_id,
                    uid: identified.credential.user.id,
                },
                Some(aead2022::UdpSession::new(&identified)?),
            )
            .await?;
            *session
                .client_addr
                .lock()
                .expect("shadowsocks UDP client addr lock poisoned") = source;
            let decoded = {
                let mut codec = session
                    .aead2022
                    .as_ref()
                    .expect("Shadowsocks 2022 UDP session missing codec")
                    .lock()
                    .expect("Shadowsocks 2022 UDP codec lock poisoned");
                aead2022::decode_udp_request_body(packet, &identified, &mut codec)
                    .context("decode Shadowsocks 2022 UDP packet")?
            };
            (
                identified.credential,
                decoded.destination,
                decoded.payload,
                decoded.wire_len,
                session,
            )
        }
        _ => {
            let decoded =
                decode_udp_packet(packet, &users).context("decode Shadowsocks UDP packet")?;
            let session = get_or_create_udp_session(
                inbound_socket.clone(),
                source,
                &decoded.credential,
                accounting.clone(),
                sessions,
                UdpSessionKey::Legacy {
                    client: source,
                    uid: decoded.credential.user.id,
                },
                None,
            )
            .await?;
            *session
                .client_addr
                .lock()
                .expect("shadowsocks UDP client addr lock poisoned") = source;
            (
                decoded.credential,
                decoded.destination,
                decoded.payload,
                decoded.wire_len,
                session,
            )
        }
    };

    let target = transport::resolve_destination(&destination, &routing, "udp")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no UDP addresses resolved for {}", destination))?;
    let target = transport::normalize_udp_target(&session.outbound, target);
    let upload = TrafficRecorder::upload(accounting, credential.user.id);
    let control = session._lease.control();
    upload.limit(wire_len as u64, &control).await;
    if control.is_cancelled() {
        return Ok(());
    }
    let sent = session
        .outbound
        .send_to(&payload, target)
        .await
        .with_context(|| format!("send Shadowsocks UDP payload to {target}"))?;
    ensure!(
        sent == payload.len(),
        "short Shadowsocks UDP send: expected {}, wrote {}",
        payload.len(),
        sent
    );
    upload.record(wire_len as u64);
    Ok(())
}

async fn get_or_create_udp_session(
    inbound_socket: Arc<UdpSocket>,
    source: SocketAddr,
    credential: &UserCredential,
    accounting: Arc<Accounting>,
    sessions: Arc<AsyncMutex<HashMap<UdpSessionKey, Arc<UdpSession>>>>,
    key: UdpSessionKey,
    aead2022_session: Option<aead2022::UdpSession>,
) -> anyhow::Result<Arc<UdpSession>> {
    let mut guard = sessions.lock().await;
    if let Some(session) = guard.get(&key) {
        return Ok(session.clone());
    }

    let outbound = Arc::new(transport::bind_udp_socket().await?);
    let lease = accounting.open_session(&credential.user, source)?;
    let session = Arc::new(UdpSession {
        _lease: lease,
        outbound: outbound.clone(),
        credential: credential.clone(),
        client_addr: Arc::new(Mutex::new(source)),
        aead2022: aead2022_session.map(Mutex::new),
    });
    guard.insert(key, session.clone());
    drop(guard);

    tokio::spawn(run_udp_session(
        key,
        inbound_socket,
        session.clone(),
        accounting,
        sessions,
    ));
    Ok(session)
}

async fn run_udp_session(
    key: UdpSessionKey,
    inbound_socket: Arc<UdpSocket>,
    session: Arc<UdpSession>,
    accounting: Arc<Accounting>,
    sessions: Arc<AsyncMutex<HashMap<UdpSessionKey, Arc<UdpSession>>>>,
) {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let recv = timeout(
            UDP_SESSION_IDLE_TIMEOUT,
            session.outbound.recv_from(&mut buffer),
        )
        .await;
        let (size, source) = match recv {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                warn!(%error, uid = session.credential.user.id, "receive Shadowsocks UDP response failed");
                break;
            }
            Err(_) => break,
        };
        let client_addr = *session
            .client_addr
            .lock()
            .expect("shadowsocks UDP client addr lock poisoned");
        let encoded = if matches!(session.credential.method, Method::Aead2022(_)) {
            let mut codec = session
                .aead2022
                .as_ref()
                .expect("Shadowsocks 2022 UDP session missing codec")
                .lock()
                .expect("Shadowsocks 2022 UDP codec lock poisoned");
            match aead2022::encode_udp_response(
                &mut codec,
                &SocksAddr::Ip(transport::normalize_udp_source(source)),
                &buffer[..size],
            ) {
                Ok(encoded) => encoded,
                Err(error) => {
                    warn!(%error, uid = session.credential.user.id, "encode Shadowsocks 2022 UDP response failed");
                    break;
                }
            }
        } else {
            match encode_udp_packet(
                &session.credential,
                &SocksAddr::Ip(transport::normalize_udp_source(source)),
                &buffer[..size],
            ) {
                Ok(encoded) => encoded,
                Err(error) => {
                    warn!(%error, uid = session.credential.user.id, "encode Shadowsocks UDP response failed");
                    break;
                }
            }
        };
        let target = transport::normalize_udp_target(&inbound_socket, client_addr);
        let download = TrafficRecorder::download(accounting.clone(), session.credential.user.id);
        let control = session._lease.control();
        download.limit(encoded.len() as u64, &control).await;
        if control.is_cancelled() {
            break;
        }
        match inbound_socket.send_to(&encoded, target).await {
            Ok(sent) if sent == encoded.len() => {
                download.record(encoded.len() as u64);
            }
            Ok(sent) => {
                warn!(
                    uid = session.credential.user.id,
                    expected = encoded.len(),
                    actual = sent,
                    "short Shadowsocks UDP response send"
                );
                break;
            }
            Err(error) => {
                warn!(%error, uid = session.credential.user.id, "send Shadowsocks UDP response failed");
                break;
            }
        }
    }

    sessions.lock().await.remove(&key);
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
                Err(error) => return Err(error).context("read proxied Shadowsocks chunk"),
            },
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        if let Some(traffic) = traffic.as_ref() {
            traffic.limit(read as u64, &control).await;
            if control.is_cancelled() {
                return Ok(total);
            }
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
                Err(error) => return Err(error).context("write proxied Shadowsocks chunk"),
            },
        }
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
    }
}

async fn handle_sing_mux_connection<R, W>(
    mut reader: R,
    writer: W,
    routing: routing::RoutingTable,
    control: Arc<SessionControl>,
    upload: TrafficRecorder,
    download: TrafficRecorder,
    config: MultiplexConfig,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let request = SingMuxRequest::read_from(&mut reader).await?;
    ensure!(
        request.protocol == config.protocol,
        "unsupported Shadowsocks sing-mux protocol"
    );
    ensure!(
        !request.padding || config.padding,
        "Shadowsocks sing-mux padded connection is not enabled for this node"
    );

    let stream = PrefixedIo::new(reader, writer, request.remaining);
    let stream = if request.padding {
        SingMuxConnection::Padded(SingMuxPaddingIo::new(stream))
    } else {
        SingMuxConnection::Plain(stream)
    };
    let mut session = tokio_yamux::Session::new_server(stream, tokio_yamux::Config::default());
    while let Some(stream) = session.next().await {
        let stream = stream.context("accept Shadowsocks sing-mux stream")?;
        let routing = routing.clone();
        let control = control.clone();
        let upload = upload.clone();
        let download = download.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_sing_mux_stream(stream, routing, control, upload, download).await
            {
                warn!(%error, "Shadowsocks sing-mux stream terminated with error");
            }
        });
    }
    Ok(())
}

async fn handle_sing_mux_stream<S>(
    mut stream: S,
    routing: routing::RoutingTable,
    control: Arc<SessionControl>,
    upload: TrafficRecorder,
    download: TrafficRecorder,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = SingMuxStreamRequest::read_from(&mut stream).await?;
    ensure!(
        matches!(request.network, SingMuxNetwork::Tcp),
        "Shadowsocks sing-mux UDP stream is not implemented yet"
    );
    let remote = match transport::connect_tcp_destination(&request.destination, &routing).await {
        Ok(remote) => remote,
        Err(error) => {
            write_sing_mux_error(&mut stream, &error.to_string()).await?;
            return Err(error).context("connect sing-mux destination");
        }
    };

    stream.write_u8(SING_MUX_STATUS_SUCCESS).await?;
    let (mut remote_reader, mut remote_writer) = split(remote);
    let (mut stream_reader, mut stream_writer) = split(stream);
    let result = tokio::try_join!(
        copy_with_traffic(
            &mut stream_reader,
            &mut remote_writer,
            control.clone(),
            Some(upload),
        ),
        copy_with_traffic(
            &mut remote_reader,
            &mut stream_writer,
            control.clone(),
            Some(download),
        )
    );
    result.map(|_| ())
}

fn is_sing_mux_destination(destination: &SocksAddr) -> bool {
    matches!(
        destination,
        SocksAddr::Domain(host, 444) if host.eq_ignore_ascii_case("sp.mux.sing-box.arpa")
    )
}

const SING_MUX_VERSION_0: u8 = 0;
const SING_MUX_VERSION_1: u8 = 1;
const SING_MUX_PROTOCOL_YAMUX: u8 = 1;
const SING_MUX_STATUS_SUCCESS: u8 = 0;
const SING_MUX_STATUS_ERROR: u8 = 1;
const SING_MUX_FLAG_UDP: u16 = 1;
const SING_MUX_FLAG_ADDR: u16 = 2;

struct SingMuxRequest {
    protocol: SingMuxProtocol,
    padding: bool,
    remaining: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct SingMuxStreamRequest {
    network: SingMuxNetwork,
    destination: SocksAddr,
    packet_addr: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum SingMuxNetwork {
    Tcp,
    Udp,
}

impl SingMuxRequest {
    async fn read_from<R>(reader: &mut R) -> anyhow::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let version = reader.read_u8().await.context("read sing-mux version")?;
        ensure!(
            matches!(version, SING_MUX_VERSION_0 | SING_MUX_VERSION_1),
            "unsupported sing-mux version {version}"
        );
        let protocol = match reader.read_u8().await.context("read sing-mux protocol")? {
            SING_MUX_PROTOCOL_YAMUX => SingMuxProtocol::Yamux,
            other => bail!("unsupported sing-mux protocol {other}"),
        };
        let mut padding = false;
        if version == SING_MUX_VERSION_1 {
            padding = reader
                .read_u8()
                .await
                .context("read sing-mux padding flag")?
                != 0;
            if padding {
                let padding_len = reader
                    .read_u16()
                    .await
                    .context("read sing-mux padding length")?;
                let mut padding_bytes = vec![0u8; padding_len as usize];
                reader
                    .read_exact(&mut padding_bytes)
                    .await
                    .context("read sing-mux padding")?;
            }
        }
        Ok(Self {
            protocol,
            padding,
            remaining: Vec::new(),
        })
    }
}

impl SingMuxStreamRequest {
    async fn read_from<R>(reader: &mut R) -> anyhow::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let flags = reader
            .read_u16()
            .await
            .context("read sing-mux stream flags")?;
        let destination = SocksAddr::read_from(reader)
            .await
            .context("read sing-mux stream destination")?;
        let network = if flags & SING_MUX_FLAG_UDP == 0 {
            SingMuxNetwork::Tcp
        } else {
            SingMuxNetwork::Udp
        };
        Ok(Self {
            network,
            destination,
            packet_addr: flags & SING_MUX_FLAG_ADDR != 0,
        })
    }
}

enum SingMuxConnection<T> {
    Plain(T),
    Padded(SingMuxPaddingIo<T>),
}

impl<T> AsyncRead for SingMuxConnection<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
            Self::Padded(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for SingMuxConnection<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(inner) => Pin::new(inner).poll_write(cx, buf),
            Self::Padded(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(inner) => Pin::new(inner).poll_flush(cx),
            Self::Padded(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(inner) => Pin::new(inner).poll_shutdown(cx),
            Self::Padded(inner) => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

struct SingMuxPaddingIo<T> {
    inner: T,
    read_padding_count: usize,
    write_padding_count: usize,
    read_remaining: VecDeque<u8>,
    read_state: PaddingReadState,
    write_state: Option<PaddingWriteState>,
}

enum PaddingReadState {
    Header {
        bytes: [u8; 4],
        filled: usize,
    },
    Data {
        data: Vec<u8>,
        filled: usize,
        padding_len: usize,
    },
    Padding {
        remaining: usize,
    },
    Raw,
}

impl Default for PaddingReadState {
    fn default() -> Self {
        Self::Header {
            bytes: [0; 4],
            filled: 0,
        }
    }
}

struct PaddingWriteState {
    frame: Vec<u8>,
    written: usize,
    data_len: usize,
}

impl<T> SingMuxPaddingIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            read_padding_count: 0,
            write_padding_count: 0,
            read_remaining: VecDeque::new(),
            read_state: PaddingReadState::Header {
                bytes: [0; 4],
                filled: 0,
            },
            write_state: None,
        }
    }
}

impl<T> AsyncRead for SingMuxPaddingIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            while buf.remaining() > 0 {
                let Some(byte) = self.read_remaining.pop_front() else {
                    break;
                };
                buf.put_slice(&[byte]);
            }
            if !buf.filled().is_empty() || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let state = std::mem::take(&mut self.read_state);
            match state {
                PaddingReadState::Raw => return Pin::new(&mut self.inner).poll_read(cx, buf),
                PaddingReadState::Header {
                    mut bytes,
                    mut filled,
                } => {
                    let mut header_buf = ReadBuf::new(&mut bytes[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut header_buf) {
                        Poll::Ready(Ok(())) if header_buf.filled().is_empty() => {
                            self.read_state = PaddingReadState::Header { bytes, filled };
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(())) => {
                            filled += header_buf.filled().len();
                            if filled < bytes.len() {
                                self.read_state = PaddingReadState::Header { bytes, filled };
                                continue;
                            }
                            let data_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                            let padding_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
                            self.read_state = PaddingReadState::Data {
                                data: vec![0u8; data_len],
                                filled: 0,
                                padding_len,
                            };
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = PaddingReadState::Header { bytes, filled };
                            return Poll::Pending;
                        }
                    }
                }
                PaddingReadState::Data {
                    mut data,
                    mut filled,
                    padding_len,
                } => {
                    let mut data_buf = ReadBuf::new(&mut data[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut data_buf) {
                        Poll::Ready(Ok(())) if data_buf.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "short sing-mux padded data",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            filled += data_buf.filled().len();
                            if filled < data.len() {
                                self.read_state = PaddingReadState::Data {
                                    data,
                                    filled,
                                    padding_len,
                                };
                                continue;
                            }
                            for byte in data {
                                self.read_remaining.push_back(byte);
                            }
                            self.read_padding_count += 1;
                            self.read_state = if padding_len > 0 {
                                PaddingReadState::Padding {
                                    remaining: padding_len,
                                }
                            } else if self.read_padding_count >= 16 {
                                PaddingReadState::Raw
                            } else {
                                PaddingReadState::Header {
                                    bytes: [0; 4],
                                    filled: 0,
                                }
                            };
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = PaddingReadState::Data {
                                data,
                                filled,
                                padding_len,
                            };
                            return Poll::Pending;
                        }
                    }
                }
                PaddingReadState::Padding { mut remaining } => {
                    let mut scratch = [0u8; 512];
                    let take = remaining.min(scratch.len());
                    let mut skip_buf = ReadBuf::new(&mut scratch[..take]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut skip_buf) {
                        Poll::Ready(Ok(())) if skip_buf.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "short sing-mux padding",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            remaining -= skip_buf.filled().len();
                            if remaining == 0 {
                                self.read_state = if self.read_padding_count >= 16 {
                                    PaddingReadState::Raw
                                } else {
                                    PaddingReadState::Header {
                                        bytes: [0; 4],
                                        filled: 0,
                                    }
                                };
                            } else {
                                self.read_state = PaddingReadState::Padding { remaining };
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = PaddingReadState::Padding { remaining };
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

impl<T> AsyncWrite for SingMuxPaddingIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_padding_count >= 16 {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        if self.write_state.is_none() {
            let data_len = buf.len().min(u16::MAX as usize);
            let padding_len = 256 + rand::rng().random_range(0..512usize);
            let mut frame = Vec::with_capacity(4 + data_len + padding_len);
            frame.extend_from_slice(&(data_len as u16).to_be_bytes());
            frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
            frame.extend_from_slice(&buf[..data_len]);
            frame.resize(4 + data_len + padding_len, 0);
            self.write_state = Some(PaddingWriteState {
                frame,
                written: 0,
                data_len,
            });
        }

        let mut state = self.write_state.take().expect("padding write state");
        loop {
            match Pin::new(&mut self.inner).poll_write(cx, &state.frame[state.written..]) {
                Poll::Ready(Ok(0)) => {
                    self.write_state = Some(state);
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short sing-mux padded write",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    state.written += written;
                    if state.written == state.frame.len() {
                        let data_len = state.data_len;
                        self.write_padding_count += 1;
                        return Poll::Ready(Ok(data_len));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.write_state = Some(state);
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn write_sing_mux_error<W>(writer: &mut W, message: &str) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(SING_MUX_STATUS_ERROR).await?;
    write_uvarint(writer, message.len() as u64).await?;
    writer.write_all(message.as_bytes()).await?;
    Ok(())
}

async fn write_uvarint<W>(writer: &mut W, mut value: u64) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while value >= 0x80 {
        writer.write_u8((value as u8) | 0x80).await?;
        value >>= 7;
    }
    writer.write_u8(value as u8).await?;
    Ok(())
}

struct PrefixedIo<R, W> {
    reader: R,
    writer: W,
    prefetched: VecDeque<u8>,
}

impl<R, W> PrefixedIo<R, W> {
    fn new(reader: R, writer: W, prefetched: Vec<u8>) -> Self {
        Self {
            reader,
            writer,
            prefetched: prefetched.into(),
        }
    }
}

impl<R, W> AsyncRead for PrefixedIo<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        while buf.remaining() > 0 {
            let Some(byte) = self.prefetched.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for PrefixedIo<R, W>
where
    R: Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn build_users(
    method: &Method,
    server_key: &str,
    users: &[PanelUser],
) -> anyhow::Result<Vec<UserCredential>> {
    let credentials = match method {
        Method::Aead2022(kind) => {
            let server_secret = aead2022::decode_server_psk(server_key, *kind)
                .context("decode Shadowsocks 2022 server_key")?;
            ensure!(
                !matches!(kind, crypto::Aead2022Method::ChaCha20Poly1305) || users.len() <= 1,
                "Shadowsocks 2022 chacha20-poly1305 does not support multi-user"
            );
            if users.len() == 1 {
                return Ok(vec![UserCredential {
                    user: UserEntry::from_panel_user(&users[0]),
                    method: method.clone(),
                    identity_hash: aead2022::identity_hash(&server_secret),
                    server_secret: server_secret.clone(),
                    secret: server_secret,
                }]);
            }
            users
                .iter()
                .map(|user| {
                    let secret = aead2022::derive_user_psk(user, *kind)?;
                    Ok(UserCredential {
                        user: UserEntry::from_panel_user(user),
                        method: method.clone(),
                        identity_hash: aead2022::identity_hash(&secret),
                        server_secret: server_secret.clone(),
                        secret,
                    })
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        }
        _ => users
            .iter()
            .map(|user| UserCredential::from_panel_user(user, method.clone()))
            .collect::<Result<Vec<_>, _>>()?,
    };

    if method.is_none() {
        ensure!(
            credentials.len() <= 1,
            "Shadowsocks none cipher does not support multi-user"
        );
    }

    let mut seen = HashSet::new();
    for credential in &credentials {
        ensure!(
            seen.insert(credential.secret.clone()),
            "duplicate Shadowsocks credentials for user {}",
            credential.user.id
        );
    }
    Ok(credentials)
}

fn parse_method(remote: &NodeConfigResponse) -> anyhow::Result<Method> {
    let cipher = remote.cipher.trim();
    if cipher.is_empty() {
        bail!("XBoard cipher is required for Shadowsocks nodes");
    }
    let method =
        Method::parse(cipher).ok_or_else(|| anyhow!("unsupported Shadowsocks cipher {cipher}"))?;
    if matches!(method, Method::Aead2022(_)) {
        ensure!(
            !remote.server_key.trim().is_empty(),
            "XBoard server_key is required for Shadowsocks 2022 nodes"
        );
    }
    Ok(method)
}

fn parse_networks(network: &str, method: &Method) -> anyhow::Result<EnabledNetworks> {
    let network = network.trim();
    if network.is_empty() {
        if matches!(method, Method::Aead2022(_)) {
            return Ok(EnabledNetworks {
                tcp: true,
                udp: true,
            });
        }
        return Ok(EnabledNetworks {
            tcp: true,
            udp: false,
        });
    }

    let mut networks = EnabledNetworks {
        tcp: false,
        udp: false,
    };
    for item in network.split(|ch: char| ch == ',' || ch.is_ascii_whitespace()) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.eq_ignore_ascii_case("tcp") {
            networks.tcp = true;
        } else if item.eq_ignore_ascii_case("udp") {
            networks.udp = true;
        } else {
            bail!("unsupported Shadowsocks network {item}");
        }
    }
    ensure!(networks.any(), "no Shadowsocks network enabled");
    Ok(networks)
}

fn parse_plugin(remote: &NodeConfigResponse) -> anyhow::Result<Option<PluginConfig>> {
    let command = remote.plugin.trim();
    let opts = remote.plugin_opts.trim();
    if command.is_empty() && opts.is_empty() {
        return Ok(None);
    }
    ensure!(
        !command.is_empty(),
        "Xboard plugin is required when plugin_opts is set"
    );
    Ok(Some(PluginConfig {
        command: command.to_string(),
        opts: opts.to_string(),
    }))
}

fn parse_multiplex(remote: &NodeConfigResponse) -> anyhow::Result<MultiplexConfig> {
    let Some(value) = remote.multiplex.as_ref() else {
        return Ok(MultiplexConfig::default());
    };
    if !crate::panel::json_value_is_enabled(value) {
        return Ok(MultiplexConfig::default());
    }
    match value {
        Value::Object(object) => {
            let protocol = object
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("yamux")
                .trim();
            ensure!(
                protocol.is_empty() || protocol.eq_ignore_ascii_case("yamux"),
                "only Shadowsocks yamux multiplex is implemented"
            );
            Ok(MultiplexConfig {
                enabled: true,
                protocol: SingMuxProtocol::Yamux,
                padding: object
                    .get("padding")
                    .is_some_and(crate::panel::json_value_is_enabled),
            })
        }
        _ => Ok(MultiplexConfig {
            enabled: true,
            ..Default::default()
        }),
    }
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if remote.tls.is_some()
        || remote.tls_settings.is_configured()
        || remote.tls_settings.has_reality_key_material()
        || remote.reality_settings.is_configured()
        || remote.cert_config.is_some()
    {
        bail!("Xboard tls/reality settings are not supported for Shadowsocks nodes");
    }
    if remote
        .network_settings
        .as_ref()
        .is_some_and(network_settings_enabled)
    {
        bail!("XBoard networkSettings is not supported by NodeRS Shadowsocks server");
    }
    parse_plugin(remote)?;
    parse_multiplex(remote)?;
    if remote.transport.as_ref().is_some_and(value_enabled) {
        bail!("Shadowsocks transport is not supported");
    }
    Ok(())
}

fn network_settings_enabled(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => {
            number.as_i64().is_some_and(|value| value != 0)
                || number.as_u64().is_some_and(|value| value != 0)
                || number.as_f64().is_some_and(|value| value != 0.0)
        }
        Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            !matches!(
                normalized.as_str(),
                "" | "0" | "false" | "off" | "no" | "none" | "disabled"
            )
        }
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => {
            if object.is_empty() {
                return false;
            }
            if let Some(enabled) = object.get("enabled") {
                return value_enabled(enabled);
            }
            object.iter().any(|(key, value)| {
                let normalized = normalize_option_key(key);
                if normalized == "acceptproxyprotocol" {
                    return false;
                }
                value_enabled(value)
            })
        }
    }
}

fn value_enabled(value: &Value) -> bool {
    crate::panel::json_value_is_enabled(value)
}

fn loopback_listen_ip(listen_ip: &str) -> &'static str {
    if listen_ip
        .trim()
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_ipv6())
    {
        "::1"
    } else {
        "127.0.0.1"
    }
}

fn reserve_loopback_port(listen_ip: &str) -> anyhow::Result<u16> {
    let addr = SocketAddr::new(
        listen_ip
            .parse::<IpAddr>()
            .with_context(|| format!("parse loopback listen IP {listen_ip}"))?,
        0,
    );
    let listener = std::net::TcpListener::bind(addr)
        .with_context(|| format!("reserve Shadowsocks plugin loopback port on {addr}"))?;
    Ok(listener.local_addr()?.port())
}

fn start_plugin_processes(
    plugin: &PluginConfig,
    external_ip: &str,
    external_port: u16,
    local_ip: &str,
    local_port: u16,
) -> anyhow::Result<Vec<Child>> {
    let external_addrs = plugin_external_addrs(external_ip, external_port)?;
    let mut processes = Vec::new();
    for external in external_addrs {
        let child = tokio::process::Command::new(&plugin.command)
            .env("SS_REMOTE_HOST", external.ip().to_string())
            .env("SS_REMOTE_PORT", external.port().to_string())
            .env("SS_LOCAL_HOST", local_ip)
            .env("SS_LOCAL_PORT", local_port.to_string())
            .env("SS_PLUGIN_OPTIONS", &plugin.opts)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("start Shadowsocks SIP003 plugin {}", plugin.command))?;
        processes.push(child);
    }
    Ok(processes)
}

fn plugin_external_addrs(listen_ip: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    let listen_ip = listen_ip.trim();
    if listen_ip.is_empty() || listen_ip == "0.0.0.0" || listen_ip == "::" || listen_ip == "[::]" {
        return Ok(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        ]);
    }
    let ip = listen_ip
        .parse::<IpAddr>()
        .with_context(|| format!("parse Shadowsocks plugin listen_ip {listen_ip}"))?;
    Ok(vec![SocketAddr::new(ip, port)])
}

async fn stop_plugin_processes(processes: Vec<Child>) {
    for mut process in processes {
        let _ = process.start_kill();
        let _ = process.wait().await;
    }
}

fn normalize_option_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_plugin_path() -> PathBuf {
        std::env::current_exe()
            .expect("current exe")
            .with_file_name(if cfg!(windows) {
                "dummy_ss_plugin.bat"
            } else {
                "dummy_ss_plugin.sh"
            })
    }

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "shadowsocks".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 8388,
            cipher: "aes-128-gcm".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn legacy_defaults_to_tcp_only() {
        let config = EffectiveNodeConfig::from_remote(&base_remote()).expect("config");
        assert!(config.networks.tcp);
        assert!(!config.networks.udp);
    }

    #[test]
    fn shadowsocks_2022_defaults_to_both_networks() {
        let remote = NodeConfigResponse {
            cipher: "2022-blake3-aes-128-gcm".to_string(),
            server_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(config.networks.tcp);
        assert!(config.networks.udp);
    }

    #[test]
    fn accepts_plugin_configuration() {
        let remote = NodeConfigResponse {
            plugin: "obfs-local".to_string(),
            plugin_opts: "obfs=http".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("plugin");
        let plugin = config.plugin.expect("plugin config");
        assert_eq!(plugin.command, "obfs-local");
        assert_eq!(plugin.opts, "obfs=http");
    }

    #[tokio::test]
    async fn starts_sip003_plugin_and_loopback_tcp_listener() {
        let plugin_path = dummy_plugin_path();
        let script = if cfg!(windows) {
            "@echo off\r\nset > %SS_PLUGIN_OPTIONS%\r\nping -n 6 127.0.0.1 > nul\r\n"
        } else {
            "#!/bin/sh\nset > \"$SS_PLUGIN_OPTIONS\"\nsleep 5\n"
        };
        tokio::fs::write(&plugin_path, script)
            .await
            .expect("write plugin");

        let env_path = plugin_path.with_extension("env");
        let controller = ServerController::new(Accounting::new());
        controller
            .replace_users(&[PanelUser {
                id: 1,
                password: "secret".to_string(),
                ..Default::default()
            }])
            .expect("users");
        let config = EffectiveNodeConfig {
            listen_ip: "127.0.0.1".to_string(),
            server_port: 0,
            method: Method::Legacy(crypto::LegacyAeadMethod::Aes128Gcm),
            server_key: String::new(),
            networks: EnabledNetworks {
                tcp: true,
                udp: false,
            },
            plugin: Some(PluginConfig {
                command: plugin_path.to_string_lossy().to_string(),
                opts: env_path.to_string_lossy().to_string(),
            }),
            multiplex: MultiplexConfig::default(),
            routing: routing::RoutingTable::default(),
        };

        controller.apply_config(config).await.expect("apply config");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let env = tokio::fs::read_to_string(&env_path)
            .await
            .expect("read plugin env");
        assert!(env.contains("SS_REMOTE_HOST=127.0.0.1"));
        assert!(env.contains("SS_REMOTE_PORT=0"));
        assert!(env.contains("SS_LOCAL_HOST=127.0.0.1"));
        assert!(env.contains("SS_LOCAL_PORT="));
        controller.shutdown().await;
        let _ = tokio::fs::remove_file(&plugin_path).await;
        let _ = tokio::fs::remove_file(&env_path).await;
    }

    #[test]
    fn parses_yamux_multiplex_configuration() {
        let remote = NodeConfigResponse {
            multiplex: Some(serde_json::json!({
                "enabled": true,
                "protocol": "yamux",
                "padding": true
            })),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("multiplex");
        assert!(config.multiplex.enabled);
        assert_eq!(config.multiplex.protocol, SingMuxProtocol::Yamux);
        assert!(config.multiplex.padding);
    }

    #[test]
    fn rejects_non_yamux_multiplex_configuration() {
        let remote = NodeConfigResponse {
            multiplex: Some(serde_json::json!({
                "enabled": true,
                "protocol": "h2mux"
            })),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("multiplex");
        assert!(error.to_string().contains("yamux"));
    }

    #[test]
    fn builds_users_from_password_or_uuid() {
        let users = build_users(
            &Method::Legacy(crypto::LegacyAeadMethod::Aes128Gcm),
            "",
            &[
                PanelUser {
                    id: 1,
                    password: "secret".to_string(),
                    ..Default::default()
                },
                PanelUser {
                    id: 2,
                    uuid: "fallback-secret".to_string(),
                    ..Default::default()
                },
            ],
        )
        .expect("users");
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn accepts_shadowsocks_2022_with_server_key() {
        let remote = NodeConfigResponse {
            cipher: "2022-blake3-aes-128-gcm".to_string(),
            server_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(config.method, Method::Aead2022(_)));
    }

    #[test]
    fn shadowsocks_2022_single_user_uses_server_key() {
        let users = build_users(
            &Method::Aead2022(crypto::Aead2022Method::Aes128Gcm),
            "QUJDREVGR0hJSktMTU5PUA==",
            &[PanelUser {
                id: 1,
                password: "user-password".to_string(),
                ..Default::default()
            }],
        )
        .expect("users");

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].secret, b"ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn shadowsocks_2022_multi_user_decodes_base64_user_keys() {
        let users = build_users(
            &Method::Aead2022(crypto::Aead2022Method::Aes128Gcm),
            "QUJDREVGR0hJSktMTU5PUA==",
            &[
                PanelUser {
                    id: 1,
                    password: "MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
                    ..Default::default()
                },
                PanelUser {
                    id: 2,
                    password: "YWJjZGVmMTIzNDU2Nzg5MA==".to_string(),
                    ..Default::default()
                },
            ],
        )
        .expect("users");

        assert_eq!(users.len(), 2);
        assert_eq!(users[0].secret, b"1234567890abcdef");
        assert_eq!(users[1].secret, b"abcdef1234567890");
    }

    #[test]
    fn rejects_shadowsocks_2022_multi_user_raw_key() {
        let error = build_users(
            &Method::Aead2022(crypto::Aead2022Method::Aes128Gcm),
            "QUJDREVGR0hJSktMTU5PUA==",
            &[
                PanelUser {
                    id: 1,
                    password: "not-base64-key".to_string(),
                    ..Default::default()
                },
                PanelUser {
                    id: 2,
                    password: "YWJjZGVmMTIzNDU2Nzg5MA==".to_string(),
                    ..Default::default()
                },
            ],
        )
        .expect_err("raw key should fail");
        assert!(
            error
                .to_string()
                .contains("decode Shadowsocks 2022 user 1 key")
        );
    }

    #[test]
    fn accepts_shadowsocks_2022_chacha_method() {
        let remote = NodeConfigResponse {
            cipher: "2022-blake3-chacha20-poly1305".to_string(),
            server_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string(),
            ..base_remote()
        };
        let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
        assert!(matches!(
            config.method,
            Method::Aead2022(crypto::Aead2022Method::ChaCha20Poly1305)
        ));
    }

    #[test]
    fn rejects_shadowsocks_2022_chacha_multi_user() {
        let error = build_users(
            &Method::Aead2022(crypto::Aead2022Method::ChaCha20Poly1305),
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            &[
                PanelUser {
                    id: 1,
                    uuid: "user-1".to_string(),
                    ..Default::default()
                },
                PanelUser {
                    id: 2,
                    uuid: "user-2".to_string(),
                    ..Default::default()
                },
            ],
        )
        .expect_err("multi-user chacha");
        assert!(error.to_string().contains("does not support multi-user"));
    }

    #[test]
    fn accepts_disabled_transport_extension_values() {
        let remote = NodeConfigResponse {
            network_settings: Some(serde_json::json!({ "enabled": false })),
            multiplex: Some(serde_json::json!({ "enabled": false })),
            transport: Some(serde_json::json!({ "enabled": false })),
            ..base_remote()
        };
        EffectiveNodeConfig::from_remote(&remote).expect("config");
    }

    #[test]
    fn rejects_enabled_transport_extension_values() {
        let remote = NodeConfigResponse {
            network_settings: Some(serde_json::json!({ "ws": true })),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network settings");
        assert!(error.to_string().contains("networkSettings"));
    }

    #[test]
    fn accepts_proxy_protocol_noise_in_network_settings() {
        let remote = NodeConfigResponse {
            network_settings: Some(serde_json::json!({ "acceptProxyProtocol": true })),
            ..base_remote()
        };
        EffectiveNodeConfig::from_remote(&remote).expect("config");
    }

    #[tokio::test]
    async fn parses_sing_mux_request_and_stream_request() {
        let mut request = &b"\x01\x01\x01\x00\x03abc"[..];
        let parsed = SingMuxRequest::read_from(&mut request)
            .await
            .expect("sing-mux request");
        assert_eq!(parsed.protocol, SingMuxProtocol::Yamux);
        assert!(parsed.padding);

        let mut stream_request = &b"\x00\x00\x03\x0bexample.com\x01\xbb"[..];
        let parsed = SingMuxStreamRequest::read_from(&mut stream_request)
            .await
            .expect("stream request");
        assert_eq!(parsed.network, SingMuxNetwork::Tcp);
        assert_eq!(
            parsed.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
        assert!(!parsed.packet_addr);
    }

    #[tokio::test]
    async fn serves_yamux_sing_mux_tcp_stream() {
        let target = TcpListener::bind("127.0.0.1:0").await.expect("target bind");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("target accept");
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.expect("target read");
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").await.expect("target write");
        });

        let (client, server) = tokio::io::duplex(COPY_BUFFER_LEN);
        let control = SessionControl::new();
        let accounting = Accounting::new();
        let upload = TrafficRecorder::upload(accounting.clone(), 1);
        let download = TrafficRecorder::download(accounting, 1);
        let (server_reader, server_writer) = split(server);
        let server_task = tokio::spawn(handle_sing_mux_connection(
            server_reader,
            server_writer,
            routing::RoutingTable::default(),
            control.clone(),
            upload,
            download,
            MultiplexConfig {
                enabled: true,
                protocol: SingMuxProtocol::Yamux,
                padding: false,
            },
        ));

        let mut client = client;
        client
            .write_all(&[SING_MUX_VERSION_0, SING_MUX_PROTOCOL_YAMUX])
            .await
            .expect("write mux request");
        let mut session = tokio_yamux::Session::new_client(client, tokio_yamux::Config::default());
        let mut control_stream = session.control();
        let driver = tokio::spawn(async move { while session.next().await.is_some() {} });
        let mut stream = control_stream.open_stream().await.expect("open stream");
        write_socksaddr_for_test(&mut stream, &SocksAddr::Ip(target_addr))
            .await
            .expect("write destination");
        stream.write_all(b"ping").await.expect("write payload");
        let status = stream.read_u8().await.expect("read status");
        assert_eq!(status, SING_MUX_STATUS_SUCCESS);
        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .expect("read response");
        assert_eq!(&response, b"pong");

        control.cancel();
        drop(stream);
        driver.abort();
        let _ = target_task.await;
        let _ = server_task.await.expect("server task");
    }

    async fn write_socksaddr_for_test<W>(writer: &mut W, addr: &SocksAddr) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_u16(0).await?;
        addr.write_to(writer).await
    }
}
