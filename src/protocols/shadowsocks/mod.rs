mod aead2022;
mod crypto;

use anyhow::{Context, anyhow, bail, ensure};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
    pub routing: routing::RoutingTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnabledNetworks {
    tcp: bool,
    udp: bool,
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
    handles: Vec<JoinHandle<()>>,
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

        if config.networks.tcp {
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
                let routing = self.routing.clone();
                let tcp_replay = self.tcp_replay.clone();
                handles.push(tokio::spawn(async move {
                    accept_tcp_loop(listener, accounting, users, routing, tcp_replay).await;
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
            handles,
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
            if let Err(error) =
                serve_tcp_connection(stream, source, accounting, users, routing, tcp_replay).await
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
    TrafficRecorder::upload(accounting, credential.user.id).record(wire_len as u64);
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
        match inbound_socket.send_to(&encoded, target).await {
            Ok(sent) if sent == encoded.len() => {
                TrafficRecorder::download(accounting.clone(), session.credential.user.id)
                    .record(encoded.len() as u64);
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
    if !remote.plugin.trim().is_empty() || !remote.plugin_opts.trim().is_empty() {
        bail!("Shadowsocks SIP003 plugin is not implemented yet");
    }
    if remote.multiplex_enabled() {
        bail!("Shadowsocks multiplex is not implemented yet");
    }
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
    fn rejects_plugin_configuration() {
        let remote = NodeConfigResponse {
            plugin: "obfs-local".to_string(),
            plugin_opts: "obfs=http".to_string(),
            ..base_remote()
        };
        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("plugin");
        assert!(error.to_string().contains("plugin"));
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
}
