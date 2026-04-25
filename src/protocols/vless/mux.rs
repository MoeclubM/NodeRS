use anyhow::{Context as _, anyhow, bail, ensure};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::AbortHandle;

use crate::accounting::SessionControl;

use super::super::anytls::{
    routing::RoutingTable, socksaddr::SocksAddr, traffic::TrafficRecorder, transport,
};

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;

const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

const STREAM_CHUNK_LEN: usize = 8 * 1024;

static NEXT_SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

type Sessions = Arc<Mutex<HashMap<u16, Arc<SessionEntry>>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetNetwork {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameTarget {
    network: TargetNetwork,
    destination: SocksAddr,
}

#[derive(Debug)]
struct Frame {
    session_id: u16,
    status: u8,
    has_data: bool,
    target: Option<FrameTarget>,
    payload: Vec<u8>,
    wire_len: usize,
}

struct SessionEntry {
    generation: u64,
    kind: SessionKind,
    abort: AbortHandle,
}

enum SessionKind {
    Tcp {
        writer: Arc<AsyncMutex<WriteHalf<TcpStream>>>,
    },
    Udp(UdpSession),
}

#[derive(Clone)]
struct UdpSession {
    socket: Arc<UdpSocket>,
    default_destination: SocksAddr,
    destination_cache: Arc<Mutex<HashMap<String, SocketAddr>>>,
}

impl SessionEntry {
    async fn shutdown(&self) {
        self.abort.abort();
        if let SessionKind::Tcp { writer } = &self.kind {
            let mut writer = writer.lock().await;
            let _ = writer.shutdown().await;
        }
    }
}

pub async fn relay<S>(
    stream: S,
    routing: RoutingTable,
    control: Arc<SessionControl>,
    upload: TrafficRecorder,
    download: TrafficRecorder,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = split(stream);
    let writer = Arc::new(AsyncMutex::new(writer));
    let sessions = Arc::new(Mutex::new(HashMap::new()));

    let result = relay_frames(
        &mut reader,
        writer,
        sessions.clone(),
        routing,
        control,
        upload,
        download,
    )
    .await;

    close_all_sessions(sessions).await;
    result
}

async fn relay_frames<R, W>(
    reader: &mut R,
    writer: Arc<AsyncMutex<W>>,
    sessions: Sessions,
    routing: RoutingTable,
    control: Arc<SessionControl>,
    upload: TrafficRecorder,
    download: TrafficRecorder,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let frame = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            frame = read_frame(reader) => frame?,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let wire_len = frame.wire_len;
        let count_traffic = handle_frame(
            frame,
            writer.clone(),
            &sessions,
            &routing,
            &control,
            &download,
        )
        .await?;
        if count_traffic {
            upload.record(wire_len as u64);
        }
    }
}

async fn handle_frame<W>(
    frame: Frame,
    writer: Arc<AsyncMutex<W>>,
    sessions: &Sessions,
    routing: &RoutingTable,
    control: &Arc<SessionControl>,
    download: &TrafficRecorder,
) -> anyhow::Result<bool>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    match frame.status {
        STATUS_NEW => handle_new(frame, writer, sessions, routing, control, download).await,
        STATUS_KEEP => handle_keep(frame, writer, sessions, routing, control, download).await,
        STATUS_END => {
            shutdown_session(sessions, frame.session_id).await;
            Ok(false)
        }
        STATUS_KEEPALIVE => Ok(false),
        other => bail!("unsupported VLESS mux status {other:#x}"),
    }
}

async fn handle_new<W>(
    frame: Frame,
    writer: Arc<AsyncMutex<W>>,
    sessions: &Sessions,
    routing: &RoutingTable,
    control: &Arc<SessionControl>,
    download: &TrafficRecorder,
) -> anyhow::Result<bool>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let target = frame
        .target
        .clone()
        .ok_or_else(|| anyhow!("VLESS mux new frame is missing its destination"))?;

    if let Some(previous) = take_session(sessions, frame.session_id) {
        previous.shutdown().await;
    }

    let session = match target.network {
        TargetNetwork::Tcp => {
            open_tcp_session(
                frame.session_id,
                target.destination.clone(),
                writer.clone(),
                sessions.clone(),
                routing,
                control.clone(),
                download.clone(),
            )
            .await?
        }
        TargetNetwork::Udp => {
            open_udp_session(
                frame.session_id,
                target.destination.clone(),
                writer.clone(),
                sessions.clone(),
                control.clone(),
                download.clone(),
            )
            .await?
        }
    };

    insert_session(sessions, frame.session_id, session.clone());

    if !frame.has_data {
        return Ok(false);
    }

    match send_frame_to_session(&session, None, &frame.payload, routing, control).await {
        Ok(()) => Ok(true),
        Err(_) => {
            shutdown_session(sessions, frame.session_id).await;
            if !control.is_cancelled() {
                let _ = write_end_frame(&writer, frame.session_id, true, control).await;
            }
            Ok(false)
        }
    }
}

async fn handle_keep<W>(
    frame: Frame,
    writer: Arc<AsyncMutex<W>>,
    sessions: &Sessions,
    routing: &RoutingTable,
    control: &Arc<SessionControl>,
    _download: &TrafficRecorder,
) -> anyhow::Result<bool>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    if !frame.has_data {
        return Ok(false);
    }

    let Some(session) = get_session(sessions, frame.session_id) else {
        write_end_frame(&writer, frame.session_id, false, control).await?;
        return Ok(false);
    };

    match send_frame_to_session(
        &session,
        frame.target.as_ref(),
        &frame.payload,
        routing,
        control,
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(_) => {
            shutdown_session(sessions, frame.session_id).await;
            if !control.is_cancelled() {
                let _ = write_end_frame(&writer, frame.session_id, true, control).await;
            }
            Ok(false)
        }
    }
}

async fn open_tcp_session<W>(
    session_id: u16,
    destination: SocksAddr,
    writer: Arc<AsyncMutex<W>>,
    sessions: Sessions,
    routing: &RoutingTable,
    control: Arc<SessionControl>,
    download: TrafficRecorder,
) -> anyhow::Result<Arc<SessionEntry>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let generation = next_session_generation();
    let remote = transport::connect_tcp_destination(&destination, routing)
        .await
        .with_context(|| format!("connect VLESS mux TCP destination {destination}"))?;
    let (remote_reader, remote_writer) = split(remote);
    let remote_writer = Arc::new(AsyncMutex::new(remote_writer));

    let task = tokio::spawn({
        let writer = writer.clone();
        let sessions = sessions.clone();
        let control = control.clone();
        let download = download.clone();
        async move {
            tokio::task::yield_now().await;
            let has_error = relay_tcp_to_client(
                session_id,
                remote_reader,
                writer.clone(),
                control.clone(),
                download,
            )
            .await
            .is_err();
            let finished_current =
                take_session_if_generation_matches(&sessions, session_id, generation).is_some();
            if finished_current && !control.is_cancelled() {
                let _ = write_end_frame(&writer, session_id, has_error, &control).await;
            }
        }
    });

    Ok(Arc::new(SessionEntry {
        generation,
        kind: SessionKind::Tcp {
            writer: remote_writer,
        },
        abort: task.abort_handle(),
    }))
}

async fn open_udp_session<W>(
    session_id: u16,
    destination: SocksAddr,
    writer: Arc<AsyncMutex<W>>,
    sessions: Sessions,
    control: Arc<SessionControl>,
    download: TrafficRecorder,
) -> anyhow::Result<Arc<SessionEntry>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let generation = next_session_generation();
    let socket = Arc::new(transport::bind_udp_socket().await?);
    let session = UdpSession {
        socket: socket.clone(),
        default_destination: destination,
        destination_cache: Arc::new(Mutex::new(HashMap::new())),
    };

    let task = tokio::spawn({
        let writer = writer.clone();
        let sessions = sessions.clone();
        let control = control.clone();
        let download = download.clone();
        async move {
            tokio::task::yield_now().await;
            let has_error = relay_udp_to_client(
                session_id,
                socket,
                writer.clone(),
                control.clone(),
                download,
            )
            .await
            .is_err();
            let finished_current =
                take_session_if_generation_matches(&sessions, session_id, generation).is_some();
            if finished_current && !control.is_cancelled() {
                let _ = write_end_frame(&writer, session_id, has_error, &control).await;
            }
        }
    });

    Ok(Arc::new(SessionEntry {
        generation,
        kind: SessionKind::Udp(session),
        abort: task.abort_handle(),
    }))
}

async fn send_frame_to_session(
    session: &SessionEntry,
    target_override: Option<&FrameTarget>,
    payload: &[u8],
    routing: &RoutingTable,
    control: &Arc<SessionControl>,
) -> anyhow::Result<()> {
    match &session.kind {
        SessionKind::Tcp { writer } => {
            ensure!(
                target_override.is_none(),
                "VLESS mux TCP session does not accept per-frame target overrides"
            );
            let mut writer = writer.lock().await;
            tokio::select! {
                _ = control.cancelled() => Ok(()),
                result = writer.write_all(payload) => result.context("write VLESS mux TCP payload"),
            }
        }
        SessionKind::Udp(session) => {
            send_udp_payload(session, target_override, payload, routing, control).await
        }
    }
}

async fn send_udp_payload(
    session: &UdpSession,
    target_override: Option<&FrameTarget>,
    payload: &[u8],
    routing: &RoutingTable,
    control: &Arc<SessionControl>,
) -> anyhow::Result<()> {
    let destination = match target_override {
        Some(target) => {
            ensure!(
                target.network == TargetNetwork::Udp,
                "VLESS mux UDP session received a non-UDP target override"
            );
            &target.destination
        }
        None => &session.default_destination,
    };
    let target = resolve_udp_target(destination, routing, &session.destination_cache).await?;
    let target = transport::normalize_udp_target(&session.socket, target);
    let sent = tokio::select! {
        _ = control.cancelled() => return Ok(()),
        sent = session.socket.send_to(payload, target) => sent.with_context(|| format!("send VLESS mux UDP payload to {target}"))?,
    };
    ensure!(
        sent == payload.len(),
        "short VLESS mux UDP send: expected {}, wrote {}",
        payload.len(),
        sent
    );
    Ok(())
}

async fn relay_tcp_to_client<W>(
    session_id: u16,
    mut reader: ReadHalf<TcpStream>,
    writer: Arc<AsyncMutex<W>>,
    control: Arc<SessionControl>,
    download: TrafficRecorder,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = vec![0u8; STREAM_CHUNK_LEN];
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => read.context("read VLESS mux TCP response")?,
        };
        if read == 0 {
            return Ok(());
        }
        write_data_frame(
            &writer,
            session_id,
            None,
            &buffer[..read],
            &download,
            &control,
        )
        .await?;
    }
}

async fn relay_udp_to_client<W>(
    session_id: u16,
    socket: Arc<UdpSocket>,
    writer: Arc<AsyncMutex<W>>,
    control: Arc<SessionControl>,
    download: TrafficRecorder,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (payload_len, source) = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = socket.recv_from(&mut buffer) => read.context("receive VLESS mux UDP response")?,
        };
        let source = transport::normalize_udp_source(source);
        write_data_frame(
            &writer,
            session_id,
            Some(&FrameTarget {
                network: TargetNetwork::Udp,
                destination: SocksAddr::Ip(source),
            }),
            &buffer[..payload_len],
            &download,
            &control,
        )
        .await?;
    }
}

async fn write_data_frame<W>(
    writer: &Arc<AsyncMutex<W>>,
    session_id: u16,
    target: Option<&FrameTarget>,
    payload: &[u8],
    traffic: &TrafficRecorder,
    control: &Arc<SessionControl>,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_frame(session_id, STATUS_KEEP, target, payload, false)?;
    write_frame_bytes(writer, frame, Some(traffic), control).await
}

async fn write_end_frame<W>(
    writer: &Arc<AsyncMutex<W>>,
    session_id: u16,
    has_error: bool,
    control: &Arc<SessionControl>,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_frame(session_id, STATUS_END, None, &[], has_error)?;
    write_frame_bytes(writer, frame, None, control).await
}

async fn write_frame_bytes<W>(
    writer: &Arc<AsyncMutex<W>>,
    frame: Vec<u8>,
    traffic: Option<&TrafficRecorder>,
    control: &Arc<SessionControl>,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = writer.lock().await;
    tokio::select! {
        _ = control.cancelled() => Ok(()),
        result = writer.write_all(&frame) => {
            result.context("write VLESS mux frame")?;
            if let Some(traffic) = traffic {
                traffic.record(frame.len() as u64);
            }
            Ok(())
        }
    }
}

async fn read_frame<R>(reader: &mut R) -> anyhow::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let Some(metadata_len) = read_length_or_eof(reader, "read VLESS mux metadata length").await?
    else {
        return Ok(None);
    };
    ensure!(
        metadata_len >= 4,
        "short VLESS mux metadata length {metadata_len}"
    );

    let mut metadata = vec![0u8; metadata_len as usize];
    reader
        .read_exact(&mut metadata)
        .await
        .context("read VLESS mux metadata")?;

    let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let has_data = metadata[3] & OPTION_DATA != 0;

    let target = if status == STATUS_NEW {
        ensure!(
            metadata.len() >= 5,
            "VLESS mux new frame is missing its network type"
        );
        let (target, consumed) = parse_target(metadata[4], &metadata[5..])?;
        let trailing = metadata.len() - 5 - consumed;
        ensure!(
            trailing == 0 || (target.network == TargetNetwork::Udp && trailing == 8),
            "unsupported VLESS mux metadata tail length {trailing}"
        );
        Some(target)
    } else {
        match status {
            STATUS_KEEP if metadata.len() == 4 => None,
            STATUS_KEEP if metadata.len() > 4 => {
                ensure!(
                    metadata[4] == NETWORK_UDP,
                    "unsupported VLESS mux keep metadata network {}",
                    metadata[4]
                );
                let (target, consumed) = parse_target(metadata[4], &metadata[5..])?;
                let trailing = metadata.len() - 5 - consumed;
                ensure!(
                    trailing == 0,
                    "unsupported VLESS mux metadata tail length {trailing}"
                );
                Some(target)
            }
            STATUS_END | STATUS_KEEPALIVE => {
                ensure!(
                    metadata.len() == 4,
                    "unsupported VLESS mux metadata length {} for status {status:#x}",
                    metadata.len()
                );
                None
            }
            _ => None,
        }
    };

    let mut wire_len = 2 + metadata.len();
    let payload = if has_data {
        let payload_len = read_u16(reader, "read VLESS mux payload length").await? as usize;
        let mut payload = vec![0u8; payload_len];
        reader
            .read_exact(&mut payload)
            .await
            .context("read VLESS mux payload")?;
        wire_len += 2 + payload_len;
        payload
    } else {
        Vec::new()
    };

    Ok(Some(Frame {
        session_id,
        status,
        has_data,
        target,
        payload,
        wire_len,
    }))
}

fn parse_target(network: u8, bytes: &[u8]) -> anyhow::Result<(FrameTarget, usize)> {
    let network = match network {
        NETWORK_TCP => TargetNetwork::Tcp,
        NETWORK_UDP => TargetNetwork::Udp,
        other => bail!("unsupported VLESS mux network type {other:#x}"),
    };
    let (destination, consumed) = parse_destination(bytes)?;
    Ok((
        FrameTarget {
            network,
            destination,
        },
        consumed,
    ))
}

fn parse_destination(bytes: &[u8]) -> anyhow::Result<(SocksAddr, usize)> {
    ensure!(bytes.len() >= 3, "short VLESS mux destination");
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        ATYP_IPV4 => {
            ensure!(bytes.len() >= 7, "short VLESS mux IPv4 destination");
            Ok((
                SocksAddr::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(bytes[3], bytes[4], bytes[5], bytes[6])),
                    port,
                )),
                7,
            ))
        }
        ATYP_IPV6 => {
            ensure!(bytes.len() >= 19, "short VLESS mux IPv6 destination");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[3..19]);
            Ok((
                SocksAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        ATYP_DOMAIN => {
            ensure!(bytes.len() >= 4, "short VLESS mux domain destination");
            let len = bytes[3] as usize;
            ensure!(bytes.len() >= 4 + len, "short VLESS mux domain destination");
            Ok((
                SocksAddr::Domain(
                    String::from_utf8(bytes[4..4 + len].to_vec())
                        .context("decode VLESS mux domain")?,
                    port,
                ),
                4 + len,
            ))
        }
        other => bail!("unsupported VLESS mux address type {other:#x}"),
    }
}

fn encode_frame(
    session_id: u16,
    status: u8,
    target: Option<&FrameTarget>,
    payload: &[u8],
    has_error: bool,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "VLESS mux payload too large"
    );

    let mut metadata = Vec::new();
    metadata.extend_from_slice(&session_id.to_be_bytes());
    metadata.push(status);

    let mut option = 0u8;
    if !payload.is_empty() {
        option |= OPTION_DATA;
    }
    if has_error {
        option |= OPTION_ERROR;
    }
    metadata.push(option);

    if let Some(target) = target {
        metadata.push(match target.network {
            TargetNetwork::Tcp => NETWORK_TCP,
            TargetNetwork::Udp => NETWORK_UDP,
        });
        write_destination(&mut metadata, &target.destination)?;
    }

    let mut encoded = Vec::with_capacity(
        2 + metadata.len()
            + if payload.is_empty() {
                0
            } else {
                2 + payload.len()
            },
    );
    encoded.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&metadata);
    if !payload.is_empty() {
        encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        encoded.extend_from_slice(payload);
    }
    Ok(encoded)
}

fn write_destination(buffer: &mut Vec<u8>, destination: &SocksAddr) -> anyhow::Result<()> {
    let port = match destination {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());

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
            ensure!(host.len() <= u8::MAX as usize, "VLESS mux domain too long");
            buffer.push(ATYP_DOMAIN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host);
        }
    }
    Ok(())
}

async fn resolve_udp_target(
    destination: &SocksAddr,
    routing: &RoutingTable,
    cache: &Arc<Mutex<HashMap<String, SocketAddr>>>,
) -> anyhow::Result<SocketAddr> {
    let cache_key = destination.to_string();
    if let Some(target) = cache
        .lock()
        .expect("vless mux UDP cache poisoned")
        .get(&cache_key)
        .copied()
    {
        return Ok(target);
    }

    let target = transport::resolve_destination(destination, routing, "udp")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no UDP addresses resolved for {destination}"))?;

    cache
        .lock()
        .expect("vless mux UDP cache poisoned")
        .insert(cache_key, target);
    Ok(target)
}

async fn close_all_sessions(sessions: Sessions) {
    let entries = {
        let mut sessions = sessions.lock().expect("vless mux session map poisoned");
        std::mem::take(&mut *sessions)
            .into_values()
            .collect::<Vec<_>>()
    };
    for session in entries {
        session.shutdown().await;
    }
}

async fn shutdown_session(sessions: &Sessions, session_id: u16) {
    if let Some(session) = take_session(sessions, session_id) {
        session.shutdown().await;
    }
}

fn insert_session(sessions: &Sessions, session_id: u16, session: Arc<SessionEntry>) {
    sessions
        .lock()
        .expect("vless mux session map poisoned")
        .insert(session_id, session);
}

fn get_session(sessions: &Sessions, session_id: u16) -> Option<Arc<SessionEntry>> {
    sessions
        .lock()
        .expect("vless mux session map poisoned")
        .get(&session_id)
        .cloned()
}

fn take_session(sessions: &Sessions, session_id: u16) -> Option<Arc<SessionEntry>> {
    sessions
        .lock()
        .expect("vless mux session map poisoned")
        .remove(&session_id)
}

fn take_session_if_generation_matches(
    sessions: &Sessions,
    session_id: u16,
    generation: u64,
) -> Option<Arc<SessionEntry>> {
    let mut sessions = sessions.lock().expect("vless mux session map poisoned");
    let current = sessions.get(&session_id)?;
    if current.generation != generation {
        return None;
    }
    sessions.remove(&session_id)
}

fn next_session_generation() -> u64 {
    NEXT_SESSION_GENERATION.fetch_add(1, Ordering::Relaxed)
}

async fn read_length_or_eof<R>(reader: &mut R, context: &str) -> anyhow::Result<Option<u16>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    match reader.read_exact(&mut bytes).await {
        Ok(_) => Ok(Some(u16::from_be_bytes(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error).context(context.to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::Accounting;

    async fn test_udp_session_entry(generation: u64) -> Arc<SessionEntry> {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("bind UDP socket"),
        );
        let destination = SocksAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 53)));
        let task = tokio::spawn(async {});
        Arc::new(SessionEntry {
            generation,
            kind: SessionKind::Udp(UdpSession {
                socket,
                default_destination: destination,
                destination_cache: Arc::new(Mutex::new(HashMap::new())),
            }),
            abort: task.abort_handle(),
        })
    }

    fn tcp_target(addr: SocketAddr) -> FrameTarget {
        FrameTarget {
            network: TargetNetwork::Tcp,
            destination: SocksAddr::Ip(addr),
        }
    }

    fn udp_target(addr: SocketAddr) -> FrameTarget {
        FrameTarget {
            network: TargetNetwork::Udp,
            destination: SocksAddr::Ip(addr),
        }
    }

    #[tokio::test]
    async fn parses_udp_new_frame_with_trailing_global_id() {
        let target = FrameTarget {
            network: TargetNetwork::Udp,
            destination: SocksAddr::Domain("example.com".to_string(), 53),
        };
        let metadata = [
            vec![
                0,
                7,
                STATUS_NEW,
                OPTION_DATA,
                NETWORK_UDP,
                0,
                53,
                ATYP_DOMAIN,
                11,
            ],
            b"example.com".to_vec(),
            vec![1; 8],
        ]
        .concat();
        let encoded = [
            (metadata.len() as u16).to_be_bytes().to_vec(),
            metadata,
            (5u16).to_be_bytes().to_vec(),
            b"hello".to_vec(),
        ]
        .concat();
        let mut cursor = encoded.as_slice();

        let frame = read_frame(&mut cursor)
            .await
            .expect("read frame")
            .expect("frame exists");

        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.target, Some(target));
        assert_eq!(frame.payload.as_slice(), b"hello");
    }

    #[test]
    fn encodes_udp_keep_frame_with_port_first_destination() {
        let encoded = encode_frame(
            3,
            STATUS_KEEP,
            Some(&udp_target(SocketAddr::from(([1, 2, 3, 4], 53)))),
            b"ok",
            false,
        )
        .expect("encode frame");

        assert_eq!(
            encoded.as_slice(),
            b"\0\x0c\0\x03\x02\x01\x02\0\x35\x01\x01\x02\x03\x04\0\x02ok"
        );
    }

    #[tokio::test]
    async fn stale_session_cleanup_does_not_remove_reused_session_id() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let old_session = test_udp_session_entry(11).await;
        let new_session = test_udp_session_entry(12).await;

        insert_session(&sessions, 7, old_session);
        insert_session(&sessions, 7, new_session.clone());

        assert!(take_session_if_generation_matches(&sessions, 7, 11).is_none());
        let current = get_session(&sessions, 7).expect("current session");
        assert_eq!(current.generation, 12);

        let removed = take_session_if_generation_matches(&sessions, 7, 12)
            .expect("matching generation removed current session");
        assert_eq!(removed.generation, 12);
        assert!(get_session(&sessions, 7).is_none());
    }

    #[tokio::test]
    async fn stale_session_cleanup_reports_not_current() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let old_session = test_udp_session_entry(21).await;
        let new_session = test_udp_session_entry(22).await;

        insert_session(&sessions, 9, old_session);
        insert_session(&sessions, 9, new_session.clone());

        let finished_current = take_session_if_generation_matches(&sessions, 9, 21).is_some();
        assert!(!finished_current);

        let current = get_session(&sessions, 9).expect("current session");
        assert_eq!(current.generation, 22);
    }

    #[tokio::test]
    async fn relays_tcp_session_round_trip() {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind listener");
        let listen_addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept client");
            let mut inbound = [0u8; 4];
            socket.read_exact(&mut inbound).await.expect("read request");
            assert_eq!(&inbound, b"ping");
            socket.write_all(b"pong").await.expect("write response");
        });

        let (client, server) = tokio::io::duplex(16 * 1024);
        let accounting = Accounting::new();
        let control = SessionControl::new();
        let server_task = tokio::spawn(relay(
            server,
            RoutingTable::default(),
            control.clone(),
            TrafficRecorder::upload(accounting.clone(), 1),
            TrafficRecorder::download(accounting, 1),
        ));

        let mut client = client;
        let request = encode_frame(
            1,
            STATUS_NEW,
            Some(&tcp_target(listen_addr)),
            b"ping",
            false,
        )
        .expect("encode request");
        client.write_all(&request).await.expect("write request");

        let response = read_frame(&mut client)
            .await
            .expect("read response")
            .expect("response frame");
        assert_eq!(response.session_id, 1);
        assert_eq!(response.status, STATUS_KEEP);
        assert!(response.target.is_none());
        assert_eq!(response.payload.as_slice(), b"pong");

        let end = read_frame(&mut client)
            .await
            .expect("read end")
            .expect("end frame");
        assert_eq!(end.session_id, 1);
        assert_eq!(end.status, STATUS_END);
        assert!(!end.has_data);

        drop(client);
        server_task.await.expect("join relay").expect("relay ok");
        assert!(!control.is_cancelled());
    }
}
