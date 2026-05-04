mod channel;
mod frame;
mod io;
mod writer;

use anyhow::{Context, anyhow, bail};
use rustc_hash::FxHashMap;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf, ReadHalf, split};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

use super::activity::{ActivityTracker, HEARTBEAT_INTERVAL, SESSION_IDLE_TIMEOUT};
use super::padding::PaddingScheme;
use super::uot;
use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::protocols::shared::{
    routing::RoutingTable, socksaddr::SocksAddr, traffic::TrafficRecorder, transport,
};
use channel::{ChannelReader, PayloadBuffer, PayloadPool};
use frame::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, FrameHeader,
    MAX_STREAMS_PER_SESSION, STREAM_INBOUND_QUEUE_BYTES, STREAM_INBOUND_QUEUE_CAPACITY, is_eof,
    padding_md5, parse_settings,
};
use io::{pump_copy, pump_inbound_to_remote, pump_remote_to_client};
use writer::{FrameWriter, write_frame, write_frame_pair_immediate};

const WHOLE_PAYLOAD_RETRY_MIN_AVAILABLE_BUDGET: usize = 8 * 1024;
const WHOLE_PAYLOAD_RETRY_GRACE: std::time::Duration = std::time::Duration::from_millis(1);
const DISCARD_SCRATCH_LEN: usize = 8 * 1024;
const UOT_BRIDGE_BUFFER_SIZE: usize = 1024 * 1024;
const PREFETCH_FIRST_DOWNLOAD_BYTES: usize = 32 * 1024;
const FIRST_DOWNLOAD_PREFETCH_GRACE: std::time::Duration = std::time::Duration::from_millis(2);

type TlsStream = tokio_boring::SslStream<TcpStream>;
const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PAYLOAD_POOL_MAX_CACHED: usize = 512;

pub async fn serve_connection(
    mut stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    padding: PaddingScheme,
    routing: RoutingTable,
) -> anyhow::Result<()> {
    let user = tokio::time::timeout(
        AUTHENTICATION_TIMEOUT,
        authenticate(&mut stream, &accounting),
    )
    .await
    .context("authentication timed out")??;
    let lease = accounting.open_session(&user, source)?;
    let control = lease.control();
    let activity = ActivityTracker::new();
    let (reader, writer) = split(stream);
    let session = Session {
        user: user.clone(),
        lease,
        accounting: accounting.clone(),
        padding,
        routing,
        activity,
        reader,
        writer: FrameWriter::spawn(writer),
        state: Arc::new(SessionState::default()),
        payload_pool: Arc::new(PayloadPool::new(PAYLOAD_POOL_MAX_CACHED)),
    };
    let result = session.run().await;
    if control.is_cancelled() {
        return Ok(());
    }
    result
}

async fn authenticate(
    stream: &mut TlsStream,
    accounting: &Accounting,
) -> anyhow::Result<UserEntry> {
    let mut hash = [0u8; 32];
    stream
        .read_exact(&mut hash)
        .await
        .context("read password hash")?;
    let padding_length = stream
        .read_u16()
        .await
        .context("read preface padding length")? as usize;
    if padding_length > 0 {
        discard_exact(stream, padding_length)
            .await
            .context("read preface padding bytes")?;
    }
    accounting
        .find_user_by_hash(&hash)
        .ok_or_else(|| anyhow!("unknown AnyTLS user"))
}

struct Session {
    user: UserEntry,
    lease: SessionLease,
    accounting: Arc<Accounting>,
    padding: PaddingScheme,
    routing: RoutingTable,
    activity: Arc<ActivityTracker>,
    reader: ReadHalf<TlsStream>,
    writer: FrameWriter,
    state: Arc<SessionState>,
    payload_pool: Arc<PayloadPool>,
}

struct SessionState {
    received_settings: AtomicBool,
    peer_version: AtomicU8,
    streams: RwLock<FxHashMap<u32, StreamState>>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            received_settings: AtomicBool::new(false),
            peer_version: AtomicU8::new(0),
            streams: RwLock::new(FxHashMap::default()),
        }
    }
}

struct StreamState {
    inbound: Option<channel::InboundSender>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct StreamContext {
    writer: FrameWriter,
    control: Arc<SessionControl>,
    routing: RoutingTable,
    activity: Arc<ActivityTracker>,
    upload_traffic: TrafficRecorder,
    download_traffic: TrafficRecorder,
    send_synack: bool,
}

struct TcpStreamContext {
    writer: FrameWriter,
    stream_id: u32,
    control: Arc<SessionControl>,
    activity: Arc<ActivityTracker>,
    upload_traffic: TrafficRecorder,
    download_traffic: TrafficRecorder,
}

impl Session {
    async fn run(mut self) -> anyhow::Result<()> {
        let control = self.lease.control();
        let state = self.state.clone();
        let writer = self.writer.clone();
        let activity = self.activity.clone();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let result = loop {
            let header = tokio::select! {
                biased;
                _ = control.cancelled() => break Err(anyhow!("session cancelled")),
                _ = heartbeat.tick() => {
                    let idle_for = activity.idle_for();
                    if idle_for >= SESSION_IDLE_TIMEOUT {
                        break Err(anyhow!("session idle timeout"));
                    }
                    if idle_for >= HEARTBEAT_INTERVAL
                        && state.received_settings.load(Ordering::Relaxed)
                        && peer_supports_v2(state.peer_version.load(Ordering::Relaxed))
                    {
                        write_frame(&writer, CMD_HEART_REQUEST, 0, &[]).await?;
                    }
                    continue;
                }
                header = read_header(&mut self.reader) => match header {
                    Ok(header) => header,
                    Err(error) if is_eof(&error) => break Ok(()),
                    Err(error) => break Err(error),
                }
            };
            self.activity.record();
            match header.cmd {
                CMD_PSH => self.handle_psh(header).await?,
                CMD_SYN => self.handle_syn(header.stream_id).await?,
                CMD_FIN => self.handle_fin(header.stream_id).await,
                CMD_WASTE => self.discard(header.length as usize).await?,
                CMD_SETTINGS => self.handle_settings(header.length as usize).await?,
                CMD_ALERT => self.handle_alert(header.length as usize).await?,
                CMD_HEART_REQUEST => {
                    self.write_frame(CMD_HEART_RESPONSE, header.stream_id, &[])
                        .await?
                }
                CMD_HEART_RESPONSE => {}
                CMD_UPDATE_PADDING_SCHEME => self.discard(header.length as usize).await?,
                CMD_SERVER_SETTINGS => self.discard(header.length as usize).await?,
                CMD_SYNACK => self.discard(header.length as usize).await?,
                other => {
                    warn!(cmd = other, user = %self.user.uuid, "unknown session command ignored");
                    if header.length > 0 {
                        self.discard(header.length as usize).await?;
                    }
                }
            }
        };
        self.shutdown().await;
        result
    }

    async fn shutdown(&self) {
        let streams =
            std::mem::take(&mut *self.state.streams.write().expect("streams lock poisoned"));
        for (_, stream) in streams {
            stream.task.abort();
        }
    }

    async fn handle_psh(&mut self, header: FrameHeader) -> anyhow::Result<()> {
        let mut payload = self.payload_pool.take(header.length as usize);
        read_exact_payload(&mut self.reader, &mut payload, header.length as usize).await?;

        let inbound = {
            let streams = self.state.streams.read().expect("streams lock poisoned");
            streams
                .get(&header.stream_id)
                .and_then(|stream| stream.inbound.clone())
        };
        if let Some(inbound) = inbound
            && let Err(error) = self.forward_inbound_payload(inbound, payload).await
        {
            debug!(
                stream_id = header.stream_id,
                user = %self.user.uuid,
                %error,
                "dropping stream after inbound forwarding failure"
            );
            self.drop_stream(header.stream_id).await;
        }
        Ok(())
    }

    async fn handle_syn(&self, stream_id: u32) -> anyhow::Result<()> {
        let received_settings = self.state.received_settings.load(Ordering::Relaxed);
        let peer_version = self.state.peer_version.load(Ordering::Relaxed);
        if !received_settings {
            self.write_frame(CMD_ALERT, 0, b"client did not send its settings")
                .await?;
            bail!("AnyTLS client did not send settings before SYN")
        }
        let stream_gate = {
            let streams = self.state.streams.read().expect("streams lock poisoned");
            (
                streams.contains_key(&stream_id),
                streams.len() >= MAX_STREAMS_PER_SESSION,
            )
        };
        if stream_gate.0 {
            return Ok(());
        }
        if stream_gate.1 {
            let error = format!("too many concurrent streams: limit={MAX_STREAMS_PER_SESSION}");
            if peer_supports_v2(peer_version) {
                self.write_frame(CMD_SYNACK, stream_id, error.as_bytes())
                    .await?;
            }
            return Ok(());
        }

        let (inbound_tx, inbound_rx) = channel::bounded_inbound_channel(
            STREAM_INBOUND_QUEUE_CAPACITY,
            STREAM_INBOUND_QUEUE_BYTES,
        );

        let writer = self.writer.clone();
        let accounting = self.accounting.clone();
        let user = self.user.clone();
        let control = self.lease.control();
        let context = StreamContext {
            writer: writer.clone(),
            control: control.clone(),
            routing: self.routing.clone(),
            activity: self.activity.clone(),
            upload_traffic: TrafficRecorder::upload(accounting.clone(), user.id),
            download_traffic: TrafficRecorder::download(accounting, user.id),
            send_synack: peer_supports_v2(peer_version),
        };
        let state = self.state.clone();
        let task = tokio::spawn(async move {
            let outcome =
                handle_stream(stream_id, ChannelReader::new(inbound_rx), user, context).await;

            let _ = state
                .streams
                .write()
                .expect("streams lock poisoned")
                .remove(&stream_id);

            if let Err(error) = outcome {
                warn!(%error, stream_id, "AnyTLS stream handler failed");
                if !control.is_cancelled() {
                    let _ = write_frame(&writer, CMD_FIN, stream_id, &[]).await;
                }
            }
        });

        self.state
            .streams
            .write()
            .expect("streams lock poisoned")
            .insert(
                stream_id,
                StreamState {
                    inbound: Some(inbound_tx),
                    task,
                },
            );
        Ok(())
    }

    async fn handle_fin(&self, stream_id: u32) {
        close_peer_stream(&self.state, stream_id);
    }

    async fn drop_stream(&self, stream_id: u32) {
        let stream = take_stream(&self.state, stream_id);
        if let Some(stream) = stream {
            stream.task.abort();
            let _ = self.write_frame(CMD_FIN, stream_id, &[]).await;
        }
    }

    async fn handle_settings(&mut self, length: usize) -> anyhow::Result<()> {
        if length == 0 {
            return Ok(());
        }
        let mut bytes = vec![0u8; length];
        self.reader
            .read_exact(&mut bytes)
            .await
            .context("read settings frame")?;
        let settings = parse_settings(&bytes);
        self.state.received_settings.store(true, Ordering::Relaxed);
        let peer_version = negotiated_peer_version(&settings);
        self.state
            .peer_version
            .store(peer_version, Ordering::Relaxed);

        let expected_padding_md5 = padding_md5(self.padding.raw_lines());
        if settings.get("padding-md5") != Some(&expected_padding_md5) {
            self.write_frame(
                CMD_UPDATE_PADDING_SCHEME,
                0,
                self.padding.raw_lines().join("\n").as_bytes(),
            )
            .await?;
        }
        if peer_supports_v2(peer_version) {
            self.write_frame(CMD_SERVER_SETTINGS, 0, b"v=2").await?;
        }
        Ok(())
    }

    async fn handle_alert(&mut self, length: usize) -> anyhow::Result<()> {
        let mut bytes = vec![0u8; length];
        self.reader
            .read_exact(&mut bytes)
            .await
            .context("read alert frame")?;
        bail!("peer alert: {}", String::from_utf8_lossy(&bytes))
    }

    async fn discard(&mut self, length: usize) -> anyhow::Result<()> {
        discard_exact(&mut self.reader, length).await
    }

    async fn write_frame(&self, cmd: u8, stream_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        write_frame(&self.writer, cmd, stream_id, payload).await
    }

    async fn forward_inbound_payload(
        &self,
        inbound: channel::InboundSender,
        payload: PayloadBuffer,
    ) -> anyhow::Result<()> {
        forward_buffered_inbound_payload(&inbound, self.lease.control(), payload).await
    }
}

#[cfg(test)]
async fn forward_inbound_payload_to_channel(
    inbound: &channel::InboundSender,
    control: &Arc<SessionControl>,
    payload: PayloadBuffer,
) -> anyhow::Result<()> {
    forward_buffered_inbound_payload(inbound, control.clone(), payload).await
}

async fn read_header(reader: &mut ReadHalf<TlsStream>) -> anyhow::Result<FrameHeader> {
    let mut header = [0u8; 7];
    reader
        .read_exact(&mut header)
        .await
        .context("read frame header")?;
    Ok(FrameHeader {
        cmd: header[0],
        stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        length: u16::from_be_bytes([header[5], header[6]]),
    })
}

async fn discard_exact<R>(reader: &mut R, length: usize) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    if length == 0 {
        return Ok(());
    }
    let mut remaining = length;
    let mut scratch = [0u8; DISCARD_SCRATCH_LEN];
    while remaining > 0 {
        let read_len = remaining.min(scratch.len());
        reader
            .read_exact(&mut scratch[..read_len])
            .await
            .context("discard frame payload")?;
        remaining -= read_len;
    }
    Ok(())
}

async fn read_exact_payload<R>(
    reader: &mut R,
    payload: &mut PayloadBuffer,
    len: usize,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    payload.clear();
    payload.reserve(len);
    while payload.len() < len {
        let read = poll_fn(|cx| {
            let remaining = len - payload.len();
            // Read straight into spare capacity so pooled buffers do not pay for
            // zero-filling bytes that will be overwritten immediately.
            let mut read_buf = ReadBuf::uninit(&mut payload.spare_capacity_mut()[..remaining]);
            match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .context("read PSH payload")?;
        if read == 0 {
            bail!("unexpected EOF while reading PSH payload");
        }
        // SAFETY: `poll_read` only reports bytes in `filled()` after initializing them.
        unsafe {
            payload.advance_mut(read);
        }
    }
    Ok(())
}

async fn forward_buffered_inbound_payload(
    inbound: &channel::InboundSender,
    control: Arc<SessionControl>,
    payload: PayloadBuffer,
) -> anyhow::Result<()> {
    // sing-anytls keeps PSH delivery as a whole-frame backpressure boundary instead of
    // re-slicing the payload under pressure. Our frame size is already capped to u16::MAX,
    // so forwarding the pooled buffer as a single unit avoids extra copies and fragmentation.
    match inbound.try_send_data(payload) {
        Ok(()) => Ok(()),
        Err(channel::TrySendError::Closed) => Err(anyhow!(
            "inbound channel closed before data could be delivered"
        )),
        Err(channel::TrySendError::Full(mut payload)) => {
            if should_retry_whole_payload_after_backpressure(inbound.available_send_budget()) {
                // Keep the whole-frame fast path alive for brief scheduler-scale contention so
                // high-RTT uploads can still queue full payloads instead of immediately sleeping
                // on a budget wait when the previous chunk is about to drain.
                let deadline = tokio::time::Instant::now() + WHOLE_PAYLOAD_RETRY_GRACE;
                loop {
                    tokio::task::yield_now().await;
                    if control.is_cancelled() {
                        return Ok(());
                    }
                    match inbound.try_send_data(payload) {
                        Ok(()) => return Ok(()),
                        Err(channel::TrySendError::Closed) => {
                            return Err(anyhow!(
                                "inbound channel closed before data could be delivered"
                            ));
                        }
                        Err(channel::TrySendError::Full(next_payload)) => {
                            payload = next_payload;
                            if tokio::time::Instant::now() >= deadline {
                                break;
                            }
                        }
                    }
                }
            }
            tokio::select! {
                _ = control.cancelled() => Ok(()),
                result = inbound.send_data(payload) => result,
            }
        }
    }
}

fn should_retry_whole_payload_after_backpressure(available_budget: usize) -> bool {
    available_budget >= WHOLE_PAYLOAD_RETRY_MIN_AVAILABLE_BUDGET
}

fn take_stream(state: &SessionState, stream_id: u32) -> Option<StreamState> {
    state
        .streams
        .write()
        .expect("streams lock poisoned")
        .remove(&stream_id)
}

fn close_peer_stream(state: &SessionState, stream_id: u32) {
    // sing-anytls treats peer FIN as a full stream close instead of a half-close.
    if let Some(stream) = take_stream(state, stream_id) {
        stream.task.abort();
    }
}

fn negotiated_peer_version(settings: &std::collections::HashMap<String, String>) -> u8 {
    match settings
        .get("v")
        .and_then(|value| value.parse::<u16>().ok())
    {
        Some(version) if version >= 2 => 2,
        Some(1) => 1,
        _ => 0,
    }
}

fn peer_supports_v2(peer_version: u8) -> bool {
    peer_version >= 2
}

async fn handle_stream(
    stream_id: u32,
    mut app_side: ChannelReader,
    user: UserEntry,
    context: StreamContext,
) -> anyhow::Result<()> {
    if context.control.is_cancelled() {
        return Err(anyhow!("session cancelled before stream setup"));
    }
    let destination = match SocksAddr::read_from(&mut app_side)
        .await
        .context("read target address")
    {
        Ok(destination) => destination,
        Err(error) => return Err(error),
    };
    let has_pending_upload = app_side.has_pending_data();
    if let Some(version) = uot::version_for(&destination) {
        let request = match uot::read_request(&mut app_side, version).await {
            Ok(request) => request,
            Err(error) => return Err(error),
        };
        let prepared = uot::prepare(request, &context.routing).await;
        let result = async {
            match prepared {
                Ok(prepared) => {
                    if context.send_synack {
                        write_frame(&context.writer, CMD_SYNACK, stream_id, &[]).await?;
                    }
                    let (session_side, app_bridge_side) = tokio::io::duplex(UOT_BRIDGE_BUFFER_SIZE);
                    let (mut session_reader, mut session_writer) = split(session_side);
                    // UOT keeps streaming through ChannelReader after the parser stage, so it can
                    // release byte budget as bytes are copied onward instead of waiting for a
                    // queued-tail handoff like the TCP upload path does.
                    app_side.enable_budget_release_on_read();
                    let bridge_control = context.control.clone();
                    let bridge_task = tokio::spawn(async move {
                        pump_copy(
                            &mut app_side,
                            &mut session_writer,
                            bridge_control,
                            None,
                            None,
                        )
                        .await
                    });
                    let writer = context.writer.clone();
                    let pump_control = context.control.clone();
                    let pump_activity = context.activity.clone();
                    let outbound_task = tokio::spawn(async move {
                        pump_remote_to_client(
                            &mut session_reader,
                            writer,
                            stream_id,
                            pump_control,
                            None,
                            Some(pump_activity),
                            None,
                        )
                        .await
                    });
                    prepared
                        .run(
                            app_bridge_side,
                            context.control,
                            context.upload_traffic,
                            context.download_traffic,
                        )
                        .await?;
                    bridge_task.abort();
                    outbound_task.abort();
                    debug!(stream_id, user = %user.uuid, version = ?version, "UOT stream closed");
                    Ok(())
                }
                Err(error) => {
                    if context.send_synack {
                        write_frame(
                            &context.writer,
                            CMD_SYNACK,
                            stream_id,
                            error.to_string().as_bytes(),
                        )
                        .await?;
                    }
                    Err(error)
                }
            }
        }
        .await;
        return result;
    }

    let remote = transport::connect_tcp_destination(&destination, &context.routing)
        .await
        .with_context(|| format!("connect remote destination {destination}"));

    let result = async {
        match remote {
            Ok(mut stream) => {
                let mut prefetched_download = prefetch_remote_download_with_grace(
                    &stream,
                    if has_pending_upload {
                        std::time::Duration::ZERO
                    } else {
                        FIRST_DOWNLOAD_PREFETCH_GRACE
                    },
                )
                .await?;
                let mut initial_download_bytes = 0u64;
                if context.send_synack {
                    if let Some(prefetched) = prefetched_download.take() {
                        context
                            .download_traffic
                            .limit(prefetched.len() as u64, &context.control)
                            .await;
                        if context.control.is_cancelled() {
                            return Ok((0, 0));
                        }
                        write_frame_pair_immediate(
                            &context.writer,
                            CMD_SYNACK,
                            stream_id,
                            &[],
                            CMD_PSH,
                            stream_id,
                            &prefetched,
                        )
                        .await?;
                        initial_download_bytes = prefetched.len() as u64;
                        context.download_traffic.record(initial_download_bytes);
                        context.activity.record();
                    } else {
                        write_frame(&context.writer, CMD_SYNACK, stream_id, &[]).await?;
                    }
                }
                let tcp_context = TcpStreamContext {
                    writer: context.writer.clone(),
                    stream_id,
                    control: context.control,
                    activity: context.activity,
                    upload_traffic: context.upload_traffic,
                    download_traffic: context.download_traffic,
                };
                handle_tcp_stream(
                    app_side,
                    &mut stream,
                    prefetched_download,
                    initial_download_bytes,
                    tcp_context,
                )
                .await
            }
            Err(error) => {
                if context.send_synack {
                    write_frame(
                        &context.writer,
                        CMD_SYNACK,
                        stream_id,
                        error.to_string().as_bytes(),
                    )
                    .await?;
                }
                Err(anyhow!(error.to_string()))
            }
        }
    }
    .await;

    result.map(|(uploaded, downloaded)| {
        debug!(stream_id, user = %user.uuid, destination = %destination, uploaded, downloaded, "stream closed");
    })
}

async fn handle_tcp_stream(
    app_side: ChannelReader,
    stream: &mut TcpStream,
    prefetched_download: Option<Vec<u8>>,
    initial_download_bytes: u64,
    context: TcpStreamContext,
) -> anyhow::Result<(u64, u64)> {
    let (mut read_b, mut write_b) = stream.split();
    let (pending, pending_front_offset, inbound_rx, inbound_finished) = app_side.into_parts();
    let upload = pump_inbound_to_remote(
        pending,
        pending_front_offset,
        inbound_rx,
        inbound_finished,
        &mut write_b,
        context.control.clone(),
        Some(context.upload_traffic),
    );
    let download = pump_remote_to_client(
        &mut read_b,
        context.writer,
        context.stream_id,
        context.control,
        Some(context.download_traffic),
        Some(context.activity),
        prefetched_download,
    );
    let (uploaded, downloaded) = tokio::try_join!(upload, download)?;
    Ok((uploaded, downloaded + initial_download_bytes))
}

fn prefetch_immediate_remote_download(stream: &TcpStream) -> anyhow::Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; PREFETCH_FIRST_DOWNLOAD_BYTES];
    match stream.try_read(&mut buffer) {
        Ok(0) => Ok(None),
        Ok(read) => {
            buffer.truncate(read);
            Ok(Some(buffer))
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error).context("prefetch immediate remote download"),
    }
}

async fn prefetch_remote_download_with_grace(
    stream: &TcpStream,
    grace: std::time::Duration,
) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(prefetched) = prefetch_immediate_remote_download(stream)? {
        return Ok(Some(prefetched));
    }
    if grace.is_zero() {
        return Ok(None);
    }
    match tokio::time::timeout(grace, stream.readable()).await {
        Ok(Ok(())) => prefetch_immediate_remote_download(stream),
        Ok(Err(error)) => Err(error).context("wait for remote prefetch readability"),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::channel::{
        ChannelReader, InboundMessage, PayloadBuffer, PayloadPool, bounded_inbound_channel,
        test_chunk,
    };
    use super::frame::{
        CMD_PSH, CMD_SYNACK, MAX_FRAME_PAYLOAD_LEN, PayloadTier, download_coalesce_target,
        parse_settings, payload_tier, should_flush_frame, upload_batch_policy,
    };
    use super::io::{
        advance_chunk_batch, chunk_batch_policy, chunk_batch_slices, coalesce_download_reads,
        coalesce_download_reads_without_deferred_wait, pump_copy, write_chunk_batch_for_test,
    };
    use super::{
        SessionState, StreamState, close_peer_stream, forward_buffered_inbound_payload,
        forward_inbound_payload_to_channel, negotiated_peer_version,
        prefetch_remote_download_with_grace, read_exact_payload,
    };
    use crate::accounting::{Accounting, SessionControl};
    use crate::protocols::shared::traffic::TrafficRecorder;
    use std::collections::VecDeque as TestVecDeque;
    use std::io::IoSlice;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{Instant, Sleep};
    struct SegmentedReader {
        segments: TestVecDeque<Vec<u8>>,
    }

    impl SegmentedReader {
        fn new(segments: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                segments: segments.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for SegmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(segment) = self.segments.pop_front() else {
                return Poll::Pending;
            };
            let to_copy = segment.len().min(buf.remaining());
            buf.put_slice(&segment[..to_copy]);
            if to_copy < segment.len() {
                self.segments.push_front(segment[to_copy..].to_vec());
            }
            Poll::Ready(Ok(()))
        }
    }

    struct PendingOnceSegmentedReader {
        segments: TestVecDeque<Vec<u8>>,
        delivered_reads: usize,
        pending_once_after_first_read: bool,
    }

    impl PendingOnceSegmentedReader {
        fn new(segments: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                segments: segments.into_iter().collect(),
                delivered_reads: 0,
                pending_once_after_first_read: true,
            }
        }
    }

    impl AsyncRead for PendingOnceSegmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.delivered_reads > 0 && self.pending_once_after_first_read {
                self.pending_once_after_first_read = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let Some(segment) = self.segments.pop_front() else {
                return Poll::Pending;
            };
            let to_copy = segment.len().min(buf.remaining());
            buf.put_slice(&segment[..to_copy]);
            if to_copy < segment.len() {
                self.segments.push_front(segment[to_copy..].to_vec());
            }
            self.delivered_reads += 1;
            Poll::Ready(Ok(()))
        }
    }

    struct DelayedSegmentedReader {
        segments: TestVecDeque<Vec<u8>>,
        delivered_reads: usize,
        delay: Duration,
        wake: Option<Pin<Box<Sleep>>>,
    }

    impl DelayedSegmentedReader {
        fn new(delay: Duration, segments: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                segments: segments.into_iter().collect(),
                delivered_reads: 0,
                delay,
                wake: None,
            }
        }
    }

    impl AsyncRead for DelayedSegmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.delivered_reads > 0 {
                if self.wake.is_none() {
                    self.wake = Some(Box::pin(tokio::time::sleep_until(
                        Instant::now() + self.delay,
                    )));
                }
                if self
                    .wake
                    .as_mut()
                    .expect("wake timer initialized")
                    .as_mut()
                    .poll(cx)
                    .is_pending()
                {
                    return Poll::Pending;
                }
                self.wake = None;
            }

            let Some(segment) = self.segments.pop_front() else {
                return Poll::Pending;
            };
            let to_copy = segment.len().min(buf.remaining());
            buf.put_slice(&segment[..to_copy]);
            if to_copy < segment.len() {
                self.segments.push_front(segment[to_copy..].to_vec());
            }
            self.delivered_reads += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct WriteModeRecorder {
        scalar_writes: usize,
        vectored_writes: usize,
    }

    impl AsyncWrite for WriteModeRecorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.scalar_writes += 1;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.vectored_writes += 1;
            let written: usize = bufs.iter().map(|buf| buf.len()).sum();
            Poll::Ready(Ok(written))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn parses_settings_lines() {
        let settings = parse_settings(b"v=2\nclient=test");
        assert_eq!(settings.get("v"), Some(&"2".to_string()));
        assert_eq!(settings.get("client"), Some(&"test".to_string()));
    }

    #[test]
    fn negotiates_anytls_v2_for_current_and_future_versions() {
        assert_eq!(negotiated_peer_version(&parse_settings(b"v=1")), 1);
        assert_eq!(negotiated_peer_version(&parse_settings(b"v=2")), 2);
        assert_eq!(negotiated_peer_version(&parse_settings(b"v=300")), 2);
        assert_eq!(negotiated_peer_version(&parse_settings(b"client=test")), 0);
    }

    #[test]
    fn flushes_control_and_small_payload_frames() {
        assert!(should_flush_frame(CMD_SYNACK, 0));
        assert!(should_flush_frame(CMD_PSH, 1024));
        assert!(!should_flush_frame(CMD_PSH, 8192));
    }

    #[test]
    fn classifies_payload_tiers() {
        assert_eq!(payload_tier(512), PayloadTier::Small);
        assert_eq!(payload_tier(8 * 1024), PayloadTier::Medium);
        assert_eq!(payload_tier(32 * 1024), PayloadTier::Large);
    }

    #[test]
    fn derives_size_specific_batch_and_download_policies() {
        let small = upload_batch_policy(512);
        let medium = upload_batch_policy(8 * 1024);
        let large = upload_batch_policy(32 * 1024);
        assert!(small.max_iovecs > medium.max_iovecs);
        assert!(large.max_iovecs < medium.max_iovecs);
        assert!(large.max_bytes > medium.max_bytes);
        assert!(download_coalesce_target(1024).is_some());
        assert!(download_coalesce_target(8 * 1024).is_none());
        #[cfg(not(target_env = "musl"))]
        assert_eq!(
            download_coalesce_target(32 * 1024),
            Some(MAX_FRAME_PAYLOAD_LEN)
        );
    }

    #[test]
    fn caps_frame_payload_to_protocol_limit() {
        assert_eq!(MAX_FRAME_PAYLOAD_LEN, u16::MAX as usize);
    }

    #[tokio::test]
    async fn pump_copy_records_traffic_before_stream_close() {
        let accounting = Accounting::new();
        let control = SessionControl::new();
        let (mut source_reader, mut source_writer) = tokio::io::duplex(64);
        let (mut sink_writer, mut sink_reader) = tokio::io::duplex(64);

        let task = tokio::spawn({
            let control = control.clone();
            let accounting = accounting.clone();
            async move {
                pump_copy(
                    &mut source_reader,
                    &mut sink_writer,
                    control,
                    Some(TrafficRecorder::upload(accounting, 7)),
                    None,
                )
                .await
            }
        });
        source_writer
            .write_all(b"hello")
            .await
            .expect("write source");
        let mut buf = [0u8; 5];
        sink_reader.read_exact(&mut buf).await.expect("read sink");
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(accounting.snapshot_traffic(0).remove(&7), Some([5, 0]));

        drop(source_writer);
        let transferred = task.await.expect("join pump").expect("pump succeeds");
        assert_eq!(transferred, 5);
    }

    #[tokio::test]
    async fn channel_reader_coalesces_multiple_chunks() {
        let (tx, rx) = mpsc::channel(4);
        tx.send(InboundMessage::Data(test_chunk(b"hello")))
            .await
            .expect("send first chunk");
        tx.send(InboundMessage::Data(test_chunk(b"world")))
            .await
            .expect("send second chunk");
        drop(tx);

        let mut reader = ChannelReader::new(rx);
        let mut buf = [0u8; 10];
        reader
            .read_exact(&mut buf)
            .await
            .expect("read combined chunk");
        assert_eq!(&buf, b"helloworld");
    }

    #[tokio::test]
    async fn coalesces_immediately_available_download_reads() {
        let mut reader = SegmentedReader::new([vec![1u8; 1024], vec![2u8; 1024]]);
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) = coalesce_download_reads(&mut reader, &mut buffer, first, 2048)
            .await
            .expect("coalesce available reads");
        assert_eq!(filled, 2048);
        assert!(!saw_eof);
        assert!(buffer[..1024].iter().all(|byte| *byte == 1));
        assert!(buffer[1024..2048].iter().all(|byte| *byte == 2));
    }

    #[tokio::test]
    async fn coalesces_download_reads_after_one_scheduler_yield() {
        let mut reader = PendingOnceSegmentedReader::new([vec![1u8; 1024], vec![2u8; 1024]]);
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) = coalesce_download_reads(&mut reader, &mut buffer, first, 2048)
            .await
            .expect("coalesce deferred read");

        assert_eq!(filled, 2048);
        assert!(!saw_eof);
        assert!(buffer[..1024].iter().all(|byte| *byte == 1));
        assert!(buffer[1024..2048].iter().all(|byte| *byte == 2));
    }

    #[tokio::test]
    async fn coalesces_download_reads_after_brief_delay() {
        let mut reader = DelayedSegmentedReader::new(
            Duration::from_millis(1),
            [vec![1u8; 1024], vec![2u8; 1024]],
        );
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) = coalesce_download_reads(&mut reader, &mut buffer, first, 2048)
            .await
            .expect("coalesce delayed read");

        assert_eq!(filled, 2048);
        assert!(!saw_eof);
        assert!(buffer[..1024].iter().all(|byte| *byte == 1));
        assert!(buffer[1024..2048].iter().all(|byte| *byte == 2));
    }

    #[tokio::test]
    async fn first_download_chunk_skips_deferred_coalesce_wait() {
        let mut reader = DelayedSegmentedReader::new(
            Duration::from_millis(1),
            [vec![1u8; 1024], vec![2u8; 1024]],
        );
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) =
            coalesce_download_reads_without_deferred_wait(&mut reader, &mut buffer, first, 2048)
                .await
                .expect("skip deferred coalesce wait");

        assert_eq!(filled, 1024);
        assert!(!saw_eof);
        assert!(buffer[..1024].iter().all(|byte| *byte == 1));
    }

    #[tokio::test]
    async fn first_download_chunk_still_coalesces_immediately_available_reads() {
        let mut reader = SegmentedReader::new([vec![1u8; 1024], vec![2u8; 1024]]);
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) =
            coalesce_download_reads_without_deferred_wait(&mut reader, &mut buffer, first, 2048)
                .await
                .expect("coalesce immediate read without deferred wait");

        assert_eq!(filled, 2048);
        assert!(!saw_eof);
        assert!(buffer[..1024].iter().all(|byte| *byte == 1));
        assert!(buffer[1024..2048].iter().all(|byte| *byte == 2));
    }

    #[tokio::test]
    async fn prefetch_remote_download_with_grace_captures_prompt_data() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(2)).await;
            stream.write_all(b"hello").await.expect("write payload");
        });

        let stream = TcpStream::connect(addr).await.expect("connect stream");
        let prefetched = prefetch_remote_download_with_grace(&stream, Duration::from_millis(20))
            .await
            .expect("prefetch with grace");

        server.await.expect("join server");
        assert_eq!(prefetched.as_deref(), Some(&b"hello"[..]));
    }

    #[tokio::test]
    async fn prefetch_remote_download_with_grace_times_out_without_data() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(30)).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connect stream");
        let started = Instant::now();
        let prefetched = prefetch_remote_download_with_grace(&stream, Duration::from_millis(5))
            .await
            .expect("prefetch without data");

        server.await.expect("join server");
        assert!(prefetched.is_none());
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn coalesces_immediately_available_large_download_reads_without_waiting() {
        let mut reader = SegmentedReader::new([vec![1u8; 32 * 1024], vec![2u8; 24 * 1024]]);
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..32 * 1024])
            .await
            .expect("read first large chunk");
        assert_eq!(first, 32 * 1024);

        let target = download_coalesce_target(first).expect("large reads should coalesce");
        let (filled, saw_eof) = coalesce_download_reads(&mut reader, &mut buffer, first, target)
            .await
            .expect("coalesce immediate large read");

        assert_eq!(filled, 56 * 1024);
        assert!(!saw_eof);
        assert!(buffer[..32 * 1024].iter().all(|byte| *byte == 1));
        assert!(buffer[32 * 1024..56 * 1024].iter().all(|byte| *byte == 2));
    }

    #[tokio::test]
    async fn coalescing_download_reads_does_not_wait_when_no_more_data_arrives() {
        let mut reader = SegmentedReader::new([vec![7u8; 1024]]);
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) = tokio::time::timeout(
            Duration::from_millis(50),
            coalesce_download_reads(&mut reader, &mut buffer, first, 2048),
        )
        .await
        .expect("coalesce should return without blocking")
        .expect("coalesce result");

        assert_eq!(filled, 1024);
        assert!(!saw_eof);
    }

    #[tokio::test]
    async fn reads_psh_payload_into_pooled_buffer_without_presizing_len() {
        let pool = Arc::new(PayloadPool::new(1));
        let mut payload = pool.take(16);
        assert_eq!(payload.len(), 0);

        let mut reader = SegmentedReader::new([b"hel".to_vec(), b"lo".to_vec()]);
        read_exact_payload(&mut reader, &mut payload, 5)
            .await
            .expect("read pooled payload");
        assert_eq!(payload.as_slice(), b"hello");
    }

    #[tokio::test]
    async fn keeps_whole_buffered_payload_when_queue_has_budget() {
        let payload_len = 48 * 1024;
        let (inbound, mut rx) = bounded_inbound_channel(8, payload_len * 2);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);

        forward_buffered_inbound_payload(&inbound, control, payload)
            .await
            .expect("forward buffered payload");

        let first = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("payload should arrive")
            .expect("inbound message");
        let InboundMessage::Data(first) = first;
        assert_eq!(first.len(), payload_len);
        assert!(first.bytes().iter().all(|byte| *byte == 7));
    }

    #[tokio::test]
    async fn closed_inbound_channel_surfaces_error_for_whole_payload_forwarding() {
        let payload_len = 48 * 1024;
        let (inbound, rx) = bounded_inbound_channel(8, payload_len * 2);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);
        drop(rx);

        let error = forward_buffered_inbound_payload(&inbound, control, payload)
            .await
            .expect_err("closed inbound channel should fail");
        assert!(
            error
                .to_string()
                .contains("inbound channel closed before data could be delivered")
        );
    }

    #[tokio::test]
    async fn large_inbound_payload_keeps_whole_when_queue_has_budget() {
        let payload_len = 48 * 1024;
        let (inbound, mut rx) = bounded_inbound_channel(8, payload_len * 2);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);

        forward_inbound_payload_to_channel(&inbound, &control, payload)
            .await
            .expect("forward inbound payload");

        let first = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("payload should arrive")
            .expect("inbound message");
        let InboundMessage::Data(first) = first;
        assert_eq!(first.len(), payload_len);
        assert!(first.bytes().iter().all(|byte| *byte == 7));
    }

    #[tokio::test]
    async fn large_inbound_payload_waits_for_whole_forwarding_under_backpressure() {
        let payload_len = 48 * 1024;
        let first_payload_len = 64 * 1024;
        let budget_len = 64 * 1024;
        let (inbound, mut rx) = bounded_inbound_channel(8, budget_len);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);

        inbound
            .try_send_data(PayloadBuffer::new(vec![3u8; first_payload_len]))
            .expect("fill queue budget with first payload");

        let forward_task = tokio::spawn({
            let inbound = inbound.clone();
            let control = control.clone();
            async move { forward_inbound_payload_to_channel(&inbound, &control, payload).await }
        });
        tokio::task::yield_now().await;

        let first = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("first queued payload should arrive")
            .expect("first inbound message");
        let InboundMessage::Data(first) = first;
        assert_eq!(first.len(), first_payload_len);
        drop(first);

        let second = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("whole payload should arrive once budget is released")
            .expect("second inbound message");
        let InboundMessage::Data(second) = second;
        assert_eq!(second.len(), payload_len);
        assert!(second.bytes().iter().all(|byte| *byte == 7));

        forward_task
            .await
            .expect("join forward task")
            .expect("forward inbound payload");
    }

    #[tokio::test]
    async fn closed_inbound_channel_surfaces_error_while_waiting_for_whole_payload() {
        let payload_len = 48 * 1024;
        let first_payload_len = 64 * 1024;
        let (inbound, rx) = bounded_inbound_channel(8, first_payload_len);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);

        inbound
            .try_send_data(PayloadBuffer::new(vec![3u8; first_payload_len]))
            .expect("fill queue budget with first payload");

        let forward_task = tokio::spawn({
            let inbound = inbound.clone();
            let control = control.clone();
            async move { forward_buffered_inbound_payload(&inbound, control, payload).await }
        });
        tokio::task::yield_now().await;
        drop(rx);

        let error = forward_task
            .await
            .expect("join forward task")
            .expect_err("closed inbound channel should fail");
        assert!(
            error
                .to_string()
                .contains("inbound channel closed before data could be delivered")
        );
    }

    #[tokio::test]
    async fn backpressured_whole_payload_waits_for_single_delivery() {
        let payload_len = 48 * 1024;
        let first_payload_len = 64 * 1024;
        let budget_len = 64 * 1024;
        let (inbound, mut rx) = bounded_inbound_channel(8, budget_len);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);

        inbound
            .try_send_data(PayloadBuffer::new(vec![3u8; first_payload_len]))
            .expect("fill queue budget with first payload");

        let forward_task = tokio::spawn({
            let inbound = inbound.clone();
            let control = control.clone();
            async move { forward_buffered_inbound_payload(&inbound, control, payload).await }
        });
        tokio::task::yield_now().await;

        let first = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("first queued payload should arrive")
            .expect("first inbound message");
        let InboundMessage::Data(first) = first;
        assert_eq!(first.len(), first_payload_len);
        assert!(first.bytes().iter().all(|byte| *byte == 3));

        drop(first);

        let second = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("whole payload should arrive")
            .expect("second inbound message");
        let InboundMessage::Data(second) = second;
        assert_eq!(second.len(), payload_len);
        assert!(second.bytes().iter().all(|byte| *byte == 7));

        forward_task
            .await
            .expect("join forward task")
            .expect("forward buffered payload");
    }

    #[tokio::test]
    async fn transient_backpressure_gets_one_whole_payload_retry() {
        let payload_len = 48 * 1024;
        let first_payload_len = 52 * 1024;
        let budget_len = 64 * 1024;
        let (inbound, mut rx) = bounded_inbound_channel(8, budget_len);
        let control = SessionControl::new();
        let payload = PayloadBuffer::new(vec![7u8; payload_len]);

        inbound
            .try_send_data(PayloadBuffer::new(vec![3u8; first_payload_len]))
            .expect("fill queue budget with first payload");

        let forward_task = tokio::spawn({
            let inbound = inbound.clone();
            let control = control.clone();
            async move { forward_buffered_inbound_payload(&inbound, control, payload).await }
        });
        tokio::task::yield_now().await;

        let first = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("first queued payload should arrive")
            .expect("first inbound message");
        let InboundMessage::Data(first) = first;
        assert_eq!(first.len(), first_payload_len);
        drop(first);

        let second = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("whole payload should arrive after grace retry")
            .expect("second inbound message");
        let InboundMessage::Data(second) = second;
        assert_eq!(second.len(), payload_len);
        assert!(second.bytes().iter().all(|byte| *byte == 7));

        forward_task
            .await
            .expect("join forward task")
            .expect("forward buffered payload");
    }

    #[test]
    fn advance_chunk_batch_handles_partial_write() {
        let mut chunks =
            std::collections::VecDeque::from([test_chunk(b"hello"), test_chunk(b"world")]);
        let mut front_offset = 0;
        advance_chunk_batch(&mut chunks, &mut front_offset, 7);
        assert_eq!(chunks.len(), 1);
        assert_eq!(front_offset, 2);
        assert_eq!(chunks.front().expect("remaining chunk").bytes(), b"world");
    }

    #[tokio::test]
    async fn advance_chunk_batch_releases_consumed_chunk_budget() {
        let (sender, mut rx) = bounded_inbound_channel(8, 8);
        sender
            .try_send_data(PayloadBuffer::new(vec![1; 4]))
            .expect("send first chunk");
        sender
            .try_send_data(PayloadBuffer::new(vec![2; 4]))
            .expect("send second chunk");

        let first = match rx.recv().await.expect("receive first chunk") {
            InboundMessage::Data(chunk) => chunk,
        };
        let second = match rx.recv().await.expect("receive second chunk") {
            InboundMessage::Data(chunk) => chunk,
        };
        let mut chunks = std::collections::VecDeque::from([first, second]);
        let mut front_offset = 0usize;

        advance_chunk_batch(&mut chunks, &mut front_offset, 4);

        assert_eq!(chunks.len(), 1);
        assert_eq!(front_offset, 0);
        assert!(
            sender.try_send_data(PayloadBuffer::new(vec![3; 4])).is_ok(),
            "released chunk budget should be reusable immediately"
        );
    }

    #[tokio::test]
    async fn advance_chunk_batch_keeps_partial_chunk_budget_reserved() {
        let (sender, mut rx) = bounded_inbound_channel(8, 8);
        sender
            .try_send_data(PayloadBuffer::new(vec![1; 4]))
            .expect("send first chunk");
        sender
            .try_send_data(PayloadBuffer::new(vec![2; 4]))
            .expect("send second chunk");

        let first = match rx.recv().await.expect("receive first chunk") {
            InboundMessage::Data(chunk) => chunk,
        };
        let second = match rx.recv().await.expect("receive second chunk") {
            InboundMessage::Data(chunk) => chunk,
        };
        let mut chunks = std::collections::VecDeque::from([first, second]);
        let mut front_offset = 0usize;

        advance_chunk_batch(&mut chunks, &mut front_offset, 5);

        assert_eq!(chunks.len(), 1);
        assert_eq!(front_offset, 1);
        assert!(
            sender.try_send_data(PayloadBuffer::new(vec![3; 4])).is_ok(),
            "partially written bytes should release matching budget immediately"
        );
        assert!(
            sender
                .try_send_data(PayloadBuffer::new(vec![4; 2]))
                .is_err(),
            "the unread tail of the partially consumed chunk must stay reserved"
        );
    }

    #[tokio::test]
    async fn peer_fin_removes_stream_from_state() {
        let state = Arc::new(SessionState::default());
        let task = tokio::spawn(async move { std::future::pending::<()>().await });
        state
            .streams
            .write()
            .expect("streams lock poisoned")
            .insert(
                7,
                StreamState {
                    inbound: None,
                    task,
                },
            );

        close_peer_stream(&state, 7);

        assert!(
            !state
                .streams
                .read()
                .expect("streams lock poisoned")
                .contains_key(&7)
        );
    }

    #[test]
    fn chunk_batch_slices_respects_front_offset() {
        let chunks = std::collections::VecDeque::from([test_chunk(b"hello"), test_chunk(b"world")]);
        let slices = chunk_batch_slices(&chunks, 2, upload_batch_policy(5));
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].len(), 3);
        assert_eq!(slices[1].len(), 5);
    }

    #[test]
    fn partial_front_write_preserves_large_upload_batch_policy() {
        let large = vec![7u8; 32 * 1024];
        let chunks = std::collections::VecDeque::from([
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
            test_chunk(&large),
        ]);
        let policy = chunk_batch_policy(&chunks, 31 * 1024);
        let slices = chunk_batch_slices(&chunks, 31 * 1024, policy);
        let total: usize = slices.iter().map(|slice| slice.len()).sum();

        assert_eq!(policy.max_bytes, upload_batch_policy(large.len()).max_bytes);
        assert_eq!(
            policy.max_iovecs,
            upload_batch_policy(large.len()).max_iovecs
        );
        assert_eq!(total, policy.max_bytes);
    }

    #[test]
    fn tiny_front_chunk_does_not_downgrade_large_upload_batch_policy() {
        let tiny = vec![1u8; 512];
        let large = vec![7u8; 32 * 1024];
        let chunks = std::collections::VecDeque::from([test_chunk(&tiny), test_chunk(&large)]);
        let policy = chunk_batch_policy(&chunks, 0);

        assert_eq!(policy.max_bytes, upload_batch_policy(large.len()).max_bytes);
        assert_eq!(
            policy.max_iovecs,
            upload_batch_policy(large.len()).max_iovecs
        );
    }

    #[cfg(not(target_env = "musl"))]
    #[tokio::test]
    async fn single_chunk_upload_batch_uses_scalar_write_fast_path() {
        let chunks = std::collections::VecDeque::from([test_chunk(b"hello")]);
        let mut writer = WriteModeRecorder::default();

        let written = write_chunk_batch_for_test(&mut writer, &chunks, 0, upload_batch_policy(5))
            .await
            .expect("write single chunk batch");

        assert_eq!(written, 5);
        assert_eq!(writer.scalar_writes, 1);
        assert_eq!(writer.vectored_writes, 0);
    }

    #[cfg(not(target_env = "musl"))]
    #[tokio::test]
    async fn tiny_multi_chunk_upload_batch_uses_inline_scalar_write() {
        let chunks = std::collections::VecDeque::from([test_chunk(b"he"), test_chunk(b"llo")]);
        let mut writer = WriteModeRecorder::default();

        let written = write_chunk_batch_for_test(&mut writer, &chunks, 0, upload_batch_policy(5))
            .await
            .expect("write tiny multi chunk batch");

        assert_eq!(written, 5);
        assert_eq!(writer.scalar_writes, 1);
        assert_eq!(writer.vectored_writes, 0);
    }

    #[tokio::test]
    async fn large_single_chunk_upload_batch_keeps_vectored_write_path() {
        let payload = vec![7u8; 32 * 1024];
        let chunks = std::collections::VecDeque::from([test_chunk(&payload)]);
        let mut writer = WriteModeRecorder::default();

        let written =
            write_chunk_batch_for_test(&mut writer, &chunks, 0, upload_batch_policy(payload.len()))
                .await
                .expect("write large single chunk batch");

        assert_eq!(written, payload.len());
        assert_eq!(writer.scalar_writes, 0);
        assert_eq!(writer.vectored_writes, 1);
    }
}
