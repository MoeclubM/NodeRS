use anyhow::{Context as _, anyhow, ensure};
use bytes::{Buf as _, Bytes};
use futures_util::future::poll_fn;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::task::JoinHandle;
use tracing::warn;

const PIPE_CAPACITY: usize = 64 * 1024;
const COPY_BUFFER_LEN: usize = 16 * 1024;
const PATH_ESCAPE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcConfig {
    pub service_name: String,
    pub service_path: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self::from_service_name("GunService")
    }
}

impl GrpcConfig {
    pub fn from_network_settings(value: Option<&Value>) -> anyhow::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("gRPC networkSettings must be an object"))?;
        let service_name = object
            .get("serviceName")
            .or_else(|| object.get("service_name"))
            .and_then(Value::as_str)
            .unwrap_or("GunService")
            .trim();
        ensure!(!service_name.is_empty(), "gRPC serviceName is required");
        Ok(Self::from_service_name(service_name))
    }

    fn from_service_name(service_name: &str) -> Self {
        let compact = service_name.trim();
        let service_path = service_path(compact);
        Self {
            service_name: compact.to_string(),
            service_path,
        }
    }

    fn matches_path(&self, request_path: &str) -> bool {
        request_path.trim() == self.service_path
    }
}

pub struct GrpcStream {
    reader: DuplexStream,
    writer: DuplexStream,
    _request_task: JoinHandle<anyhow::Result<()>>,
    _response_task: JoinHandle<anyhow::Result<()>>,
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for GrpcStream {
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

pub async fn serve_h2<S>(
    stream: S,
    config: GrpcConfig,
    on_stream: std::sync::Arc<dyn Fn(GrpcStream) + Send + Sync>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream)
        .await
        .context("accept VLESS gRPC h2 connection")?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result.context("accept VLESS gRPC request")?;
        let config = config.clone();
        let on_stream = on_stream.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_h2_request(request, respond, config, on_stream).await {
                warn!(%error, "VLESS gRPC request failed");
            }
        });
    }
    Ok(())
}

async fn handle_h2_request(
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    config: GrpcConfig,
    on_stream: std::sync::Arc<dyn Fn(GrpcStream) + Send + Sync>,
) -> anyhow::Result<()> {
    let (parts, body) = request.into_parts();
    if let Err(error) = validate_request(&parts, &config) {
        let status = match error.to_string().as_str() {
            text if text.contains("method") => 405,
            text if text.contains("content-type") => 400,
            _ => 404,
        };
        return respond_error(respond, status, Some(error.to_string())).await;
    }

    let (request_sink, reader) = duplex(PIPE_CAPACITY);
    let (writer, response_source) = duplex(PIPE_CAPACITY);

    let request_task = tokio::spawn(async move {
        let result = pump_request(H2BodyReader::new(body), request_sink).await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    let response_task = tokio::spawn(async move {
        let result = pump_response(respond, response_source).await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    on_stream(GrpcStream {
        reader,
        writer,
        _request_task: request_task,
        _response_task: response_task,
    });
    Ok(())
}

fn validate_request(parts: &http::request::Parts, config: &GrpcConfig) -> anyhow::Result<()> {
    ensure!(
        parts.method == http::Method::POST,
        "gRPC method must be POST"
    );
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.path())
        .unwrap_or("/");
    ensure!(config.matches_path(path), "unexpected gRPC path {path}");

    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    ensure!(
        content_type.eq_ignore_ascii_case("application/grpc")
            || content_type
                .to_ascii_lowercase()
                .starts_with("application/grpc+"),
        "invalid gRPC content-type {content_type}"
    );
    Ok(())
}

async fn respond_error(
    mut respond: h2::server::SendResponse<Bytes>,
    status: u16,
    grpc_message: Option<String>,
) -> anyhow::Result<()> {
    let builder = http::Response::builder()
        .status(status)
        .header("content-type", "application/grpc")
        .header("trailer", "grpc-status, grpc-message");
    let response = builder
        .body(())
        .with_context(|| format!("build VLESS gRPC {status} response"))?;
    let mut sender = respond
        .send_response(response, false)
        .with_context(|| format!("write VLESS gRPC {status} response"))?;
    send_grpc_trailers(
        &mut sender,
        status_to_grpc_status(status),
        grpc_message.as_deref(),
    )
    .await?;
    Ok(())
}

async fn pump_request<R>(mut reader: R, mut sink: DuplexStream) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(payload) = read_grpc_frame(&mut reader).await? else {
            sink.shutdown().await.ok();
            return Ok(());
        };
        sink.write_all(&payload)
            .await
            .context("write gRPC payload into VLESS pipe")?;
    }
}

async fn pump_response(
    mut respond: h2::server::SendResponse<Bytes>,
    mut response_source: DuplexStream,
) -> anyhow::Result<()> {
    let mut sender = send_response_head(&mut respond)?;
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = response_source
            .read(&mut buffer)
            .await
            .context("read VLESS payload for gRPC response")?;
        if read == 0 {
            send_grpc_trailers(&mut sender, "0", None)
                .await
                .context("write VLESS gRPC response trailer")?;
            return Ok(());
        }
        let payload = encode_grpc_frame(&buffer[..read]);
        send_grpc_data(&mut sender, payload, false)
            .await
            .context("write VLESS gRPC response payload")?;
    }
}

fn send_response_head(
    respond: &mut h2::server::SendResponse<Bytes>,
) -> anyhow::Result<h2::SendStream<Bytes>> {
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("trailer", "grpc-status, grpc-message")
        .body(())
        .context("build VLESS gRPC response")?;
    respond
        .send_response(response, false)
        .context("write VLESS gRPC response headers")
}

async fn send_grpc_data(
    sender: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_of_stream: bool,
) -> anyhow::Result<()> {
    if data.is_empty() {
        sender
            .send_data(data, end_of_stream)
            .context("write empty VLESS gRPC data frame")?;
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < data.len() {
        sender.reserve_capacity(data.len() - offset);
        let capacity = poll_fn(|cx| sender.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("VLESS gRPC response stream closed"))?
            .context("reserve VLESS gRPC response capacity")?;
        if capacity == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        let take = capacity.min(data.len() - offset);
        let end = end_of_stream && offset + take == data.len();
        sender
            .send_data(data.slice(offset..offset + take), end)
            .context("write VLESS gRPC data frame")?;
        offset += take;
    }
    Ok(())
}

async fn send_grpc_trailers(
    sender: &mut h2::SendStream<Bytes>,
    grpc_status: &str,
    grpc_message: Option<&str>,
) -> anyhow::Result<()> {
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "grpc-status",
        http::HeaderValue::from_str(grpc_status).context("encode gRPC status trailer")?,
    );
    if let Some(message) = grpc_message.filter(|value| !value.is_empty()) {
        trailers.insert(
            "grpc-message",
            http::HeaderValue::from_str(message).context("encode gRPC message trailer")?,
        );
    }
    sender
        .send_trailers(trailers)
        .context("write gRPC trailers")?;
    Ok(())
}

async fn read_grpc_frame<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read gRPC frame header"),
    }

    ensure!(header[0] == 0, "compressed gRPC messages are not supported");
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut message = vec![0u8; length];
    reader
        .read_exact(&mut message)
        .await
        .context("read gRPC frame payload")?;

    let mut cursor = 0usize;
    let key = read_varint(&message, &mut cursor).context("read gRPC hunk field key")?;
    ensure!(key == 0x0a, "unsupported gRPC hunk field key {key:#x}");
    let data_len = read_varint(&message, &mut cursor).context("read gRPC hunk length")?;
    let data_len = usize::try_from(data_len).context("gRPC hunk length does not fit usize")?;
    ensure!(
        cursor + data_len == message.len(),
        "invalid gRPC hunk payload length"
    );
    Ok(Some(message[cursor..cursor + data_len].to_vec()))
}

fn encode_grpc_frame(payload: &[u8]) -> Bytes {
    let mut message = Vec::with_capacity(payload.len() + 8);
    message.push(0x0a);
    write_varint(payload.len() as u64, &mut message);
    message.extend_from_slice(payload);

    let mut frame = Vec::with_capacity(message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> anyhow::Result<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        ensure!(*cursor < bytes.len(), "truncated gRPC varint");
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        ensure!(shift < 64, "gRPC varint is too large");
    }
}

fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn service_path(service_name: &str) -> String {
    if !service_name.starts_with('/') {
        let service = utf8_percent_encode(service_name, &PATH_ESCAPE_SET).to_string();
        return format!("/{service}/Tun");
    }

    let raw_last_index = service_name.rfind('/').unwrap_or(0);
    let last_index = raw_last_index.max(1);
    let raw_service = &service_name[1..last_index];
    let mut service = String::new();
    for part in raw_service.split('/') {
        if !service.is_empty() {
            service.push('/');
        }
        service.push_str(&utf8_percent_encode(part, &PATH_ESCAPE_SET).to_string());
    }

    let ending = &service_name[raw_last_index + 1..];
    let stream = ending.split('|').next().unwrap_or("Tun");
    let stream = utf8_percent_encode(stream, &PATH_ESCAPE_SET).to_string();
    format!("/{service}/{stream}")
}

fn status_to_grpc_status(status: u16) -> &'static str {
    match status {
        400 => "3",
        404 => "12",
        405 => "12",
        _ => "13",
    }
}

struct H2BodyReader {
    body: h2::RecvStream,
    current: Option<Bytes>,
}

impl Unpin for H2BodyReader {}

impl H2BodyReader {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            current: None,
        }
    }
}

impl AsyncRead for H2BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(current) = self.current.as_mut() {
                let take = current.len().min(buf.remaining());
                buf.put_slice(&current[..take]);
                current.advance(take);
                if current.is_empty() {
                    self.current = None;
                }
                return Poll::Ready(Ok(()));
            }

            match self.body.poll_data(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = self.body.flow_control().release_capacity(bytes.len());
                    if bytes.is_empty() {
                        continue;
                    }
                    self.current = Some(bytes);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| {
                error.kind() == std::io::ErrorKind::BrokenPipe
                    || error.kind() == std::io::ErrorKind::ConnectionReset
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_grpc_network_settings() {
        let config = GrpcConfig::from_network_settings(Some(&serde_json::json!({
            "serviceName": "TunService"
        })))
        .expect("parse config");
        assert_eq!(config.service_name, "TunService");
        assert_eq!(config.service_path, "/TunService/Tun");
    }

    #[test]
    fn supports_custom_xray_style_service_paths() {
        let config = GrpcConfig::from_network_settings(Some(&serde_json::json!({
            "service_name": "/my/service/Tun|TunMulti"
        })))
        .expect("parse config");
        assert_eq!(config.service_path, "/my/service/Tun");
    }

    #[test]
    fn encodes_and_decodes_grpc_hunk_frames() {
        let encoded = encode_grpc_frame(b"hello");
        let mut slice = encoded.as_ref();
        let decoded = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async { read_grpc_frame(&mut slice).await })
            .expect("decode")
            .expect("frame");
        assert_eq!(decoded, b"hello");
    }
}
