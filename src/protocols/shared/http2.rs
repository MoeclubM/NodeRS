use anyhow::{Context as _, anyhow, ensure};
use bytes::{Buf as _, Bytes};
use futures_util::future::poll_fn;
use serde_json::Value;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::task::JoinHandle;
use tracing::warn;

use super::http1::{normalize_host, normalize_path, parse_hosts};

const PIPE_CAPACITY: usize = 64 * 1024;
const COPY_BUFFER_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct H2Config {
    pub path: String,
    pub hosts: Vec<String>,
    pub headers: Vec<(String, String)>,
}

impl Default for H2Config {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            hosts: Vec::new(),
            headers: Vec::new(),
        }
    }
}

impl H2Config {
    pub fn from_network_settings(value: Option<&Value>) -> anyhow::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("HTTP/2 networkSettings must be an object"))?;
        let path = normalize_path(
            object
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .trim(),
        );
        let hosts = parse_hosts(object.get("host"))?;
        let headers = parse_response_headers(object.get("headers"))?;
        Ok(Self {
            path,
            hosts,
            headers,
        })
    }

    fn matches_path(&self, request_path: &str) -> bool {
        let request_path = normalize_path(request_path.trim());
        self.path == "/" || request_path.starts_with(&self.path)
    }

    fn matches_host(&self, request_host: &str) -> bool {
        self.hosts.is_empty()
            || self
                .hosts
                .iter()
                .any(|expected| expected == &normalize_host(request_host))
    }
}

pub struct H2Stream {
    reader: DuplexStream,
    writer: DuplexStream,
    _request_task: JoinHandle<anyhow::Result<()>>,
    _response_task: JoinHandle<anyhow::Result<()>>,
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Stream {
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
    config: H2Config,
    on_stream: std::sync::Arc<dyn Fn(H2Stream) + Send + Sync>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream)
        .await
        .context("accept HTTP/2 transport connection")?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result.context("accept HTTP/2 transport request")?;
        let config = config.clone();
        let on_stream = on_stream.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_h2_request(request, respond, config, on_stream).await {
                warn!(%error, "HTTP/2 transport request failed");
            }
        });
    }
    Ok(())
}

async fn handle_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: H2Config,
    on_stream: std::sync::Arc<dyn Fn(H2Stream) + Send + Sync>,
) -> anyhow::Result<()> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let host = parts
        .uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or_default();
    if !config.matches_host(host) || !config.matches_path(path) {
        respond_empty_status(&mut respond, 404).await?;
        return Ok(());
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
        let result = pump_response(respond, response_source, config).await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    on_stream(H2Stream {
        reader,
        writer,
        _request_task: request_task,
        _response_task: response_task,
    });
    Ok(())
}

async fn pump_request<R>(mut reader: R, mut sink: DuplexStream) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    tokio::io::copy(&mut reader, &mut sink)
        .await
        .context("copy HTTP/2 request body")?;
    sink.shutdown().await.ok();
    Ok(())
}

async fn pump_response(
    mut respond: h2::server::SendResponse<Bytes>,
    mut response_source: DuplexStream,
    config: H2Config,
) -> anyhow::Result<()> {
    let mut sender = send_response_head(&mut respond, &config)?;
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = response_source
            .read(&mut buffer)
            .await
            .context("read payload for HTTP/2 response")?;
        if read == 0 {
            send_h2_data(&mut sender, Bytes::new(), true)
                .await
                .context("finish HTTP/2 response body")?;
            return Ok(());
        }
        send_h2_data(&mut sender, Bytes::copy_from_slice(&buffer[..read]), false)
            .await
            .context("write HTTP/2 response body")?;
    }
}

fn send_response_head(
    respond: &mut h2::server::SendResponse<Bytes>,
    config: &H2Config,
) -> anyhow::Result<h2::SendStream<Bytes>> {
    let mut builder = http::Response::builder()
        .status(200)
        .header("cache-control", "no-store");
    for (name, value) in &config.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let response = builder
        .body(())
        .context("build HTTP/2 transport response")?;
    respond
        .send_response(response, false)
        .context("write HTTP/2 transport response headers")
}

async fn respond_empty_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: u16,
) -> anyhow::Result<()> {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .with_context(|| format!("build HTTP/2 {status} response"))?;
    respond
        .send_response(response, true)
        .with_context(|| format!("write HTTP/2 {status} response"))?;
    Ok(())
}

async fn send_h2_data(
    sender: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_of_stream: bool,
) -> anyhow::Result<()> {
    if data.is_empty() {
        sender
            .send_data(data, end_of_stream)
            .context("write empty HTTP/2 data frame")?;
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < data.len() {
        sender.reserve_capacity(data.len() - offset);
        let capacity = poll_fn(|cx| sender.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("HTTP/2 response stream closed"))?
            .context("reserve HTTP/2 response capacity")?;
        if capacity == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        let take = capacity.min(data.len() - offset);
        let end = end_of_stream && offset + take == data.len();
        sender
            .send_data(data.slice(offset..offset + take), end)
            .context("write HTTP/2 data frame")?;
        offset += take;
    }
    Ok(())
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

fn parse_response_headers(value: Option<&Value>) -> anyhow::Result<Vec<(String, String)>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("HTTP/2 headers must be an object"))?;
    let mut headers = Vec::new();
    for (name, value) in object {
        ensure!(!name.trim().is_empty(), "HTTP/2 header name is required");
        match value {
            Value::String(text) => headers.push((name.trim().to_string(), text.trim().to_string())),
            Value::Array(values) => {
                for value in values {
                    let text = value
                        .as_str()
                        .ok_or_else(|| anyhow!("HTTP/2 header values must be strings"))?;
                    headers.push((name.trim().to_string(), text.trim().to_string()));
                }
            }
            _ => return Err(anyhow!("HTTP/2 header values must be strings")),
        }
    }
    Ok(headers)
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
    fn parses_http2_network_settings() {
        let config = H2Config::from_network_settings(Some(&serde_json::json!({
            "path": "h2",
            "host": ["example.com:443", "cdn.example.com"],
            "headers": {
                "X-Service": "noders"
            }
        })))
        .expect("parse config");

        assert_eq!(config.path, "/h2");
        assert_eq!(
            config.hosts,
            vec!["example.com".to_string(), "cdn.example.com".to_string()]
        );
        assert_eq!(
            config.headers,
            vec![("X-Service".to_string(), "noders".to_string())]
        );
    }

    #[test]
    fn matches_http2_path_prefix() {
        let config = H2Config::from_network_settings(Some(&serde_json::json!({
            "path": "/h2"
        })))
        .expect("parse config");

        assert!(config.matches_path("/h2"));
        assert!(config.matches_path("/h2/stream"));
        assert!(!config.matches_path("/other"));
    }
}
