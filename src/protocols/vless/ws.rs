use anyhow::{Context as _, anyhow, bail};
use base64::Engine as _;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message, protocol::Role};

use super::http1::{PrefixedIo, normalize_path, parse_hosts, read_request_head, respond_status};

const PIPE_CAPACITY: usize = 64 * 1024;
const COPY_BUFFER_LEN: usize = 16 * 1024;
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, PartialEq)]
pub struct WsConfig {
    pub path: String,
    pub hosts: Vec<String>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            hosts: Vec::new(),
        }
    }
}

impl WsConfig {
    pub fn from_network_settings(value: Option<&Value>) -> anyhow::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("WebSocket networkSettings must be an object"))?;
        let path = normalize_path(
            object
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .trim(),
        );
        let hosts = match object.get("headers").and_then(Value::as_object) {
            Some(headers) => parse_hosts(headers.get("Host"))?,
            None => parse_hosts(object.get("host"))?,
        };
        Ok(Self { path, hosts })
    }

    fn matches_path(&self, request_path: &str) -> bool {
        let request_path = normalize_path(request_path.trim());
        self.path == "/" || request_path == self.path
    }

    fn matches_host(&self, request_host: &str) -> bool {
        self.hosts.is_empty()
            || self
                .hosts
                .iter()
                .any(|expected| expected == &super::http1::normalize_host(request_host))
    }
}

pub struct WsStream {
    reader: DuplexStream,
    writer: DuplexStream,
    _request_task: JoinHandle<anyhow::Result<()>>,
    _response_task: JoinHandle<anyhow::Result<()>>,
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsStream {
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

pub async fn accept<S>(mut stream: S, config: &WsConfig) -> anyhow::Result<Option<WsStream>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let parsed = match read_request_head(&mut stream).await {
        Ok(parsed) => parsed,
        Err(_) => {
            respond_status(&mut stream, None, 400, "Bad Request").await?;
            return Ok(None);
        }
    };

    if !parsed.request.method.eq_ignore_ascii_case("GET") {
        respond_status(
            &mut stream,
            Some(&parsed.request),
            405,
            "Method Not Allowed",
        )
        .await?;
        return Ok(None);
    }
    if !config.matches_host(&parsed.request.host) || !config.matches_path(&parsed.request.path) {
        respond_status(&mut stream, Some(&parsed.request), 404, "Not Found").await?;
        return Ok(None);
    }
    if !has_token(parsed.request.header("Connection"), "upgrade")
        || !matches_header_value(parsed.request.header("Upgrade"), "websocket")
    {
        respond_status(&mut stream, Some(&parsed.request), 400, "Bad Request").await?;
        return Ok(None);
    }
    if !matches_header_value(parsed.request.header("Sec-WebSocket-Version"), "13") {
        respond_status(&mut stream, Some(&parsed.request), 426, "Upgrade Required").await?;
        return Ok(None);
    }
    let key = parsed
        .request
        .header("Sec-WebSocket-Key")
        .ok_or_else(|| anyhow!("missing Sec-WebSocket-Key"))?;

    let accept_key = websocket_accept_key(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write WebSocket upgrade response")?;

    let prefixed = PrefixedIo::new(stream, parsed.buffered_body);
    let websocket = WebSocketStream::from_raw_socket(prefixed, Role::Server, None).await;
    let (request_sink, reader) = duplex(PIPE_CAPACITY);
    let (writer, response_source) = duplex(PIPE_CAPACITY);
    let (socket_writer, socket_reader) = websocket.split();

    let request_task = tokio::spawn(async move {
        let result = pump_request(socket_reader, request_sink).await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_closed_error(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });
    let response_task = tokio::spawn(async move {
        let result = pump_response(socket_writer, response_source).await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_closed_error(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    Ok(Some(WsStream {
        reader,
        writer,
        _request_task: request_task,
        _response_task: response_task,
    }))
}

async fn pump_request<S>(
    mut reader: SplitStream<WebSocketStream<PrefixedIo<S>>>,
    mut sink: DuplexStream,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(message) = reader.next().await {
        match message.context("read WebSocket frame")? {
            Message::Binary(payload) => sink
                .write_all(payload.as_ref())
                .await
                .context("write WebSocket payload into VLESS pipe")?,
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => break,
            Message::Text(_) => bail!("WebSocket text frames are not supported"),
            Message::Frame(_) => {}
        }
    }
    sink.shutdown().await.ok();
    Ok(())
}

async fn pump_response<S>(
    mut writer: SplitSink<WebSocketStream<PrefixedIo<S>>, Message>,
    mut response_source: DuplexStream,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = response_source
            .read(&mut buffer)
            .await
            .context("read VLESS payload for WebSocket response")?;
        if read == 0 {
            writer.close().await.ok();
            return Ok(());
        }
        writer
            .send(Message::Binary(buffer[..read].to_vec().into()))
            .await
            .context("write WebSocket binary frame")?;
    }
}

fn websocket_accept_key(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.trim().as_bytes());
    sha1.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

fn matches_header_value(value: Option<&str>, expected: &str) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn has_token(value: Option<&str>, token: &str) -> bool {
    value.is_some_and(|value| {
        value
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    })
}

fn is_closed_error(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<WebSocketError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed
                )
            })
            || source
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_tungstenite::client_async;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    #[test]
    fn parses_xboard_websocket_network_settings() {
        let config = WsConfig::from_network_settings(Some(&serde_json::json!({
            "path": "ws",
            "headers": {
                "Host": ["example.com:443", "cdn.example.com"]
            }
        })))
        .expect("parse config");
        assert_eq!(config.path, "/ws");
        assert_eq!(
            config.hosts,
            vec!["example.com".to_string(), "cdn.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn accepts_websocket_binary_stream() {
        let config = WsConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/ws",
            "headers": {
                "Host": "example.com"
            }
        })))
        .expect("parse config");
        let (client, server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            let Some(mut stream) = accept(server, &config).await.expect("accept") else {
                panic!("expected WebSocket stream");
            };
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown");
        });

        let request = "ws://example.com/ws"
            .into_client_request()
            .expect("request");
        let (mut client_ws, _) = client_async(request, client).await.expect("client");
        client_ws
            .send(Message::Binary(b"hello".to_vec().into()))
            .await
            .expect("send request");
        let response = client_ws
            .next()
            .await
            .expect("response exists")
            .expect("response frame");
        assert_eq!(response.into_data().as_ref(), b"world");

        server_task.await.expect("join server task");
    }
}
