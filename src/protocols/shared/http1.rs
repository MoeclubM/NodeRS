use anyhow::{Context as _, anyhow, bail, ensure};
use serde_json::Value;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const DEFAULT_HEADER_BYTES_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug)]
pub struct ParsedRequestHead {
    pub request: HttpRequest,
    pub buffered_body: Vec<u8>,
}

#[derive(Debug)]
pub struct PrefixedIo<S> {
    inner: S,
    prefix: Vec<u8>,
    offset: usize,
    capture_inner: bool,
    captured_inner: Vec<u8>,
}

impl<S> PrefixedIo<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
            capture_inner: false,
            captured_inner: Vec::new(),
        }
    }

    pub fn capture_inner_reads(mut self) -> Self {
        self.capture_inner = true;
        self
    }

    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.inner, self.captured_inner)
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn prepend_prefix(mut self, prefix: Vec<u8>) -> Self {
        if prefix.is_empty() {
            return self;
        }

        let mut combined = prefix;
        if self.offset < self.prefix.len() {
            combined.extend_from_slice(&self.prefix[self.offset..]);
        }
        self.prefix = combined;
        self.offset = 0;
        self
    }
}

impl<S> AsyncRead for PrefixedIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.offset += take;
            return Poll::Ready(Ok(()));
        }
        let filled_len = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if self.capture_inner {
                    self.captured_inner
                        .extend_from_slice(&buf.filled()[filled_len..]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> AsyncWrite for PrefixedIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
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

pub async fn read_request_head<S>(stream: &mut S) -> anyhow::Result<ParsedRequestHead>
where
    S: AsyncRead + Unpin,
{
    read_request_head_with_limit(stream, DEFAULT_HEADER_BYTES_LIMIT).await
}

pub async fn read_request_head_with_limit<S>(
    stream: &mut S,
    header_bytes_limit: usize,
) -> anyhow::Result<ParsedRequestHead>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(position) = find_header_end(&bytes) {
            break position;
        }
        ensure!(
            bytes.len() <= header_bytes_limit,
            "HTTP request headers exceed {header_bytes_limit} bytes"
        );
        let mut buffer = [0u8; 2048];
        let read = stream
            .read(&mut buffer)
            .await
            .context("read HTTP request headers")?;
        ensure!(read > 0, "unexpected EOF before HTTP headers completed");
        bytes.extend_from_slice(&buffer[..read]);
        ensure!(
            bytes.len() <= header_bytes_limit,
            "HTTP request headers exceed {header_bytes_limit} bytes"
        );
    };

    let header_bytes = &bytes[..header_end];
    let buffered_body = bytes[header_end + 4..].to_vec();
    let text = std::str::from_utf8(header_bytes).context("decode HTTP headers as UTF-8")?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?
        .to_string();
    let version = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?
        .to_string();
    ensure!(
        version.eq_ignore_ascii_case("HTTP/1.1") || version.eq_ignore_ascii_case("HTTP/1.0"),
        "unsupported HTTP version {version}"
    );

    let mut headers = Vec::new();
    let mut host = String::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid HTTP header line"))?;
        let key = name.trim().to_string();
        let value = value.trim().to_string();
        if key.eq_ignore_ascii_case("host") {
            host = value.clone();
        }
        headers.push((key, value));
    }
    ensure!(!host.trim().is_empty(), "HTTP Host header is required");

    Ok(ParsedRequestHead {
        request: HttpRequest {
            method,
            path,
            host,
            version,
            headers,
        },
        buffered_body,
    })
}

pub async fn respond_status<S>(
    stream: &mut S,
    request: Option<&HttpRequest>,
    code: u16,
    reason: &str,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = format!("HTTP/1.1 {code} {reason}\r\n");
    append_common_headers(&mut response, request);
    response.push_str("Connection: close\r\nContent-Length: 0\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .await
        .with_context(|| format!("write HTTP {code} response"))?;
    stream.shutdown().await.ok();
    Ok(())
}

pub fn append_common_headers(response: &mut String, request: Option<&HttpRequest>) {
    if let Some(origin) = request.and_then(|request| request.header("Origin")) {
        response.push_str("Access-Control-Allow-Origin: ");
        response.push_str(origin);
        response.push_str("\r\nAccess-Control-Allow-Credentials: true\r\n");
    } else {
        response.push_str("Access-Control-Allow-Origin: *\r\n");
    }
}

pub fn normalize_path(path: &str) -> String {
    let trimmed = path
        .trim()
        .split_once('?')
        .map_or(path.trim(), |(path, _)| path);
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let trimmed = trimmed.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub fn parse_hosts(value: Option<&Value>) -> anyhow::Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let mut hosts = Vec::new();
    match value {
        Value::Null => {}
        Value::String(text) => {
            for item in text.split(',') {
                let host = normalize_host(item);
                if !host.is_empty() {
                    hosts.push(host);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                let host = value
                    .as_str()
                    .ok_or_else(|| anyhow!("HTTP host array must contain strings"))?;
                let host = normalize_host(host);
                if !host.is_empty() {
                    hosts.push(host);
                }
            }
        }
        _ => bail!("HTTP host must be a string or string array"),
    }
    Ok(hosts)
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    if host.is_empty() {
        return String::new();
    }

    let host = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[1..end],
            None => host,
        }
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if !name.contains(':') && port.chars().all(|char| char.is_ascii_digit()) {
            name
        } else {
            host
        }
    } else {
        host
    };

    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn normalizes_host_and_path() {
        assert_eq!(normalize_path("edge/"), "/edge");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_host("Example.com:443"), "example.com");
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[tokio::test]
    async fn reads_request_head_and_preserves_buffered_body() {
        let (mut client, mut server) = duplex(4096);
        let request = tokio::spawn(async move { read_request_head(&mut server).await });

        client
            .write_all(b"POST /demo HTTP/1.1\r\nHost: example.com\r\n\r\nhello")
            .await
            .expect("write request");
        let parsed = request.await.expect("join").expect("parse");
        assert_eq!(parsed.request.method, "POST");
        assert_eq!(parsed.request.path, "/demo");
        assert_eq!(parsed.request.host, "example.com");
        assert_eq!(parsed.buffered_body, b"hello");
    }

    #[tokio::test]
    async fn prefixed_io_reads_prefix_before_inner_stream() {
        let (mut client, server) = duplex(4096);
        let mut stream = PrefixedIo::new(server, b"hello".to_vec());

        client.write_all(b"world").await.expect("write");

        let mut buffer = [0u8; 10];
        stream
            .read_exact(&mut buffer)
            .await
            .expect("read prefixed stream");
        assert_eq!(&buffer, b"helloworld");
    }

    #[tokio::test]
    async fn prefixed_io_into_parts_returns_underlying_stream_without_captured_bytes() {
        let (mut client, server) = duplex(4096);
        let mut stream = PrefixedIo::new(server, b"hello".to_vec());

        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.expect("read prefix");
        assert_eq!(&prefix, b"he");

        let (mut inner, captured_inner) = stream.into_parts();
        assert!(captured_inner.is_empty());
        client.write_all(b"world").await.expect("write");

        let mut buffer = [0u8; 5];
        inner.read_exact(&mut buffer).await.expect("read inner");
        assert_eq!(&buffer, b"world");
    }

    #[tokio::test]
    async fn prefixed_io_into_parts_preserves_consumed_inner_bytes() {
        let (mut client, server) = duplex(4096);
        let mut stream = PrefixedIo::new(server, b"hello".to_vec()).capture_inner_reads();

        client.write_all(b"world").await.expect("write");

        let mut buffer = [0u8; 7];
        stream
            .read_exact(&mut buffer)
            .await
            .expect("read prefixed stream with inner capture");
        assert_eq!(&buffer, b"hellowo");

        let (mut inner, captured_inner) = stream.into_parts();
        assert_eq!(captured_inner, b"wo");

        let mut remaining = [0u8; 3];
        inner
            .read_exact(&mut remaining)
            .await
            .expect("read remaining inner");
        assert_eq!(&remaining, b"rld");
    }
}
