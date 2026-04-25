use anyhow::{Context as _, anyhow};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::http1::{
    PrefixedIo, normalize_host, normalize_path, parse_hosts, read_request_head, respond_status,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub hosts: Vec<String>,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            hosts: Vec::new(),
        }
    }
}

impl HttpUpgradeConfig {
    pub fn from_network_settings(value: Option<&Value>) -> anyhow::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("HTTPUpgrade networkSettings must be an object"))?;
        let path = normalize_path(
            object
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .trim(),
        );
        let hosts = parse_hosts(object.get("host"))?;
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
                .any(|expected| expected == &normalize_host(request_host))
    }
}

pub async fn accept<S>(
    mut stream: S,
    config: &HttpUpgradeConfig,
) -> anyhow::Result<Option<PrefixedIo<S>>>
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

    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .context("write HTTPUpgrade response")?;

    Ok(Some(PrefixedIo::new(stream, parsed.buffered_body)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn parses_xboard_httpupgrade_network_settings() {
        let config = HttpUpgradeConfig::from_network_settings(Some(&serde_json::json!({
            "path": "upgrade",
            "host": ["example.com:443", "cdn.example.com"]
        })))
        .expect("parse config");
        assert_eq!(config.path, "/upgrade");
        assert_eq!(
            config.hosts,
            vec!["example.com".to_string(), "cdn.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn upgrades_http_request_and_preserves_prefetched_bytes() {
        let config = HttpUpgradeConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/upgrade",
            "host": "example.com"
        })))
        .expect("parse config");
        let (mut client, server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            let Some(mut stream) = accept(server, &config).await.expect("accept") else {
                panic!("expected upgraded stream");
            };
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read body");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write body");
            stream.shutdown().await.expect("shutdown");
        });

        client
            .write_all(
                b"GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello",
            )
            .await
            .expect("write request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        server_task.await.expect("join server task");

        let text = String::from_utf8(response).expect("utf8");
        assert!(text.contains("101 Switching Protocols"));
        assert!(text.ends_with("world"));
    }
}
