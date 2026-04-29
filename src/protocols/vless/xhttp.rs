use anyhow::{Context as _, anyhow, bail, ensure};
use base64::Engine as _;
use bytes::{Buf as _, Bytes};
use futures_util::future::poll_fn;
use rand::RngExt;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex, split,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::warn;

use super::http1::{
    HttpRequest as XhttpRequest, ParsedRequestHead as HttpParsedRequestHead, PrefixedIo,
    normalize_host, normalize_path, parse_hosts,
    read_request_head_with_limit as read_http_request_head_with_limit,
};

const PIPE_CAPACITY: usize = 256 * 1024;
const COPY_BUFFER_LEN: usize = 16 * 1024;
const DEFAULT_SC_MAX_EACH_POST_BYTES: usize = 1_000_000;
const DEFAULT_SC_MAX_BUFFERED_POSTS: usize = 30;
const DEFAULT_SC_STREAM_UP_SERVER_SECS: Range = Range { min: 20, max: 80 };
const DEFAULT_SERVER_MAX_HEADER_BYTES: usize = 8192;
const DEFAULT_X_PADDING_BYTES: Range = Range {
    min: 100,
    max: 1000,
};
const HTTP_REQUEST_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
const SESSION_REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const TOKENISH_VALIDATION_TOLERANCE: usize = 2;
const TOKENISH_MAX_ADJUST_ITERATIONS: usize = 150;
const TOKENISH_BASE62_CHARSET: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HPACK_HUFFMAN_CODE_LENGTHS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[derive(Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub hosts: Vec<String>,
    pub mode: String,
    pub extra: Option<Value>,
    session_placement: Placement,
    session_key: String,
    seq_placement: Placement,
    seq_key: String,
    uplink_http_method: String,
    uplink_data_placement: UplinkDataPlacement,
    uplink_data_key: String,
    headers: Vec<(String, String)>,
    x_padding_bytes: Range,
    x_padding_obfs_mode: bool,
    x_padding_key: String,
    x_padding_header: String,
    x_padding_placement: XPaddingPlacement,
    x_padding_method: XPaddingMethod,
    no_sse_header: bool,
    sc_max_each_post_bytes: usize,
    sc_max_buffered_posts: usize,
    sc_stream_up_server_secs: Range,
    server_max_header_bytes: usize,
    sessions: Arc<SessionTable>,
}

impl fmt::Debug for XhttpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XhttpConfig")
            .field("path", &self.path)
            .field("hosts", &self.hosts)
            .field("mode", &self.mode)
            .field("extra", &self.extra)
            .field("session_placement", &self.session_placement)
            .field("session_key", &self.session_key)
            .field("seq_placement", &self.seq_placement)
            .field("seq_key", &self.seq_key)
            .field("uplink_http_method", &self.uplink_http_method)
            .field("uplink_data_placement", &self.uplink_data_placement)
            .field("uplink_data_key", &self.uplink_data_key)
            .field("headers", &self.headers)
            .field("x_padding_bytes", &self.x_padding_bytes)
            .field("x_padding_obfs_mode", &self.x_padding_obfs_mode)
            .field("x_padding_key", &self.x_padding_key)
            .field("x_padding_header", &self.x_padding_header)
            .field("x_padding_placement", &self.x_padding_placement)
            .field("x_padding_method", &self.x_padding_method)
            .field("no_sse_header", &self.no_sse_header)
            .field("sc_max_each_post_bytes", &self.sc_max_each_post_bytes)
            .field("sc_max_buffered_posts", &self.sc_max_buffered_posts)
            .field("sc_stream_up_server_secs", &self.sc_stream_up_server_secs)
            .field("server_max_header_bytes", &self.server_max_header_bytes)
            .finish()
    }
}

impl PartialEq for XhttpConfig {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.hosts == other.hosts
            && self.mode == other.mode
            && self.extra == other.extra
            && self.session_placement == other.session_placement
            && self.session_key == other.session_key
            && self.seq_placement == other.seq_placement
            && self.seq_key == other.seq_key
            && self.uplink_http_method == other.uplink_http_method
            && self.uplink_data_placement == other.uplink_data_placement
            && self.uplink_data_key == other.uplink_data_key
            && self.headers == other.headers
            && self.x_padding_bytes == other.x_padding_bytes
            && self.x_padding_obfs_mode == other.x_padding_obfs_mode
            && self.x_padding_key == other.x_padding_key
            && self.x_padding_header == other.x_padding_header
            && self.x_padding_placement == other.x_padding_placement
            && self.x_padding_method == other.x_padding_method
            && self.no_sse_header == other.no_sse_header
            && self.sc_max_each_post_bytes == other.sc_max_each_post_bytes
            && self.sc_max_buffered_posts == other.sc_max_buffered_posts
            && self.sc_stream_up_server_secs == other.sc_stream_up_server_secs
            && self.server_max_header_bytes == other.server_max_header_bytes
    }
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            hosts: Vec::new(),
            mode: "auto".to_string(),
            extra: None,
            session_placement: Placement::Path,
            session_key: String::new(),
            seq_placement: Placement::Path,
            seq_key: String::new(),
            uplink_http_method: "POST".to_string(),
            uplink_data_placement: UplinkDataPlacement::Body,
            uplink_data_key: String::new(),
            headers: Vec::new(),
            x_padding_bytes: DEFAULT_X_PADDING_BYTES,
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".to_string(),
            x_padding_header: "X-Padding".to_string(),
            x_padding_placement: XPaddingPlacement::QueryInHeader,
            x_padding_method: XPaddingMethod::RepeatX,
            no_sse_header: false,
            sc_max_each_post_bytes: DEFAULT_SC_MAX_EACH_POST_BYTES,
            sc_max_buffered_posts: DEFAULT_SC_MAX_BUFFERED_POSTS,
            sc_stream_up_server_secs: DEFAULT_SC_STREAM_UP_SERVER_SECS,
            server_max_header_bytes: DEFAULT_SERVER_MAX_HEADER_BYTES,
            sessions: Arc::new(SessionTable::default()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    min: usize,
    max: usize,
}

impl Range {
    fn sample(self) -> usize {
        if self.min >= self.max {
            self.min
        } else {
            rand::rng().random_range(self.min..=self.max)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Path,
    Query,
    Header,
    Cookie,
}

impl Placement {
    fn parse(value: &str, field: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "path" => Ok(Self::Path),
            "query" => Ok(Self::Query),
            "header" => Ok(Self::Header),
            "cookie" => Ok(Self::Cookie),
            other => Err(anyhow!("unsupported XHTTP {field} {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UplinkDataPlacement {
    Auto,
    Body,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XPaddingPlacement {
    Header,
    Query,
    Cookie,
    QueryInHeader,
}

impl XPaddingPlacement {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "header" => Ok(Self::Header),
            "query" => Ok(Self::Query),
            "cookie" => Ok(Self::Cookie),
            "queryinheader" | "query-in-header" | "query_in_header" => Ok(Self::QueryInHeader),
            other => bail!("unsupported XHTTP xPaddingPlacement {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XPaddingMethod {
    RepeatX,
    Tokenish,
}

impl XPaddingMethod {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "repeat-x" | "repeatx" => Ok(Self::RepeatX),
            "tokenish" => Ok(Self::Tokenish),
            other => bail!("unsupported XHTTP xPaddingMethod {other}"),
        }
    }
}

impl UplinkDataPlacement {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "body" => Ok(Self::Body),
            "header" => Ok(Self::Header),
            "cookie" => Ok(Self::Cookie),
            other => Err(anyhow!("unsupported XHTTP uplinkDataPlacement {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Body => "body",
            Self::Header => "header",
            Self::Cookie => "cookie",
        }
    }
}

struct SessionTable {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    max_buffered_posts: usize,
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new(DEFAULT_SC_MAX_BUFFERED_POSTS)
    }
}

impl SessionTable {
    fn new(max_buffered_posts: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_buffered_posts,
        }
    }

    fn upsert(self: &Arc<Self>, session_id: &str) -> Arc<Session> {
        let mut sessions = self.sessions.lock().expect("xhttp session table poisoned");
        if let Some(session) = sessions.get(session_id) {
            return session.clone();
        }

        let session = Session::new(self.max_buffered_posts);
        sessions.insert(session_id.to_string(), session.clone());

        let sessions = self.clone();
        let session_id = session_id.to_string();
        let expected = session.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SESSION_REAP_TIMEOUT).await;
            if !expected.is_connected() {
                sessions.remove_if_same(&session_id, &expected);
            }
        });

        session
    }

    fn remove(&self, session_id: &str) {
        self.sessions
            .lock()
            .expect("xhttp session table poisoned")
            .remove(session_id);
    }

    fn remove_if_same(&self, session_id: &str, expected: &Arc<Session>) {
        let mut sessions = self.sessions.lock().expect("xhttp session table poisoned");
        if sessions
            .get(session_id)
            .is_some_and(|current| Arc::ptr_eq(current, expected))
        {
            sessions.remove(session_id);
        }
    }
}

struct Session {
    reader: Mutex<Option<DuplexStream>>,
    connected: AtomicBool,
    stream_upload_started: Mutex<bool>,
    uploads: mpsc::Sender<UploadItem>,
}

impl Session {
    fn new(max_buffered_posts: usize) -> Arc<Self> {
        let (reader, writer) = duplex(PIPE_CAPACITY);
        let (uploads, queue) = mpsc::channel(max_buffered_posts.max(1));
        tokio::spawn(async move {
            let _ = pump_session_uploads(writer, queue, max_buffered_posts.max(1)).await;
        });
        Arc::new(Self {
            reader: Mutex::new(Some(reader)),
            connected: AtomicBool::new(false),
            stream_upload_started: Mutex::new(false),
            uploads,
        })
    }

    fn take_reader(&self) -> Option<DuplexStream> {
        self.connected.store(true, Ordering::Relaxed);
        self.reader
            .lock()
            .expect("xhttp session reader lock poisoned")
            .take()
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn push_packet(&self, seq: u64, payload: Vec<u8>) -> anyhow::Result<bool> {
        ensure!(
            !*self
                .stream_upload_started
                .lock()
                .expect("xhttp stream upload lock poisoned"),
            "XHTTP stream-up request already exists for this session"
        );
        match self.uploads.send(UploadItem::Packet { seq, payload }).await {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn push_stream(
        &self,
        reader: Box<dyn AsyncRead + Send + Unpin>,
        buffered_body: Vec<u8>,
        body_kind: RequestBodyKind,
        completed: oneshot::Sender<anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        {
            let mut stream_upload_started = self
                .stream_upload_started
                .lock()
                .expect("xhttp stream upload lock poisoned");
            ensure!(!*stream_upload_started, "duplicate XHTTP stream-up request");
            *stream_upload_started = true;
        }
        self.uploads
            .send(UploadItem::Stream {
                reader,
                buffered_body,
                body_kind,
                completed,
            })
            .await
            .map_err(|_| anyhow!("XHTTP upload session is closed"))
    }
}

enum UploadItem {
    Packet {
        seq: u64,
        payload: Vec<u8>,
    },
    Stream {
        reader: Box<dyn AsyncRead + Send + Unpin>,
        buffered_body: Vec<u8>,
        body_kind: RequestBodyKind,
        completed: oneshot::Sender<anyhow::Result<()>>,
    },
}

async fn pump_session_uploads(
    mut writer: DuplexStream,
    mut queue: mpsc::Receiver<UploadItem>,
    max_buffered_posts: usize,
) -> anyhow::Result<()> {
    let mut next_seq = 0u64;
    let mut pending = BTreeMap::<u64, Vec<u8>>::new();

    while let Some(item) = queue.recv().await {
        match item {
            UploadItem::Packet { seq, payload } => {
                if seq < next_seq {
                    continue;
                }
                pending.entry(seq).or_insert(payload);
                while let Some(payload) = pending.remove(&next_seq) {
                    write_pipe(&mut writer, &payload).await?;
                    next_seq += 1;
                }
                ensure!(
                    pending.len() <= max_buffered_posts.max(1),
                    "XHTTP packet queue is too large"
                );
            }
            UploadItem::Stream {
                mut reader,
                buffered_body,
                body_kind,
                completed,
            } => {
                let result = pump_request_body(&mut *reader, &mut writer, buffered_body, body_kind)
                    .await
                    .map(|_| ());
                let _ = completed.send(match result {
                    Ok(()) => Ok(()),
                    Err(error) => Err(error),
                });
                writer.shutdown().await.ok();
                return Ok(());
            }
        }
    }

    writer.shutdown().await.ok();
    Ok(())
}

struct SessionCleanup {
    sessions: Arc<SessionTable>,
    session_id: String,
}

pub(super) enum AcceptResult<S> {
    Stream(XhttpStream),
    Responded(ResponseState<S>),
}

pub(super) enum ResponseState<S> {
    Continue(S),
    Closed,
}

pub struct XhttpStream {
    reader: DuplexStream,
    writer: DuplexStream,
    cleanup: Option<SessionCleanup>,
    _tasks: Vec<JoinHandle<anyhow::Result<()>>>,
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup.sessions.remove(&cleanup.session_id);
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
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

impl XhttpConfig {
    pub fn from_network_settings(value: Option<&Value>) -> anyhow::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("XHTTP networkSettings must be an object"))?;

        let extra = object.get("extra").map(parse_extra).transpose()?.flatten();
        let mut config = Self::default();

        if let Some(extra_object) = extra.as_ref().and_then(Value::as_object) {
            apply_network_settings(&mut config, extra_object)?;
        }
        config.extra = extra;
        apply_network_settings(&mut config, object)?;

        if config.session_key.is_empty() {
            config.session_key = default_session_key(config.session_placement).to_string();
        }
        if config.seq_key.is_empty() {
            config.seq_key = default_seq_key(config.seq_placement).to_string();
        }
        if config.uplink_data_key.is_empty() {
            config.uplink_data_key =
                default_uplink_data_key(config.uplink_data_placement).to_string();
        }
        config.uplink_http_method = normalize_method(&config.uplink_http_method);
        config.sessions = Arc::new(SessionTable::new(config.sc_max_buffered_posts));

        if matches!(
            config.uplink_data_placement,
            UplinkDataPlacement::Header | UplinkDataPlacement::Cookie
        ) && config.mode != "packet-up"
        {
            bail!(
                "XHTTP uplinkDataPlacement {} is only supported in packet-up mode",
                config.uplink_data_placement.as_str()
            );
        }
        if config.uplink_http_method == "GET" && config.mode != "packet-up" {
            bail!("XHTTP uplinkHTTPMethod GET is only supported in packet-up mode");
        }
        ensure!(
            config.x_padding_bytes.min > 0 && config.x_padding_bytes.max > 0,
            "XHTTP xPaddingBytes cannot be disabled"
        );
        if config.x_padding_obfs_mode {
            ensure!(
                !config.x_padding_key.is_empty()
                    || matches!(config.x_padding_placement, XPaddingPlacement::Header),
                "XHTTP xPaddingKey is required for non-header obfs placements"
            );
            ensure!(
                !config.x_padding_header.is_empty()
                    || !matches!(
                        config.x_padding_placement,
                        XPaddingPlacement::Header | XPaddingPlacement::QueryInHeader
                    ),
                "XHTTP xPaddingHeader is required for header-based obfs placements"
            );
        }

        Ok(config)
    }

    pub fn matches_path(&self, request_path: &str) -> bool {
        let request_path = normalize_path(request_path.trim());
        request_path == self.path
            || self.path == "/"
            || request_path.starts_with(&(self.path.clone() + "/"))
    }

    pub fn matches_host(&self, request_host: &str) -> bool {
        self.hosts.is_empty()
            || self
                .hosts
                .iter()
                .any(|expected| expected == &normalize_host(request_host))
    }

    fn allows_stream_one(&self) -> bool {
        self.mode == "auto" || self.mode == "stream-one" || self.mode == "stream-up"
    }

    fn allows_stream_up(&self) -> bool {
        self.mode == "auto" || self.mode == "stream-up"
    }

    fn allows_packet_up(&self) -> bool {
        self.mode == "auto" || self.mode == "packet-up"
    }

    fn uses_sse_header(&self) -> bool {
        !self.no_sse_header
    }

    fn uses_cors_credentials(&self) -> bool {
        self.session_placement == Placement::Cookie
            || self.seq_placement == Placement::Cookie
            || self.uplink_data_placement == UplinkDataPlacement::Cookie
            || self.x_padding_placement == XPaddingPlacement::Cookie
    }

    fn extract_request_x_padding(&self, request: &XhttpRequest) -> String {
        if !self.x_padding_obfs_mode {
            if let Some(referer) = request.header("Referer") {
                return url_like_query_value(referer, "x_padding");
            }
            return request_query_value(request, "x_padding");
        }

        let key = if self.x_padding_key.is_empty() {
            "x_padding"
        } else {
            self.x_padding_key.as_str()
        };
        let cookies = parse_cookies(request.header("Cookie"));
        if let Some(padding) = cookies.get(key).filter(|value| !value.is_empty()) {
            return padding.clone();
        }

        let header = if self.x_padding_header.is_empty() {
            "X-Padding"
        } else {
            self.x_padding_header.as_str()
        };
        if let Some(value) = request
            .header(header)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return if self.x_padding_placement == XPaddingPlacement::Header {
                value.to_string()
            } else {
                url_like_query_value(value, key)
            };
        }

        let padding = request_query_value(request, key);
        if !padding.is_empty() {
            return padding;
        }

        String::new()
    }

    fn has_valid_request_x_padding(&self, request: &XhttpRequest) -> bool {
        is_x_padding_valid(
            &self.extract_request_x_padding(request),
            self.x_padding_bytes,
            self.x_padding_method,
        )
    }

    fn extract_meta(&self, request: &XhttpRequest) -> (String, String) {
        let (path_only, query) = split_request_target(&request.path);
        let path_segments = suffix_segments(&self.path, path_only);
        let query_values = parse_query(query);
        let cookies = parse_cookies(request.header("Cookie"));
        let mut path_index = 0usize;

        let session_id = match self.session_placement {
            Placement::Path => {
                let value = path_segments.get(path_index).cloned().unwrap_or_default();
                if !value.is_empty() {
                    path_index += 1;
                }
                value.to_string()
            }
            Placement::Query => query_values
                .get(self.session_key.as_str())
                .cloned()
                .unwrap_or_default(),
            Placement::Header => request
                .header(&self.session_key)
                .unwrap_or("")
                .trim()
                .to_string(),
            Placement::Cookie => cookies
                .get(self.session_key.as_str())
                .cloned()
                .unwrap_or_default(),
        };

        let seq = match self.seq_placement {
            Placement::Path => path_segments.get(path_index).cloned().unwrap_or_default(),
            Placement::Query => query_values
                .get(self.seq_key.as_str())
                .cloned()
                .unwrap_or_default(),
            Placement::Header => request
                .header(&self.seq_key)
                .unwrap_or("")
                .trim()
                .to_string(),
            Placement::Cookie => cookies
                .get(self.seq_key.as_str())
                .cloned()
                .unwrap_or_default(),
        };

        (session_id, seq)
    }
}

fn apply_network_settings(
    config: &mut XhttpConfig,
    object: &serde_json::Map<String, Value>,
) -> anyhow::Result<()> {
    if let Some(path) = setting_str(object, &["path"]) {
        config.path = normalize_path(path.trim());
    }
    if object.contains_key("host") {
        config.hosts = parse_hosts(object.get("host"))?;
    }
    if let Some(mode) = setting_str(object, &["mode"]) {
        config.mode = normalize_mode(mode)?;
    }
    if let Some(placement) = setting_str(object, &["sessionPlacement", "session_placement"]) {
        config.session_placement = Placement::parse(placement, "sessionPlacement")?;
    }
    if let Some(key) = setting_str(object, &["sessionKey", "session_key"]) {
        config.session_key = key.trim().to_string();
    }
    if let Some(placement) = setting_str(object, &["seqPlacement", "seq_placement"]) {
        config.seq_placement = Placement::parse(placement, "seqPlacement")?;
    }
    if let Some(key) = setting_str(object, &["seqKey", "seq_key"]) {
        config.seq_key = key.trim().to_string();
    }
    if let Some(method) = setting_str(object, &["uplinkHTTPMethod", "uplink_http_method"]) {
        config.uplink_http_method = normalize_method(method);
    }
    if let Some(placement) = setting_str(object, &["uplinkDataPlacement", "uplink_data_placement"])
    {
        config.uplink_data_placement = UplinkDataPlacement::parse(placement)?;
    }
    if let Some(key) = setting_str(object, &["uplinkDataKey", "uplink_data_key"]) {
        config.uplink_data_key = key.trim().to_string();
    }
    if let Some(headers) = object.get("headers") {
        config.headers = parse_headers(headers)?;
    }
    if let Some(value) = setting_value(object, &["xPaddingBytes", "x_padding_bytes"]) {
        config.x_padding_bytes = parse_non_negative_range(value, "xPaddingBytes")?;
    }
    if let Some(value) = setting_bool(object, &["xPaddingObfsMode", "x_padding_obfs_mode"]) {
        config.x_padding_obfs_mode = value;
    }
    if let Some(value) = setting_str(object, &["xPaddingKey", "x_padding_key"]) {
        config.x_padding_key = value.trim().to_string();
    }
    if let Some(value) = setting_str(object, &["xPaddingHeader", "x_padding_header"]) {
        config.x_padding_header = value.trim().to_string();
    }
    if let Some(value) = setting_str(object, &["xPaddingPlacement", "x_padding_placement"]) {
        config.x_padding_placement = XPaddingPlacement::parse(value)?;
    }
    if let Some(value) = setting_str(object, &["xPaddingMethod", "x_padding_method"]) {
        config.x_padding_method = XPaddingMethod::parse(value)?;
    }
    if let Some(no_sse_header) = setting_bool(object, &["noSSEHeader", "no_sse_header"]) {
        config.no_sse_header = no_sse_header;
    }
    if let Some(limit) = setting_value(object, &["scMaxEachPostBytes", "sc_max_each_post_bytes"]) {
        let limit = parse_positive_range_upper(limit, "scMaxEachPostBytes")?;
        if limit > 0 {
            config.sc_max_each_post_bytes = limit;
        }
    }
    if let Some(limit) = setting_value(object, &["scMaxBufferedPosts", "sc_max_buffered_posts"]) {
        let limit = parse_non_negative_usize(limit, "scMaxBufferedPosts")?;
        if limit > 0 {
            config.sc_max_buffered_posts = limit;
        }
    }
    if let Some(value) = setting_value(
        object,
        &["scStreamUpServerSecs", "sc_stream_up_server_secs"],
    ) {
        config.sc_stream_up_server_secs = parse_non_negative_range(value, "scStreamUpServerSecs")?;
    }
    if let Some(limit) = setting_value(object, &["serverMaxHeaderBytes", "server_max_header_bytes"])
    {
        let limit = parse_non_negative_usize(limit, "serverMaxHeaderBytes")?;
        if limit > 0 {
            config.server_max_header_bytes = limit;
        }
    }
    Ok(())
}

fn setting_value<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn setting_str<'a>(object: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    setting_value(object, keys).and_then(Value::as_str)
}

fn setting_bool(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<bool> {
    setting_value(object, keys).and_then(crate::panel::value_to_bool)
}

#[cfg(test)]
async fn accept<S>(stream: S, config: &XhttpConfig) -> anyhow::Result<AcceptResult<PrefixedIo<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept_prefixed(PrefixedIo::new(stream, Vec::new()), config).await
}

pub(super) async fn accept_prefixed<S>(
    mut stream: PrefixedIo<S>,
    config: &XhttpConfig,
) -> anyhow::Result<AcceptResult<PrefixedIo<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let parsed = match match tokio::time::timeout(
        HTTP_REQUEST_HEAD_TIMEOUT,
        read_request_head_with_limit(&mut stream, config.server_max_header_bytes),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            stream.shutdown().await.ok();
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }
    } {
        Ok(parsed) => parsed,
        Err(_) => {
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .context("write XHTTP bad request response")?;
            stream.shutdown().await.ok();
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }
    };
    let allow_credentials = config.uses_cors_credentials();

    if !config.matches_host(&parsed.request.host) || !config.matches_path(&parsed.request.path) {
        respond_status(
            config,
            &mut stream,
            &parsed.request,
            404,
            "Not Found",
            allow_credentials,
        )
        .await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    }

    if parsed.request.method.eq_ignore_ascii_case("OPTIONS") {
        respond_options(config, &mut stream, &parsed.request, allow_credentials).await?;
        if request_body_is_empty(parsed.body_kind) {
            return Ok(AcceptResult::Responded(ResponseState::Continue(
                stream.prepend_prefix(parsed.buffered_body),
            )));
        }
        close_response(&mut stream).await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    }

    if !config.has_valid_request_x_padding(&parsed.request) {
        respond_status(
            config,
            &mut stream,
            &parsed.request,
            400,
            "Bad Request",
            allow_credentials,
        )
        .await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    }

    let (session_id, seq_str) = config.extract_meta(&parsed.request);
    if session_id.is_empty() && !config.allows_stream_one() {
        respond_status(
            config,
            &mut stream,
            &parsed.request,
            400,
            "Bad Request",
            allow_credentials,
        )
        .await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    }

    let is_uplink_request = if parsed.request.method.eq_ignore_ascii_case("GET") {
        !seq_str.is_empty()
    } else {
        true
    };

    if is_uplink_request && !session_id.is_empty() {
        let session = config.sessions.upsert(&session_id);
        if seq_str.is_empty() {
            if !config.allows_stream_up() {
                respond_status(
                    config,
                    &mut stream,
                    &parsed.request,
                    400,
                    "Bad Request",
                    allow_credentials,
                )
                .await?;
                return Ok(AcceptResult::Responded(ResponseState::Closed));
            }

            let response_request = parsed.request.clone();
            let (stream_reader, mut stream_writer) = split(stream);
            let (completed_tx, mut completed_rx) = oneshot::channel();
            if session
                .push_stream(
                    Box::new(stream_reader),
                    parsed.buffered_body,
                    parsed.body_kind,
                    completed_tx,
                )
                .await
                .is_err()
            {
                respond_status(
                    config,
                    &mut stream_writer,
                    &response_request,
                    409,
                    "Conflict",
                    allow_credentials,
                )
                .await?;
                return Ok(AcceptResult::Responded(ResponseState::Closed));
            }
            stream_writer
                .write_all(&build_stream_response_head(
                    config,
                    &response_request,
                    false,
                    allow_credentials,
                ))
                .await
                .context("write XHTTP stream-up response headers")?;
            stream_writer.flush().await.ok();

            let mut completed_result = None;
            if response_request.header("Referer").is_some()
                && config.sc_stream_up_server_secs.max > 0
            {
                loop {
                    let sleep_secs = config.sc_stream_up_server_secs.sample() as u64;
                    if sleep_secs == 0 {
                        break;
                    }
                    tokio::select! {
                        result = &mut completed_rx => {
                            completed_result = Some(result);
                            break;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)) => {}
                    }
                    let padding_len = config.x_padding_bytes.sample();
                    if padding_len == 0 {
                        continue;
                    }
                    let chunk = "X".repeat(padding_len);
                    let head = format!("{:X}\r\n", chunk.len());
                    if stream_writer.write_all(head.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream_writer.write_all(chunk.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream_writer.write_all(b"\r\n").await.is_err() {
                        break;
                    }
                    if stream_writer.flush().await.is_err() {
                        break;
                    }
                }
            }

            match match completed_result {
                Some(result) => result,
                None => completed_rx.await,
            } {
                Ok(Ok(())) => {}
                Ok(Err(error)) if is_broken_pipe(&error) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(anyhow!("XHTTP stream-up session closed unexpectedly")),
            }

            stream_writer
                .write_all(b"0\r\n\r\n")
                .await
                .context("write XHTTP stream-up response trailer")?;
            stream_writer.flush().await.ok();
            stream_writer.shutdown().await.ok();
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }

        if !config.allows_packet_up() {
            respond_status(
                config,
                &mut stream,
                &parsed.request,
                400,
                "Bad Request",
                allow_credentials,
            )
            .await?;
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }

        let seq = match seq_str.parse::<u64>() {
            Ok(seq) => seq,
            Err(_) => {
                respond_status(
                    config,
                    &mut stream,
                    &parsed.request,
                    500,
                    "Internal Server Error",
                    allow_credentials,
                )
                .await?;
                return Ok(AcceptResult::Responded(ResponseState::Closed));
            }
        };
        let (payload, next_prefix) = match read_uplink_payload(&mut stream, &parsed, config).await {
            Ok(result) => result,
            Err(UplinkPayloadError::PayloadTooLarge) => {
                respond_status(
                    config,
                    &mut stream,
                    &parsed.request,
                    413,
                    "Payload Too Large",
                    allow_credentials,
                )
                .await?;
                return Ok(AcceptResult::Responded(ResponseState::Closed));
            }
            Err(UplinkPayloadError::BadRequest) => {
                respond_status(
                    config,
                    &mut stream,
                    &parsed.request,
                    400,
                    "Bad Request",
                    allow_credentials,
                )
                .await?;
                return Ok(AcceptResult::Responded(ResponseState::Closed));
            }
        };
        if !session.push_packet(seq, payload).await? {
            respond_upload_ack(config, &mut stream, &parsed.request, allow_credentials).await?;
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }
        respond_upload_ack(config, &mut stream, &parsed.request, allow_credentials).await?;
        if can_keep_alive_after_packet_upload(config, parsed.body_kind) {
            return Ok(AcceptResult::Responded(ResponseState::Continue(
                stream.prepend_prefix(next_prefix),
            )));
        }
        close_response(&mut stream).await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    }

    if session_id.is_empty() {
        if parsed.request.method.eq_ignore_ascii_case("GET") {
            respond_status(
                config,
                &mut stream,
                &parsed.request,
                405,
                "Method Not Allowed",
                allow_credentials,
            )
            .await?;
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }
        if matches!(parsed.body_kind, RequestBodyKind::Empty) {
            respond_status(
                config,
                &mut stream,
                &parsed.request,
                400,
                "Bad Request",
                allow_credentials,
            )
            .await?;
            return Ok(AcceptResult::Responded(ResponseState::Closed));
        }
        return accept_stream_one(stream, parsed, config).await;
    }

    if !parsed.request.method.eq_ignore_ascii_case("GET") {
        respond_status(
            config,
            &mut stream,
            &parsed.request,
            405,
            "Method Not Allowed",
            allow_credentials,
        )
        .await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    }

    let session = config.sessions.upsert(&session_id);
    let Some(reader) = session.take_reader() else {
        respond_status(
            config,
            &mut stream,
            &parsed.request,
            409,
            "Conflict",
            allow_credentials,
        )
        .await?;
        return Ok(AcceptResult::Responded(ResponseState::Closed));
    };

    let response_request = parsed.request.clone();
    let (_, stream_writer) = split(stream);
    let (writer, response_source) = duplex(PIPE_CAPACITY);
    let use_sse_header = config.uses_sse_header();
    let response_config = config.clone();
    let response_task = tokio::spawn(async move {
        let result = pump_response_body(
            stream_writer,
            response_source,
            &response_config,
            &response_request,
            use_sse_header,
            allow_credentials,
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    Ok(AcceptResult::Stream(XhttpStream {
        reader,
        writer,
        cleanup: Some(SessionCleanup {
            sessions: config.sessions.clone(),
            session_id,
        }),
        _tasks: vec![response_task],
    }))
}

pub(super) async fn serve_h2<S>(
    stream: S,
    config: XhttpConfig,
    on_stream: Arc<dyn Fn(XhttpStream) + Send + Sync>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream)
        .await
        .context("accept XHTTP h2 connection")?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result.context("accept XHTTP h2 request")?;
        let config = config.clone();
        let on_stream = on_stream.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_h2_request(request, respond, config, on_stream).await {
                warn!(%error, "VLESS XHTTP h2 request failed");
            }
        });
    }
    Ok(())
}

async fn handle_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: XhttpConfig,
    on_stream: Arc<dyn Fn(XhttpStream) + Send + Sync>,
) -> anyhow::Result<()> {
    let body_kind = if request.body().is_end_stream() {
        RequestBodyKind::Empty
    } else {
        RequestBodyKind::UntilEnd
    };
    let (parts, body) = request.into_parts();
    let request = match xhttp_request_from_h2_parts(&parts) {
        Ok(request) => request,
        Err(_) => {
            respond_h2_empty_status(&mut respond, 400).await?;
            return Ok(());
        }
    };
    if h2_header_bytes_len(&request) > config.server_max_header_bytes {
        respond_h2_status(&mut respond, &config, &request, 400, false).await?;
        return Ok(());
    }
    let allow_credentials = config.uses_cors_credentials();

    if !config.matches_host(&request.host) || !config.matches_path(&request.path) {
        respond_h2_status(&mut respond, &config, &request, 404, allow_credentials).await?;
        return Ok(());
    }

    if request.method.eq_ignore_ascii_case("OPTIONS") {
        respond_h2_options(&mut respond, &config, &request, allow_credentials).await?;
        return Ok(());
    }

    if !config.has_valid_request_x_padding(&request) {
        respond_h2_status(&mut respond, &config, &request, 400, allow_credentials).await?;
        return Ok(());
    }

    let (session_id, seq_str) = config.extract_meta(&request);
    if session_id.is_empty() && !config.allows_stream_one() {
        respond_h2_status(&mut respond, &config, &request, 400, allow_credentials).await?;
        return Ok(());
    }

    let is_uplink_request = if request.method.eq_ignore_ascii_case("GET") {
        !seq_str.is_empty()
    } else {
        true
    };

    if is_uplink_request && !session_id.is_empty() {
        let session = config.sessions.upsert(&session_id);
        if seq_str.is_empty() {
            if !config.allows_stream_up() {
                respond_h2_status(&mut respond, &config, &request, 400, allow_credentials).await?;
                return Ok(());
            }

            let (completed_tx, mut completed_rx) = oneshot::channel();
            if session
                .push_stream(
                    Box::new(H2BodyReader::new(body)),
                    Vec::new(),
                    body_kind,
                    completed_tx,
                )
                .await
                .is_err()
            {
                respond_h2_status(&mut respond, &config, &request, 409, allow_credentials).await?;
                return Ok(());
            }

            let mut sender = send_h2_stream_response_head(
                &mut respond,
                &config,
                &request,
                false,
                allow_credentials,
            )?;
            let mut completed_result = None;
            if request.header("Referer").is_some() && config.sc_stream_up_server_secs.max > 0 {
                loop {
                    let sleep_secs = config.sc_stream_up_server_secs.sample() as u64;
                    if sleep_secs == 0 {
                        break;
                    }
                    tokio::select! {
                        result = &mut completed_rx => {
                            completed_result = Some(result);
                            break;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)) => {}
                    }
                    let padding_len = config.x_padding_bytes.sample();
                    if padding_len == 0 {
                        continue;
                    }
                    let chunk = Bytes::from("X".repeat(padding_len));
                    if send_h2_data(&mut sender, chunk, false).await.is_err() {
                        break;
                    }
                }
            }

            match match completed_result {
                Some(result) => result,
                None => completed_rx.await,
            } {
                Ok(Ok(())) => {}
                Ok(Err(error)) if is_broken_pipe(&error) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(anyhow!("XHTTP h2 stream-up session closed unexpectedly")),
            }

            send_h2_data(&mut sender, Bytes::new(), true)
                .await
                .context("write XHTTP h2 stream-up response trailer")?;
            return Ok(());
        }

        if !config.allows_packet_up() {
            respond_h2_status(&mut respond, &config, &request, 400, allow_credentials).await?;
            return Ok(());
        }

        let seq = match seq_str.parse::<u64>() {
            Ok(seq) => seq,
            Err(_) => {
                respond_h2_status(&mut respond, &config, &request, 500, allow_credentials).await?;
                return Ok(());
            }
        };
        let payload = match read_h2_uplink_payload(body, request.clone(), body_kind, &config).await
        {
            Ok(payload) => payload,
            Err(UplinkPayloadError::PayloadTooLarge) => {
                respond_h2_status(&mut respond, &config, &request, 413, allow_credentials).await?;
                return Ok(());
            }
            Err(UplinkPayloadError::BadRequest) => {
                respond_h2_status(&mut respond, &config, &request, 400, allow_credentials).await?;
                return Ok(());
            }
        };
        if !session.push_packet(seq, payload).await? {
            respond_h2_upload_ack(&mut respond, &config, &request, allow_credentials).await?;
            return Ok(());
        }
        respond_h2_upload_ack(&mut respond, &config, &request, allow_credentials).await?;
        return Ok(());
    }

    if session_id.is_empty() {
        if request.method.eq_ignore_ascii_case("GET") {
            respond_h2_status(&mut respond, &config, &request, 405, allow_credentials).await?;
            return Ok(());
        }
        if request_body_is_empty(body_kind) {
            respond_h2_status(&mut respond, &config, &request, 400, allow_credentials).await?;
            return Ok(());
        }
        accept_h2_stream_one(
            body,
            request,
            body_kind,
            respond,
            config,
            allow_credentials,
            on_stream,
        )?;
        return Ok(());
    }

    if !request.method.eq_ignore_ascii_case("GET") {
        respond_h2_status(&mut respond, &config, &request, 405, allow_credentials).await?;
        return Ok(());
    }

    let session = config.sessions.upsert(&session_id);
    let Some(reader) = session.take_reader() else {
        respond_h2_status(&mut respond, &config, &request, 409, allow_credentials).await?;
        return Ok(());
    };

    let (writer, response_source) = duplex(PIPE_CAPACITY);
    let use_sse_header = config.uses_sse_header();
    let response_request = request.clone();
    let sessions = config.sessions.clone();
    let response_task = tokio::spawn(async move {
        let result = pump_h2_response_body(
            respond,
            response_source,
            config,
            response_request,
            use_sse_header,
            allow_credentials,
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    on_stream(XhttpStream {
        reader,
        writer,
        cleanup: Some(SessionCleanup {
            sessions,
            session_id,
        }),
        _tasks: vec![response_task],
    });
    Ok(())
}

fn accept_h2_stream_one(
    body: h2::RecvStream,
    request: XhttpRequest,
    body_kind: RequestBodyKind,
    respond: h2::server::SendResponse<Bytes>,
    config: XhttpConfig,
    allow_credentials: bool,
    on_stream: Arc<dyn Fn(XhttpStream) + Send + Sync>,
) -> anyhow::Result<()> {
    let (request_sink, reader) = duplex(PIPE_CAPACITY);
    let (writer, response_source) = duplex(PIPE_CAPACITY);
    let response_request = request.clone();
    let response_config = config.clone();
    let use_sse_header = config.uses_sse_header();

    let request_task = tokio::spawn(async move {
        let result =
            pump_request_body(H2BodyReader::new(body), request_sink, Vec::new(), body_kind).await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    let response_task = tokio::spawn(async move {
        let result = pump_h2_response_body(
            respond,
            response_source,
            response_config,
            response_request,
            use_sse_header,
            allow_credentials,
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    on_stream(XhttpStream {
        reader,
        writer,
        cleanup: None,
        _tasks: vec![request_task, response_task],
    });
    Ok(())
}

async fn accept_stream_one<S>(
    stream: PrefixedIo<S>,
    parsed: ParsedRequestHead,
    config: &XhttpConfig,
) -> anyhow::Result<AcceptResult<PrefixedIo<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let response_request = parsed.request.clone();
    let (request_sink, reader) = duplex(PIPE_CAPACITY);
    let (writer, response_source) = duplex(PIPE_CAPACITY);
    let (stream_reader, stream_writer) = split(stream);
    let allow_credentials = config.uses_cors_credentials();
    let use_sse_header = config.uses_sse_header();
    let response_config = config.clone();

    let request_task = tokio::spawn(async move {
        let result = pump_request_body(
            stream_reader,
            request_sink,
            parsed.buffered_body,
            parsed.body_kind,
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    let response_task = tokio::spawn(async move {
        let result = pump_response_body(
            stream_writer,
            response_source,
            &response_config,
            &response_request,
            use_sse_header,
            allow_credentials,
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_broken_pipe(&error) => Ok(()),
            Err(error) => Err(error),
        }
    });

    Ok(AcceptResult::Stream(XhttpStream {
        reader,
        writer,
        cleanup: None,
        _tasks: vec![request_task, response_task],
    }))
}

#[derive(Debug)]
struct ParsedRequestHead {
    request: XhttpRequest,
    buffered_body: Vec<u8>,
    body_kind: RequestBodyKind,
}

#[derive(Debug, Clone, Copy)]
enum RequestBodyKind {
    Empty,
    Fixed(usize),
    Chunked,
    UntilEnd,
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

fn xhttp_request_from_h2_parts(parts: &http::request::Parts) -> anyhow::Result<XhttpRequest> {
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let mut host = parts
        .uri
        .authority()
        .map(|value| value.as_str().to_string())
        .unwrap_or_default();
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        let value = value
            .to_str()
            .context("decode XHTTP h2 header value")?
            .trim()
            .to_string();
        if name.as_str().eq_ignore_ascii_case("host") && host.is_empty() {
            host = value.clone();
        }
        headers.push((name.as_str().to_string(), value));
    }

    Ok(XhttpRequest {
        method: parts.method.as_str().to_string(),
        path,
        host,
        version: "HTTP/2".to_string(),
        headers,
    })
}

fn h2_header_bytes_len(request: &XhttpRequest) -> usize {
    request.method.len()
        + request.path.len()
        + request.host.len()
        + request.version.len()
        + request
            .headers
            .iter()
            .map(|(key, value)| key.len() + value.len() + 4)
            .sum::<usize>()
}

async fn read_h2_uplink_payload(
    body: h2::RecvStream,
    request: XhttpRequest,
    body_kind: RequestBodyKind,
    config: &XhttpConfig,
) -> Result<Vec<u8>, UplinkPayloadError> {
    let mut reader = H2BodyReader::new(body);
    let parsed = ParsedRequestHead {
        request,
        buffered_body: Vec::new(),
        body_kind,
    };
    let (payload, _) = read_uplink_payload(&mut reader, &parsed, config).await?;
    Ok(payload)
}

async fn respond_h2_empty_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    code: u16,
) -> anyhow::Result<()> {
    let response = http::Response::builder()
        .status(code)
        .header("content-length", "0")
        .body(())
        .context("build XHTTP h2 status response")?;
    respond
        .send_response(response, true)
        .context("write XHTTP h2 status response")?;
    Ok(())
}

async fn respond_h2_options(
    respond: &mut h2::server::SendResponse<Bytes>,
    config: &XhttpConfig,
    request: &XhttpRequest,
    allow_credentials: bool,
) -> anyhow::Result<()> {
    let mut builder = build_h2_response(config, request, 200, allow_credentials);
    if let Some(method) = request.header("Access-Control-Request-Method") {
        builder = builder.header("access-control-allow-methods", method);
    } else {
        builder = builder.header("access-control-allow-methods", "*");
    }
    if let Some(headers) = request.header("Access-Control-Request-Headers") {
        builder = builder.header("access-control-allow-headers", headers);
    } else {
        builder = builder.header("access-control-allow-headers", "*");
    }
    let response = builder
        .header("content-length", "0")
        .body(())
        .context("build XHTTP h2 preflight response")?;
    respond
        .send_response(response, true)
        .context("write XHTTP h2 preflight response")?;
    Ok(())
}

async fn respond_h2_upload_ack(
    respond: &mut h2::server::SendResponse<Bytes>,
    config: &XhttpConfig,
    request: &XhttpRequest,
    allow_credentials: bool,
) -> anyhow::Result<()> {
    let response = build_h2_response(config, request, 200, allow_credentials)
        .header("cache-control", "no-store")
        .header("content-length", "0")
        .body(())
        .context("build XHTTP h2 upload response")?;
    respond
        .send_response(response, true)
        .context("write XHTTP h2 upload response")?;
    Ok(())
}

async fn respond_h2_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    config: &XhttpConfig,
    request: &XhttpRequest,
    code: u16,
    allow_credentials: bool,
) -> anyhow::Result<()> {
    let response = build_h2_response(config, request, code, allow_credentials)
        .header("content-length", "0")
        .body(())
        .with_context(|| format!("build XHTTP h2 {code} response"))?;
    respond
        .send_response(response, true)
        .with_context(|| format!("write XHTTP h2 {code} response"))?;
    Ok(())
}

async fn pump_h2_response_body(
    mut respond: h2::server::SendResponse<Bytes>,
    mut response_source: DuplexStream,
    config: XhttpConfig,
    request: XhttpRequest,
    use_sse_header: bool,
    allow_credentials: bool,
) -> anyhow::Result<()> {
    let mut sender = send_h2_stream_response_head(
        &mut respond,
        &config,
        &request,
        use_sse_header,
        allow_credentials,
    )?;
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = response_source
            .read(&mut buffer)
            .await
            .context("read XHTTP h2 response payload")?;
        if read == 0 {
            send_h2_data(&mut sender, Bytes::new(), true)
                .await
                .context("write XHTTP h2 response trailer")?;
            return Ok(());
        }

        send_h2_data(&mut sender, Bytes::copy_from_slice(&buffer[..read]), false)
            .await
            .context("write XHTTP h2 response payload")?;
    }
}

fn send_h2_stream_response_head(
    respond: &mut h2::server::SendResponse<Bytes>,
    config: &XhttpConfig,
    request: &XhttpRequest,
    use_sse_header: bool,
    allow_credentials: bool,
) -> anyhow::Result<h2::SendStream<Bytes>> {
    let mut builder = build_h2_response(config, request, 200, allow_credentials)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no");
    if use_sse_header {
        builder = builder.header("content-type", "text/event-stream");
    }
    let response = builder.body(()).context("build XHTTP h2 stream response")?;
    respond
        .send_response(response, false)
        .context("write XHTTP h2 stream response headers")
}

async fn send_h2_data(
    sender: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_of_stream: bool,
) -> anyhow::Result<()> {
    if data.is_empty() {
        sender
            .send_data(data, end_of_stream)
            .context("write XHTTP h2 empty data frame")?;
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < data.len() {
        sender.reserve_capacity(data.len() - offset);
        let capacity = poll_fn(|cx| sender.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("XHTTP h2 response stream closed"))?
            .context("reserve XHTTP h2 response capacity")?;
        if capacity == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        let take = capacity.min(data.len() - offset);
        let end = end_of_stream && offset + take == data.len();
        sender
            .send_data(data.slice(offset..offset + take), end)
            .context("write XHTTP h2 data frame")?;
        offset += take;
    }
    Ok(())
}

fn build_h2_response(
    config: &XhttpConfig,
    request: &XhttpRequest,
    code: u16,
    allow_credentials: bool,
) -> http::response::Builder {
    let mut builder = http::Response::builder().status(code);
    for (name, value) in response_header_pairs(config, request, allow_credentials) {
        builder = builder.header(name.to_ascii_lowercase(), value);
    }
    builder
}

#[derive(Debug)]
enum UplinkPayloadError {
    BadRequest,
    PayloadTooLarge,
}

impl From<anyhow::Error> for UplinkPayloadError {
    fn from(_: anyhow::Error) -> Self {
        Self::BadRequest
    }
}

async fn read_request_head_with_limit<S>(
    stream: &mut S,
    header_bytes_limit: usize,
) -> anyhow::Result<ParsedRequestHead>
where
    S: AsyncRead + Unpin,
{
    let HttpParsedRequestHead {
        request,
        buffered_body,
    } = read_http_request_head_with_limit(stream, header_bytes_limit).await?;
    let mut content_length = None;
    let mut chunked = false;

    for (key, value) in &request.headers {
        if key.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .with_context(|| format!("invalid XHTTP Content-Length {value}"))?,
            );
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("chunked"));
        }
    }

    let body_kind = if chunked {
        RequestBodyKind::Chunked
    } else if let Some(length) = content_length {
        RequestBodyKind::Fixed(length)
    } else {
        RequestBodyKind::Empty
    };

    Ok(ParsedRequestHead {
        request,
        buffered_body,
        body_kind,
    })
}

async fn read_uplink_payload<R>(
    reader: &mut R,
    parsed: &ParsedRequestHead,
    config: &XhttpConfig,
) -> Result<(Vec<u8>, Vec<u8>), UplinkPayloadError>
where
    R: AsyncRead + Unpin,
{
    let mut payload = Vec::new();
    let mut next_prefix = parsed.buffered_body.clone();

    if matches!(
        config.uplink_data_placement,
        UplinkDataPlacement::Auto | UplinkDataPlacement::Header
    ) {
        payload.extend(read_header_payload(
            &parsed.request,
            &config.uplink_data_key,
        )?);
    }
    if matches!(
        config.uplink_data_placement,
        UplinkDataPlacement::Auto | UplinkDataPlacement::Cookie
    ) {
        payload.extend(read_cookie_payload(
            &parsed.request,
            &config.uplink_data_key,
        )?);
    }
    if matches!(
        config.uplink_data_placement,
        UplinkDataPlacement::Auto | UplinkDataPlacement::Body
    ) {
        let (body, remaining) = read_body_bytes(
            reader,
            parsed.buffered_body.clone(),
            parsed.body_kind,
            config.sc_max_each_post_bytes,
        )
        .await?;
        payload.extend(body);
        next_prefix = remaining;
    }
    if payload.len() > config.sc_max_each_post_bytes {
        return Err(UplinkPayloadError::PayloadTooLarge);
    }

    Ok((payload, next_prefix))
}

async fn read_body_bytes<R>(
    reader: &mut R,
    mut buffered_body: Vec<u8>,
    body_kind: RequestBodyKind,
    max_payload_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), UplinkPayloadError>
where
    R: AsyncRead + Unpin,
{
    match body_kind {
        RequestBodyKind::Empty => Ok((Vec::new(), buffered_body)),
        RequestBodyKind::Fixed(mut remaining) => {
            if remaining > max_payload_len {
                return Err(UplinkPayloadError::PayloadTooLarge);
            }
            let mut payload = Vec::with_capacity(remaining.max(buffered_body.len()));
            if !buffered_body.is_empty() {
                let take = buffered_body.len().min(remaining);
                payload.extend_from_slice(&buffered_body[..take]);
                buffered_body.drain(..take);
                remaining -= take;
            }

            let mut buffer = [0u8; COPY_BUFFER_LEN];
            while remaining > 0 {
                let chunk_len = remaining.min(buffer.len());
                let read = reader
                    .read(&mut buffer[..chunk_len])
                    .await
                    .context("read XHTTP request body")?;
                if read == 0 {
                    return Err(anyhow!("unexpected EOF in XHTTP request body").into());
                }
                payload.extend_from_slice(&buffer[..read]);
                remaining -= read;
            }
            Ok((payload, buffered_body))
        }
        RequestBodyKind::Chunked => read_chunked_body(reader, buffered_body, max_payload_len).await,
        RequestBodyKind::UntilEnd => {
            let mut payload = buffered_body;
            let mut buffer = [0u8; COPY_BUFFER_LEN];
            loop {
                if payload.len() > max_payload_len {
                    return Err(UplinkPayloadError::PayloadTooLarge);
                }
                let read = reader
                    .read(&mut buffer)
                    .await
                    .context("read XHTTP request body")?;
                if read == 0 {
                    return Ok((payload, Vec::new()));
                }
                if payload.len() + read > max_payload_len {
                    return Err(UplinkPayloadError::PayloadTooLarge);
                }
                payload.extend_from_slice(&buffer[..read]);
            }
        }
    }
}

async fn read_chunked_body<R>(
    reader: &mut R,
    mut buffered: Vec<u8>,
    max_payload_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), UplinkPayloadError>
where
    R: AsyncRead + Unpin,
{
    let mut payload = Vec::new();
    let mut offset = 0usize;
    loop {
        let line = read_line(reader, &mut buffered, &mut offset).await?;
        let size = usize::from_str_radix(
            line.split(';')
                .next()
                .ok_or_else(|| anyhow!("invalid XHTTP chunk header"))?
                .trim(),
            16,
        )
        .with_context(|| format!("invalid XHTTP chunk length {line}"))?;
        if size == 0 {
            loop {
                let trailer = read_line(reader, &mut buffered, &mut offset).await?;
                if trailer.is_empty() {
                    return Ok((payload, buffered[offset..].to_vec()));
                }
            }
        }

        if payload.len() + size > max_payload_len {
            return Err(UplinkPayloadError::PayloadTooLarge);
        }
        let start = payload.len();
        payload.resize(start + size, 0);
        read_exact(
            reader,
            &mut buffered,
            &mut offset,
            &mut payload[start..start + size],
        )
        .await?;

        let mut crlf = [0u8; 2];
        read_exact(reader, &mut buffered, &mut offset, &mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(UplinkPayloadError::BadRequest);
        }
    }
}

async fn pump_request_body<R, W>(
    mut reader: R,
    mut sink: W,
    mut buffered_body: Vec<u8>,
    body_kind: RequestBodyKind,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body_kind {
        RequestBodyKind::Empty => {}
        RequestBodyKind::Fixed(mut remaining) => {
            if !buffered_body.is_empty() {
                let take = buffered_body.len().min(remaining);
                write_pipe(&mut sink, &buffered_body[..take]).await?;
                buffered_body.drain(..take);
                remaining -= take;
            }
            let mut buffer = [0u8; COPY_BUFFER_LEN];
            while remaining > 0 {
                let chunk_len = remaining.min(buffer.len());
                let read = reader
                    .read(&mut buffer[..chunk_len])
                    .await
                    .context("read XHTTP request body")?;
                ensure!(read > 0, "unexpected EOF in XHTTP request body");
                write_pipe(&mut sink, &buffer[..read]).await?;
                remaining -= read;
            }
        }
        RequestBodyKind::Chunked => {
            pump_chunked_request_body(&mut reader, &mut sink, buffered_body).await?;
        }
        RequestBodyKind::UntilEnd => {
            if !buffered_body.is_empty() {
                write_pipe(&mut sink, &buffered_body).await?;
            }
            let mut buffer = [0u8; COPY_BUFFER_LEN];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .await
                    .context("read XHTTP request body")?;
                if read == 0 {
                    break;
                }
                write_pipe(&mut sink, &buffer[..read]).await?;
            }
        }
    }
    sink.shutdown().await.ok();
    Ok(())
}

async fn pump_chunked_request_body<R, W>(
    reader: &mut R,
    sink: &mut W,
    mut buffered: Vec<u8>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut offset = 0usize;
    loop {
        let line = read_line(reader, &mut buffered, &mut offset).await?;
        let size = usize::from_str_radix(
            line.split(';')
                .next()
                .ok_or_else(|| anyhow!("invalid XHTTP chunk header"))?
                .trim(),
            16,
        )
        .with_context(|| format!("invalid XHTTP chunk length {line}"))?;
        if size == 0 {
            loop {
                let trailer = read_line(reader, &mut buffered, &mut offset).await?;
                if trailer.is_empty() {
                    return Ok(());
                }
            }
        }

        let mut remaining = size;
        let mut chunk = vec![0u8; COPY_BUFFER_LEN.min(size.max(1))];
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            read_exact(reader, &mut buffered, &mut offset, &mut chunk[..take]).await?;
            write_pipe(sink, &chunk[..take]).await?;
            remaining -= take;
        }

        let mut crlf = [0u8; 2];
        read_exact(reader, &mut buffered, &mut offset, &mut crlf).await?;
        ensure!(&crlf == b"\r\n", "invalid XHTTP chunk terminator");
    }
}

async fn pump_response_body<W>(
    mut writer: W,
    mut response_source: DuplexStream,
    config: &XhttpConfig,
    request: &XhttpRequest,
    use_sse_header: bool,
    allow_credentials: bool,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&build_stream_response_head(
            config,
            request,
            use_sse_header,
            allow_credentials,
        ))
        .await
        .context("write XHTTP response headers")?;
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = response_source
            .read(&mut buffer)
            .await
            .context("read XHTTP response payload")?;
        if read == 0 {
            writer
                .write_all(b"0\r\n\r\n")
                .await
                .context("write XHTTP response trailer")?;
            writer.flush().await.ok();
            writer.shutdown().await.ok();
            return Ok(());
        }

        let head = format!("{read:X}\r\n");
        writer
            .write_all(head.as_bytes())
            .await
            .context("write XHTTP chunk head")?;
        writer
            .write_all(&buffer[..read])
            .await
            .context("write XHTTP chunk payload")?;
        writer
            .write_all(b"\r\n")
            .await
            .context("write XHTTP chunk tail")?;
        writer.flush().await.context("flush XHTTP response chunk")?;
    }
}

async fn respond_options<S>(
    config: &XhttpConfig,
    stream: &mut S,
    request: &XhttpRequest,
    allow_credentials: bool,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = String::from("HTTP/1.1 200 OK\r\n");
    append_response_headers(&mut response, config, request, allow_credentials);
    if let Some(method) = request.header("Access-Control-Request-Method") {
        response.push_str("Access-Control-Allow-Methods: ");
        response.push_str(method);
        response.push_str("\r\n");
    } else {
        response.push_str("Access-Control-Allow-Methods: *\r\n");
    }
    if let Some(headers) = request.header("Access-Control-Request-Headers") {
        response.push_str("Access-Control-Allow-Headers: ");
        response.push_str(headers);
        response.push_str("\r\n");
    } else {
        response.push_str("Access-Control-Allow-Headers: *\r\n");
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .await
        .context("write XHTTP preflight response")?;
    Ok(())
}

async fn respond_upload_ack<S>(
    config: &XhttpConfig,
    stream: &mut S,
    request: &XhttpRequest,
    allow_credentials: bool,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = String::from("HTTP/1.1 200 OK\r\n");
    append_response_headers(&mut response, config, request, allow_credentials);
    response.push_str("Cache-Control: no-store\r\nContent-Length: 0\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .await
        .context("write XHTTP upload response")?;
    Ok(())
}

async fn respond_status<S>(
    config: &XhttpConfig,
    stream: &mut S,
    request: &XhttpRequest,
    code: u16,
    reason: &str,
    allow_credentials: bool,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = format!("HTTP/1.1 {code} {reason}\r\n");
    append_response_headers(&mut response, config, request, allow_credentials);
    response.push_str("Connection: close\r\nContent-Length: 0\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .await
        .with_context(|| format!("write XHTTP {code} response"))?;
    stream.shutdown().await.ok();
    Ok(())
}

async fn close_response<S>(stream: &mut S) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.flush().await.ok();
    stream.shutdown().await.ok();
    Ok(())
}

fn request_body_is_empty(body_kind: RequestBodyKind) -> bool {
    match body_kind {
        RequestBodyKind::Empty => true,
        RequestBodyKind::Fixed(len) => len == 0,
        RequestBodyKind::Chunked => false,
        RequestBodyKind::UntilEnd => false,
    }
}

fn can_keep_alive_after_packet_upload(config: &XhttpConfig, body_kind: RequestBodyKind) -> bool {
    request_body_is_empty(body_kind)
        || matches!(
            config.uplink_data_placement,
            UplinkDataPlacement::Auto | UplinkDataPlacement::Body
        )
}

fn build_stream_response_head(
    config: &XhttpConfig,
    request: &XhttpRequest,
    use_sse_header: bool,
    allow_credentials: bool,
) -> Vec<u8> {
    let mut response = String::from("HTTP/1.1 200 OK\r\n");
    append_response_headers(&mut response, config, request, allow_credentials);
    response.push_str("Cache-Control: no-store\r\n");
    response.push_str("X-Accel-Buffering: no\r\n");
    if use_sse_header {
        response.push_str("Content-Type: text/event-stream\r\n");
    }
    response.push_str("Transfer-Encoding: chunked\r\n\r\n");
    response.into_bytes()
}

fn append_response_headers(
    response: &mut String,
    config: &XhttpConfig,
    request: &XhttpRequest,
    allow_credentials: bool,
) {
    for (name, value) in response_header_pairs(config, request, allow_credentials) {
        response.push_str(&name);
        response.push_str(": ");
        response.push_str(&value);
        response.push_str("\r\n");
    }
}

fn response_header_pairs(
    config: &XhttpConfig,
    request: &XhttpRequest,
    allow_credentials: bool,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(origin) = request.header("Origin") {
        headers.push((
            "Access-Control-Allow-Origin".to_string(),
            origin.to_string(),
        ));
    } else {
        headers.push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));
    }
    if allow_credentials {
        headers.push((
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        ));
    }
    if let Some(header) = x_padding_response_header(config) {
        headers.push(header);
    }
    headers
}

async fn write_pipe<W>(pipe: &mut W, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    pipe.write_all(payload)
        .await
        .context("write XHTTP payload into VLESS pipe")
}

async fn read_line<R>(
    reader: &mut R,
    buffered: &mut Vec<u8>,
    offset: &mut usize,
) -> anyhow::Result<String>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = find_crlf(&buffered[*offset..]) {
            let end = *offset + position;
            let line = std::str::from_utf8(&buffered[*offset..end])
                .context("decode XHTTP chunk header")?
                .to_string();
            *offset = end + 2;
            compact_buffer(buffered, offset);
            return Ok(line);
        }

        let mut buffer = [0u8; 2048];
        let read = reader
            .read(&mut buffer)
            .await
            .context("read XHTTP chunk line")?;
        ensure!(read > 0, "unexpected EOF in XHTTP chunk line");
        buffered.extend_from_slice(&buffer[..read]);
    }
}

async fn read_exact<R>(
    reader: &mut R,
    buffered: &mut Vec<u8>,
    offset: &mut usize,
    out: &mut [u8],
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0usize;
    while filled < out.len() {
        if *offset < buffered.len() {
            let available = (buffered.len() - *offset).min(out.len() - filled);
            out[filled..filled + available]
                .copy_from_slice(&buffered[*offset..*offset + available]);
            *offset += available;
            filled += available;
            compact_buffer(buffered, offset);
            continue;
        }

        let read = reader
            .read(&mut out[filled..])
            .await
            .context("read XHTTP chunk payload")?;
        ensure!(read > 0, "unexpected EOF in XHTTP chunk payload");
        filled += read;
    }
    Ok(())
}

fn compact_buffer(buffered: &mut Vec<u8>, offset: &mut usize) {
    if *offset == buffered.len() {
        buffered.clear();
        *offset = 0;
    } else if *offset > 0 && *offset >= buffered.len() / 2 {
        buffered.drain(..*offset);
        *offset = 0;
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn normalize_mode(value: &str) -> anyhow::Result<String> {
    let mode = value.trim().to_ascii_lowercase();
    if mode.is_empty() {
        return Ok("auto".to_string());
    }
    ensure!(
        matches!(
            mode.as_str(),
            "auto" | "packet-up" | "stream-up" | "stream-one"
        ),
        "unsupported XHTTP mode {mode}"
    );
    Ok(mode)
}

fn normalize_method(value: &str) -> String {
    let method = value.trim();
    if method.is_empty() {
        "POST".to_string()
    } else {
        method.to_ascii_uppercase()
    }
}

fn default_session_key(placement: Placement) -> &'static str {
    match placement {
        Placement::Header => "X-Session",
        Placement::Cookie | Placement::Query => "x_session",
        Placement::Path => "",
    }
}

fn default_seq_key(placement: Placement) -> &'static str {
    match placement {
        Placement::Header => "X-Seq",
        Placement::Cookie | Placement::Query => "x_seq",
        Placement::Path => "",
    }
}

fn default_uplink_data_key(placement: UplinkDataPlacement) -> &'static str {
    match placement {
        UplinkDataPlacement::Cookie => "x_data",
        UplinkDataPlacement::Auto | UplinkDataPlacement::Header => "X-Data",
        UplinkDataPlacement::Body => "",
    }
}

fn split_request_target(target: &str) -> (&str, &str) {
    target
        .split_once('?')
        .map_or((target, ""), |(path, query)| (path, query))
}

fn suffix_segments(base_path: &str, request_path: &str) -> Vec<String> {
    let request_path = normalize_path(request_path.trim());
    let suffix = if base_path == "/" {
        request_path.as_str()
    } else {
        request_path.strip_prefix(base_path).unwrap_or("")
    };
    suffix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        values.insert(percent_decode(key), percent_decode(value));
    }
    values
}

fn parse_cookies(header: Option<&str>) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    let Some(header) = header else {
        return cookies;
    };

    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        cookies.insert(name.trim().to_string(), value.trim().to_string());
    }
    cookies
}

fn request_query_value(request: &XhttpRequest, key: &str) -> String {
    let (_, query) = split_request_target(&request.path);
    let mut values = parse_query(query);
    values.remove(key).unwrap_or_default()
}

fn url_like_query_value(value: &str, key: &str) -> String {
    let Some((_, query)) = value.trim().split_once('?') else {
        return String::new();
    };
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    let mut values = parse_query(query);
    values.remove(key).unwrap_or_default()
}

fn is_x_padding_valid(padding: &str, valid_range: Range, method: XPaddingMethod) -> bool {
    if padding.is_empty() {
        return false;
    }

    match method {
        XPaddingMethod::RepeatX => {
            let len = padding.len();
            len >= valid_range.min && len <= valid_range.max
        }
        XPaddingMethod::Tokenish => {
            let len = hpack_huffman_encoded_len(padding.as_bytes());
            let min = valid_range
                .min
                .saturating_sub(TOKENISH_VALIDATION_TOLERANCE);
            let max = valid_range
                .max
                .saturating_add(TOKENISH_VALIDATION_TOLERANCE);
            len >= min && len <= max
        }
    }
}

fn hpack_huffman_encoded_len(value: &[u8]) -> usize {
    let total_bits: usize = value
        .iter()
        .map(|byte| HPACK_HUFFMAN_CODE_LENGTHS[*byte as usize] as usize)
        .sum();
    total_bits.div_ceil(8)
}

fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

fn read_header_payload(request: &XhttpRequest, key: &str) -> anyhow::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let header_name = format!("{key}-{index}");
        let Some(chunk) = request.header(&header_name) else {
            break;
        };
        encoded.push_str(chunk.trim());
    }

    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode XHTTP header payload")
}

fn read_cookie_payload(request: &XhttpRequest, key: &str) -> anyhow::Result<Vec<u8>> {
    let cookies = parse_cookies(request.header("Cookie"));
    let mut encoded = String::new();
    for index in 0usize.. {
        let cookie_name = format!("{key}_{index}");
        let Some(chunk) = cookies.get(cookie_name.as_str()) else {
            break;
        };
        encoded.push_str(chunk.trim());
    }

    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode XHTTP cookie payload")
}

fn parse_extra(value: &Value) -> anyhow::Result<Option<Value>> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) if text.trim().is_empty() => Ok(None),
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(parsed) => Ok(Some(parsed)),
            Err(_) => Ok(Some(Value::String(text.clone()))),
        },
        other => Ok(Some(other.clone())),
    }
}

fn parse_headers(value: &Value) -> anyhow::Result<Vec<(String, String)>> {
    let Some(object) = value.as_object() else {
        bail!("XHTTP headers must be an object");
    };
    let mut headers = Vec::with_capacity(object.len());
    for (key, value) in object {
        let key = key.trim();
        ensure!(
            !key.is_empty(),
            "XHTTP headers cannot contain an empty name"
        );
        ensure!(
            !key.eq_ignore_ascii_case("host"),
            "XHTTP headers cannot contain Host"
        );
        let value = value
            .as_str()
            .ok_or_else(|| anyhow!("XHTTP header {key} must be a string"))?
            .trim()
            .to_string();
        headers.push((key.to_string(), value));
    }
    Ok(headers)
}

fn parse_positive_range_upper(value: &Value, field: &str) -> anyhow::Result<usize> {
    match value {
        Value::Number(number) => {
            let value = number
                .as_i64()
                .ok_or_else(|| anyhow!("XHTTP {field} must be an integer or range string"))?;
            ensure!(value >= 0, "XHTTP {field} cannot be negative");
            Ok(value as usize)
        }
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Ok(0);
            }
            let (left, right) = text
                .split_once('-')
                .map_or((text, text), |(left, right)| (left.trim(), right.trim()));
            let left = parse_non_negative_range_part(left, field)?;
            let right = parse_non_negative_range_part(right, field)?;
            Ok(left.max(right))
        }
        _ => bail!("XHTTP {field} must be an integer or range string"),
    }
}

fn parse_non_negative_range(value: &Value, field: &str) -> anyhow::Result<Range> {
    match value {
        Value::Number(number) => {
            let value = number
                .as_i64()
                .ok_or_else(|| anyhow!("XHTTP {field} must be an integer or range string"))?;
            ensure!(value >= 0, "XHTTP {field} cannot be negative");
            let value = value as usize;
            Ok(Range {
                min: value,
                max: value,
            })
        }
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Ok(Range { min: 0, max: 0 });
            }
            let (left, right) = text
                .split_once('-')
                .map_or((text, text), |(left, right)| (left.trim(), right.trim()));
            let left = parse_non_negative_range_part(left, field)?;
            let right = parse_non_negative_range_part(right, field)?;
            Ok(Range {
                min: left.min(right),
                max: left.max(right),
            })
        }
        _ => bail!("XHTTP {field} must be an integer or range string"),
    }
}

fn parse_non_negative_range_part(value: &str, field: &str) -> anyhow::Result<usize> {
    let value = value
        .parse::<i64>()
        .with_context(|| format!("invalid XHTTP {field} value {value}"))?;
    ensure!(value >= 0, "XHTTP {field} cannot be negative");
    Ok(value as usize)
}

fn parse_non_negative_usize(value: &Value, field: &str) -> anyhow::Result<usize> {
    let value = value
        .as_i64()
        .ok_or_else(|| anyhow!("XHTTP {field} must be an integer"))?;
    ensure!(value >= 0, "XHTTP {field} cannot be negative");
    Ok(value as usize)
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|error| {
            error.kind() == std::io::ErrorKind::BrokenPipe
                || error.kind() == std::io::ErrorKind::ConnectionReset
        })
}

fn x_padding_response_header(config: &XhttpConfig) -> Option<(String, String)> {
    let padding_len = config.x_padding_bytes.sample();
    if padding_len == 0 {
        return None;
    }
    let padding = generate_padding(config.x_padding_method, padding_len);
    if padding.is_empty() {
        return None;
    }

    let header = match if config.x_padding_obfs_mode {
        config.x_padding_placement
    } else {
        XPaddingPlacement::Header
    } {
        XPaddingPlacement::Header => {
            let header = if config.x_padding_obfs_mode && !config.x_padding_header.is_empty() {
                config.x_padding_header.as_str()
            } else {
                "X-Padding"
            };
            Some((header.to_string(), padding))
        }
        XPaddingPlacement::Cookie => {
            let key = if config.x_padding_key.is_empty() {
                "x_padding"
            } else {
                config.x_padding_key.as_str()
            };
            Some(("Set-Cookie".to_string(), format!("{key}={padding}; Path=/")))
        }
        XPaddingPlacement::Query => None,
        XPaddingPlacement::QueryInHeader => {
            let header = config.x_padding_header.as_str();
            let key = if config.x_padding_key.is_empty() {
                "x_padding"
            } else {
                config.x_padding_key.as_str()
            };
            Some((header.to_string(), format!("?{key}={padding}")))
        }
    };
    header
}

fn generate_padding(method: XPaddingMethod, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    match method {
        XPaddingMethod::RepeatX => "X".repeat(len),
        XPaddingMethod::Tokenish => generate_tokenish_padding(len),
    }
}

fn generate_tokenish_padding(len: usize) -> String {
    if len == 0 {
        return String::new();
    }

    let mut initial_len = len.saturating_mul(5).saturating_add(3) / 4;
    if initial_len == 0 {
        initial_len = 1;
    }

    let mut rng = rand::rng();
    let mut padding: String = (0..initial_len)
        .map(|_| {
            let index = rng.random_range(0..TOKENISH_BASE62_CHARSET.len());
            TOKENISH_BASE62_CHARSET[index] as char
        })
        .collect();
    let mut adjust_char = 'X';

    for _ in 0..TOKENISH_MAX_ADJUST_ITERATIONS {
        let current_len = hpack_huffman_encoded_len(padding.as_bytes());
        if current_len.abs_diff(len) <= TOKENISH_VALIDATION_TOLERANCE {
            return padding;
        }

        if current_len < len {
            padding.push(adjust_char);
            adjust_char = if adjust_char == 'X' { 'Z' } else { 'X' };
        } else if padding.len() > 1 {
            padding.pop();
        } else {
            return padding;
        }
    }

    padding
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn parses_xboard_network_settings() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "edge",
            "host": ["example.com:443", "cdn.example.com"],
            "mode": "packet-up",
            "extra": "{\"sessionPlacement\":\"header\",\"seqPlacement\":\"query\",\"uplinkDataPlacement\":\"cookie\",\"scMaxEachPostBytes\":\"64-128\",\"scMaxBufferedPosts\":7,\"serverMaxHeaderBytes\":4096,\"scStreamUpServerSecs\":\"2-4\",\"xPaddingBytes\":\"8-12\",\"xPaddingObfsMode\":true,\"xPaddingKey\":\"pad\",\"xPaddingHeader\":\"X-Pad\",\"xPaddingPlacement\":\"cookie\",\"xPaddingMethod\":\"tokenish\",\"headers\":{\"X-Test\":\"yes\"}}"
        })))
        .expect("parse config");

        assert_eq!(config.path, "/edge");
        assert_eq!(
            config.hosts,
            vec!["example.com".to_string(), "cdn.example.com".to_string()]
        );
        assert_eq!(config.mode, "packet-up");
        assert_eq!(config.session_placement, Placement::Header);
        assert_eq!(config.seq_placement, Placement::Query);
        assert_eq!(config.uplink_data_placement, UplinkDataPlacement::Cookie);
        assert_eq!(config.session_key, "X-Session");
        assert_eq!(config.seq_key, "x_seq");
        assert_eq!(config.uplink_data_key, "x_data");
        assert_eq!(
            config.headers,
            vec![("X-Test".to_string(), "yes".to_string())]
        );
        assert_eq!(config.sc_max_each_post_bytes, 128);
        assert_eq!(config.sc_max_buffered_posts, 7);
        assert_eq!(config.sc_stream_up_server_secs, Range { min: 2, max: 4 });
        assert_eq!(config.x_padding_bytes, Range { min: 8, max: 12 });
        assert!(config.x_padding_obfs_mode);
        assert_eq!(config.x_padding_key, "pad");
        assert_eq!(config.x_padding_header, "X-Pad");
        assert_eq!(config.x_padding_placement, XPaddingPlacement::Cookie);
        assert_eq!(config.x_padding_method, XPaddingMethod::Tokenish);
        assert_eq!(config.server_max_header_bytes, 4096);
    }

    #[test]
    fn parses_snake_case_network_settings_aliases() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "edge",
            "mode": "packet-up",
            "session_placement": "header",
            "session_key": "X-Sid",
            "seq_placement": "query",
            "seq_key": "seq",
            "uplink_http_method": "GET",
            "uplink_data_placement": "header",
            "uplink_data_key": "data",
            "x_padding_bytes": "4-8",
            "x_padding_obfs_mode": "true",
            "x_padding_key": "pad",
            "x_padding_header": "X-Pad",
            "x_padding_placement": "header",
            "x_padding_method": "repeat-x",
            "no_sse_header": 1,
            "sc_max_each_post_bytes": 64,
            "sc_max_buffered_posts": 3,
            "sc_stream_up_server_secs": "1-2",
            "server_max_header_bytes": 2048
        })))
        .expect("parse snake case config");

        assert_eq!(config.session_placement, Placement::Header);
        assert_eq!(config.session_key, "X-Sid");
        assert_eq!(config.seq_placement, Placement::Query);
        assert_eq!(config.seq_key, "seq");
        assert_eq!(config.uplink_http_method, "GET");
        assert_eq!(config.uplink_data_placement, UplinkDataPlacement::Header);
        assert_eq!(config.uplink_data_key, "data");
        assert_eq!(config.x_padding_bytes, Range { min: 4, max: 8 });
        assert!(config.x_padding_obfs_mode);
        assert_eq!(config.x_padding_key, "pad");
        assert_eq!(config.x_padding_header, "X-Pad");
        assert_eq!(config.x_padding_placement, XPaddingPlacement::Header);
        assert_eq!(config.x_padding_method, XPaddingMethod::RepeatX);
        assert!(config.no_sse_header);
        assert_eq!(config.sc_max_each_post_bytes, 64);
        assert_eq!(config.sc_max_buffered_posts, 3);
        assert_eq!(config.sc_stream_up_server_secs, Range { min: 1, max: 2 });
        assert_eq!(config.server_max_header_bytes, 2048);
    }

    #[test]
    fn tokenish_padding_generation_matches_hpack_length_tolerance() {
        for len in [1usize, 4, 16, 64] {
            let padding = generate_padding(XPaddingMethod::Tokenish, len);
            assert!(is_x_padding_valid(
                &padding,
                Range { min: len, max: len },
                XPaddingMethod::Tokenish,
            ));
        }
    }

    #[test]
    fn request_padding_supports_query_in_header_obfs() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "extra": {
                "xPaddingBytes": 4,
                "xPaddingObfsMode": true,
                "xPaddingPlacement": "query-in-header",
                "xPaddingHeader": "X-Pad",
                "xPaddingKey": "pad"
            }
        })))
        .expect("parse config");

        let request = XhttpRequest {
            method: "POST".to_string(),
            path: "/xhttp".to_string(),
            host: "example.com".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("X-Pad".to_string(), "?pad=XXXX".to_string())],
        };

        assert!(config.has_valid_request_x_padding(&request));
    }

    #[tokio::test]
    async fn stream_responses_include_cookie_padding_and_cors_credentials() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "extra": {
                "headers": {
                    "X-Test": "yes"
                },
                "xPaddingBytes": 4,
                "xPaddingObfsMode": true,
                "xPaddingPlacement": "cookie",
                "xPaddingKey": "pad"
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(server, &config).await.expect("accept")
            else {
                panic!("expected XHTTP stream");
            };

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp HTTP/1.1\r\nHost: example.com\r\nCookie: pad=XXXX\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .expect("write request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        server_task.await.expect("join server task");

        let response = String::from_utf8(response).expect("utf8 response");
        assert!(response.contains("Set-Cookie: pad="));
        assert!(response.contains("Access-Control-Allow-Credentials: true\r\n"));
    }

    #[test]
    fn stream_responses_support_query_in_header_padding() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "extra": {
                "xPaddingBytes": 4,
                "xPaddingObfsMode": true,
                "xPaddingPlacement": "query-in-header",
                "xPaddingHeader": "X-Pad",
                "xPaddingKey": "pad"
            }
        })))
        .expect("parse config");

        let request = XhttpRequest {
            method: "GET".to_string(),
            path: "/xhttp/session".to_string(),
            host: "example.com".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
        };

        let response =
            String::from_utf8(build_stream_response_head(&config, &request, false, false))
                .expect("utf8 response");
        assert!(response.contains("X-Pad: ?pad=XXXX\r\n"));
        assert!(!response.contains("Set-Cookie:"));
    }

    #[tokio::test]
    async fn stream_up_referer_emits_keepalive_padding_chunk() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "stream-up",
            "extra": {
                "xPaddingBytes": 2,
                "scStreamUpServerSecs": 1
            }
        })))
        .expect("parse config");

        let download_config = config.clone();
        let upload_config = config.clone();
        let (download_client, download_server) = duplex(16384);
        let download_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(download_server, &download_config)
                .await
                .expect("accept download")
            else {
                panic!("expected XHTTP download stream");
            };

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let (upload_client, upload_server) = duplex(16384);
        let upload_task = tokio::spawn(async move {
            let result = accept(upload_server, &upload_config)
                .await
                .expect("accept upload");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Closed)
            ));
        });

        let mut download_client = download_client;
        download_client
            .write_all(
                b"GET /xhttp/session-keepalive?x_padding=XX HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .await
            .expect("write download request");

        let (mut upload_reader, mut upload_writer) = split(upload_client);
        upload_writer
            .write_all(
                b"POST /xhttp/session-keepalive HTTP/1.1\r\nHost: example.com\r\nReferer: https://ref.example/?x_padding=XX\r\nContent-Length: 5\r\n\r\nhe",
            )
            .await
            .expect("write upload request");
        let upload_response_task = tokio::spawn(async move {
            let mut upload_response = Vec::new();
            upload_reader
                .read_to_end(&mut upload_response)
                .await
                .expect("read upload response");
            upload_response
        });
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        upload_writer
            .write_all(b"llo")
            .await
            .expect("finish upload request");
        upload_writer
            .shutdown()
            .await
            .expect("shutdown upload client");

        let upload_response = upload_response_task
            .await
            .expect("join upload response task");
        upload_task.await.expect("join upload task");
        download_task.await.expect("join download task");

        let upload_response = String::from_utf8(upload_response).expect("utf8 upload response");
        assert!(upload_response.contains("2\r\nXX\r\n"));

        let mut download_response = Vec::new();
        download_client
            .read_to_end(&mut download_response)
            .await
            .expect("read download response");
        let download_response =
            String::from_utf8(download_response).expect("utf8 download response");
        assert!(download_response.ends_with("5\r\nworld\r\n0\r\n\r\n"));
    }

    #[test]
    fn rejects_packet_only_uplink_settings_outside_packet_up() {
        let uplink_data_error = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "mode": "stream-up",
            "extra": {
                "uplinkDataPlacement": "header"
            }
        })))
        .expect_err("reject non-packet uplinkDataPlacement");
        assert!(uplink_data_error.to_string().contains("packet-up mode"));

        let uplink_method_error = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "mode": "stream-one",
            "extra": {
                "uplinkHTTPMethod": "GET"
            }
        })))
        .expect_err("reject non-packet GET uplink method");
        assert!(uplink_method_error.to_string().contains("packet-up mode"));
    }

    #[tokio::test]
    async fn options_response_reflects_request_and_cookie_credentials() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "extra": {
                "sessionPlacement": "cookie"
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let result = accept(server, &config).await.expect("accept options");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Continue(_))
            ));
        });

        let mut client = client;
        client
            .write_all(
                b"OPTIONS /xhttp HTTP/1.1\r\nHost: example.com\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: X-Data-0\r\n\r\n",
            )
            .await
            .expect("write options request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read options response");
        server_task.await.expect("join options task");

        let response = String::from_utf8(response).expect("utf8 options response");
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("Access-Control-Allow-Origin: https://app.example"));
        assert!(response.contains("Access-Control-Allow-Credentials: true"));
        assert!(response.contains("Access-Control-Allow-Methods: POST"));
        assert!(response.contains("Access-Control-Allow-Headers: X-Data-0"));
    }

    #[tokio::test]
    async fn options_response_keeps_connection_open_for_next_request() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "packet-up",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let download_config = config.clone();
        let (client, server) = duplex(16384);
        let server_task = tokio::spawn(async move {
            let mut stream = PrefixedIo::new(server, Vec::new());
            let first = accept_prefixed(stream, &config)
                .await
                .expect("accept options");
            stream = match first {
                AcceptResult::Responded(ResponseState::Continue(stream)) => stream,
                _ => panic!("expected keep-alive options response"),
            };

            let AcceptResult::Stream(mut stream) = accept_prefixed(stream, &download_config)
                .await
                .expect("accept download")
            else {
                panic!("expected XHTTP stream after options");
            };

            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let mut client = client;
        client
            .write_all(
                b"OPTIONS /xhttp HTTP/1.1\r\nHost: example.com\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: GET\r\n\r\nGET /xhttp/session-opt?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .await
            .expect("write pipelined requests");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read pipelined response");
        server_task.await.expect("join options keep-alive task");

        let response = String::from_utf8(response).expect("utf8 response");
        assert!(
            response
                .contains("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://app.example")
        );
        assert!(response.contains("Transfer-Encoding: chunked"));
        assert!(response.ends_with("5\r\nworld\r\n0\r\n\r\n"));
    }

    #[tokio::test]
    async fn accepts_single_post_stream_and_writes_chunked_response() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "auto",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(server, &config).await.expect("accept")
            else {
                panic!("expected XHTTP stream");
            };

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .expect("write request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        server_task.await.expect("join server task");

        let response = String::from_utf8(response).expect("utf8 response");
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("Transfer-Encoding: chunked"));
        assert!(response.ends_with("5\r\nworld\r\n0\r\n\r\n"));
    }

    #[tokio::test]
    async fn decodes_chunked_request_body() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/v",
            "host": "example.com",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(server, &config).await.expect("accept")
            else {
                panic!("expected XHTTP stream");
            };

            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.expect("read body");
            assert_eq!(data, b"abcdef");
        });

        let mut client = client;
        client
            .write_all(
                b"POST /v?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
            )
            .await
            .expect("write chunked request");
        client.shutdown().await.expect("shutdown client");

        server_task.await.expect("join server task");
    }

    #[tokio::test]
    async fn bridges_packet_up_session_requests() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "packet-up",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let download_config = config.clone();
        let (download_client, download_server) = duplex(16384);
        let download_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(download_server, &download_config)
                .await
                .expect("accept download")
            else {
                panic!("expected XHTTP download stream");
            };

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let upload_config = config.clone();
        let (upload_client, upload_server) = duplex(16384);
        let upload_task = tokio::spawn(async move {
            let result = accept(upload_server, &upload_config)
                .await
                .expect("accept upload");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Continue(_))
            ));
        });

        let mut upload_client = upload_client;
        upload_client
            .write_all(
                b"POST /xhttp/session-1/0?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .expect("write upload request");
        let mut upload_response = Vec::new();
        upload_client
            .read_to_end(&mut upload_response)
            .await
            .expect("read upload response");
        assert!(
            String::from_utf8(upload_response)
                .expect("upload utf8")
                .contains("HTTP/1.1 200 OK")
        );

        let mut download_client = download_client;
        download_client
            .write_all(b"GET /xhttp/session-1?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write download request");
        let mut download_response = Vec::new();
        download_client
            .read_to_end(&mut download_response)
            .await
            .expect("read download response");
        let download_response = String::from_utf8(download_response).expect("download utf8");
        assert!(download_response.contains("HTTP/1.1 200 OK"));
        assert!(download_response.ends_with("5\r\nworld\r\n0\r\n\r\n"));

        upload_task.await.expect("join upload task");
        download_task.await.expect("join download task");
    }

    #[tokio::test]
    async fn packet_up_upload_ack_keeps_connection_open_for_next_request() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "packet-up",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let download_config = config.clone();
        let (client, server) = duplex(32768);
        let server_task = tokio::spawn(async move {
            let mut stream = PrefixedIo::new(server, Vec::new());
            let first = accept_prefixed(stream, &config)
                .await
                .expect("accept upload");
            stream = match first {
                AcceptResult::Responded(ResponseState::Continue(stream)) => stream,
                _ => panic!("expected keep-alive upload ack"),
            };

            let AcceptResult::Stream(mut stream) = accept_prefixed(stream, &download_config)
                .await
                .expect("accept download")
            else {
                panic!("expected XHTTP stream after upload ack");
            };

            let mut request = [0u8; 5];
            stream
                .read_exact(&mut request)
                .await
                .expect("read upload payload");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp/session-keep/0?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloGET /xhttp/session-keep?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .await
            .expect("write pipelined upload and download");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read pipelined response");
        server_task.await.expect("join upload keep-alive task");

        let response = String::from_utf8(response).expect("utf8 response");
        assert!(
            response
                .contains("Cache-Control: no-store\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK")
        );
        assert!(response.ends_with("5\r\nworld\r\n0\r\n\r\n"));
    }

    #[tokio::test]
    async fn bridges_packet_up_get_header_payload_requests() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "packet-up",
            "extra": {
                "xPaddingBytes": 4,
                "uplinkHTTPMethod": "GET",
                "uplinkDataPlacement": "header"
            }
        })))
        .expect("parse config");

        let download_config = config.clone();
        let (download_client, download_server) = duplex(16384);
        let download_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(download_server, &download_config)
                .await
                .expect("accept download")
            else {
                panic!("expected XHTTP download stream");
            };

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let upload_config = config.clone();
        let (upload_client, upload_server) = duplex(16384);
        let upload_task = tokio::spawn(async move {
            let result = accept(upload_server, &upload_config)
                .await
                .expect("accept upload");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Continue(_))
            ));
        });

        let mut upload_client = upload_client;
        upload_client
            .write_all(
                b"GET /xhttp/session-3/0?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nX-Data-0: aGVsbG8\r\n\r\n",
            )
            .await
            .expect("write upload request");
        let mut upload_response = Vec::new();
        upload_client
            .read_to_end(&mut upload_response)
            .await
            .expect("read upload response");
        assert!(
            String::from_utf8(upload_response)
                .expect("upload utf8")
                .contains("HTTP/1.1 200 OK")
        );

        let mut download_client = download_client;
        download_client
            .write_all(b"GET /xhttp/session-3?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write download request");
        let mut download_response = Vec::new();
        download_client
            .read_to_end(&mut download_response)
            .await
            .expect("read download response");
        let download_response = String::from_utf8(download_response).expect("download utf8");
        assert!(download_response.contains("HTTP/1.1 200 OK"));
        assert!(download_response.ends_with("5\r\nworld\r\n0\r\n\r\n"));

        upload_task.await.expect("join upload task");
        download_task.await.expect("join download task");
    }

    #[tokio::test]
    async fn packet_upload_rejects_payloads_exceeding_sc_max_each_post_bytes() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "packet-up",
            "extra": {
                "xPaddingBytes": 4,
                "uplinkDataPlacement": "auto",
                "scMaxEachPostBytes": 5
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let result = accept(server, &config)
                .await
                .expect("accept oversized upload");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Closed)
            ));
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp/session-oversized/0?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nX-Data-0: YWJj\r\nContent-Length: 3\r\n\r\ndef",
            )
            .await
            .expect("write oversized upload request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read oversized upload response");
        server_task.await.expect("join oversized upload task");

        let response = String::from_utf8(response).expect("utf8 oversized upload response");
        assert!(response.contains("HTTP/1.1 413 Payload Too Large"));
    }

    #[tokio::test]
    async fn rejects_requests_exceeding_server_max_header_bytes() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "extra": {
                "serverMaxHeaderBytes": 64
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let result = accept(server, &config)
                .await
                .expect("accept oversized headers");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Closed)
            ));
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp HTTP/1.1\r\nHost: example.com\r\nX-Long: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .expect("write oversized header request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read oversized header response");
        server_task.await.expect("join oversized header task");

        let response = String::from_utf8(response).expect("utf8 oversized header response");
        assert!(response.contains("HTTP/1.1 400 Bad Request"));
    }

    #[tokio::test]
    async fn bridges_stream_up_session_requests() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "stream-up",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let download_config = config.clone();
        let (download_client, download_server) = duplex(16384);
        let download_task = tokio::spawn(async move {
            let AcceptResult::Stream(mut stream) = accept(download_server, &download_config)
                .await
                .expect("accept download")
            else {
                panic!("expected XHTTP download stream");
            };

            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.expect("write response");
            stream.shutdown().await.expect("shutdown response");
        });

        let upload_config = config.clone();
        let (upload_client, upload_server) = duplex(16384);
        let upload_task = tokio::spawn(async move {
            let result = accept(upload_server, &upload_config)
                .await
                .expect("accept upload");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Closed)
            ));
        });

        let mut download_client = download_client;
        download_client
            .write_all(b"GET /xhttp/session-2?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write download request");

        let mut upload_client = upload_client;
        upload_client
            .write_all(
                b"POST /xhttp/session-2?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .expect("write upload request");
        upload_client
            .shutdown()
            .await
            .expect("shutdown upload client");

        let mut upload_response = Vec::new();
        upload_client
            .read_to_end(&mut upload_response)
            .await
            .expect("read upload response");
        assert!(
            String::from_utf8(upload_response)
                .expect("upload utf8")
                .contains("HTTP/1.1 200 OK")
        );

        let mut download_response = Vec::new();
        download_client
            .read_to_end(&mut download_response)
            .await
            .expect("read download response");
        let download_response = String::from_utf8(download_response).expect("download utf8");
        assert!(download_response.contains("HTTP/1.1 200 OK"));
        assert!(download_response.ends_with("5\r\nworld\r\n0\r\n\r\n"));

        upload_task.await.expect("join upload task");
        download_task.await.expect("join download task");
    }

    #[tokio::test]
    async fn stream_up_upload_response_omits_sse_header() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "mode": "stream-up",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let result = accept(server, &config)
                .await
                .expect("accept stream-up upload");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Closed)
            ));
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp/session-up?x_padding=XXXX HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .expect("write stream-up request");
        client.shutdown().await.expect("shutdown upload client");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read stream-up response");
        server_task.await.expect("join stream-up upload task");

        let response = String::from_utf8(response).expect("utf8 stream-up response");
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("Transfer-Encoding: chunked"));
        assert!(response.contains("X-Accel-Buffering: no"));
        assert!(!response.contains("Content-Type: text/event-stream"));
    }

    #[tokio::test]
    async fn rejects_requests_without_valid_x_padding() {
        let config = XhttpConfig::from_network_settings(Some(&serde_json::json!({
            "path": "/xhttp",
            "host": "example.com",
            "extra": {
                "xPaddingBytes": 4
            }
        })))
        .expect("parse config");

        let (client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let result = accept(server, &config)
                .await
                .expect("accept invalid padding request");
            assert!(matches!(
                result,
                AcceptResult::Responded(ResponseState::Closed)
            ));
        });

        let mut client = client;
        client
            .write_all(
                b"POST /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .expect("write invalid padding request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read invalid padding response");
        server_task.await.expect("join invalid padding task");

        let response = String::from_utf8(response).expect("utf8 invalid padding response");
        assert!(response.contains("HTTP/1.1 400 Bad Request"));
    }
}
