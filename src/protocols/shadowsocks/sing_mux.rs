use anyhow::{Context, bail, ensure};
use futures_util::StreamExt;
use rand::RngExt;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use tracing::warn;

use crate::accounting::SessionControl;

use super::super::shared::{routing, socksaddr::SocksAddr, traffic::TrafficRecorder, transport};
use super::{MultiplexConfig, SingMuxProtocol, copy_with_traffic};

pub(super) async fn handle_sing_mux_connection<R, W>(
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

pub(super) fn is_sing_mux_destination(destination: &SocksAddr) -> bool {
    const SING_MUX_DESTINATION: &str = concat!("sp.mux.sing", "-box.arpa");

    matches!(
        destination,
        SocksAddr::Domain(host, 444) if host.eq_ignore_ascii_case(SING_MUX_DESTINATION)
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

#[cfg(test)]
mod tests {
    use super::super::COPY_BUFFER_LEN;
    use super::*;
    use crate::accounting::{Accounting, SessionControl};
    use crate::protocols::shared::{routing, socksaddr::SocksAddr, traffic::TrafficRecorder};
    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
    use tokio::net::TcpListener;

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
