use anyhow::{Context as _, anyhow, bail, ensure};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::UdpSocket;

use crate::accounting::SessionControl;

use super::super::shared::{
    routing::RoutingTable, socksaddr::SocksAddr, traffic::TrafficRecorder, transport,
};

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x04;
const NETWORK_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

struct ClientPacket {
    destination: SocksAddr,
    payload: Vec<u8>,
    wire_len: usize,
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
    let socket = Arc::new(transport::bind_udp_socket().await?);
    let (reader, writer) = split(stream);
    let select_control = control.clone();

    let mut client_task = tokio::spawn({
        let socket = socket.clone();
        let control = control.clone();
        let routing = routing.clone();
        async move { relay_client_to_udp(reader, socket, control, upload, routing).await }
    });
    let mut server_task =
        tokio::spawn(async move { relay_udp_to_client(writer, socket, control, download).await });

    tokio::select! {
        _ = select_control.cancelled() => {
            client_task.abort();
            server_task.abort();
            Ok(())
        }
        result = &mut client_task => {
            server_task.abort();
            flatten_join(result)
        }
        result = &mut server_task => {
            client_task.abort();
            flatten_join(result)
        }
    }
}

async fn relay_client_to_udp<R>(
    mut reader: ReadHalf<R>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
    routing: RoutingTable,
) -> anyhow::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut destination_cache = HashMap::new();
    let mut current_destination = None;
    loop {
        let packet = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            packet = read_client_packet(&mut reader, &mut current_destination) => packet?,
        };
        let Some(packet) = packet else {
            return Ok(());
        };

        let target =
            resolve_udp_target(&packet.destination, &routing, &mut destination_cache).await?;
        let target = transport::normalize_udp_target(&socket, target);
        traffic.limit(packet.wire_len as u64, &control).await;
        if control.is_cancelled() {
            return Ok(());
        }
        let sent = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            sent = socket.send_to(&packet.payload, target) => sent.with_context(|| format!("send XUDP payload to {target}"))?,
        };
        ensure!(
            sent == packet.payload.len(),
            "short XUDP UDP send: expected {}, wrote {}",
            packet.payload.len(),
            sent
        );
        traffic.record(packet.wire_len as u64);
    }
}

async fn relay_udp_to_client<W>(
    mut writer: WriteHalf<W>,
    socket: Arc<UdpSocket>,
    control: Arc<SessionControl>,
    traffic: TrafficRecorder,
) -> anyhow::Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (payload_len, source) = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = socket.recv_from(&mut buffer) => read.context("receive XUDP UDP payload")?,
        };
        let encoded = encode_response_packet(
            &SocksAddr::Ip(transport::normalize_udp_source(source)),
            &buffer[..payload_len],
        )?;
        traffic.limit(encoded.len() as u64, &control).await;
        if control.is_cancelled() {
            return Ok(());
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&encoded) => result.context("write XUDP response")?,
        }
        traffic.record(encoded.len() as u64);
    }
}

async fn read_client_packet<R>(
    reader: &mut R,
    current_destination: &mut Option<SocksAddr>,
) -> anyhow::Result<Option<ClientPacket>>
where
    R: AsyncRead + Unpin,
{
    let Some(metadata_len) = read_length_or_eof(reader, "read XUDP metadata length").await? else {
        return Ok(None);
    };
    ensure!(
        metadata_len >= 4,
        "short XUDP metadata length {metadata_len}"
    );

    let mut metadata = vec![0u8; metadata_len as usize];
    reader
        .read_exact(&mut metadata)
        .await
        .context("read XUDP metadata")?;
    let payload_len = read_u16(reader, "read XUDP payload length").await? as usize;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read XUDP payload")?;

    let status = metadata[2];
    if status == STATUS_END {
        return Ok(None);
    }
    ensure!(
        status == STATUS_NEW || status == STATUS_KEEP,
        "unsupported XUDP status {status:#x}"
    );

    let destination = if metadata.len() > 4 {
        ensure!(
            metadata[4] == NETWORK_UDP,
            "unsupported XUDP network type {}",
            metadata[4]
        );
        let (destination, consumed) = parse_destination(&metadata[5..])?;
        let trailing = metadata.len() - 5 - consumed;
        ensure!(
            trailing == 0 || trailing == 8,
            "unsupported XUDP metadata tail length {trailing}"
        );
        *current_destination = Some(destination.clone());
        destination
    } else {
        current_destination
            .clone()
            .ok_or_else(|| anyhow!("XUDP packet is missing destination metadata"))?
    };

    Ok(Some(ClientPacket {
        destination,
        payload,
        wire_len: 2 + metadata.len() + 2 + payload_len,
    }))
}

fn encode_response_packet(source: &SocksAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        bail!("XUDP payload too large: {}", payload.len());
    }

    let mut metadata = vec![0u8, 0u8, STATUS_KEEP, 0x01, NETWORK_UDP];
    write_destination(&mut metadata, source)?;

    let mut encoded = Vec::with_capacity(2 + metadata.len() + 2 + payload.len());
    encoded.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&metadata);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

async fn resolve_udp_target(
    destination: &SocksAddr,
    routing: &RoutingTable,
    cache: &mut HashMap<String, SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    let cache_key = destination.to_string();
    if let Some(target) = cache.get(&cache_key) {
        return Ok(*target);
    }
    let target = transport::resolve_destination(destination, routing, "udp")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no UDP addresses resolved for {destination}"))?;
    cache.insert(cache_key, target);
    Ok(target)
}

fn parse_destination(bytes: &[u8]) -> anyhow::Result<(SocksAddr, usize)> {
    ensure!(!bytes.is_empty(), "missing XUDP address type");
    match bytes[0] {
        ATYP_IPV4 => {
            ensure!(bytes.len() >= 7, "short XUDP IPv4 destination");
            Ok((
                SocksAddr::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4])),
                    u16::from_be_bytes([bytes[5], bytes[6]]),
                )),
                7,
            ))
        }
        ATYP_IPV6 => {
            ensure!(bytes.len() >= 19, "short XUDP IPv6 destination");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            Ok((
                SocksAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    u16::from_be_bytes([bytes[17], bytes[18]]),
                )),
                19,
            ))
        }
        ATYP_DOMAIN => {
            ensure!(bytes.len() >= 2, "short XUDP domain destination");
            let len = bytes[1] as usize;
            ensure!(bytes.len() >= 2 + len + 2, "short XUDP domain destination");
            Ok((
                SocksAddr::Domain(
                    String::from_utf8(bytes[2..2 + len].to_vec()).context("decode XUDP domain")?,
                    u16::from_be_bytes([bytes[2 + len], bytes[3 + len]]),
                ),
                2 + len + 2,
            ))
        }
        other => bail!("unsupported XUDP address type {other:#x}"),
    }
}

fn write_destination(buffer: &mut Vec<u8>, destination: &SocksAddr) -> anyhow::Result<()> {
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
            ensure!(host.len() <= u8::MAX as usize, "XUDP domain too long");
            buffer.push(ATYP_DOMAIN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host);
        }
    }
    let port = match destination {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());
    Ok(())
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

fn flatten_join(result: Result<anyhow::Result<()>, tokio::task::JoinError>) -> anyhow::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error).context("join VLESS XUDP relay task"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_request_packet(
        status: u8,
        destination: Option<&SocksAddr>,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut metadata = vec![0u8, 0u8, status, 0x01];
        if let Some(destination) = destination {
            metadata.push(NETWORK_UDP);
            write_destination(&mut metadata, destination)?;
        }
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&metadata);
        encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        encoded.extend_from_slice(payload);
        Ok(encoded)
    }

    #[tokio::test]
    async fn reads_new_packet_destination_and_payload() {
        let destination = SocksAddr::Domain("example.com".to_string(), 53);
        let encoded =
            encode_request_packet(STATUS_NEW, Some(&destination), b"hello").expect("encode");
        let packet = read_client_packet(&mut encoded.as_slice(), &mut None)
            .await
            .expect("read packet")
            .expect("packet");
        assert_eq!(packet.destination, destination);
        assert_eq!(packet.payload, b"hello");
    }

    #[tokio::test]
    async fn reads_keep_packet_with_cached_destination() {
        let destination = SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 443)));
        let mut current_destination = Some(destination.clone());
        let encoded = encode_request_packet(STATUS_KEEP, None, b"abc").expect("encode");
        let packet = read_client_packet(&mut encoded.as_slice(), &mut current_destination)
            .await
            .expect("read packet")
            .expect("packet");
        assert_eq!(packet.destination, destination);
        assert_eq!(packet.payload, b"abc");
    }

    #[test]
    fn encodes_response_packet_with_source_address() {
        let encoded =
            encode_response_packet(&SocksAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 53))), b"ok")
                .expect("encode");
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]) as usize, 12);
        assert_eq!(
            &encoded[2..14],
            b"\0\0\x02\x01\x02\x01\x08\x08\x08\x08\0\x35"
        );
        assert_eq!(&encoded[14..], b"\0\x02ok");
    }
}
