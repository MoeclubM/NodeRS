use anyhow::{Context, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocols::shared::socksaddr::SocksAddr;

pub const VERSION: u8 = 0x00;
const ADDONS_LEN_NONE: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;
pub const XUDP_MUX_DESTINATION: &str = "v1.mux.cool";
pub const XUDP_MUX_PORT: u16 = 666;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub user: [u8; 16],
    pub addons: Addons,
    pub command: Command,
    pub destination: SocksAddr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addons {
    pub flow: String,
    pub seed: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFrame {
    pub payload: Vec<u8>,
    pub wire_len: usize,
}

pub async fn read_request<R>(reader: &mut R, consumed: &mut Vec<u8>) -> anyhow::Result<Request>
where
    R: AsyncRead + Unpin,
{
    let version = read_u8_recorded(reader, consumed, "read VLESS version").await?;
    ensure!(version == VERSION, "unsupported VLESS version {version:#x}");

    let mut user = [0u8; 16];
    read_exact_recorded(reader, &mut user, consumed, "read VLESS user uuid").await?;

    let addons_len = read_u8_recorded(reader, consumed, "read VLESS addons length").await?;
    let addons = read_addons_recorded(reader, consumed, addons_len).await?;

    let command = match read_u8_recorded(reader, consumed, "read VLESS command").await? {
        CMD_TCP => Command::Tcp,
        CMD_UDP => Command::Udp,
        CMD_MUX => Command::Mux,
        other => bail!("unsupported VLESS command {other:#x}"),
    };

    let destination = match command {
        Command::Mux => SocksAddr::Domain(XUDP_MUX_DESTINATION.to_string(), XUDP_MUX_PORT),
        Command::Tcp | Command::Udp => read_destination_recorded(reader, consumed).await?,
    };
    Ok(Request {
        user,
        addons,
        command,
        destination,
    })
}

pub async fn write_response_header<W>(writer: &mut W) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[VERSION, ADDONS_LEN_NONE])
        .await
        .context("write VLESS response header")
}

pub async fn read_udp_frame<R>(reader: &mut R) -> anyhow::Result<Option<UdpFrame>>
where
    R: AsyncRead + Unpin,
{
    let Some(length) = read_length_or_eof(reader).await? else {
        return Ok(None);
    };

    let mut payload = vec![0u8; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .context("read VLESS UDP payload")?;
    Ok(Some(UdpFrame {
        payload,
        wire_len: 2 + length as usize,
    }))
}

pub fn encode_udp_frame(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        bail!("VLESS UDP payload too large: {}", payload.len());
    }
    let mut encoded = Vec::with_capacity(2 + payload.len());
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

async fn read_length_or_eof<R>(reader: &mut R) -> anyhow::Result<Option<u16>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    match reader.read_exact(&mut bytes).await {
        Ok(_) => Ok(Some(u16::from_be_bytes(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error).context("read VLESS UDP frame length"),
    }
}

async fn read_destination_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
) -> anyhow::Result<SocksAddr>
where
    R: AsyncRead + Unpin,
{
    let port = read_u16_recorded(reader, consumed, "read VLESS destination port").await?;
    let atyp = read_u8_recorded(reader, consumed, "read VLESS address type").await?;
    match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            read_exact_recorded(reader, &mut octets, consumed, "read VLESS IPv4 address").await?;
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            read_exact_recorded(reader, &mut octets, consumed, "read VLESS IPv6 address").await?;
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let length = read_u8_recorded(reader, consumed, "read VLESS domain length").await?;
            let mut domain = vec![0u8; length as usize];
            read_exact_recorded(reader, &mut domain, consumed, "read VLESS domain").await?;
            Ok(SocksAddr::Domain(
                String::from_utf8(domain).context("decode VLESS domain")?,
                port,
            ))
        }
        other => bail!("unsupported VLESS address type {other:#x}"),
    }
}

async fn read_addons_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
    addons_len: u8,
) -> anyhow::Result<Addons>
where
    R: AsyncRead + Unpin,
{
    if addons_len == ADDONS_LEN_NONE {
        return Ok(Addons::default());
    }

    let mut encoded = vec![0u8; addons_len as usize];
    read_exact_recorded(reader, &mut encoded, consumed, "read VLESS addons payload").await?;
    decode_addons(&encoded)
}

fn decode_addons(encoded: &[u8]) -> anyhow::Result<Addons> {
    let mut addons = Addons::default();
    let mut cursor = 0usize;

    while cursor < encoded.len() {
        let key = read_varint(encoded, &mut cursor).context("read VLESS addons field key")?;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        match (field_number, wire_type) {
            (1, 2) => {
                let value = read_length_delimited(encoded, &mut cursor)
                    .context("read VLESS addons flow")?;
                addons.flow =
                    String::from_utf8(value.to_vec()).context("decode VLESS addons flow")?;
            }
            (2, 2) => {
                let value = read_length_delimited(encoded, &mut cursor)
                    .context("read VLESS addons seed")?;
                addons.seed = value.to_vec();
            }
            (_, 0) => {
                let _ = read_varint(encoded, &mut cursor).context("skip VLESS addons varint")?;
            }
            (_, 1) => {
                ensure!(
                    cursor + 8 <= encoded.len(),
                    "truncated VLESS addons fixed64 field"
                );
                cursor += 8;
            }
            (_, 2) => {
                let _ = read_length_delimited(encoded, &mut cursor)
                    .context("skip VLESS addons length-delimited field")?;
            }
            (_, 5) => {
                ensure!(
                    cursor + 4 <= encoded.len(),
                    "truncated VLESS addons fixed32 field"
                );
                cursor += 4;
            }
            _ => bail!("unsupported VLESS addons wire type {wire_type}"),
        }
    }

    Ok(addons)
}

fn read_varint(encoded: &[u8], cursor: &mut usize) -> anyhow::Result<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        ensure!(*cursor < encoded.len(), "truncated VLESS addons varint");
        let byte = encoded[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        ensure!(shift < 64, "VLESS addons varint is too large");
    }
}

fn read_length_delimited<'a>(encoded: &'a [u8], cursor: &mut usize) -> anyhow::Result<&'a [u8]> {
    let len = read_varint(encoded, cursor).context("read VLESS addons length")?;
    let len = usize::try_from(len).context("VLESS addons length does not fit usize")?;
    ensure!(
        *cursor + len <= encoded.len(),
        "truncated VLESS addons payload"
    );
    let start = *cursor;
    *cursor += len;
    Ok(&encoded[start..start + len])
}

async fn read_u8_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
    context: &str,
) -> anyhow::Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    read_exact_recorded(reader, &mut byte, consumed, context).await?;
    Ok(byte[0])
}

async fn read_u16_recorded<R>(
    reader: &mut R,
    consumed: &mut Vec<u8>,
    context: &str,
) -> anyhow::Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    read_exact_recorded(reader, &mut bytes, consumed, context).await?;
    Ok(u16::from_be_bytes(bytes))
}

async fn read_exact_recorded<R>(
    reader: &mut R,
    buffer: &mut [u8],
    consumed: &mut Vec<u8>,
    context: &str,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    reader
        .read_exact(buffer)
        .await
        .with_context(|| context.to_string())?;
    consumed.extend_from_slice(buffer);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_UUID: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x10,
    ];

    #[tokio::test]
    async fn reads_vless_tcp_request_domain() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        bytes.push(0);
        bytes.push(CMD_TCP);
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes.push(ATYP_DOMAIN);
        bytes.push(11);
        bytes.extend_from_slice(b"example.com");

        let request = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect("read request");
        assert_eq!(request.user, USER_UUID);
        assert_eq!(request.addons, Addons::default());
        assert_eq!(request.command, Command::Tcp);
        assert_eq!(
            request.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
    }

    #[tokio::test]
    async fn reads_vless_udp_request_ipv4() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        bytes.push(0);
        bytes.push(CMD_UDP);
        bytes.extend_from_slice(&53u16.to_be_bytes());
        bytes.push(ATYP_IPV4);
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let request = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect("read request");
        assert_eq!(request.addons, Addons::default());
        assert_eq!(request.command, Command::Udp);
        assert_eq!(
            request.destination,
            SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 53)))
        );
    }

    #[tokio::test]
    async fn reads_addons_flow_and_seed() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        let addons = [
            0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-', b'v', b'i',
            b's', b'i', b'o', b'n', 0x12, 0x03, 0x01, 0x02, 0x03,
        ];
        bytes.push(addons.len() as u8);
        bytes.extend_from_slice(&addons);
        bytes.push(CMD_TCP);
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes.push(ATYP_DOMAIN);
        bytes.push(11);
        bytes.extend_from_slice(b"example.com");

        let request = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect("addons should parse");
        assert_eq!(request.addons.flow, "xtls-rprx-vision");
        assert_eq!(request.addons.seed, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn rejects_truncated_addons_payload() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        bytes.push(2);
        bytes.push(0x0a);

        let error = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect_err("addons should be rejected");
        assert!(error.to_string().contains("addons"));
    }

    #[tokio::test]
    async fn reads_vless_mux_request() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        bytes.push(0);
        bytes.push(CMD_MUX);

        let request = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect("read mux request");
        assert_eq!(request.addons, Addons::default());
        assert_eq!(request.command, Command::Mux);
        assert_eq!(
            request.destination,
            SocksAddr::Domain(XUDP_MUX_DESTINATION.to_string(), XUDP_MUX_PORT)
        );
    }

    #[tokio::test]
    async fn writes_exact_response_header() {
        let mut buffer = Vec::new();
        write_response_header(&mut buffer)
            .await
            .expect("write response header");
        assert_eq!(buffer, vec![VERSION, 0]);
    }

    #[tokio::test]
    async fn udp_frame_roundtrip_preserves_zero_length_datagram() {
        let encoded = encode_udp_frame(&[]).expect("encode zero datagram");
        assert_eq!(encoded, vec![0, 0]);

        let frame = read_udp_frame(&mut encoded.as_slice())
            .await
            .expect("read frame")
            .expect("frame exists");
        assert_eq!(frame.payload, Vec::<u8>::new());
        assert_eq!(frame.wire_len, 2);
    }
}
