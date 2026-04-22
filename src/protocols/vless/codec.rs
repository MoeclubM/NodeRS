use anyhow::{Context, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocols::anytls::socksaddr::SocksAddr;

pub const VERSION: u8 = 0x00;
const ADDONS_LEN_NONE: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub user: [u8; 16],
    pub command: Command,
    pub destination: SocksAddr,
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
    ensure!(
        addons_len == ADDONS_LEN_NONE,
        "VLESS addons are not supported"
    );

    let command = match read_u8_recorded(reader, consumed, "read VLESS command").await? {
        CMD_TCP => Command::Tcp,
        CMD_UDP => Command::Udp,
        CMD_MUX => bail!("VLESS mux is not supported"),
        other => bail!("unsupported VLESS command {other:#x}"),
    };

    let destination = read_destination_recorded(reader, consumed).await?;
    Ok(Request {
        user,
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
        assert_eq!(request.command, Command::Udp);
        assert_eq!(
            request.destination,
            SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 53)))
        );
    }

    #[tokio::test]
    async fn rejects_nonzero_addons_len() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        bytes.push(1);

        let error = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect_err("addons should be rejected");
        assert!(error.to_string().contains("addons"));
    }

    #[tokio::test]
    async fn rejects_mux_command() {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&USER_UUID);
        bytes.push(0);
        bytes.push(CMD_MUX);
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes.push(ATYP_DOMAIN);
        bytes.push(11);
        bytes.extend_from_slice(b"example.com");

        let error = read_request(&mut bytes.as_slice(), &mut Vec::new())
            .await
            .expect_err("mux should be rejected");
        assert!(error.to_string().contains("mux"));
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
