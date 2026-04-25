use anyhow::{Context, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocols::anytls::socksaddr::SocksAddr;

pub const METADATA_LEN: usize = 32;
pub const MAX_SESSION_PAYLOAD_LEN: usize = 1024;
pub const SOCKS_VERSION: u8 = 0x05;
pub const SOCKS_REPLY_SUCCESS: u8 = 0x00;
pub const SOCKS_REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    OpenSessionRequest = 2,
    OpenSessionResponse = 3,
    CloseSessionRequest = 4,
    CloseSessionResponse = 5,
    DataClientToServer = 6,
    DataServerToClient = 7,
    AckClientToServer = 8,
    AckServerToClient = 9,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    pub protocol: ProtocolType,
    pub session_id: u32,
    pub seq: u32,
    pub status_code: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMetadata {
    pub protocol: ProtocolType,
    pub session_id: u32,
    pub seq: u32,
    pub unack_seq: u32,
    pub window_size: u16,
    pub fragment: u8,
    pub prefix_len: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Metadata {
    Session(SessionMetadata),
    Data(DataMetadata),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCommand {
    Connect,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub command: SocksCommand,
    pub destination: SocksAddr,
    pub consumed_len: usize,
}

impl ProtocolType {
    pub fn from_byte(value: u8) -> anyhow::Result<Self> {
        Ok(match value {
            2 => Self::OpenSessionRequest,
            3 => Self::OpenSessionResponse,
            4 => Self::CloseSessionRequest,
            5 => Self::CloseSessionResponse,
            6 => Self::DataClientToServer,
            7 => Self::DataServerToClient,
            8 => Self::AckClientToServer,
            9 => Self::AckServerToClient,
            other => bail!("unsupported Mieru protocol type {other}"),
        })
    }
}

pub fn decode_metadata(bytes: &[u8]) -> anyhow::Result<Metadata> {
    ensure!(
        bytes.len() == METADATA_LEN,
        "invalid Mieru metadata size {}",
        bytes.len()
    );

    let protocol = ProtocolType::from_byte(bytes[0])?;
    let timestamp = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let current = current_timestamp_minutes()?;
    ensure!(
        current.abs_diff(u64::from(timestamp)) <= 1,
        "invalid Mieru metadata timestamp {}",
        u64::from(timestamp) * 60
    );

    Ok(match protocol {
        ProtocolType::OpenSessionRequest
        | ProtocolType::OpenSessionResponse
        | ProtocolType::CloseSessionRequest
        | ProtocolType::CloseSessionResponse => {
            let payload_len = u16::from_be_bytes([bytes[15], bytes[16]]);
            ensure!(
                usize::from(payload_len) <= MAX_SESSION_PAYLOAD_LEN,
                "Mieru session payload too large: {}",
                payload_len
            );
            Metadata::Session(SessionMetadata {
                protocol,
                session_id: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
                seq: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
                status_code: bytes[14],
                payload_len,
                suffix_len: bytes[17],
            })
        }
        ProtocolType::DataClientToServer
        | ProtocolType::DataServerToClient
        | ProtocolType::AckClientToServer
        | ProtocolType::AckServerToClient => Metadata::Data(DataMetadata {
            protocol,
            session_id: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            seq: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            unack_seq: u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]),
            window_size: u16::from_be_bytes([bytes[18], bytes[19]]),
            fragment: bytes[20],
            prefix_len: bytes[21],
            payload_len: u16::from_be_bytes([bytes[22], bytes[23]]),
            suffix_len: bytes[24],
        }),
    })
}

pub fn encode_session_metadata(
    protocol: ProtocolType,
    session_id: u32,
    seq: u32,
    status_code: u8,
    payload_len: usize,
) -> anyhow::Result<[u8; METADATA_LEN]> {
    ensure!(
        payload_len <= MAX_SESSION_PAYLOAD_LEN,
        "Mieru session payload too large: {payload_len}"
    );
    let mut bytes = [0u8; METADATA_LEN];
    bytes[0] = protocol as u8;
    bytes[2..6].copy_from_slice(&(current_timestamp_minutes()? as u32).to_be_bytes());
    bytes[6..10].copy_from_slice(&session_id.to_be_bytes());
    bytes[10..14].copy_from_slice(&seq.to_be_bytes());
    bytes[14] = status_code;
    bytes[15..17].copy_from_slice(&(payload_len as u16).to_be_bytes());
    Ok(bytes)
}

pub fn encode_data_metadata(
    protocol: ProtocolType,
    session_id: u32,
    seq: u32,
    payload_len: usize,
) -> anyhow::Result<[u8; METADATA_LEN]> {
    ensure!(
        payload_len <= u16::MAX as usize,
        "Mieru data payload too large: {payload_len}"
    );
    let mut bytes = [0u8; METADATA_LEN];
    bytes[0] = protocol as u8;
    bytes[2..6].copy_from_slice(&(current_timestamp_minutes()? as u32).to_be_bytes());
    bytes[6..10].copy_from_slice(&session_id.to_be_bytes());
    bytes[10..14].copy_from_slice(&seq.to_be_bytes());
    bytes[22..24].copy_from_slice(&(payload_len as u16).to_be_bytes());
    Ok(bytes)
}

pub fn parse_socks5_request(buffer: &[u8]) -> anyhow::Result<Option<SocksRequest>> {
    if buffer.len() < 4 {
        return Ok(None);
    }

    ensure!(
        buffer[0] == SOCKS_VERSION,
        "unsupported Mieru SOCKS version {}",
        buffer[0]
    );
    ensure!(
        buffer[2] == 0,
        "invalid Mieru SOCKS reserved byte {}",
        buffer[2]
    );

    let command = match buffer[1] {
        SOCKS_CMD_CONNECT => SocksCommand::Connect,
        SOCKS_CMD_UDP_ASSOCIATE => SocksCommand::UdpAssociate,
        other => bail!("unsupported Mieru SOCKS command {other}"),
    };

    let (destination, consumed_len) = match buffer[3] {
        SOCKS_ATYP_IPV4 => {
            if buffer.len() < 10 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
            let port = u16::from_be_bytes([buffer[8], buffer[9]]);
            (
                SocksAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                10usize,
            )
        }
        SOCKS_ATYP_DOMAIN => {
            if buffer.len() < 5 {
                return Ok(None);
            }
            let domain_len = buffer[4] as usize;
            if buffer.len() < 5 + domain_len + 2 {
                return Ok(None);
            }
            let domain = String::from_utf8(buffer[5..5 + domain_len].to_vec())
                .context("decode Mieru SOCKS domain")?;
            let port = u16::from_be_bytes([buffer[5 + domain_len], buffer[6 + domain_len]]);
            (SocksAddr::Domain(domain, port), 5 + domain_len + 2)
        }
        SOCKS_ATYP_IPV6 => {
            if buffer.len() < 22 {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buffer[4..20]);
            let port = u16::from_be_bytes([buffer[20], buffer[21]]);
            (
                SocksAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                22usize,
            )
        }
        other => bail!("unsupported Mieru SOCKS address type {other:#x}"),
    };

    Ok(Some(SocksRequest {
        command,
        destination,
        consumed_len,
    }))
}

pub fn encode_socks5_response(reply: u8, bind: &SocksAddr) -> anyhow::Result<Vec<u8>> {
    let mut bytes = vec![SOCKS_VERSION, reply, 0];
    match bind {
        SocksAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                bytes.push(SOCKS_ATYP_IPV4);
                bytes.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes.push(SOCKS_ATYP_IPV6);
                bytes.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain(domain, _) => {
            ensure!(
                domain.len() <= u8::MAX as usize,
                "Mieru SOCKS domain too long"
            );
            bytes.push(SOCKS_ATYP_DOMAIN);
            bytes.push(domain.len() as u8);
            bytes.extend_from_slice(domain.as_bytes());
        }
    }
    let port = match bind {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    };
    bytes.extend_from_slice(&port.to_be_bytes());
    Ok(bytes)
}

fn current_timestamp_minutes() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs()
        / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_request_with_remaining_payload() {
        let request = [
            SOCKS_VERSION,
            SOCKS_CMD_CONNECT,
            0,
            SOCKS_ATYP_DOMAIN,
            11,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
            0x01,
            0xbb,
            b'p',
            b'i',
            b'n',
            b'g',
        ];
        let parsed = parse_socks5_request(&request)
            .expect("parse")
            .expect("request");
        assert_eq!(parsed.command, SocksCommand::Connect);
        assert_eq!(
            parsed.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
        assert_eq!(parsed.consumed_len, 18);
    }

    #[test]
    fn encodes_ipv4_response() {
        let encoded = encode_socks5_response(
            SOCKS_REPLY_SUCCESS,
            &SocksAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 1080))),
        )
        .expect("encode");
        assert_eq!(encoded, vec![5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38]);
    }

    #[test]
    fn roundtrips_data_metadata() {
        let bytes =
            encode_data_metadata(ProtocolType::DataServerToClient, 7, 9, 32).expect("encode");
        let metadata = decode_metadata(&bytes).expect("decode");
        let Metadata::Data(data) = metadata else {
            panic!("expected data metadata");
        };
        assert_eq!(data.protocol, ProtocolType::DataServerToClient);
        assert_eq!(data.session_id, 7);
        assert_eq!(data.seq, 9);
        assert_eq!(data.payload_len, 32);
    }
}
