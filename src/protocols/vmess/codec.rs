use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, bail, ensure};

use crate::protocols::shared::socksaddr::SocksAddr;

use super::crypto::{BodyConfig, RequestOptions, SecurityType};

const VMESS_VERSION: u8 = 0x01;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const COMMAND_MUX: u8 = 0x03;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x02;
const ADDRESS_IPV6: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub destination: SocksAddr,
    pub response_header: u8,
    pub options: RequestOptions,
    pub security: SecurityType,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
}

impl Request {
    pub fn request_body_config(&self) -> anyhow::Result<BodyConfig> {
        BodyConfig::new_request(
            self.security,
            self.options,
            self.request_body_key,
            self.request_body_iv,
        )
    }

    pub fn response_body_config(&self) -> anyhow::Result<BodyConfig> {
        BodyConfig::new_response(
            self.security,
            self.options,
            self.request_body_key,
            self.request_body_iv,
        )
    }
}

pub fn parse_request_header(header: &[u8]) -> anyhow::Result<Request> {
    ensure!(
        header.len() >= 42,
        "VMess request header too short: {}",
        header.len()
    );
    ensure!(
        header[0] == VMESS_VERSION,
        "unsupported VMess version: {}",
        header[0]
    );

    let actual_checksum = fnv1a32(&header[..header.len() - 4]);
    let expected_checksum = u32::from_be_bytes([
        header[header.len() - 4],
        header[header.len() - 3],
        header[header.len() - 2],
        header[header.len() - 1],
    ]);
    ensure!(
        actual_checksum == expected_checksum,
        "invalid VMess request checksum"
    );

    let mut request_body_iv = [0u8; 16];
    request_body_iv.copy_from_slice(&header[1..17]);
    let mut request_body_key = [0u8; 16];
    request_body_key.copy_from_slice(&header[17..33]);
    let response_header = header[33];

    let mut options = RequestOptions::new(header[34]);
    ensure!(
        !options.has_unknown_bits(),
        "unsupported VMess request option bits: 0x{:02x}",
        options.bits() & !RequestOptions::supported_mask()
    );

    let padding_len = (header[35] >> 4) as usize;
    let raw_security = SecurityType::from_raw(header[35] & 0x0f)?;
    if raw_security == SecurityType::Zero {
        options.clear_chunk_stream();
        options.clear_chunk_masking();
    }
    let security = raw_security.normalized();

    ensure!(
        header[36] == 0,
        "unsupported VMess reserved byte: {}",
        header[36]
    );

    let command = match header[37] {
        COMMAND_TCP => Command::Tcp,
        COMMAND_UDP => Command::Udp,
        COMMAND_MUX => bail!("VMess mux is not supported"),
        other => bail!("unsupported VMess command: {other}"),
    };

    let (destination, address_len) = parse_destination(&header[38..])?;
    let padding_start = 38 + address_len;
    ensure!(
        header.len() == padding_start + padding_len + 4,
        "invalid VMess header padding length"
    );

    Ok(Request {
        command,
        destination,
        response_header,
        options,
        security,
        request_body_iv,
        request_body_key,
    })
}

fn parse_destination(data: &[u8]) -> anyhow::Result<(SocksAddr, usize)> {
    ensure!(data.len() >= 3, "short VMess address header");
    let port = u16::from_be_bytes([data[0], data[1]]);
    match data[2] {
        ADDRESS_IPV4 => {
            ensure!(data.len() >= 7, "short VMess IPv4 destination");
            let ip = IpAddr::V4(Ipv4Addr::new(data[3], data[4], data[5], data[6]));
            Ok((SocksAddr::Ip(SocketAddr::new(ip, port)), 7))
        }
        ADDRESS_DOMAIN => {
            ensure!(data.len() >= 4, "short VMess domain destination");
            let len = data[3] as usize;
            ensure!(data.len() >= 4 + len, "short VMess domain destination");
            let host = String::from_utf8(data[4..4 + len].to_vec())
                .context("decode VMess domain destination")?;
            Ok((SocksAddr::Domain(host, port), 4 + len))
        }
        ADDRESS_IPV6 => {
            ensure!(data.len() >= 19, "short VMess IPv6 destination");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[3..19]);
            Ok((
                SocksAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        other => bail!("unsupported VMess address type: {other:#x}"),
    }
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(
        command: Command,
        security: SecurityType,
        options: RequestOptions,
        destination: SocksAddr,
        padding_len: usize,
    ) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(VMESS_VERSION);
        header.extend_from_slice(&[0x11; 16]);
        header.extend_from_slice(&[0x22; 16]);
        header.push(0x7f);
        header.push(options.bits());
        header.push(
            ((padding_len as u8) << 4)
                | match security {
                    SecurityType::Aes128Gcm => 0x03,
                    SecurityType::ChaCha20Poly1305 => 0x04,
                    SecurityType::None => 0x05,
                    SecurityType::Zero => 0x06,
                },
        );
        header.push(0);
        header.push(match command {
            Command::Tcp => COMMAND_TCP,
            Command::Udp => COMMAND_UDP,
        });
        match destination {
            SocksAddr::Ip(SocketAddr::V4(addr)) => {
                header.extend_from_slice(&addr.port().to_be_bytes());
                header.push(ADDRESS_IPV4);
                header.extend_from_slice(&addr.ip().octets());
            }
            SocksAddr::Ip(SocketAddr::V6(addr)) => {
                header.extend_from_slice(&addr.port().to_be_bytes());
                header.push(ADDRESS_IPV6);
                header.extend_from_slice(&addr.ip().octets());
            }
            SocksAddr::Domain(host, port) => {
                header.extend_from_slice(&port.to_be_bytes());
                header.push(ADDRESS_DOMAIN);
                header.push(host.len() as u8);
                header.extend_from_slice(host.as_bytes());
            }
        }
        header.extend(std::iter::repeat_n(0xaa, padding_len));
        let checksum = fnv1a32(&header).to_be_bytes();
        header.extend_from_slice(&checksum);
        header
    }

    #[test]
    fn parses_port_then_domain_destination() {
        let header = build_header(
            Command::Tcp,
            SecurityType::Aes128Gcm,
            RequestOptions::new(0x0d),
            SocksAddr::Domain("example.com".to_string(), 443),
            2,
        );
        let request = parse_request_header(&header).unwrap();
        assert_eq!(request.command, Command::Tcp);
        assert_eq!(
            request.destination,
            SocksAddr::Domain("example.com".into(), 443)
        );
        assert_eq!(request.response_header, 0x7f);
        assert_eq!(request.options.bits(), 0x0d);
        assert_eq!(request.security, SecurityType::Aes128Gcm);
    }

    #[test]
    fn normalizes_zero_security() {
        let header = build_header(
            Command::Tcp,
            SecurityType::Zero,
            RequestOptions::new(0x05),
            SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)),
            0,
        );
        let request = parse_request_header(&header).unwrap();
        assert_eq!(request.security, SecurityType::None);
        assert_eq!(request.options.bits(), 0x00);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut header = build_header(
            Command::Udp,
            SecurityType::None,
            RequestOptions::new(0x01),
            SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)),
            0,
        );
        let last = header.len() - 1;
        header[last] ^= 0xff;
        assert!(parse_request_header(&header).is_err());
    }
}
