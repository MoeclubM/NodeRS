use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

#[cfg(test)]
use tokio::io::{AsyncWrite, AsyncWriteExt};

const AF_IPV4: u8 = 0x01;
const AF_FQDN: u8 = 0x03;
const AF_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddr {
    pub async fn read_from<R>(reader: &mut R) -> anyhow::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let family = reader.read_u8().await.context("read address family")?;
        match family {
            AF_IPV4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await.context("read IPv4")?;
                let port = reader.read_u16().await.context("read port")?;
                Ok(Self::Ip(SocketAddr::new(IpAddr::from(octets), port)))
            }
            AF_IPV6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await.context("read IPv6")?;
                let port = reader.read_u16().await.context("read port")?;
                Ok(Self::Ip(SocketAddr::new(IpAddr::from(octets), port)))
            }
            AF_FQDN => {
                let length = reader.read_u8().await.context("read domain length")?;
                let mut domain = vec![0u8; length as usize];
                reader
                    .read_exact(&mut domain)
                    .await
                    .context("read domain")?;
                let port = reader.read_u16().await.context("read port")?;
                Ok(Self::Domain(
                    String::from_utf8(domain).context("decode domain")?,
                    port,
                ))
            }
            other => bail!("unsupported socks address family {other:#x}"),
        }
    }

    #[cfg(test)]
    pub async fn write_to<W>(&self, writer: &mut W) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Self::Ip(addr) if addr.is_ipv4() => {
                writer
                    .write_u8(AF_IPV4)
                    .await
                    .context("write IPv4 family")?;
                if let IpAddr::V4(ip) = addr.ip() {
                    writer
                        .write_all(&ip.octets())
                        .await
                        .context("write IPv4 address")?;
                }
                writer.write_u16(addr.port()).await.context("write port")?;
            }
            Self::Ip(addr) => {
                writer
                    .write_u8(AF_IPV6)
                    .await
                    .context("write IPv6 family")?;
                if let IpAddr::V6(ip) = addr.ip() {
                    writer
                        .write_all(&ip.octets())
                        .await
                        .context("write IPv6 address")?;
                }
                writer.write_u16(addr.port()).await.context("write port")?;
            }
            Self::Domain(host, port) => {
                let host = host.as_bytes();
                if host.len() > u8::MAX as usize {
                    bail!("domain name is too long: {} bytes", host.len());
                }
                writer
                    .write_u8(AF_FQDN)
                    .await
                    .context("write domain family")?;
                writer
                    .write_u8(host.len() as u8)
                    .await
                    .context("write domain length")?;
                writer.write_all(host).await.context("write domain")?;
                writer.write_u16(*port).await.context("write port")?;
            }
        }
        Ok(())
    }
}

impl Display for SocksAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_domain_address() {
        let mut bytes = &b"\x03\x0bexample.com\x01\xbb"[..];
        let addr = SocksAddr::read_from(&mut bytes).await.expect("parse addr");
        assert_eq!(addr, SocksAddr::Domain("example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn writes_domain_address() {
        let mut bytes = Vec::new();
        SocksAddr::Domain("example.com".to_string(), 443)
            .write_to(&mut bytes)
            .await
            .expect("write addr");
        assert_eq!(bytes, b"\x03\x0bexample.com\x01\xbb");
    }
}
