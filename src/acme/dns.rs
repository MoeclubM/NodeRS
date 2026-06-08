use anyhow::{Context, anyhow, bail, ensure};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::timeout;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);
pub(super) async fn lookup_txt_records(
    name: &str,
    nameserver: &str,
) -> anyhow::Result<Vec<String>> {
    let servers = resolve_nameserver_endpoints(nameserver).await?;
    let mut last_error = None;
    for server in servers {
        match query_txt_server(server, name).await {
            Ok(records) if !records.is_empty() => return Ok(records),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(Vec::new())
}

async fn resolve_nameserver_endpoints(spec: &str) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    let (host, port) = parse_nameserver_spec(spec)?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    let resolved = lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("resolve nameserver {spec}"))?
        .collect::<Vec<_>>();
    if resolved.is_empty() {
        bail!("no addresses resolved for nameserver {spec}")
    }
    Ok(resolved)
}

fn parse_nameserver_spec(spec: &str) -> anyhow::Result<(String, u16)> {
    let spec = spec.trim().trim_end_matches('/');
    ensure!(!spec.is_empty(), "empty nameserver specification");

    let spec = if let Some(rest) = spec.strip_prefix("udp://") {
        rest
    } else if let Some(rest) = spec.strip_prefix("dns://") {
        rest
    } else if spec.contains("://") {
        bail!("unsupported DNS scheme in {spec}")
    } else {
        spec
    };

    if let Ok(ip) = spec.parse::<std::net::IpAddr>() {
        return Ok((ip.to_string(), 53));
    }

    if let Ok(addr) = spec.parse::<std::net::SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }

    if let Some(host) = spec.strip_prefix('[') {
        let (host, port) = host
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed nameserver {spec}"))?;
        if port.is_empty() {
            return Ok((host.to_string(), 53));
        }
        let port = port
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("invalid bracketed nameserver {spec}"))?
            .parse::<u16>()?;
        return Ok((host.to_string(), port));
    }

    if let Some((host, port)) = spec.rsplit_once(':')
        && !host.contains(':')
    {
        return Ok((host.to_string(), port.parse::<u16>()?));
    }

    Ok((spec.to_string(), 53))
}

async fn query_txt_server(server: std::net::SocketAddr, name: &str) -> anyhow::Result<Vec<String>> {
    let bind_addr = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind UDP socket for DNS TXT query to {server}"))?;
    let id = NEXT_DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_dns_query(name, 16, id)?;
    socket
        .send_to(&query, server)
        .await
        .with_context(|| format!("send DNS TXT query to {server}"))?;

    let mut response = [0u8; 1500];
    let (received, from) = timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut response))
        .await
        .context("DNS TXT query timed out")?
        .with_context(|| format!("read DNS TXT response from {server}"))?;
    ensure!(
        from.ip() == server.ip(),
        "unexpected DNS response source {from}"
    );
    parse_txt_response(&response[..received], id)
}

fn build_dns_query(name: &str, record_type: u16, id: u16) -> anyhow::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(name, &mut packet)?;
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

fn encode_dns_name(name: &str, packet: &mut Vec<u8>) -> anyhow::Result<()> {
    let normalized = name.trim().trim_end_matches('.');
    ensure!(!normalized.is_empty(), "DNS host must not be empty");
    for label in normalized.split('.') {
        ensure!(!label.is_empty(), "DNS label must not be empty");
        ensure!(label.len() <= 63, "DNS label too long in {name}");
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    Ok(())
}

fn parse_txt_response(packet: &[u8], id: u16) -> anyhow::Result<Vec<String>> {
    ensure!(packet.len() >= 12, "DNS response too short");
    ensure!(
        read_dns_u16(packet, 0)? == id,
        "DNS transaction ID mismatch"
    );
    let flags = read_dns_u16(packet, 2)?;
    ensure!(flags & 0x8000 != 0, "DNS response missing QR bit");
    let rcode = flags & 0x000f;
    ensure!(rcode == 0, "DNS server returned rcode {rcode}");

    let questions = read_dns_u16(packet, 4)? as usize;
    let answers = read_dns_u16(packet, 6)? as usize;
    let mut offset = 12usize;

    for _ in 0..questions {
        offset = skip_dns_name(packet, offset)?;
        ensure!(offset + 4 <= packet.len(), "DNS question truncated");
        offset += 4;
    }

    let mut records = Vec::new();
    for _ in 0..answers {
        offset = skip_dns_name(packet, offset)?;
        ensure!(offset + 10 <= packet.len(), "DNS answer header truncated");
        let rr_type = read_dns_u16(packet, offset)?;
        let rr_class = read_dns_u16(packet, offset + 2)?;
        let rd_len = read_dns_u16(packet, offset + 8)? as usize;
        offset += 10;
        ensure!(
            offset + rd_len <= packet.len(),
            "DNS answer payload truncated"
        );
        if rr_class == 1 && rr_type == 16 {
            records.push(parse_txt_rdata(&packet[offset..offset + rd_len])?);
        }
        offset += rd_len;
    }

    Ok(records)
}

fn parse_txt_rdata(rdata: &[u8]) -> anyhow::Result<String> {
    let mut offset = 0usize;
    let mut text = String::new();
    while offset < rdata.len() {
        let len = *rdata
            .get(offset)
            .ok_or_else(|| anyhow!("truncated DNS TXT record"))? as usize;
        offset += 1;
        ensure!(offset + len <= rdata.len(), "truncated DNS TXT chunk");
        text.push_str(
            std::str::from_utf8(&rdata[offset..offset + len]).context("decode DNS TXT chunk")?,
        );
        offset += len;
    }
    Ok(text)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> anyhow::Result<usize> {
    loop {
        ensure!(offset < packet.len(), "DNS name out of bounds");
        let len = packet[offset];
        if len & 0b1100_0000 == 0b1100_0000 {
            ensure!(offset + 1 < packet.len(), "DNS pointer truncated");
            return Ok(offset + 2);
        }
        if len == 0 {
            return Ok(offset + 1);
        }
        offset += 1;
        ensure!(offset + len as usize <= packet.len(), "DNS label truncated");
        offset += len as usize;
    }
}

fn read_dns_u16(packet: &[u8], offset: usize) -> anyhow::Result<u16> {
    ensure!(offset + 2 <= packet.len(), "read_dns_u16 out of bounds");
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_txt_response() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x10, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x05, 0x04,
            b't', b'e', b's', b't',
        ];
        let parsed = parse_txt_response(&response, 0x1234).expect("parse TXT response");
        assert_eq!(parsed, vec!["test".to_string()]);
    }
}
