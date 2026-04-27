use anyhow::{Context, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::config::IpStrategy;

use super::configure_tcp_stream;
use super::dns;
use super::routing::RoutingTable;
use super::socksaddr::SocksAddr;

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_SOCKET_BUFFER_SIZE: usize = 2 * 1024 * 1024;

pub async fn connect_tcp_destination(
    destination: &SocksAddr,
    routing: &RoutingTable,
) -> anyhow::Result<TcpStream> {
    let outbound = routing.outbound_for(destination, "tcp")?;
    match destination {
        SocksAddr::Ip(addr) => connect_target(*addr)
            .await
            .context("connect IP destination"),
        SocksAddr::Domain(host, port) => {
            let resolved = resolve_destination(destination, routing, "tcp")
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            let mut last_error = None;
            let mut attempts = JoinSet::new();
            for (target, delay) in dial_plan(&resolved, outbound.ip_strategy) {
                attempts.spawn(async move {
                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                    connect_target(target)
                        .await
                        .map_err(|error| (target, error))
                });
            }
            while let Some(result) = attempts.join_next().await {
                match result {
                    Ok(Ok(stream)) => {
                        attempts.abort_all();
                        return Ok(stream);
                    }
                    Ok(Err((target, error))) => last_error = Some((target, error)),
                    Err(error) => {
                        last_error = Some((
                            SocketAddr::from(([0, 0, 0, 0], *port)),
                            std::io::Error::other(format!("dial task failed: {error}")),
                        ));
                    }
                }
            }
            if let Some((target, error)) = last_error {
                return Err(error).with_context(|| format!("connect {host}:{port} via {target}"));
            }
            bail!("no addresses resolved for {host}:{port}")
        }
    }
}

pub async fn resolve_destination(
    destination: &SocksAddr,
    routing: &RoutingTable,
    protocol: &str,
) -> anyhow::Result<Vec<SocketAddr>> {
    let outbound = routing.outbound_for(destination, protocol)?;
    match destination {
        SocksAddr::Ip(addr) => Ok(vec![*addr]),
        SocksAddr::Domain(host, port) => {
            let resolved = dns::resolve_domain(host, None, &outbound)
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            if resolved.is_empty() {
                bail!("no addresses resolved for {host}:{port}");
            }
            Ok(resolved
                .into_iter()
                .map(|ip| SocketAddr::new(ip, *port))
                .collect())
        }
    }
}

pub(crate) async fn bind_udp_socket() -> anyhow::Result<UdpSocket> {
    if let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        socket.set_reuse_address(true).ok();
        socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE).ok();
        socket.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE).ok();
        if socket.set_only_v6(false).is_ok()
            && socket
                .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())
                .is_ok()
        {
            socket
                .set_nonblocking(true)
                .context("set IPv6 UDP socket nonblocking")?;
            let std_socket: std::net::UdpSocket = socket.into();
            return UdpSocket::from_std(std_socket).context("adopt IPv6 UDP socket");
        }
    }

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("create IPv4 UDP socket")?;
    socket.set_reuse_address(true).ok();
    socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE).ok();
    socket.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE).ok();
    socket
        .bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())
        .context("bind IPv4 UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("set IPv4 UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("adopt IPv4 UDP socket")
}

pub(crate) fn normalize_udp_source(source: SocketAddr) -> SocketAddr {
    match source {
        SocketAddr::V4(_) => source,
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), addr.port()))
            .unwrap_or(SocketAddr::V6(addr)),
    }
}

pub(crate) fn normalize_udp_target(socket: &UdpSocket, target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(addr)
            if socket
                .local_addr()
                .map(|local| local.is_ipv6())
                .unwrap_or(false) =>
        {
            SocketAddr::V6(SocketAddrV6::new(
                addr.ip().to_ipv6_mapped(),
                addr.port(),
                0,
                0,
            ))
        }
        _ => target,
    }
}

async fn connect_target(target: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    configure_tcp_stream(&stream);
    Ok(stream)
}

fn dial_plan(resolved: &[SocketAddr], ip_strategy: IpStrategy) -> Vec<(SocketAddr, Duration)> {
    if resolved.is_empty() {
        return Vec::new();
    }

    match ip_strategy {
        IpStrategy::System => resolved
            .iter()
            .copied()
            .map(|addr| (addr, Duration::ZERO))
            .collect(),
        IpStrategy::PreferIpv4 | IpStrategy::PreferIpv6 => {
            let (preferred, fallback): (Vec<_>, Vec<_>) = resolved
                .iter()
                .copied()
                .partition(|addr| prefers_family(*addr, ip_strategy));
            if preferred.is_empty() || fallback.is_empty() {
                return resolved
                    .iter()
                    .copied()
                    .map(|addr| (addr, Duration::ZERO))
                    .collect();
            }

            preferred
                .into_iter()
                .map(|addr| (addr, Duration::ZERO))
                .chain(
                    fallback
                        .into_iter()
                        .map(|addr| (addr, HAPPY_EYEBALLS_DELAY)),
                )
                .collect()
        }
    }
}

fn prefers_family(addr: SocketAddr, ip_strategy: IpStrategy) -> bool {
    match ip_strategy {
        IpStrategy::PreferIpv4 => addr.is_ipv4(),
        IpStrategy::PreferIpv6 => addr.is_ipv6(),
        IpStrategy::System => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[test]
    fn prefer_ipv6_dials_ipv4_after_fallback_delay() {
        let plan = dial_plan(
            &[
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ],
            IpStrategy::PreferIpv6,
        );
        assert_eq!(plan[0].1, Duration::ZERO);
        assert_eq!(plan[1].1, HAPPY_EYEBALLS_DELAY);
        assert!(plan[0].0.is_ipv6());
        assert!(plan[1].0.is_ipv4());
    }

    #[test]
    fn system_strategy_keeps_parallel_attempts() {
        let plan = dial_plan(
            &[
                SocketAddr::from(([127, 0, 0, 1], 80)),
                SocketAddr::from(([127, 0, 0, 2], 80)),
            ],
            IpStrategy::System,
        );
        assert!(plan.iter().all(|(_, delay)| delay.is_zero()));
    }

    #[test]
    fn normalizes_ipv4_mapped_sources() {
        let source = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304])),
            53,
        );
        assert_eq!(
            normalize_udp_source(source),
            SocketAddr::from(([1, 2, 3, 4], 53))
        );
    }

    #[tokio::test]
    async fn bound_udp_socket_can_exchange_ipv4_loopback_packets() {
        let listener = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind listener");
        let socket = bind_udp_socket().await.expect("bind shared UDP socket");
        let payload = b"ping";
        let target = normalize_udp_target(&socket, listener.local_addr().expect("listener addr"));
        socket
            .send_to(payload, target)
            .await
            .expect("send to listener");

        let mut inbound = [0u8; 4];
        let (received, peer) = timeout(Duration::from_secs(1), listener.recv_from(&mut inbound))
            .await
            .expect("listener receive timeout")
            .expect("listener receive");
        assert_eq!(&inbound[..received], payload);

        let response = b"pong";
        listener
            .send_to(response, peer)
            .await
            .expect("send to shared socket");

        let mut outbound = [0u8; 4];
        let (received, source) = timeout(Duration::from_secs(1), socket.recv_from(&mut outbound))
            .await
            .expect("shared socket receive timeout")
            .expect("shared socket receive");
        assert_eq!(&outbound[..received], response);
        assert_eq!(
            normalize_udp_source(source),
            listener.local_addr().expect("listener addr")
        );
    }
}
