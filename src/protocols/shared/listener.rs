use anyhow::Context;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpListener, UdpSocket};
use tracing::warn;

use crate::panel::NodeConfigResponse;

const DEFAULT_LISTEN_IP: &str = "0.0.0.0";
const TCP_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

pub(crate) fn configure_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    let socket = SockRef::from(stream);
    let _ = socket.set_tcp_keepalive(&keepalive);
}

pub(crate) fn bind_listeners(listen_ip: &str, port: u16) -> anyhow::Result<Vec<TcpListener>> {
    let specs = listener_specs(listen_ip, port)?;
    let mut listeners = Vec::new();
    for spec in specs {
        match bind_listener(spec.bind_addr, spec.only_v6) {
            Ok(listener) => listeners.push(listener),
            Err(error) if spec.optional => {
                warn!(%error, listen = %spec.bind_addr, "optional listener bind failed")
            }
            Err(error) => return Err(error),
        }
    }
    if listeners.is_empty() {
        anyhow::bail!("no TCP listeners could be started");
    }
    Ok(listeners)
}

pub(crate) fn bind_udp_sockets(listen_ip: &str, port: u16) -> anyhow::Result<Vec<UdpSocket>> {
    let specs = listener_specs(listen_ip, port)?;
    let mut sockets = Vec::new();
    for spec in specs {
        match bind_udp_socket(spec.bind_addr, spec.only_v6) {
            Ok(socket) => sockets.push(socket),
            Err(error) if spec.optional => {
                warn!(%error, listen = %spec.bind_addr, "optional UDP socket bind failed")
            }
            Err(error) => return Err(error),
        }
    }
    if sockets.is_empty() {
        anyhow::bail!("no UDP sockets could be started");
    }
    Ok(sockets)
}

fn bind_listener(bind_addr: SocketAddr, only_v6: bool) -> anyhow::Result<TcpListener> {
    let domain = if bind_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .with_context(|| format!("create listener socket for {bind_addr}"))?;
    socket.set_reuse_address(true).ok();
    if bind_addr.is_ipv6() {
        socket
            .set_only_v6(only_v6)
            .with_context(|| format!("set IPv6-only mode for {bind_addr}"))?;
    }
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("bind {bind_addr}"))?;
    socket
        .listen(1024)
        .with_context(|| format!("listen on {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .with_context(|| format!("set nonblocking on {bind_addr}"))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).with_context(|| format!("adopt listener {bind_addr}"))
}

fn bind_udp_socket(bind_addr: SocketAddr, only_v6: bool) -> anyhow::Result<UdpSocket> {
    let domain = if bind_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("create UDP socket for {bind_addr}"))?;
    socket.set_reuse_address(true).ok();
    if bind_addr.is_ipv6() {
        socket
            .set_only_v6(only_v6)
            .with_context(|| format!("set IPv6-only UDP mode for {bind_addr}"))?;
    }
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("bind UDP {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .with_context(|| format!("set UDP nonblocking on {bind_addr}"))?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).with_context(|| format!("adopt UDP socket {bind_addr}"))
}

#[derive(Clone, Copy)]
struct ListenerSpec {
    bind_addr: SocketAddr,
    only_v6: bool,
    optional: bool,
}

fn listener_specs(listen_ip: &str, port: u16) -> anyhow::Result<Vec<ListenerSpec>> {
    let listen_ip = listen_ip.trim();
    if listen_ip.is_empty() || listen_ip == "0.0.0.0" || listen_ip == "::" || listen_ip == "[::]" {
        return Ok(vec![
            ListenerSpec {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                only_v6: false,
                optional: false,
            },
            ListenerSpec {
                bind_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
                only_v6: true,
                optional: true,
            },
        ]);
    }

    let bind_ip = listen_ip
        .parse::<IpAddr>()
        .with_context(|| format!("parse listen_ip {listen_ip}"))?;
    Ok(vec![ListenerSpec {
        bind_addr: SocketAddr::new(bind_ip, port),
        only_v6: bind_ip.is_ipv6(),
        optional: false,
    }])
}

pub(crate) fn effective_listen_ip(remote: &NodeConfigResponse) -> String {
    let listen_ip = remote.listen_ip.trim();
    if listen_ip.is_empty() {
        DEFAULT_LISTEN_IP.to_string()
    } else {
        listen_ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_listen_generates_dual_stack_specs() {
        let specs = listener_specs("0.0.0.0", 443).expect("listener specs");
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv4()));
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv6()));
    }
}
