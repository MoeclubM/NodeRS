pub(crate) mod dns;
pub(crate) mod reality;
pub(crate) mod reality_tls;
pub(crate) mod routing;
pub(crate) mod rules;
pub(crate) mod socksaddr;
pub(crate) mod tls;
pub(crate) mod traffic;
pub(crate) mod transport;

use anyhow::{Context, ensure};
use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use tokio::net::{TcpListener, UdpSocket};
use tracing::warn;

use crate::acme;
use crate::panel::{CertConfig, NodeConfigResponse};

const DEFAULT_LISTEN_IP: &str = "0.0.0.0";
const TCP_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveTlsConfig {
    pub source: tls::TlsMaterialSource,
    pub ech: Option<tls::EchConfigSource>,
    pub reality: Option<RealityConfig>,
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RealityConfig {
    pub server_name: String,
    pub server_names: Vec<String>,
    pub server_port: u16,
    pub allow_insecure: bool,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
}

impl EffectiveTlsConfig {
    pub(crate) fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        let cert_mode = remote
            .cert_config
            .as_ref()
            .map(|config| config.cert_mode())
            .unwrap_or("self_signed");
        let normalized_cert_mode = cert_mode.to_ascii_lowercase();
        match normalized_cert_mode.as_str() {
            "file" | "path" => {
                let cert_config = remote
                    .cert_config
                    .as_ref()
                    .context("Xboard cert_config is required for file certificate mode")?;
                let cert_path = cert_config
                    .resolved_cert_path()
                    .context("Xboard cert_config must include cert_path and key_path")?;
                let key_path = cert_config
                    .resolved_key_path()
                    .context("Xboard cert_config must include cert_path and key_path")?;
                Ok(Self {
                    source: tls::TlsMaterialSource::Files {
                        cert_path: cert_path.into(),
                        key_path: key_path.into(),
                    },
                    ech: effective_ech_config(remote)?,
                    reality: effective_reality_config(remote)?,
                    alpn: effective_alpn(remote),
                })
            }
            "inline" | "pem" | "content" => {
                let cert_config = remote
                    .cert_config
                    .as_ref()
                    .context("Xboard cert_config is required for inline certificate mode")?;
                let cert_pem = cert_config.resolved_cert_pem().context(
                    "Xboard cert_config inline mode must include certificate PEM and private key PEM",
                )?;
                let key_pem = cert_config.resolved_key_pem().context(
                    "Xboard cert_config inline mode must include certificate PEM and private key PEM",
                )?;
                Ok(Self {
                    source: tls::TlsMaterialSource::Inline {
                        cert_pem: cert_pem.into_bytes(),
                        key_pem: key_pem.into_bytes(),
                    },
                    ech: effective_ech_config(remote)?,
                    reality: effective_reality_config(remote)?,
                    alpn: effective_alpn(remote),
                })
            }
            "acme" | "letsencrypt" | "http" | "dns" => {
                let cert_config = remote
                    .cert_config
                    .as_ref()
                    .context("Xboard cert_config is required for ACME certificate mode")?;
                let domains = effective_acme_domains(remote, cert_config);
                if domains.is_empty() {
                    anyhow::bail!(
                        "Xboard cert_config acme mode must include domain, domains, or server_name"
                    );
                }
                let storage_name = acme_storage_name(&domains);
                let cert_path = cert_config
                    .resolved_cert_path()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(format!("acme/{storage_name}/fullchain.pem")));
                let key_path = if let Some(key_path) = cert_config.resolved_key_path() {
                    key_path.into()
                } else {
                    cert_path
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("acme"))
                        .join("privkey.pem")
                };
                let account_key_path = if !cert_config.account_key_path().is_empty() {
                    cert_config.account_key_path().into()
                } else {
                    cert_path.with_extension("account.pem")
                };
                Ok(Self {
                    source: tls::TlsMaterialSource::Acme {
                        cert_path,
                        key_path,
                        config: acme::AcmeConfig {
                            directory_url: cert_config.directory_url().to_string(),
                            email: cert_config.email().to_string(),
                            domains,
                            renew_before_days: cert_config.renew_before_days(),
                            account_key_path,
                            challenge: effective_acme_challenge(
                                normalized_cert_mode.as_str(),
                                cert_config,
                            )?,
                        },
                    },
                    ech: effective_ech_config(remote)?,
                    reality: effective_reality_config(remote)?,
                    alpn: effective_alpn(remote),
                })
            }
            "none" | "self_signed" | "self-signed" => {
                let mut subject_alt_names = Vec::new();
                push_unique_domain(&mut subject_alt_names, remote.server_name.trim());
                push_unique_domain(
                    &mut subject_alt_names,
                    remote.tls_settings.server_name.trim(),
                );
                for name in &remote.tls_settings.server_names {
                    push_unique_domain(&mut subject_alt_names, name.trim());
                }
                if subject_alt_names.is_empty() {
                    subject_alt_names.push("localhost".to_string());
                }
                Ok(Self {
                    source: tls::TlsMaterialSource::SelfSigned { subject_alt_names },
                    ech: effective_ech_config(remote)?,
                    reality: effective_reality_config(remote)?,
                    alpn: effective_alpn(remote),
                })
            }
            _ => anyhow::bail!("unsupported Xboard cert_config.cert_mode {cert_mode}"),
        }
    }
}

fn effective_alpn(remote: &NodeConfigResponse) -> Vec<String> {
    remote
        .alpn
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn effective_acme_domains(remote: &NodeConfigResponse, cert_config: &CertConfig) -> Vec<String> {
    let mut domains = cert_config.domains();
    if domains.is_empty() {
        push_unique_domain(&mut domains, remote.server_name.trim());
        push_unique_domain(&mut domains, remote.tls_settings.server_name.trim());
        for name in &remote.tls_settings.server_names {
            push_unique_domain(&mut domains, name.trim());
        }
    }
    domains
}

fn push_unique_domain(domains: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        return;
    }
    if !domains
        .iter()
        .any(|domain| domain.eq_ignore_ascii_case(value))
    {
        domains.push(value.to_string());
    }
}

fn acme_storage_name(domains: &[String]) -> String {
    let candidate = domains
        .iter()
        .find(|domain| !domain.trim().starts_with("*."))
        .or_else(|| domains.first())
        .map(|domain| domain.trim().trim_start_matches("*."))
        .unwrap_or_default();
    let storage_name: String = candidate
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if storage_name.is_empty() {
        "default".to_string()
    } else {
        storage_name
    }
}

fn effective_acme_challenge(
    cert_mode: &str,
    cert_config: &CertConfig,
) -> anyhow::Result<acme::AcmeChallengeConfig> {
    let challenge_name = match cert_mode {
        "dns" => "dns",
        "http" => "http",
        _ => match cert_config
            .acme_challenge()
            .as_deref()
            .and_then(normalize_acme_challenge_name)
        {
            Some(challenge) => challenge,
            None if cert_config.dns_provider().is_some()
                || infer_dns_provider(cert_config).is_some() =>
            {
                "dns"
            }
            None => "http",
        },
    };

    match challenge_name {
        "http" => Ok(acme::AcmeChallengeConfig::Http01 {
            listen: cert_config.challenge_listen().to_string(),
        }),
        "dns" => Ok(acme::AcmeChallengeConfig::Dns01(acme::Dns01Config {
            provider: build_dns_provider_config(cert_config)?,
            propagation_timeout_secs: cert_config.dns_propagation_timeout_secs(),
            propagation_interval_secs: cert_config.dns_propagation_interval_secs(),
        })),
        other => anyhow::bail!("unsupported Xboard cert_config ACME challenge {other}"),
    }
}

fn normalize_acme_challenge_name(challenge: &str) -> Option<&'static str> {
    match challenge.trim().to_ascii_lowercase().as_str() {
        "http" | "http01" | "http-01" => Some("http"),
        "dns" | "dns01" | "dns-01" => Some("dns"),
        _ => None,
    }
}

fn infer_dns_provider(cert_config: &CertConfig) -> Option<&'static str> {
    if cert_config.cloudflare_api_token().is_some()
        || cert_config.cloudflare_api_key().is_some()
        || cert_config.cloudflare_api_email().is_some()
        || cert_config.dns_zone_id().is_some()
    {
        Some("cloudflare")
    } else if cert_config.alidns_access_key_id().is_some()
        || cert_config.alidns_access_key_secret().is_some()
    {
        Some("alidns")
    } else {
        None
    }
}

fn build_dns_provider_config(cert_config: &CertConfig) -> anyhow::Result<acme::DnsProviderConfig> {
    let provider_name = cert_config
        .dns_provider()
        .or_else(|| infer_dns_provider(cert_config).map(ToString::to_string))
        .context("Xboard cert_config dns mode requires dns_provider or provider credentials")?;
    match provider_name.trim().to_ascii_lowercase().as_str() {
        "cloudflare" | "cf" => {
            let api_token = cert_config.cloudflare_api_token();
            let api_key = cert_config.cloudflare_api_key();
            let api_email = cert_config.cloudflare_api_email();
            if api_token.is_none() && !(api_key.is_some() && api_email.is_some()) {
                anyhow::bail!(
                    "Xboard cert_config cloudflare dns mode requires api_token or api_key + api_email"
                );
            }
            Ok(acme::DnsProviderConfig::Cloudflare {
                api_token,
                api_key,
                api_email,
                zone_id: cert_config.dns_zone_id(),
                zone_name: cert_config.dns_zone_name(),
                ttl: cert_config.dns_ttl(),
            })
        }
        "alidns" | "aliyun" | "ali" => {
            let access_key_id = cert_config
                .alidns_access_key_id()
                .context("Xboard cert_config alidns dns mode requires access_key_id")?;
            let access_key_secret = cert_config
                .alidns_access_key_secret()
                .context("Xboard cert_config alidns dns mode requires access_key_secret")?;
            Ok(acme::DnsProviderConfig::AliDns {
                access_key_id,
                access_key_secret,
                zone_name: cert_config.dns_zone_name(),
                ttl: cert_config.dns_ttl(),
            })
        }
        other => anyhow::bail!("unsupported Xboard cert_config dns_provider {other}"),
    }
}

fn effective_ech_config(
    remote: &NodeConfigResponse,
) -> anyhow::Result<Option<tls::EchConfigSource>> {
    if !remote.tls_settings.ech.is_enabled() {
        return Ok(None);
    }

    let key_path = remote.tls_settings.ech.key_path.trim();
    let config_path = remote.tls_settings.ech.config_path.trim();
    let key = remote.tls_settings.ech.key.trim();
    let config = remote.tls_settings.ech.config.trim();

    if !key_path.is_empty() {
        return Ok(Some(tls::EchConfigSource::Files {
            key_path: key_path.into(),
            config_path: if config_path.is_empty() {
                None
            } else {
                Some(config_path.into())
            },
        }));
    }

    if !key.is_empty() {
        return Ok(Some(tls::EchConfigSource::Inline {
            key: key.as_bytes().to_vec(),
            config: if config.is_empty() {
                None
            } else {
                Some(config.as_bytes().to_vec())
            },
        }));
    }

    anyhow::bail!("Xboard tls_settings.ech must include key or key_path")
}

pub(crate) fn effective_reality_config(
    remote: &NodeConfigResponse,
) -> anyhow::Result<Option<RealityConfig>> {
    if remote.tls_mode() != 2 {
        return Ok(None);
    }

    let settings = remote.effective_reality_settings();
    let server_names = effective_reality_server_names(&settings);
    ensure!(
        !server_names.is_empty(),
        "Xboard reality_settings.server_name or server_names is required for tls mode 2"
    );
    let private_key = settings.private_key.trim();
    ensure!(
        !private_key.is_empty(),
        "Xboard reality_settings.private_key is required for tls mode 2"
    );

    let short_ids =
        decode_reality_short_ids(&settings).context("decode Xboard reality_settings.short_id")?;

    Ok(Some(RealityConfig {
        server_name: server_names[0].clone(),
        server_names,
        server_port: if settings.server_port == 0 {
            remote.server_port
        } else {
            settings.server_port
        },
        allow_insecure: settings.allow_insecure,
        private_key: decode_reality_key(private_key)
            .context("decode Xboard reality_settings.private_key")?,
        short_ids,
    }))
}

fn effective_reality_server_names(settings: &crate::panel::NodeRealitySettings) -> Vec<String> {
    let mut names = Vec::new();
    push_reality_server_name(&mut names, settings.server_name.trim());
    for name in &settings.server_names {
        push_reality_server_name(&mut names, name.trim());
    }
    names
}

fn push_reality_server_name(names: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        return;
    }
    if !names.iter().any(|name| name == value) {
        names.push(value.to_string());
    }
}

fn decode_reality_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .with_context(|| format!("invalid base64url key {encoded}"))?;
    ensure!(decoded.len() == 32, "REALITY key must decode to 32 bytes");
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn decode_reality_short_ids(
    settings: &crate::panel::NodeRealitySettings,
) -> anyhow::Result<Vec<[u8; 8]>> {
    let mut values = settings
        .short_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if !settings.short_id.trim().is_empty() || values.is_empty() {
        values.insert(0, settings.short_id.as_str());
    }

    let mut short_ids = Vec::with_capacity(values.len());
    for value in values {
        let short_id = decode_reality_short_id(value.trim())?;
        if !short_ids.contains(&short_id) {
            short_ids.push(short_id);
        }
    }
    Ok(short_ids)
}

fn decode_reality_short_id(hex: &str) -> anyhow::Result<[u8; 8]> {
    ensure!(
        hex.len() <= 16,
        "REALITY short_id must be at most 16 hex characters"
    );
    ensure!(
        hex.len() % 2 == 0,
        "REALITY short_id must contain an even number of hex characters"
    );
    let mut short_id = [0u8; 8];
    let decoded_len = hex.len() / 2;
    hex::decode_to_slice(hex.as_bytes(), &mut short_id[..decoded_len])
        .with_context(|| format!("invalid REALITY short_id {hex}"))?;
    Ok(short_id)
}

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
    use crate::panel::{CertConfig, NodeConfigResponse, NodeTlsSettings};

    const REALITY_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "vless".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            server_name: "node.example.com".to_string(),
            cert_config: Some(CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn wildcard_listen_generates_dual_stack_specs() {
        let specs = listener_specs("0.0.0.0", 443).expect("listener specs");
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv4()));
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv6()));
    }

    #[test]
    fn self_signed_tls_includes_server_names_array() {
        let remote = NodeConfigResponse {
            cert_config: Some(CertConfig {
                cert_mode: "self_signed".to_string(),
                ..Default::default()
            }),
            tls_settings: NodeTlsSettings {
                server_name: "tls.example.com".to_string(),
                server_names: vec!["cdn.example.com".to_string(), "TLS.EXAMPLE.COM".to_string()],
                ..Default::default()
            },
            ..base_remote()
        };

        let effective = EffectiveTlsConfig::from_remote(&remote).expect("tls config");
        match effective.source {
            tls::TlsMaterialSource::SelfSigned { subject_alt_names } => {
                assert_eq!(
                    subject_alt_names,
                    vec![
                        "node.example.com".to_string(),
                        "tls.example.com".to_string(),
                        "cdn.example.com".to_string()
                    ]
                );
            }
            _ => unreachable!("expected self-signed TLS source"),
        }
    }

    #[test]
    fn acme_tls_includes_server_names_array_when_domains_are_empty() {
        let remote = NodeConfigResponse {
            cert_config: Some(CertConfig {
                cert_mode: "acme".to_string(),
                ..Default::default()
            }),
            tls_settings: NodeTlsSettings {
                server_names: vec!["cdn.example.com".to_string()],
                ..Default::default()
            },
            ..base_remote()
        };

        let effective = EffectiveTlsConfig::from_remote(&remote).expect("tls config");
        match effective.source {
            tls::TlsMaterialSource::Acme { config, .. } => {
                assert_eq!(
                    config.domains,
                    vec![
                        "node.example.com".to_string(),
                        "cdn.example.com".to_string()
                    ]
                );
            }
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn rejects_reality_tls_mode_without_private_key() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            reality_settings: crate::panel::NodeRealitySettings {
                server_name: "reality.example.com".to_string(),
                public_key: REALITY_KEY_B64.to_string(),
                ..Default::default()
            },
            ..base_remote()
        };

        let error = effective_reality_config(&remote).expect_err("reality settings");
        assert!(error.to_string().contains("reality_settings.private_key"));
    }

    #[test]
    fn rejects_reality_tls_mode_without_any_server_name() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            server_name: String::new(),
            reality_settings: crate::panel::NodeRealitySettings {
                public_key: REALITY_KEY_B64.to_string(),
                private_key: REALITY_KEY_B64.to_string(),
                ..Default::default()
            },
            ..base_remote()
        };

        let error = effective_reality_config(&remote).expect_err("reality server name");
        assert!(
            error
                .to_string()
                .contains("reality_settings.server_name or server_names")
        );
    }

    #[test]
    fn parses_reality_config_from_tls_mode_two() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "tls": 2,
            "tls_settings": {
                "server_name": "reality.example.com",
                "server_port": 8443,
                "allow_insecure": true,
                "public_key": REALITY_KEY_B64,
                "private_key": REALITY_KEY_B64,
                "short_id": "a1b2"
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse remote");

        let reality = effective_reality_config(&remote)
            .expect("reality config")
            .expect("reality config present");
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(
            reality.server_names,
            vec!["reality.example.com".to_string()]
        );
        assert_eq!(reality.server_port, 8443);
        assert!(reality.allow_insecure);
        assert_eq!(reality.private_key, [0u8; 32]);
        assert_eq!(reality.short_ids, vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]]);
    }

    #[test]
    fn reality_config_defaults_port_and_accepts_camel_case_fields() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 2443,
            "server_name": "node.example.com",
            "tls": 2,
            "realitySettings": {
                "server_name": "reality.example.com",
                "publicKey": REALITY_KEY_B64,
                "privateKey": REALITY_KEY_B64,
                "shortId": ""
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse remote");

        let reality = effective_reality_config(&remote)
            .expect("reality config")
            .expect("reality config present");
        assert_eq!(reality.server_port, 2443);
        assert_eq!(reality.short_ids, vec![[0u8; 8]]);
    }

    #[test]
    fn reality_config_accepts_server_names_array() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 2443,
            "tls": 2,
            "realitySettings": {
                "serverName": "cas-bridge.xethub.hf.co",
                "serverNames": ["oracle-osa-01.telecom.moe", "cdn.example.com"],
                "publicKey": REALITY_KEY_B64,
                "privateKey": REALITY_KEY_B64,
                "shortIds": ["a1b2"]
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse remote");

        let reality = effective_reality_config(&remote)
            .expect("reality config")
            .expect("reality config present");
        assert_eq!(
            reality.server_names,
            vec![
                "cas-bridge.xethub.hf.co".to_string(),
                "oracle-osa-01.telecom.moe".to_string(),
                "cdn.example.com".to_string()
            ]
        );
    }

    #[test]
    fn reality_config_accepts_missing_public_key_for_server_side() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            reality_settings: crate::panel::NodeRealitySettings {
                server_name: "reality.example.com".to_string(),
                private_key: REALITY_KEY_B64.to_string(),
                short_id: "a1b2".to_string(),
                ..Default::default()
            },
            ..base_remote()
        };

        let reality = effective_reality_config(&remote)
            .expect("reality config")
            .expect("reality config present");
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(reality.private_key, [0u8; 32]);
    }

    #[test]
    fn parses_reality_short_ids_array() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 2443,
            "server_name": "node.example.com",
            "tls": 2,
            "realitySettings": {
                "serverName": "reality.example.com",
                "publicKey": REALITY_KEY_B64,
                "privateKey": REALITY_KEY_B64,
                "shortIds": ["a1b2", "c3d4"]
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse remote");

        let reality = effective_reality_config(&remote)
            .expect("reality config")
            .expect("reality config present");
        assert_eq!(
            reality.short_ids,
            vec![
                [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
                [0xc3, 0xd4, 0, 0, 0, 0, 0, 0]
            ]
        );
    }

    #[test]
    fn rejects_invalid_reality_settings() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "tls": 2,
            "tls_settings": {
                "server_name": "reality.example.com",
                "public_key": REALITY_KEY_B64,
                "private_key": REALITY_KEY_B64,
                "short_id": "not-hex"
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse remote");

        let error = effective_reality_config(&remote).expect_err("invalid short id");
        assert!(error.to_string().contains("short_id"));

        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "tls": 2,
            "tls_settings": {
                "server_name": "reality.example.com",
                "public_key": REALITY_KEY_B64
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse remote");

        let error = effective_reality_config(&remote).expect_err("missing private key");
        assert!(error.to_string().contains("private_key"));
    }
}
