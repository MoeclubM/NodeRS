mod activity;
pub(crate) mod dns;
mod padding;
mod reality;
pub(crate) mod routing;
pub(crate) mod rules;
mod session;
pub(crate) mod socksaddr;
pub(crate) mod tls;
pub(crate) mod traffic;
pub(crate) mod transport;
mod uot;

use anyhow::{Context, ensure};
use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::Accounting;
use crate::acme;
use crate::panel::{CertConfig, NodeConfigResponse, PanelUser, RouteConfig};

use self::padding::PaddingScheme;
use self::routing::RoutingTable;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const DEFAULT_LISTEN_IP: &str = "0.0.0.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub padding_scheme: Vec<String>,
    pub routes: Vec<RouteConfig>,
    pub custom_outbounds: Vec<serde_json::Value>,
    pub custom_routes: Vec<serde_json::Value>,
    pub tls: EffectiveTlsConfig,
}

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
    pub server_port: u16,
    pub allow_insecure: bool,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
    pub short_id: [u8; 8],
}

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            padding_scheme: if remote.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                remote.padding_scheme.clone()
            },
            routes: remote.routes.clone(),
            custom_outbounds: remote.custom_outbounds.clone(),
            custom_routes: remote.custom_routes.clone(),
            tls: EffectiveTlsConfig::from_remote(remote)?,
        })
    }
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
                let server_name = remote.server_name.trim();
                if !server_name.is_empty() {
                    subject_alt_names.push(server_name.to_string());
                }
                let tls_server_name = remote.tls_settings.server_name.trim();
                if !tls_server_name.is_empty()
                    && !subject_alt_names
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(tls_server_name))
                {
                    subject_alt_names.push(tls_server_name.to_string());
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
        let server_name = remote.server_name.trim();
        if !server_name.is_empty() {
            domains.push(server_name.to_string());
        }
        let tls_server_name = remote.tls_settings.server_name.trim();
        if !tls_server_name.is_empty()
            && !domains
                .iter()
                .any(|value| value.eq_ignore_ascii_case(tls_server_name))
        {
            domains.push(tls_server_name.to_string());
        }
    }
    domains
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

fn effective_reality_config(remote: &NodeConfigResponse) -> anyhow::Result<Option<RealityConfig>> {
    if remote.tls_mode() != 2 {
        return Ok(None);
    }

    let settings = remote.effective_reality_settings();
    let server_name = settings.server_name.trim();
    ensure!(
        !server_name.is_empty(),
        "Xboard reality_settings.server_name is required for tls mode 2"
    );
    let public_key = settings.public_key.trim();
    ensure!(
        !public_key.is_empty(),
        "Xboard reality_settings.public_key is required for tls mode 2"
    );
    let private_key = settings.private_key.trim();
    ensure!(
        !private_key.is_empty(),
        "Xboard reality_settings.private_key is required for tls mode 2"
    );

    Ok(Some(RealityConfig {
        server_name: server_name.to_string(),
        server_port: if settings.server_port == 0 {
            remote.server_port
        } else {
            settings.server_port
        },
        allow_insecure: settings.allow_insecure,
        public_key: decode_reality_key(public_key)
            .context("decode Xboard reality_settings.public_key")?,
        private_key: decode_reality_key(private_key)
            .context("decode Xboard reality_settings.private_key")?,
        short_id: decode_reality_short_id(settings.short_id.trim())
            .context("decode Xboard reality_settings.short_id")?,
    }))
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

fn decode_reality_short_id(hex: &str) -> anyhow::Result<[u8; 8]> {
    ensure!(
        hex.len() <= 16,
        "REALITY short_id must be at most 16 hex characters"
    );
    let padded = format!("{:0>16}", hex);
    let mut short_id = [0u8; 8];
    hex::decode_to_slice(padded.as_bytes(), &mut short_id)
        .with_context(|| format!("invalid REALITY short_id {hex}"))?;
    Ok(short_id)
}

pub struct ServerController {
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    tls_materials: AsyncMutex<Option<tls::LoadedTlsMaterials>>,
    accounting: Arc<Accounting>,
    padding_scheme: Arc<RwLock<PaddingScheme>>,
    routing: Arc<RwLock<RoutingTable>>,
    inner: Mutex<Option<RunningServer>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::{
        CertConfig, NodeConfigResponse, NodeEchSettings, NodeTlsSettings, PanelUser,
    };

    const REALITY_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn base_remote() -> NodeConfigResponse {
        NodeConfigResponse {
            protocol: "anytls".to_string(),
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
    fn fills_default_padding_from_remote_config() {
        let remote = base_remote();
        let effective = EffectiveNodeConfig::from_remote(&remote).expect("effective config");
        assert_eq!(effective.listen_ip, "0.0.0.0");
        assert_eq!(effective.padding_scheme, PaddingScheme::default_lines());
    }

    #[test]
    fn wildcard_listen_generates_dual_stack_specs() {
        let specs = listener_specs("0.0.0.0", 443).expect("listener specs");
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv4()));
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv6()));
    }

    #[test]
    fn keeps_supported_custom_routing_fields() {
        let remote = NodeConfigResponse {
            custom_outbounds: vec![serde_json::json!({
                "tag": "ipv6-first",
                "type": "direct",
                "domain_strategy": "prefer_ipv6"
            })],
            custom_routes: vec![serde_json::json!({
                "domain_suffix": ["example.com"],
                "outbound": "ipv6-first"
            })],
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("effective config");
        assert_eq!(effective.custom_outbounds.len(), 1);
        assert_eq!(effective.custom_routes.len(), 1);
    }

    #[test]
    fn accepts_ech_key_payload() {
        let remote = NodeConfigResponse {
            tls_settings: NodeTlsSettings {
                server_name: "node.example.com".to_string(),
                allow_insecure: false,
                ech: NodeEchSettings {
                    enabled: true,
                    key: "-----BEGIN ECH KEYS-----\nAAAA\n-----END ECH KEYS-----".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("ech");
        assert!(matches!(
            effective.tls.ech,
            Some(tls::EchConfigSource::Inline { .. })
        ));
    }

    #[test]
    fn rejects_ech_without_key() {
        let remote = NodeConfigResponse {
            tls_settings: NodeTlsSettings {
                server_name: "node.example.com".to_string(),
                allow_insecure: false,
                ech: NodeEchSettings {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("ech");
        assert!(error.to_string().contains("tls_settings.ech"));
    }

    #[test]
    fn rejects_unsupported_cert_mode() {
        let mut remote = base_remote();
        remote.cert_config = Some(CertConfig {
            cert_mode: "pkcs12".to_string(),
            cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
            key_path: "/etc/ssl/private/privkey.pem".to_string(),
            ..Default::default()
        });

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("cert mode");
        assert!(error.to_string().contains("cert_config.cert_mode"));
    }

    #[test]
    fn accepts_inline_cert_mode() {
        let remote = NodeConfigResponse {
            cert_config: Some(CertConfig {
                cert_mode: "inline".to_string(),
                cert_path: String::new(),
                key_path: String::new(),
                cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
                    .to_string(),
                key_pem: "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----".to_string(),
                ..Default::default()
            }),
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("inline cert mode");
        assert!(matches!(
            effective.tls.source,
            tls::TlsMaterialSource::Inline { .. }
        ));
    }

    #[test]
    fn accepts_path_cert_mode_with_extended_aliases() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "path",
                "certificate_path": "/etc/ssl/fullchain.pem",
                "private_key_path": "/etc/ssl/privkey.pem"
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("path cert mode");
        match effective.tls.source {
            tls::TlsMaterialSource::Files {
                cert_path,
                key_path,
            } => {
                assert_eq!(cert_path, PathBuf::from("/etc/ssl/fullchain.pem"));
                assert_eq!(key_path, PathBuf::from("/etc/ssl/privkey.pem"));
            }
            _ => unreachable!("expected file TLS source"),
        }
    }

    #[test]
    fn accepts_content_cert_mode_with_extended_aliases() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "content",
                "cert_content": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "key_content": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("content cert mode");
        match effective.tls.source {
            tls::TlsMaterialSource::Inline { cert_pem, key_pem } => {
                assert!(
                    String::from_utf8(cert_pem)
                        .expect("cert pem")
                        .contains("BEGIN CERTIFICATE")
                );
                assert!(
                    String::from_utf8(key_pem)
                        .expect("key pem")
                        .contains("BEGIN PRIVATE KEY")
                );
            }
            _ => unreachable!("expected inline TLS source"),
        }
    }

    #[test]
    fn accepts_acme_cert_mode() {
        let remote = NodeConfigResponse {
            cert_config: Some(CertConfig {
                cert_mode: "acme".to_string(),
                cert_path: "/var/lib/noders/anytls/node.example.com/fullchain.pem".to_string(),
                key_path: "/var/lib/noders/anytls/node.example.com/privkey.pem".to_string(),
                email: "ops@example.com".to_string(),
                ..Default::default()
            }),
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("acme cert mode");
        assert!(matches!(
            effective.tls.source,
            tls::TlsMaterialSource::Acme { .. }
        ));
        match effective.tls.source {
            tls::TlsMaterialSource::Acme {
                cert_path,
                key_path,
                config,
            } => {
                assert_eq!(
                    cert_path,
                    PathBuf::from("/var/lib/noders/anytls/node.example.com/fullchain.pem")
                );
                assert_eq!(
                    key_path,
                    PathBuf::from("/var/lib/noders/anytls/node.example.com/privkey.pem")
                );
                assert_eq!(
                    config.directory_url,
                    "https://acme-v02.api.letsencrypt.org/directory"
                );
                assert_eq!(config.email, "ops@example.com");
                assert_eq!(config.domains, vec!["node.example.com".to_string()]);
                assert_eq!(config.renew_before_days, 30);
                assert_eq!(
                    config.account_key_path,
                    PathBuf::from("/var/lib/noders/anytls/node.example.com/fullchain.account.pem")
                );
                match config.challenge {
                    acme::AcmeChallengeConfig::Http01 { listen } => {
                        assert_eq!(listen, "0.0.0.0:80");
                    }
                    _ => unreachable!("expected http-01 ACME challenge"),
                }
            }
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn accepts_http_cert_mode_as_acme() {
        let remote = NodeConfigResponse {
            cert_config: Some(CertConfig {
                cert_mode: "http".to_string(),
                email: "ops@example.com".to_string(),
                ..Default::default()
            }),
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("http cert mode");
        match effective.tls.source {
            tls::TlsMaterialSource::Acme {
                cert_path,
                key_path,
                config,
            } => {
                assert_eq!(
                    cert_path,
                    PathBuf::from("acme/node.example.com/fullchain.pem")
                );
                assert_eq!(key_path, PathBuf::from("acme/node.example.com/privkey.pem"));
                assert_eq!(
                    config.account_key_path,
                    PathBuf::from("acme/node.example.com/fullchain.account.pem")
                );
                match config.challenge {
                    acme::AcmeChallengeConfig::Http01 { listen } => {
                        assert_eq!(listen, "0.0.0.0:80");
                    }
                    _ => unreachable!("expected http-01 ACME challenge"),
                }
            }
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn accepts_dns_cert_mode_as_dns01_acme() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "dns",
                "domains": ["example.com", "*.example.com"],
                "provider": "cloudflare",
                "zone_id": "zone-123",
                "env": {
                    "CF_DNS_API_TOKEN": "token-abc"
                },
                "propagation_timeout": 240,
                "propagation_interval": 7
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("dns cert mode");
        match effective.tls.source {
            tls::TlsMaterialSource::Acme {
                cert_path,
                key_path,
                config,
            } => {
                assert_eq!(cert_path, PathBuf::from("acme/example.com/fullchain.pem"));
                assert_eq!(key_path, PathBuf::from("acme/example.com/privkey.pem"));
                assert_eq!(
                    config.account_key_path,
                    PathBuf::from("acme/example.com/fullchain.account.pem")
                );
                assert_eq!(
                    config.domains,
                    vec!["example.com".to_string(), "*.example.com".to_string()]
                );
                match config.challenge {
                    acme::AcmeChallengeConfig::Dns01(acme::Dns01Config {
                        provider,
                        propagation_timeout_secs,
                        propagation_interval_secs,
                    }) => {
                        assert_eq!(propagation_timeout_secs, 240);
                        assert_eq!(propagation_interval_secs, 7);
                        match provider {
                            acme::DnsProviderConfig::Cloudflare {
                                api_token,
                                zone_id,
                                zone_name,
                                ttl,
                                ..
                            } => {
                                assert_eq!(api_token.as_deref(), Some("token-abc"));
                                assert_eq!(zone_id.as_deref(), Some("zone-123"));
                                assert_eq!(zone_name, None);
                                assert_eq!(ttl, None);
                            }
                            _ => unreachable!("expected cloudflare DNS provider"),
                        }
                    }
                    _ => unreachable!("expected dns-01 ACME challenge"),
                }
            }
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn accepts_dns_cert_mode_with_env_text_block() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "dns",
                "provider": "cloudflare",
                "env": "CF_API_TOKEN=token-abc"
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("dns cert mode");
        match effective.tls.source {
            tls::TlsMaterialSource::Acme { config, .. } => match config.challenge {
                acme::AcmeChallengeConfig::Dns01(acme::Dns01Config { provider, .. }) => {
                    match provider {
                        acme::DnsProviderConfig::Cloudflare { api_token, .. } => {
                            assert_eq!(api_token.as_deref(), Some("token-abc"));
                        }
                        _ => unreachable!("expected cloudflare DNS provider"),
                    }
                }
                _ => unreachable!("expected dns-01 ACME challenge"),
            },
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn infers_cloudflare_provider_from_env_text_block() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "acme",
                "env": "CF_API_TOKEN=token-abc"
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("acme dns provider");
        match effective.tls.source {
            tls::TlsMaterialSource::Acme { config, .. } => match config.challenge {
                acme::AcmeChallengeConfig::Dns01(acme::Dns01Config { provider, .. }) => {
                    match provider {
                        acme::DnsProviderConfig::Cloudflare { api_token, .. } => {
                            assert_eq!(api_token.as_deref(), Some("token-abc"));
                        }
                        _ => unreachable!("expected cloudflare DNS provider"),
                    }
                }
                _ => unreachable!("expected dns-01 ACME challenge"),
            },
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn accepts_dns_cert_mode_with_nested_provider_env_block() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "dns",
                "provider": "cloudflare",
                "cloudflare": {
                    "environment_variables": "CF_API_TOKEN=token-abc"
                }
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("dns cert mode");
        match effective.tls.source {
            tls::TlsMaterialSource::Acme { config, .. } => match config.challenge {
                acme::AcmeChallengeConfig::Dns01(acme::Dns01Config { provider, .. }) => {
                    match provider {
                        acme::DnsProviderConfig::Cloudflare { api_token, .. } => {
                            assert_eq!(api_token.as_deref(), Some("token-abc"));
                        }
                        _ => unreachable!("expected cloudflare DNS provider"),
                    }
                }
                _ => unreachable!("expected dns-01 ACME challenge"),
            },
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn acme_mode_with_dns_provider_defaults_to_dns01() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "acme",
                "provider": "alidns",
                "zone_name": "example.com",
                "env": {
                    "ALICLOUD_ACCESS_KEY_ID": "akid",
                    "ALICLOUD_ACCESS_KEY_SECRET": "aksecret"
                }
            }
        }))
        .expect("parse remote");

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("acme dns provider");
        match effective.tls.source {
            tls::TlsMaterialSource::Acme { config, .. } => match config.challenge {
                acme::AcmeChallengeConfig::Dns01(acme::Dns01Config { provider, .. }) => {
                    match provider {
                        acme::DnsProviderConfig::AliDns {
                            access_key_id,
                            access_key_secret,
                            zone_name,
                            ttl,
                        } => {
                            assert_eq!(access_key_id, "akid");
                            assert_eq!(access_key_secret, "aksecret");
                            assert_eq!(zone_name.as_deref(), Some("example.com"));
                            assert_eq!(ttl, None);
                        }
                        _ => unreachable!("expected alidns provider"),
                    }
                }
                _ => unreachable!("expected dns-01 ACME challenge"),
            },
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn defaults_to_self_signed_when_cert_config_is_missing() {
        let remote = NodeConfigResponse {
            cert_config: None,
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("self-signed");
        match effective.tls.source {
            tls::TlsMaterialSource::SelfSigned { subject_alt_names } => {
                assert_eq!(subject_alt_names, vec!["node.example.com".to_string()]);
            }
            _ => unreachable!("expected self-signed TLS source"),
        }
    }

    #[test]
    fn treats_cert_mode_none_as_self_signed() {
        let remote = NodeConfigResponse {
            server_name: String::new(),
            tls_settings: NodeTlsSettings {
                server_name: "tls.example.com".to_string(),
                ..Default::default()
            },
            cert_config: Some(CertConfig::default()),
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("self-signed");
        match effective.tls.source {
            tls::TlsMaterialSource::SelfSigned { subject_alt_names } => {
                assert_eq!(subject_alt_names, vec!["tls.example.com".to_string()]);
            }
            _ => unreachable!("expected self-signed TLS source"),
        }
    }

    #[test]
    fn rejects_unsupported_network() {
        let remote = NodeConfigResponse {
            network: "ws".to_string(),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network");
        assert!(error.to_string().contains("network"));
    }

    #[test]
    fn rejects_reality_tls_mode_without_reality_settings() {
        let remote = NodeConfigResponse {
            tls: Some(serde_json::json!(2)),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("reality settings");
        assert!(error.to_string().contains("reality_settings.server_name"));
    }

    #[test]
    fn rejects_unsupported_network_settings() {
        let remote = NodeConfigResponse {
            network: "tcp".to_string(),
            network_settings: Some(serde_json::json!({
                "header": {
                    "type": "none"
                }
            })),
            ..base_remote()
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network settings");
        assert!(error.to_string().contains("networkSettings"));
    }

    #[test]
    fn propagates_explicit_alpn_from_panel_config() {
        let remote = NodeConfigResponse {
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            ..base_remote()
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("effective config");
        assert_eq!(
            effective.tls.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    #[test]
    fn parses_reality_config_from_tls_mode_two() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
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
        assert_eq!(reality.server_port, 8443);
        assert!(reality.allow_insecure);
        assert_eq!(reality.public_key, [0u8; 32]);
        assert_eq!(reality.private_key, [0u8; 32]);
        assert_eq!(reality.short_id, [0, 0, 0, 0, 0, 0, 0xa1, 0xb2]);
    }

    #[test]
    fn reality_config_defaults_port_and_accepts_camel_case_fields() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
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
        assert_eq!(reality.short_id, [0u8; 8]);
    }

    #[test]
    fn rejects_invalid_reality_settings() {
        let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
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
            "protocol": "anytls",
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

    #[test]
    fn rejects_anytls_users_without_uuid() {
        let controller = ServerController::new(Accounting::new());
        let error = controller
            .replace_users(&[PanelUser {
                id: 1,
                ..Default::default()
            }])
            .expect_err("missing uuid should be rejected");

        assert!(error.to_string().contains("missing uuid"));
    }
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    handle: JoinHandle<()>,
}

impl ServerController {
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            tls_config: Arc::new(RwLock::new(None)),
            tls_materials: AsyncMutex::new(None),
            accounting,
            padding_scheme: Arc::new(RwLock::new(PaddingScheme::default())),
            routing: Arc::new(RwLock::new(RoutingTable::default())),
            inner: Mutex::new(None),
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        for user in users {
            if user.uuid.trim().is_empty() {
                anyhow::bail!("AnyTLS user {} is missing uuid", user.id);
            }
        }
        self.accounting.replace_users(users);
        Ok(())
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        let padding = if config.padding_scheme.is_empty() {
            PaddingScheme::default()
        } else {
            PaddingScheme::from_lines(&config.padding_scheme)?
        };
        let routing = RoutingTable::from_remote(
            &config.routes,
            &config.custom_outbounds,
            &config.custom_routes,
        )
        .context("compile Xboard routing")?;
        *self
            .padding_scheme
            .write()
            .expect("padding scheme lock poisoned") = padding;
        *self.routing.write().expect("routing lock poisoned") = routing;
        self.update_tls_config(&config.tls).await?;

        let old = {
            let mut guard = self.inner.lock().expect("server controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip || running.server_port != config.server_port
            });
            if !should_restart {
                return Ok(());
            }
            guard.take()
        };

        if let Some(old) = old {
            old.handle.abort();
        }

        let listeners = bind_listeners(&config.listen_ip, config.server_port)?;
        let bind_addrs = listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();
        let tls_config = self.tls_config.clone();
        let accounting = self.accounting.clone();
        let padding_scheme = self.padding_scheme.clone();
        let routing = self.routing.clone();
        let handle = tokio::spawn(async move {
            info!(listen = ?bind_addrs, "AnyTLS listeners started");
            let mut accept_loops = JoinSet::new();
            for listener in listeners {
                let tls_config = tls_config.clone();
                let accounting = accounting.clone();
                let padding_scheme = padding_scheme.clone();
                let routing = routing.clone();
                accept_loops.spawn(async move {
                    accept_loop(listener, tls_config, accounting, padding_scheme, routing).await;
                });
            }

            while let Some(result) = accept_loops.join_next().await {
                match result {
                    Ok(()) => warn!("AnyTLS accept loop exited unexpectedly"),
                    Err(error) if error.is_cancelled() => break,
                    Err(error) => error!(%error, "AnyTLS accept loop crashed"),
                }
            }
        });

        let mut guard = self.inner.lock().expect("server controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            handle,
        });
        Ok(())
    }

    pub async fn refresh_tls(&self) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let Some(tls_materials) = tls_materials.as_mut() else {
            return Ok(());
        };
        if let Some(reloaded) = tls::reload_if_changed(tls_materials).await? {
            *self.tls_config.write().expect("tls config lock poisoned") = Some(reloaded);
            info!("TLS materials reloaded from disk");
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let old = {
            let mut guard = self.inner.lock().expect("server controller poisoned");
            guard.take()
        };
        if let Some(old) = old {
            old.handle.abort();
            info!(port = old.server_port, "AnyTLS listeners stopped");
        }
    }

    async fn update_tls_config(&self, tls: &EffectiveTlsConfig) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        let reality = tls.reality.as_ref().map(|reality| tls::RealityTlsConfig {
            server_name: reality.server_name.clone(),
            private_key: reality.private_key,
            short_id: reality.short_id,
        });
        let should_reload = tls_materials.as_ref().is_none_or(|current| {
            !current.matches_source(&tls.source, tls.ech.as_ref(), reality.as_ref(), &tls.alpn)
        });
        if !should_reload {
            return Ok(());
        }

        let reloaded =
            tls::load_tls_materials(&tls.source, tls.ech.as_ref(), reality.as_ref(), &tls.alpn)
                .await
                .context("load TLS materials")?;
        *self.tls_config.write().expect("tls config lock poisoned") = Some(reloaded.acceptor());
        *tls_materials = Some(reloaded);
        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<RwLock<Option<Arc<boring::ssl::SslAcceptor>>>>,
    accounting: Arc<Accounting>,
    padding_scheme: Arc<RwLock<PaddingScheme>>,
    routing: Arc<RwLock<RoutingTable>>,
) {
    let listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "accept connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let acceptor = {
            let tls_config = tls_config.read().expect("tls config lock poisoned").clone();
            let Some(tls_config) = tls_config else {
                warn!(listen = %listen, "TLS config is not ready; dropping connection");
                continue;
            };
            tls_config
        };
        let accounting = accounting.clone();
        let padding_scheme = padding_scheme.clone();
        let routing = routing.clone();
        tokio::spawn(async move {
            let tls_stream = match timeout(
                TLS_HANDSHAKE_TIMEOUT,
                tokio_boring::accept(acceptor.as_ref(), stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    warn!(%error, %source, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    warn!(%source, "TLS handshake timed out");
                    return;
                }
            };
            let padding = padding_scheme
                .read()
                .expect("padding scheme lock poisoned")
                .clone();
            let routing = routing.read().expect("routing lock poisoned").clone();
            if let Err(error) =
                session::serve_connection(tls_stream, source, accounting, padding, routing).await
            {
                warn!(%error, %source, "session terminated with error");
            }
        });
    }
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
        anyhow::bail!("no AnyTLS listeners could be started");
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

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !remote.network.trim().is_empty() && !remote.network.eq_ignore_ascii_case("tcp") {
        anyhow::bail!("Xboard network must be tcp for AnyTLS nodes");
    }
    if remote.tls.is_some() && !matches!(remote.tls_mode(), 0 | 1 | 2) {
        anyhow::bail!(
            "Xboard tls mode {} is not supported by NodeRS-AnyTLS AnyTLS server yet",
            remote.tls_mode()
        );
    }
    if remote.network_settings.is_some() {
        anyhow::bail!("Xboard networkSettings is not supported by NodeRS-AnyTLS AnyTLS server");
    }
    Ok(())
}
