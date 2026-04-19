mod activity;
mod dns;
mod padding;
mod routing;
mod rules;
mod session;
mod socksaddr;
mod tls;
mod traffic;
mod transport;
mod uot;

use anyhow::Context;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::Accounting;
use crate::panel::{NodeConfigResponse, RouteConfig};

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
pub struct EffectiveTlsConfig {
    pub source: tls::TlsMaterialSource,
    pub ech: Option<tls::EchConfigSource>,
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
    fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        let cert_mode = remote
            .cert_config
            .as_ref()
            .map(|config| config.cert_mode())
            .unwrap_or("self_signed");
        match cert_mode {
            "file" | "path" => {
                let cert_config = remote
                    .cert_config
                    .as_ref()
                    .context("Xboard cert_config is required for file certificate mode")?;
                let cert_path = cert_config.cert_path.trim();
                let key_path = cert_config.key_path.trim();
                if cert_path.is_empty() || key_path.is_empty() {
                    anyhow::bail!("Xboard cert_config must include cert_path and key_path");
                }
                Ok(Self {
                    source: tls::TlsMaterialSource::Files {
                        cert_path: cert_path.into(),
                        key_path: key_path.into(),
                    },
                    ech: effective_ech_config(remote)?,
                })
            }
            "inline" | "pem" | "content" => {
                let cert_config = remote
                    .cert_config
                    .as_ref()
                    .context("Xboard cert_config is required for inline certificate mode")?;
                let cert_pem = cert_config.cert_pem();
                let key_pem = cert_config.key_pem();
                if cert_pem.is_empty() || key_pem.is_empty() {
                    anyhow::bail!(
                        "Xboard cert_config inline mode must include certificate PEM and private key PEM"
                    );
                }
                Ok(Self {
                    source: tls::TlsMaterialSource::Inline {
                        cert_pem: cert_pem.as_bytes().to_vec(),
                        key_pem: key_pem.as_bytes().to_vec(),
                    },
                    ech: effective_ech_config(remote)?,
                })
            }
            "acme" | "letsencrypt" | "http" => {
                let cert_config = remote
                    .cert_config
                    .as_ref()
                    .context("Xboard cert_config is required for ACME certificate mode")?;
                let cert_path = cert_config.cert_path.trim();
                let key_path = cert_config.key_path.trim();
                if cert_path.is_empty() || key_path.is_empty() {
                    anyhow::bail!(
                        "Xboard cert_config acme mode must include cert_path and key_path"
                    );
                }
                let domain = if !cert_config.domain().is_empty() {
                    cert_config.domain().to_string()
                } else if !remote.server_name.trim().is_empty() {
                    remote.server_name.trim().to_string()
                } else if !remote.tls_settings.server_name.trim().is_empty() {
                    remote.tls_settings.server_name.trim().to_string()
                } else {
                    anyhow::bail!(
                        "Xboard cert_config acme mode must include domain or server_name"
                    );
                };
                let account_key_path = if !cert_config.account_key_path().is_empty() {
                    cert_config.account_key_path().into()
                } else {
                    PathBuf::from(cert_path).with_extension("account.pem")
                };
                Ok(Self {
                    source: tls::TlsMaterialSource::Acme {
                        cert_path: cert_path.into(),
                        key_path: key_path.into(),
                        directory_url: cert_config.directory_url().to_string(),
                        email: cert_config.email().to_string(),
                        domain,
                        challenge_listen: cert_config.challenge_listen().to_string(),
                        renew_before_days: cert_config.renew_before_days(),
                        account_key_path,
                    },
                    ech: effective_ech_config(remote)?,
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
                })
            }
            cert_mode => anyhow::bail!("unsupported Xboard cert_config.cert_mode {cert_mode}"),
        }
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
    use crate::panel::NodeConfigResponse;

    #[test]
    fn fills_default_padding_from_remote_config() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };
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
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: vec![serde_json::json!({
                "tag": "ipv6-first",
                "type": "direct",
                "domain_strategy": "prefer_ipv6"
            })],
            custom_routes: vec![serde_json::json!({
                "domain_suffix": ["example.com"],
                "outbound": "ipv6-first"
            })],
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("effective config");
        assert_eq!(effective.custom_outbounds.len(), 1);
        assert_eq!(effective.custom_routes.len(), 1);
    }

    #[test]
    fn accepts_ech_key_payload() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: crate::panel::NodeTlsSettings {
                server_name: "node.example.com".to_string(),
                allow_insecure: false,
                ech: crate::panel::NodeEchSettings {
                    enabled: true,
                    key: "-----BEGIN ECH KEYS-----\nAAAA\n-----END ECH KEYS-----".to_string(),
                    ..Default::default()
                },
            },
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
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
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: crate::panel::NodeTlsSettings {
                server_name: "node.example.com".to_string(),
                allow_insecure: false,
                ech: crate::panel::NodeEchSettings {
                    enabled: true,
                    ..Default::default()
                },
            },
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("ech");
        assert!(error.to_string().contains("tls_settings.ech"));
    }

    #[test]
    fn rejects_unsupported_cert_mode() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "pkcs12".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("cert mode");
        assert!(error.to_string().contains("cert_config.cert_mode"));
    }

    #[test]
    fn accepts_inline_cert_mode() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "inline".to_string(),
                cert_path: String::new(),
                key_path: String::new(),
                cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
                    .to_string(),
                key_pem: "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("inline cert mode");
        assert!(matches!(
            effective.tls.source,
            tls::TlsMaterialSource::Inline { .. }
        ));
    }

    #[test]
    fn accepts_acme_cert_mode() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "acme".to_string(),
                cert_path: "/var/lib/noders/anytls/node.example.com/fullchain.pem".to_string(),
                key_path: "/var/lib/noders/anytls/node.example.com/privkey.pem".to_string(),
                email: "ops@example.com".to_string(),
                ..Default::default()
            }),
            base_config: None,
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
                directory_url,
                email,
                domain,
                challenge_listen,
                renew_before_days,
                account_key_path,
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
                    directory_url,
                    "https://acme-v02.api.letsencrypt.org/directory"
                );
                assert_eq!(email, "ops@example.com");
                assert_eq!(domain, "node.example.com");
                assert_eq!(challenge_listen, "0.0.0.0:80");
                assert_eq!(renew_before_days, 30);
                assert_eq!(
                    account_key_path,
                    PathBuf::from("/var/lib/noders/anytls/node.example.com/fullchain.account.pem")
                );
            }
            _ => unreachable!("expected ACME TLS source"),
        }
    }

    #[test]
    fn accepts_http_cert_mode_as_acme() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "http".to_string(),
                cert_path: "/var/lib/noders/anytls/node.example.com/fullchain.pem".to_string(),
                key_path: "/var/lib/noders/anytls/node.example.com/privkey.pem".to_string(),
                email: "ops@example.com".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let effective = EffectiveNodeConfig::from_remote(&remote).expect("http cert mode");
        assert!(matches!(
            effective.tls.source,
            tls::TlsMaterialSource::Acme { .. }
        ));
    }

    #[test]
    fn defaults_to_self_signed_when_cert_config_is_missing() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: None,
            base_config: None,
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
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: String::new(),
            network_settings: None,
            server_name: String::new(),
            tls_settings: crate::panel::NodeTlsSettings {
                server_name: "tls.example.com".to_string(),
                ..Default::default()
            },
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig::default()),
            base_config: None,
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
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: "ws".to_string(),
            network_settings: None,
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network");
        assert!(error.to_string().contains("network"));
    }

    #[test]
    fn rejects_unsupported_network_settings() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            listen_ip: "0.0.0.0".to_string(),
            server_port: 443,
            network: "tcp".to_string(),
            network_settings: Some(serde_json::json!({
                "header": {
                    "type": "none"
                }
            })),
            server_name: "node.example.com".to_string(),
            tls_settings: Default::default(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            custom_outbounds: Vec::new(),
            custom_routes: Vec::new(),
            cert_config: Some(crate::panel::CertConfig {
                cert_mode: "file".to_string(),
                cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
                key_path: "/etc/ssl/private/privkey.pem".to_string(),
                ..Default::default()
            }),
            base_config: None,
        };

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network settings");
        assert!(error.to_string().contains("networkSettings"));
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
        let should_reload = tls_materials
            .as_ref()
            .is_none_or(|current| !current.matches_source(&tls.source, tls.ech.as_ref()));
        if !should_reload {
            return Ok(());
        }

        let reloaded = tls::load_tls_materials(&tls.source, tls.ech.as_ref())
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

pub(super) fn configure_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    let socket = SockRef::from(stream);
    let _ = socket.set_tcp_keepalive(&keepalive);
}

fn bind_listeners(listen_ip: &str, port: u16) -> anyhow::Result<Vec<TcpListener>> {
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

fn effective_listen_ip(remote: &NodeConfigResponse) -> String {
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
    if remote.network_settings.is_some() {
        anyhow::bail!("Xboard networkSettings is not supported by NodeRS-AnyTLS AnyTLS server");
    }
    Ok(())
}
