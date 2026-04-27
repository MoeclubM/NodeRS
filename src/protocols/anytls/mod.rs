mod activity;
mod padding;
mod session;
mod uot;

use anyhow::Context;
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::Accounting;
use crate::panel::{NodeConfigResponse, PanelUser, RouteConfig};

use super::shared::{
    EffectiveTlsConfig, bind_listeners, configure_tcp_stream, effective_listen_ip, tls,
};

use self::padding::PaddingScheme;
use super::shared::routing::RoutingTable;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    use crate::acme;
    use crate::panel::{
        CertConfig, NodeConfigResponse, NodeEchSettings, NodeTlsSettings, PanelUser,
    };
    use std::path::PathBuf;

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
    fn rejects_reality_tls_mode_for_anytls_protocol() {
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

        let error = EffectiveNodeConfig::from_remote(&remote).expect_err("anytls reality");
        assert!(error.to_string().contains("tls mode 2"));
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
        EffectiveNodeConfig::from_remote(&remote).expect("disabled network settings");

        let remote = NodeConfigResponse {
            network: "tcp".to_string(),
            network_settings: Some(serde_json::json!({
                "path": "/ws"
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
        if tls.reality.is_some() {
            anyhow::bail!("REALITY TLS config is not valid for AnyTLS nodes");
        }

        let mut tls_materials = self.tls_materials.lock().await;
        let should_reload = tls_materials.as_ref().is_none_or(|current| {
            !current.matches_source(&tls.source, tls.ech.as_ref(), None, &tls.alpn)
        });
        if !should_reload {
            return Ok(());
        }

        let reloaded = tls::load_tls_materials(&tls.source, tls.ech.as_ref(), None, &tls.alpn)
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

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if !remote.network.trim().is_empty() && !remote.network.eq_ignore_ascii_case("tcp") {
        anyhow::bail!("Xboard network must be tcp for AnyTLS nodes");
    }
    if remote.tls.is_some() && !matches!(remote.tls_mode(), 0 | 1) {
        anyhow::bail!(
            "Xboard tls mode {} is not supported by the NodeRS AnyTLS server yet",
            remote.tls_mode()
        );
    }
    if remote.reality_settings.is_configured() || remote.tls_settings.has_reality_key_material() {
        anyhow::bail!("REALITY settings are not valid for AnyTLS nodes");
    }
    if remote
        .network_settings
        .as_ref()
        .is_some_and(crate::panel::json_value_is_enabled)
    {
        anyhow::bail!("Xboard networkSettings is not supported by the NodeRS AnyTLS server");
    }
    Ok(())
}
