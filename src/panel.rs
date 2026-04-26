use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use crate::config::PanelConfig;

const DEFAULT_PANEL_TIMEOUT_SECONDS: u64 = 15;
const DEFAULT_ACME_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const DEFAULT_ACME_CHALLENGE_LISTEN: &str = "0.0.0.0:80";
const DEFAULT_ACME_RENEW_BEFORE_DAYS: u64 = 30;
const DEFAULT_DNS_PROPAGATION_TIMEOUT_SECS: u64 = 180;
const DEFAULT_DNS_PROPAGATION_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchState<T> {
    Modified(T, Option<String>),
    NotModified,
}

#[derive(Clone)]
pub struct MachinePanelClient {
    client: Client,
    base_url: String,
    token: String,
    machine_id: i64,
}

#[derive(Clone)]
pub struct NodePanelClient {
    machine: MachinePanelClient,
    node_id: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeConfigResponse {
    pub protocol: String,
    #[serde(
        default,
        alias = "listenIp",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub listen_ip: String,
    #[serde(
        alias = "serverPort",
        deserialize_with = "deserialize_u16_from_number_or_string"
    )]
    pub server_port: u16,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub network: String,
    #[serde(default, alias = "networkSettings")]
    pub network_settings: Option<Value>,
    #[serde(
        default,
        alias = "serverName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_name: String,
    #[serde(default)]
    pub tls: Option<Value>,
    #[serde(
        default,
        alias = "tlsSettings",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub tls_settings: NodeTlsSettings,
    #[serde(
        default,
        alias = "realitySettings",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub reality_settings: NodeRealitySettings,
    #[serde(default)]
    pub multiplex: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub host: String,
    #[serde(
        default,
        alias = "security",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cipher: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub plugin: String,
    #[serde(
        default,
        alias = "pluginOpts",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub plugin_opts: String,
    #[serde(
        default,
        alias = "serverKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_key: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub flow: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub decryption: String,
    #[serde(default)]
    pub version: Option<Value>,
    #[serde(default, alias = "upMbps")]
    pub up_mbps: Option<Value>,
    #[serde(default, alias = "downMbps")]
    pub down_mbps: Option<Value>,
    #[serde(default)]
    pub obfs: Option<Value>,
    #[serde(
        default,
        alias = "obfs-password",
        alias = "obfsPassword",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub obfs_password: String,
    #[serde(
        default,
        alias = "congestionControl",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub congestion_control: String,
    #[serde(
        default,
        alias = "authTimeout",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub auth_timeout: String,
    #[serde(
        default,
        alias = "zeroRttHandshake",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub zero_rtt_handshake: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub heartbeat: String,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(
        default,
        alias = "trafficPattern",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub traffic_pattern: String,
    #[serde(
        default,
        alias = "alpnProtocols",
        alias = "alpn_protocols",
        deserialize_with = "deserialize_string_list_on_null"
    )]
    pub alpn: Vec<String>,
    #[serde(
        default,
        alias = "packetEncoding",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub packet_encoding: String,
    #[serde(
        default,
        alias = "globalPadding",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub global_padding: bool,
    #[serde(
        default,
        alias = "authenticatedLength",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub authenticated_length: bool,
    #[serde(default)]
    pub fallbacks: Option<Value>,
    #[serde(default)]
    pub fallback: Option<Value>,
    #[serde(default, alias = "fallbackForAlpn")]
    pub fallback_for_alpn: Option<Value>,
    #[serde(
        default,
        alias = "ignoreClientBandwidth",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub ignore_client_bandwidth: bool,
    #[serde(default)]
    pub masquerade: Option<Value>,
    #[serde(
        default,
        alias = "udpRelayMode",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub udp_relay_mode: String,
    #[serde(
        default,
        alias = "udpOverStream",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub udp_over_stream: bool,
    #[serde(
        default,
        alias = "paddingScheme",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub padding_scheme: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub routes: Vec<RouteConfig>,
    #[serde(
        default,
        alias = "customOutbounds",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub custom_outbounds: Vec<Value>,
    #[serde(
        default,
        alias = "customRoutes",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub custom_routes: Vec<Value>,
    #[serde(default, alias = "certConfig")]
    pub cert_config: Option<CertConfig>,
    #[serde(default, alias = "baseConfig")]
    pub base_config: Option<BaseConfig>,
}

impl NodeConfigResponse {
    pub fn tls_mode(&self) -> i64 {
        value_to_i64(self.tls.as_ref()).unwrap_or_else(|| {
            if json_value_enabled(self.tls.as_ref()) {
                1
            } else {
                0
            }
        })
    }

    pub fn multiplex_enabled(&self) -> bool {
        json_value_enabled(self.multiplex.as_ref())
    }

    pub fn effective_reality_settings(&self) -> NodeRealitySettings {
        if self.tls_mode() != 2 {
            return NodeRealitySettings::default();
        }

        let mut settings = self.tls_settings.reality_settings();
        let reality = &self.reality_settings;

        if reality.allow_insecure {
            settings.allow_insecure = true;
        }
        if !reality.server_name.trim().is_empty() {
            settings.server_name = reality.server_name.clone();
        }
        if reality.server_port != 0 {
            settings.server_port = reality.server_port;
        }
        if !reality.public_key.trim().is_empty() {
            settings.public_key = reality.public_key.clone();
        }
        if !reality.private_key.trim().is_empty() {
            settings.private_key = reality.private_key.clone();
        }
        if !reality.short_id.trim().is_empty() {
            settings.short_id = reality.short_id.clone();
        }

        settings
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeTlsSettings {
    #[serde(
        default,
        alias = "serverName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_name: String,
    #[serde(
        default,
        alias = "allowInsecure",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub allow_insecure: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub ech: NodeEchSettings,
    #[serde(
        default,
        alias = "serverPort",
        deserialize_with = "deserialize_default_u16_from_number_or_string"
    )]
    pub server_port: u16,
    #[serde(
        default,
        alias = "publicKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub public_key: String,
    #[serde(
        default,
        alias = "privateKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub private_key: String,
    #[serde(
        default,
        alias = "shortId",
        alias = "shortid",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub short_id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeRealitySettings {
    #[serde(
        default,
        alias = "allowInsecure",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub allow_insecure: bool,
    #[serde(
        default,
        alias = "serverName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub server_name: String,
    #[serde(
        default,
        alias = "serverPort",
        deserialize_with = "deserialize_default_u16_from_number_or_string"
    )]
    pub server_port: u16,
    #[serde(
        default,
        alias = "publicKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub public_key: String,
    #[serde(
        default,
        alias = "privateKey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub private_key: String,
    #[serde(
        default,
        alias = "shortId",
        alias = "shortid",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub short_id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct NodeEchSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub config: String,
    #[serde(
        default,
        alias = "queryServerName",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub query_server_name: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub key: String,
    #[serde(
        default,
        alias = "keyPath",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub key_path: String,
    #[serde(
        default,
        alias = "configPath",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub config_path: String,
}

impl NodeEchSettings {
    pub fn is_enabled(&self) -> bool {
        self.enabled
            || !self.config.trim().is_empty()
            || !self.query_server_name.trim().is_empty()
            || !self.key.trim().is_empty()
            || !self.key_path.trim().is_empty()
            || !self.config_path.trim().is_empty()
    }
}

impl NodeTlsSettings {
    pub fn is_configured(&self) -> bool {
        !self.server_name.trim().is_empty() || self.allow_insecure || self.ech.is_enabled()
    }

    pub fn has_reality_key_material(&self) -> bool {
        !self.public_key.trim().is_empty()
            || !self.private_key.trim().is_empty()
            || !self.short_id.trim().is_empty()
    }

    pub fn reality_settings(&self) -> NodeRealitySettings {
        NodeRealitySettings {
            allow_insecure: self.allow_insecure,
            server_name: self.server_name.clone(),
            server_port: self.server_port,
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            short_id: self.short_id.clone(),
        }
    }
}

impl NodeRealitySettings {
    pub fn is_configured(&self) -> bool {
        self.allow_insecure
            || !self.server_name.trim().is_empty()
            || self.server_port != 0
            || !self.public_key.trim().is_empty()
            || !self.private_key.trim().is_empty()
            || !self.short_id.trim().is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct CertConfig {
    #[serde(
        default,
        alias = "mode",
        alias = "certMode",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cert_mode: String,
    #[serde(
        default,
        alias = "certificate_path",
        alias = "certificatePath",
        alias = "fullchain_path",
        alias = "fullchainPath",
        alias = "fullchain",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cert_path: String,
    #[serde(
        default,
        alias = "private_key_path",
        alias = "privateKeyPath",
        alias = "privkey_path",
        alias = "privkeyPath",
        alias = "privkey",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub key_path: String,
    #[serde(
        default,
        alias = "cert",
        alias = "certificate",
        alias = "cert_content",
        alias = "certContent",
        alias = "certificate_pem",
        alias = "certificatePem",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub cert_pem: String,
    #[serde(
        default,
        alias = "key",
        alias = "private_key",
        alias = "key_content",
        alias = "keyContent",
        alias = "private_key_pem",
        alias = "privateKeyPem",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub key_pem: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub domain: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub email: String,
    #[serde(
        default,
        alias = "directory",
        alias = "acme_directory_url",
        alias = "directoryUrl",
        alias = "acmeDirectoryUrl",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub directory_url: String,
    #[serde(
        default,
        alias = "http01_listen",
        alias = "http01Listen",
        alias = "acme_challenge_listen",
        alias = "acmeChallengeListen",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub challenge_listen: String,
    #[serde(default, alias = "renewBeforeDays")]
    pub renew_before_days: Option<u64>,
    #[serde(
        default,
        alias = "acme_account_key_path",
        alias = "acmeAccountKeyPath",
        alias = "accountKeyPath",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub account_key_path: String,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl CertConfig {
    pub fn cert_mode(&self) -> &str {
        let cert_mode = self.cert_mode.trim();
        if cert_mode.is_empty() {
            "none"
        } else {
            cert_mode
        }
    }

    pub fn cert_pem(&self) -> &str {
        self.cert_pem.trim()
    }

    pub fn key_pem(&self) -> &str {
        self.key_pem.trim()
    }

    pub fn domain(&self) -> &str {
        self.domain.trim()
    }

    pub fn email(&self) -> &str {
        self.email.trim()
    }

    pub fn directory_url(&self) -> &str {
        let directory_url = self.directory_url.trim();
        if directory_url.is_empty() {
            DEFAULT_ACME_DIRECTORY_URL
        } else {
            directory_url
        }
    }

    pub fn challenge_listen(&self) -> &str {
        let challenge_listen = self.challenge_listen.trim();
        if challenge_listen.is_empty() {
            DEFAULT_ACME_CHALLENGE_LISTEN
        } else {
            challenge_listen
        }
    }

    pub fn renew_before_days(&self) -> u64 {
        self.renew_before_days
            .unwrap_or(DEFAULT_ACME_RENEW_BEFORE_DAYS)
    }

    pub fn account_key_path(&self) -> &str {
        self.account_key_path.trim()
    }

    pub fn resolved_cert_path(&self) -> Option<String> {
        first_non_empty([
            Some(self.cert_path.trim()),
            self.extra_string(&[
                &["certificate_path"],
                &["fullchain_path"],
                &["fullchain"],
                &["files", "cert_path"],
                &["files", "certificate_path"],
            ])
            .as_deref(),
        ])
        .map(ToString::to_string)
    }

    pub fn resolved_key_path(&self) -> Option<String> {
        first_non_empty([
            Some(self.key_path.trim()),
            self.extra_string(&[
                &["private_key_path"],
                &["privkey_path"],
                &["privkey"],
                &["files", "key_path"],
                &["files", "private_key_path"],
            ])
            .as_deref(),
        ])
        .map(ToString::to_string)
    }

    pub fn resolved_cert_pem(&self) -> Option<String> {
        first_non_empty([
            Some(self.cert_pem()),
            self.extra_string(&[
                &["cert_content"],
                &["certificate_pem"],
                &["inline", "cert"],
                &["inline", "certificate"],
                &["content", "cert"],
            ])
            .as_deref(),
        ])
        .map(ToString::to_string)
    }

    pub fn resolved_key_pem(&self) -> Option<String> {
        first_non_empty([
            Some(self.key_pem()),
            self.extra_string(&[
                &["key_content"],
                &["private_key_pem"],
                &["inline", "key"],
                &["inline", "private_key"],
                &["content", "key"],
            ])
            .as_deref(),
        ])
        .map(ToString::to_string)
    }

    pub fn domains(&self) -> Vec<String> {
        let mut domains = split_cert_domains(self.domain()).collect::<Vec<_>>();
        if domains.is_empty() {
            domains = self.extra_strings(&[
                &["domains"],
                &["domain_list"],
                &["dns_domains"],
                &["acme", "domains"],
                &["certificate", "domains"],
            ]);
        }
        if domains.is_empty()
            && let Some(domain) = self.extra_string(&[
                &["server_name"],
                &["hostname"],
                &["host"],
                &["dns", "domain"],
            ])
        {
            domains.extend(split_cert_domains(&domain));
        }

        let mut seen = HashSet::new();
        domains
            .into_iter()
            .map(|domain| domain.trim().trim_end_matches('.').to_string())
            .filter(|domain| !domain.is_empty())
            .filter(|domain| seen.insert(domain.to_ascii_lowercase()))
            .collect()
    }

    pub fn dns_provider(&self) -> Option<String> {
        self.extra_string(&[
            &["provider"],
            &["dns_provider"],
            &["acme_dns_provider"],
            &["dns", "provider"],
            &["acme", "dns_provider"],
        ])
    }

    pub fn dns_zone_name(&self) -> Option<String> {
        self.extra_string(&[
            &["zone"],
            &["zone_name"],
            &["root_domain"],
            &["domain_name"],
            &["dns_zone"],
            &["dns", "zone"],
            &["dns", "zone_name"],
            &["provider", "zone"],
        ])
    }

    pub fn dns_zone_id(&self) -> Option<String> {
        self.extra_string(&[
            &["zone_id"],
            &["dns_zone_id"],
            &["cloudflare_zone_id"],
            &["provider", "zone_id"],
            &["dns", "zone_id"],
        ])
    }

    pub fn dns_ttl(&self) -> Option<u64> {
        self.extra_u64(&[
            &["ttl"],
            &["dns_ttl"],
            &["record_ttl"],
            &["dns", "ttl"],
            &["provider", "ttl"],
        ])
    }

    pub fn dns_propagation_timeout_secs(&self) -> u64 {
        self.extra_u64(&[
            &["propagation_timeout"],
            &["dns_propagation_timeout"],
            &["propagation_timeout_secs"],
            &["dns", "propagation_timeout"],
            &["provider", "propagation_timeout"],
        ])
        .unwrap_or(DEFAULT_DNS_PROPAGATION_TIMEOUT_SECS)
    }

    pub fn dns_propagation_interval_secs(&self) -> u64 {
        self.extra_u64(&[
            &["propagation_interval"],
            &["dns_propagation_interval"],
            &["propagation_interval_secs"],
            &["dns", "propagation_interval"],
            &["provider", "propagation_interval"],
        ])
        .unwrap_or(DEFAULT_DNS_PROPAGATION_INTERVAL_SECS)
        .max(1)
    }

    pub fn acme_challenge(&self) -> Option<String> {
        self.extra_string(&[
            &["challenge"],
            &["challenge_type"],
            &["acme_challenge"],
            &["acme_challenge_type"],
            &["acme", "challenge"],
            &["acme", "challenge_type"],
        ])
    }

    pub fn cloudflare_api_token(&self) -> Option<String> {
        self.extra_string(&[
            &["token"],
            &["api_token"],
            &["dns_api_token"],
            &["cloudflare_api_token"],
            &["cloudflare", "token"],
            &["cloudflare", "api_token"],
            &["dns", "token"],
            &["dns", "api_token"],
            &["provider", "token"],
            &["provider", "api_token"],
            &["env", "CF_DNS_API_TOKEN"],
            &["env", "CF_API_TOKEN"],
            &["env", "CLOUDFLARE_API_TOKEN"],
            &["environment_variables", "CF_DNS_API_TOKEN"],
            &["environment_variables", "CF_API_TOKEN"],
            &["environment_variables", "CLOUDFLARE_API_TOKEN"],
            &["credentials", "CF_DNS_API_TOKEN"],
            &["credentials", "CF_API_TOKEN"],
            &["credentials", "CLOUDFLARE_API_TOKEN"],
            &["cloudflare", "env", "CF_DNS_API_TOKEN"],
            &["cloudflare", "env", "CF_API_TOKEN"],
            &["cloudflare", "env", "CLOUDFLARE_API_TOKEN"],
            &["cloudflare", "environment_variables", "CF_DNS_API_TOKEN"],
            &["cloudflare", "environment_variables", "CF_API_TOKEN"],
            &[
                "cloudflare",
                "environment_variables",
                "CLOUDFLARE_API_TOKEN",
            ],
            &["cloudflare", "credentials", "CF_DNS_API_TOKEN"],
            &["cloudflare", "credentials", "CF_API_TOKEN"],
            &["cloudflare", "credentials", "CLOUDFLARE_API_TOKEN"],
            &["dns", "env", "CF_DNS_API_TOKEN"],
            &["dns", "env", "CF_API_TOKEN"],
            &["dns", "env", "CLOUDFLARE_API_TOKEN"],
            &["dns", "environment_variables", "CF_DNS_API_TOKEN"],
            &["dns", "environment_variables", "CF_API_TOKEN"],
            &["dns", "environment_variables", "CLOUDFLARE_API_TOKEN"],
            &["dns", "credentials", "CF_DNS_API_TOKEN"],
            &["dns", "credentials", "CF_API_TOKEN"],
            &["dns", "credentials", "CLOUDFLARE_API_TOKEN"],
            &["provider", "env", "CF_DNS_API_TOKEN"],
            &["provider", "env", "CF_API_TOKEN"],
            &["provider", "env", "CLOUDFLARE_API_TOKEN"],
            &["provider", "environment_variables", "CF_DNS_API_TOKEN"],
            &["provider", "environment_variables", "CF_API_TOKEN"],
            &["provider", "environment_variables", "CLOUDFLARE_API_TOKEN"],
            &["provider", "credentials", "CF_DNS_API_TOKEN"],
            &["provider", "credentials", "CF_API_TOKEN"],
            &["provider", "credentials", "CLOUDFLARE_API_TOKEN"],
        ])
        .or_else(|| {
            self.extra_env_string(&["CF_DNS_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_API_TOKEN"])
        })
    }

    pub fn cloudflare_api_key(&self) -> Option<String> {
        self.extra_string(&[
            &["api_key"],
            &["dns_api_key"],
            &["cloudflare_api_key"],
            &["cloudflare", "api_key"],
            &["dns", "api_key"],
            &["provider", "api_key"],
            &["env", "CF_API_KEY"],
            &["env", "CLOUDFLARE_API_KEY"],
            &["environment_variables", "CF_API_KEY"],
            &["environment_variables", "CLOUDFLARE_API_KEY"],
            &["credentials", "CF_API_KEY"],
            &["credentials", "CLOUDFLARE_API_KEY"],
            &["cloudflare", "env", "CF_API_KEY"],
            &["cloudflare", "env", "CLOUDFLARE_API_KEY"],
            &["cloudflare", "environment_variables", "CF_API_KEY"],
            &["cloudflare", "environment_variables", "CLOUDFLARE_API_KEY"],
            &["cloudflare", "credentials", "CF_API_KEY"],
            &["cloudflare", "credentials", "CLOUDFLARE_API_KEY"],
            &["dns", "env", "CF_API_KEY"],
            &["dns", "env", "CLOUDFLARE_API_KEY"],
            &["dns", "environment_variables", "CF_API_KEY"],
            &["dns", "environment_variables", "CLOUDFLARE_API_KEY"],
            &["dns", "credentials", "CF_API_KEY"],
            &["dns", "credentials", "CLOUDFLARE_API_KEY"],
            &["provider", "env", "CF_API_KEY"],
            &["provider", "env", "CLOUDFLARE_API_KEY"],
            &["provider", "environment_variables", "CF_API_KEY"],
            &["provider", "environment_variables", "CLOUDFLARE_API_KEY"],
            &["provider", "credentials", "CF_API_KEY"],
            &["provider", "credentials", "CLOUDFLARE_API_KEY"],
        ])
        .or_else(|| self.extra_env_string(&["CF_API_KEY", "CLOUDFLARE_API_KEY"]))
    }

    pub fn cloudflare_api_email(&self) -> Option<String> {
        self.extra_string(&[
            &["api_email"],
            &["cloudflare_email"],
            &["cloudflare", "email"],
            &["dns", "email"],
            &["provider", "email"],
            &["env", "CF_API_EMAIL"],
            &["env", "CLOUDFLARE_API_EMAIL"],
            &["environment_variables", "CF_API_EMAIL"],
            &["environment_variables", "CLOUDFLARE_API_EMAIL"],
            &["credentials", "CF_API_EMAIL"],
            &["credentials", "CLOUDFLARE_API_EMAIL"],
            &["cloudflare", "env", "CF_API_EMAIL"],
            &["cloudflare", "env", "CLOUDFLARE_API_EMAIL"],
            &["cloudflare", "environment_variables", "CF_API_EMAIL"],
            &[
                "cloudflare",
                "environment_variables",
                "CLOUDFLARE_API_EMAIL",
            ],
            &["cloudflare", "credentials", "CF_API_EMAIL"],
            &["cloudflare", "credentials", "CLOUDFLARE_API_EMAIL"],
            &["dns", "env", "CF_API_EMAIL"],
            &["dns", "env", "CLOUDFLARE_API_EMAIL"],
            &["dns", "environment_variables", "CF_API_EMAIL"],
            &["dns", "environment_variables", "CLOUDFLARE_API_EMAIL"],
            &["dns", "credentials", "CF_API_EMAIL"],
            &["dns", "credentials", "CLOUDFLARE_API_EMAIL"],
            &["provider", "env", "CF_API_EMAIL"],
            &["provider", "env", "CLOUDFLARE_API_EMAIL"],
            &["provider", "environment_variables", "CF_API_EMAIL"],
            &["provider", "environment_variables", "CLOUDFLARE_API_EMAIL"],
            &["provider", "credentials", "CF_API_EMAIL"],
            &["provider", "credentials", "CLOUDFLARE_API_EMAIL"],
        ])
        .or_else(|| self.extra_env_string(&["CF_API_EMAIL", "CLOUDFLARE_API_EMAIL"]))
    }

    pub fn alidns_access_key_id(&self) -> Option<String> {
        self.extra_string(&[
            &["access_key_id"],
            &["alidns_access_key_id"],
            &["aliyun_access_key_id"],
            &["ali_access_key_id"],
            &["alidns", "access_key_id"],
            &["aliyun", "access_key_id"],
            &["dns", "access_key_id"],
            &["provider", "access_key_id"],
            &["env", "ALICLOUD_ACCESS_KEY_ID"],
            &["env", "ALIDNS_ACCESS_KEY_ID"],
            &["env", "ALIYUN_ACCESS_KEY_ID"],
            &["environment_variables", "ALICLOUD_ACCESS_KEY_ID"],
            &["environment_variables", "ALIDNS_ACCESS_KEY_ID"],
            &["environment_variables", "ALIYUN_ACCESS_KEY_ID"],
            &["credentials", "ALICLOUD_ACCESS_KEY_ID"],
            &["credentials", "ALIDNS_ACCESS_KEY_ID"],
            &["credentials", "ALIYUN_ACCESS_KEY_ID"],
            &["alidns", "env", "ALICLOUD_ACCESS_KEY_ID"],
            &["alidns", "env", "ALIDNS_ACCESS_KEY_ID"],
            &["alidns", "env", "ALIYUN_ACCESS_KEY_ID"],
            &["alidns", "environment_variables", "ALICLOUD_ACCESS_KEY_ID"],
            &["alidns", "environment_variables", "ALIDNS_ACCESS_KEY_ID"],
            &["alidns", "environment_variables", "ALIYUN_ACCESS_KEY_ID"],
            &["alidns", "credentials", "ALICLOUD_ACCESS_KEY_ID"],
            &["alidns", "credentials", "ALIDNS_ACCESS_KEY_ID"],
            &["alidns", "credentials", "ALIYUN_ACCESS_KEY_ID"],
            &["dns", "env", "ALICLOUD_ACCESS_KEY_ID"],
            &["dns", "env", "ALIDNS_ACCESS_KEY_ID"],
            &["dns", "env", "ALIYUN_ACCESS_KEY_ID"],
            &["dns", "environment_variables", "ALICLOUD_ACCESS_KEY_ID"],
            &["dns", "environment_variables", "ALIDNS_ACCESS_KEY_ID"],
            &["dns", "environment_variables", "ALIYUN_ACCESS_KEY_ID"],
            &["dns", "credentials", "ALICLOUD_ACCESS_KEY_ID"],
            &["dns", "credentials", "ALIDNS_ACCESS_KEY_ID"],
            &["dns", "credentials", "ALIYUN_ACCESS_KEY_ID"],
            &["provider", "env", "ALICLOUD_ACCESS_KEY_ID"],
            &["provider", "env", "ALIDNS_ACCESS_KEY_ID"],
            &["provider", "env", "ALIYUN_ACCESS_KEY_ID"],
            &[
                "provider",
                "environment_variables",
                "ALICLOUD_ACCESS_KEY_ID",
            ],
            &["provider", "environment_variables", "ALIDNS_ACCESS_KEY_ID"],
            &["provider", "environment_variables", "ALIYUN_ACCESS_KEY_ID"],
            &["provider", "credentials", "ALICLOUD_ACCESS_KEY_ID"],
            &["provider", "credentials", "ALIDNS_ACCESS_KEY_ID"],
            &["provider", "credentials", "ALIYUN_ACCESS_KEY_ID"],
        ])
        .or_else(|| {
            self.extra_env_string(&[
                "ALICLOUD_ACCESS_KEY_ID",
                "ALIDNS_ACCESS_KEY_ID",
                "ALIYUN_ACCESS_KEY_ID",
            ])
        })
    }

    pub fn alidns_access_key_secret(&self) -> Option<String> {
        self.extra_string(&[
            &["access_key_secret"],
            &["alidns_access_key_secret"],
            &["aliyun_access_key_secret"],
            &["ali_access_key_secret"],
            &["alidns", "access_key_secret"],
            &["aliyun", "access_key_secret"],
            &["dns", "access_key_secret"],
            &["provider", "access_key_secret"],
            &["env", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["env", "ALIDNS_ACCESS_KEY_SECRET"],
            &["env", "ALIYUN_ACCESS_KEY_SECRET"],
            &["environment_variables", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["environment_variables", "ALIDNS_ACCESS_KEY_SECRET"],
            &["environment_variables", "ALIYUN_ACCESS_KEY_SECRET"],
            &["credentials", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["credentials", "ALIDNS_ACCESS_KEY_SECRET"],
            &["credentials", "ALIYUN_ACCESS_KEY_SECRET"],
            &["alidns", "env", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["alidns", "env", "ALIDNS_ACCESS_KEY_SECRET"],
            &["alidns", "env", "ALIYUN_ACCESS_KEY_SECRET"],
            &[
                "alidns",
                "environment_variables",
                "ALICLOUD_ACCESS_KEY_SECRET",
            ],
            &[
                "alidns",
                "environment_variables",
                "ALIDNS_ACCESS_KEY_SECRET",
            ],
            &[
                "alidns",
                "environment_variables",
                "ALIYUN_ACCESS_KEY_SECRET",
            ],
            &["alidns", "credentials", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["alidns", "credentials", "ALIDNS_ACCESS_KEY_SECRET"],
            &["alidns", "credentials", "ALIYUN_ACCESS_KEY_SECRET"],
            &["dns", "env", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["dns", "env", "ALIDNS_ACCESS_KEY_SECRET"],
            &["dns", "env", "ALIYUN_ACCESS_KEY_SECRET"],
            &["dns", "environment_variables", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["dns", "environment_variables", "ALIDNS_ACCESS_KEY_SECRET"],
            &["dns", "environment_variables", "ALIYUN_ACCESS_KEY_SECRET"],
            &["dns", "credentials", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["dns", "credentials", "ALIDNS_ACCESS_KEY_SECRET"],
            &["dns", "credentials", "ALIYUN_ACCESS_KEY_SECRET"],
            &["provider", "env", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["provider", "env", "ALIDNS_ACCESS_KEY_SECRET"],
            &["provider", "env", "ALIYUN_ACCESS_KEY_SECRET"],
            &[
                "provider",
                "environment_variables",
                "ALICLOUD_ACCESS_KEY_SECRET",
            ],
            &[
                "provider",
                "environment_variables",
                "ALIDNS_ACCESS_KEY_SECRET",
            ],
            &[
                "provider",
                "environment_variables",
                "ALIYUN_ACCESS_KEY_SECRET",
            ],
            &["provider", "credentials", "ALICLOUD_ACCESS_KEY_SECRET"],
            &["provider", "credentials", "ALIDNS_ACCESS_KEY_SECRET"],
            &["provider", "credentials", "ALIYUN_ACCESS_KEY_SECRET"],
        ])
        .or_else(|| {
            self.extra_env_string(&[
                "ALICLOUD_ACCESS_KEY_SECRET",
                "ALIDNS_ACCESS_KEY_SECRET",
                "ALIYUN_ACCESS_KEY_SECRET",
            ])
        })
    }

    pub fn extra_string(&self, aliases: &[&[&str]]) -> Option<String> {
        aliases
            .iter()
            .find_map(|path| lookup_extra_string_path(&self.extra, path))
    }

    pub fn extra_env_string(&self, env_keys: &[&str]) -> Option<String> {
        lookup_env_keys_in_object(&self.extra, env_keys)
    }

    pub fn extra_strings(&self, aliases: &[&[&str]]) -> Vec<String> {
        lookup_extra_alias(&self.extra, aliases)
            .map(value_to_strings)
            .unwrap_or_default()
    }

    pub fn extra_u64(&self, aliases: &[&[&str]]) -> Option<u64> {
        lookup_extra_alias(&self.extra, aliases).and_then(|value| value_to_u64(Some(value)))
    }
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn split_list_values(raw: &str) -> impl Iterator<Item = String> + '_ {
    raw.split([',', '\n', '\r', ' '])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
}

fn split_cert_domains(raw: &str) -> impl Iterator<Item = String> + '_ {
    split_list_values(raw)
}

fn lookup_extra_string_path(
    object: &serde_json::Map<String, Value>,
    path: &[&str],
) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let value = lookup_extra_key(object, first)?;
    if rest.is_empty() {
        return value_to_trimmed_string(value);
    }

    match value {
        Value::Object(next) => lookup_extra_string_path(next, rest),
        Value::String(text) if rest.len() == 1 => lookup_key_value_text(text, rest[0]),
        _ => None,
    }
}

fn lookup_key_value_text(text: &str, key: &str) -> Option<String> {
    let normalized_key = normalize_extra_key(key);
    text.lines().find_map(|line| {
        let (candidate, value) = parse_key_value_line(line)?;
        if normalize_extra_key(candidate) == normalized_key {
            Some(strip_wrapping_quotes(value).to_string())
        } else {
            None
        }
    })
}

fn lookup_env_keys_in_object(
    object: &serde_json::Map<String, Value>,
    env_keys: &[&str],
) -> Option<String> {
    env_keys
        .iter()
        .find_map(|key| lookup_extra_key(object, key).and_then(value_to_trimmed_string))
        .or_else(|| {
            object
                .values()
                .find_map(|value| lookup_env_keys_in_value(value, env_keys))
        })
}

fn lookup_env_keys_in_value(value: &Value, env_keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => lookup_env_keys_in_object(object, env_keys),
        Value::Array(values) => values
            .iter()
            .find_map(|value| lookup_env_keys_in_value(value, env_keys)),
        Value::String(text) => env_keys
            .iter()
            .find_map(|key| lookup_key_value_text(text, key)),
        _ => None,
    }
}

fn parse_key_value_line(line: &str) -> Option<(&str, &str)> {
    let mut line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Some(rest) = line
        .strip_prefix("export ")
        .or_else(|| line.strip_prefix("export\t"))
    {
        line = rest.trim_start();
    }
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some((key, value.trim()))
    }
}

fn strip_wrapping_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn lookup_extra_alias<'a>(
    object: &'a serde_json::Map<String, Value>,
    aliases: &[&[&str]],
) -> Option<&'a Value> {
    aliases
        .iter()
        .find_map(|path| lookup_extra_path(object, path))
}

fn lookup_extra_path<'a>(
    object: &'a serde_json::Map<String, Value>,
    path: &[&str],
) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let value = lookup_extra_key(object, first)?;
    if rest.is_empty() {
        Some(value)
    } else {
        value
            .as_object()
            .and_then(|next| lookup_extra_path(next, rest))
    }
}

fn lookup_extra_key<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    object.iter().find_map(|(candidate, value)| {
        if normalize_extra_key(candidate) == normalize_extra_key(key) {
            Some(value)
        } else {
            None
        }
    })
}

fn normalize_extra_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn value_to_trimmed_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

fn value_to_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values.iter().filter_map(value_to_trimmed_string).collect(),
        Value::String(text) => split_cert_domains(text).collect(),
        other => value_to_trimmed_string(other).into_iter().collect(),
    }
}

fn value_to_split_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values.iter().flat_map(value_to_split_strings).collect(),
        Value::String(text) => split_list_values(text).collect(),
        Value::Null => Vec::new(),
        other => value_to_trimmed_string(other).into_iter().collect(),
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RouteMatch {
    String(String),
    Strings(Vec<String>),
}

impl RouteMatch {
    pub fn items(&self) -> Vec<String> {
        let raw = match self {
            Self::String(text) => text.split(',').map(ToString::to_string).collect(),
            Self::Strings(items) => items.clone(),
        };
        raw.into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: i64,
    #[serde(default, rename = "match")]
    pub match_value: Option<RouteMatch>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub action: String,
    #[serde(
        default,
        alias = "actionValue",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub action_value: String,
}

impl RouteConfig {
    pub fn match_items(&self) -> Vec<String> {
        self.match_value
            .as_ref()
            .map(RouteMatch::items)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BaseConfig {
    #[serde(default, alias = "pushInterval")]
    pub push_interval: Option<serde_json::Value>,
    #[serde(default, alias = "pullInterval")]
    pub pull_interval: Option<serde_json::Value>,
}

impl BaseConfig {
    pub fn push_interval_seconds(&self) -> Option<u64> {
        value_to_u64(self.push_interval.as_ref())
    }

    pub fn pull_interval_seconds(&self) -> Option<u64> {
        value_to_u64(self.pull_interval.as_ref())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MachineNodesResponse {
    #[serde(default)]
    pub nodes: Vec<MachineNodeSummary>,
    #[serde(default, alias = "baseConfig")]
    pub base_config: Option<BaseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MachineNodeSummary {
    pub id: i64,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UsersResponse {
    pub users: Vec<PanelUser>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct PanelUser {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub uuid: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub password: String,
    #[serde(
        default,
        alias = "alterId",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub alter_id: i64,
    #[serde(
        default,
        alias = "speedLimit",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub speed_limit: i64,
    #[serde(
        default,
        alias = "deviceLimit",
        deserialize_with = "deserialize_default_on_null"
    )]
    pub device_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AliveListResponse {
    #[serde(default)]
    pub alive: HashMap<String, i64>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HandshakeResponse {
    #[serde(default)]
    pub websocket: HandshakeWebSocket,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HandshakeWebSocket {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub ws_url: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusPayload {
    pub cpu: f64,
    pub mem: MemoryStat,
    pub swap: MemoryStat,
    pub disk: MemoryStat,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MemoryStat {
    pub total: u64,
    pub used: u64,
}

#[derive(Debug, Serialize)]
struct ReportPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    traffic: Option<&'a HashMap<i64, [u64; 2]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alive: Option<&'a HashMap<i64, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a StatusPayload>,
}

#[derive(Debug)]
pub enum TrafficReportError {
    Definite(anyhow::Error),
    Uncertain(anyhow::Error),
}

impl MachinePanelClient {
    pub fn new(config: &PanelConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_PANEL_TIMEOUT_SECONDS))
            .build()
            .context("build panel HTTP client")?;
        Ok(Self {
            client,
            base_url: config.api.trim_end_matches('/').to_string(),
            token: config.key.clone(),
            machine_id: config.machine_id,
        })
    }

    pub fn machine_id(&self) -> i64 {
        self.machine_id
    }

    pub fn node_client(&self, node_id: i64) -> NodePanelClient {
        NodePanelClient {
            machine: self.clone(),
            node_id,
        }
    }

    pub fn websocket_url(&self, ws_url: &str) -> anyhow::Result<String> {
        let mut url =
            reqwest::Url::parse(ws_url).with_context(|| format!("parse websocket url {ws_url}"))?;
        match url.scheme() {
            "ws" | "wss" => {}
            "http" => {
                url.set_scheme("ws").map_err(|_| {
                    anyhow::anyhow!("convert websocket scheme to ws failed for {ws_url}")
                })?;
            }
            "https" => {
                url.set_scheme("wss").map_err(|_| {
                    anyhow::anyhow!("convert websocket scheme to wss failed for {ws_url}")
                })?;
            }
            other => bail!("unsupported websocket scheme {other} in {ws_url}"),
        }
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("token", &self.token);
            query.append_pair("machine_id", &self.machine_id.to_string());
        }
        Ok(url.to_string())
    }

    pub async fn fetch_handshake(&self) -> anyhow::Result<HandshakeResponse> {
        let response = self
            .client
            .post(self.url("/api/v2/server/handshake"))
            .query(&self.machine_query())
            .send()
            .await
            .context("request Xboard handshake")?;
        ensure_success(response.status(), "fetch handshake")?;
        response.json().await.context("decode Xboard handshake")
    }

    pub async fn fetch_machine_nodes(&self) -> anyhow::Result<MachineNodesResponse> {
        let response = self
            .client
            .post(self.url("/api/v2/server/machine/nodes"))
            .query(&self.machine_query())
            .send()
            .await
            .context("request Xboard machine nodes")?;
        ensure_success(response.status(), "fetch machine nodes")?;
        response.json().await.context("decode machine nodes")
    }

    pub async fn report_machine_status(&self, payload: &StatusPayload) -> anyhow::Result<()> {
        let response = self
            .client
            .post(self.url("/api/v2/server/machine/status"))
            .query(&self.machine_query())
            .json(payload)
            .send()
            .await
            .context("report machine status")?;
        ensure_success(response.status(), "report machine status")
    }

    fn machine_query(&self) -> Vec<(&str, String)> {
        vec![
            ("token", self.token.clone()),
            ("machine_id", self.machine_id.to_string()),
        ]
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl NodePanelClient {
    pub async fn fetch_node_config(
        &self,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<NodeConfigResponse>> {
        self.fetch_etag("/api/v2/server/config", etag).await
    }

    pub async fn fetch_users(
        &self,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<UsersResponse>> {
        self.fetch_etag("/api/v2/server/user", etag).await
    }

    pub async fn fetch_alive_list(&self) -> anyhow::Result<AliveListResponse> {
        let response = self
            .machine
            .client
            .get(self.machine.url("/api/v2/server/alivelist"))
            .query(&self.query())
            .send()
            .await
            .context("request Xboard alive list")?;
        ensure_success(response.status(), "fetch alive list")?;
        response.json().await.context("decode alive list")
    }

    pub async fn report_traffic(
        &self,
        traffic: HashMap<i64, [u64; 2]>,
    ) -> Result<(), TrafficReportError> {
        if traffic.is_empty() {
            return Ok(());
        }
        let payload = ReportPayload {
            traffic: Some(&traffic),
            alive: None,
            status: None,
        };
        let response = self
            .machine
            .client
            .post(self.machine.url("/api/v2/server/report"))
            .query(&self.query())
            .json(&payload)
            .send()
            .await
            .map_err(classify_send_error)?;
        classify_traffic_status(response.status())
    }

    pub async fn report_alive(&self, alive: HashMap<i64, Vec<String>>) -> anyhow::Result<()> {
        if alive.is_empty() {
            return Ok(());
        }
        let payload = ReportPayload {
            traffic: None,
            alive: Some(&alive),
            status: None,
        };
        let response = self
            .machine
            .client
            .post(self.machine.url("/api/v2/server/report"))
            .query(&self.query())
            .json(&payload)
            .send()
            .await
            .context("report alive")?;
        ensure_success(response.status(), "report alive")
    }

    pub async fn report_status(&self, payload: &StatusPayload) -> anyhow::Result<()> {
        let payload = ReportPayload {
            traffic: None,
            alive: None,
            status: Some(payload),
        };
        let response = self
            .machine
            .client
            .post(self.machine.url("/api/v2/server/report"))
            .query(&self.query())
            .json(&payload)
            .send()
            .await
            .context("report node status")?;
        ensure_success(response.status(), "report node status")
    }

    async fn fetch_etag<T>(&self, path: &str, etag: Option<&str>) -> anyhow::Result<FetchState<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut request = self
            .machine
            .client
            .get(self.machine.url(path))
            .query(&self.query());
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("request {path}"))?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(FetchState::NotModified);
        }
        ensure_success(response.status(), path)?;
        let new_etag = response
            .headers()
            .get("ETag")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let decoded = response
            .json::<T>()
            .await
            .with_context(|| format!("decode {path} response"))?;
        Ok(FetchState::Modified(decoded, new_etag))
    }

    fn query(&self) -> Vec<(&str, String)> {
        vec![
            ("token", self.machine.token.clone()),
            ("machine_id", self.machine.machine_id.to_string()),
            ("node_id", self.node_id.to_string()),
        ]
    }
}

fn ensure_success(status: StatusCode, action: &str) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        bail!("Xboard {action} failed with status {status}")
    }
}

fn value_to_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn value_to_u16(value: &serde_json::Value) -> Option<u16> {
    match value {
        serde_json::Value::Number(number) => {
            number.as_u64().and_then(|value| u16::try_from(value).ok())
        }
        serde_json::Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn value_to_i64(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Bool(value) => Some(i64::from(*value)),
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn json_value_enabled(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(serde_json::Value::Number(number)) => {
            number.as_i64().is_some_and(|value| value != 0)
                || number.as_u64().is_some_and(|value| value != 0)
                || number.as_f64().is_some_and(|value| value != 0.0)
        }
        Some(serde_json::Value::String(text)) => {
            let normalized = text.trim().to_ascii_lowercase();
            !matches!(
                normalized.as_str(),
                "" | "0" | "false" | "off" | "no" | "none" | "disabled"
            )
        }
        Some(serde_json::Value::Array(items)) => !items.is_empty(),
        Some(serde_json::Value::Object(object)) => object
            .get("enabled")
            .map(|value| json_value_enabled(Some(value)))
            .unwrap_or(!object.is_empty()),
    }
}

fn deserialize_default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

pub(crate) fn deserialize_u16_from_number_or_string<'de, D>(
    deserializer: D,
) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    value_to_u16(&value).ok_or_else(|| {
        serde::de::Error::custom(format!(
            "expected u16 number or decimal string, got {value}"
        ))
    })
}

fn deserialize_default_u16_from_number_or_string<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        Some(value) => value_to_u16(&value).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "expected u16 number or decimal string, got {value}"
            ))
        }),
        None => Ok(0),
    }
}

fn deserialize_string_list_on_null<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(value) => value_to_split_strings(&value),
        None => Vec::new(),
    })
}

fn classify_send_error(error: reqwest::Error) -> TrafficReportError {
    let error = anyhow::Error::new(error).context("report traffic");
    if error
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
        .is_some_and(|reqwest| reqwest.is_connect())
    {
        TrafficReportError::Definite(error)
    } else {
        TrafficReportError::Uncertain(error)
    }
}

fn classify_traffic_status(status: StatusCode) -> Result<(), TrafficReportError> {
    if status.is_success() {
        Ok(())
    } else if status.is_client_error() {
        Err(TrafficReportError::Definite(anyhow::anyhow!(
            "Xboard report traffic failed with status {status}"
        )))
    } else {
        Err(TrafficReportError::Uncertain(anyhow::anyhow!(
            "Xboard report traffic failed with status {status}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PanelConfig;

    #[test]
    fn parses_base_config_numbers() {
        let cfg = BaseConfig {
            push_interval: Some(serde_json::json!(120)),
            pull_interval: Some(serde_json::json!("30")),
        };
        assert_eq!(cfg.push_interval_seconds(), Some(120));
        assert_eq!(cfg.pull_interval_seconds(), Some(30));
    }

    #[test]
    fn parses_route_match_from_string() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 1,
            "match": r" protocol:tcp , regexp:^example\.com$ ",
            "action": "block",
            "action_value": ""
        }))
        .expect("parse route");
        assert_eq!(
            route.match_items(),
            vec![
                "protocol:tcp".to_string(),
                r"regexp:^example\.com$".to_string()
            ]
        );
    }

    #[test]
    fn parses_route_match_from_array() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 2,
            "match": [r"regexp:^example\.org$", "protocol:udp"],
            "action": "block",
            "action_value": ""
        }))
        .expect("parse route");
        assert_eq!(
            route.match_items(),
            vec![
                r"regexp:^example\.org$".to_string(),
                "protocol:udp".to_string()
            ]
        );
    }

    #[test]
    fn accepts_nulls_in_node_config_response() {
        let config: NodeConfigResponse = serde_json::from_str(
            r#"{
                "protocol": "anytls",
                "listen_ip": "0.0.0.0",
                "server_port": 443,
                "network": null,
                "networkSettings": null,
                "server_name": "node.example.com",
                "tls": null,
                "tls_settings": {
                    "server_name": "node.example.com",
                    "allow_insecure": false,
                    "ech": null
                },
                "multiplex": null,
                "host": null,
                "cipher": null,
                "plugin": null,
                "plugin_opts": null,
                "server_key": null,
                "flow": null,
                "decryption": null,
                "version": null,
                "up_mbps": null,
                "down_mbps": null,
                "obfs": null,
                "obfs-password": null,
                "congestion_control": null,
                "auth_timeout": null,
                "zero_rtt_handshake": null,
                "heartbeat": null,
                "transport": null,
                "traffic_pattern": null,
                "alpn": null,
                "packet_encoding": null,
                "global_padding": null,
                "authenticated_length": null,
                "fallbacks": null,
                "fallback": null,
                "fallback_for_alpn": null,
                "ignoreClientBandwidth": null,
                "masquerade": null,
                "udpRelayMode": null,
                "udpOverStream": null,
                "padding_scheme": null,
                "routes": null,
                "custom_outbounds": null,
                "custom_routes": null,
                "cert_config": {
                    "cert_mode": "file",
                    "cert_path": "/etc/ssl/private/fullchain.pem",
                    "key_path": "/etc/ssl/private/privkey.pem"
                },
                "base_config": {
                    "push_interval": 60,
                    "pull_interval": 60
                }
            }"#,
        )
        .expect("parse config");
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.server_name, "node.example.com");
        assert_eq!(config.network, "");
        assert!(config.network_settings.is_none());
        assert!(config.tls.is_none());
        assert!(config.multiplex.is_none());
        assert_eq!(config.host, "");
        assert_eq!(config.cipher, "");
        assert_eq!(config.plugin, "");
        assert_eq!(config.plugin_opts, "");
        assert_eq!(config.server_key, "");
        assert_eq!(config.flow, "");
        assert_eq!(config.decryption, "");
        assert!(config.version.is_none());
        assert!(config.up_mbps.is_none());
        assert!(config.down_mbps.is_none());
        assert!(config.obfs.is_none());
        assert_eq!(config.obfs_password, "");
        assert_eq!(config.congestion_control, "");
        assert_eq!(config.auth_timeout, "");
        assert!(!config.zero_rtt_handshake);
        assert_eq!(config.heartbeat, "");
        assert!(config.transport.is_none());
        assert_eq!(config.traffic_pattern, "");
        assert!(config.alpn.is_empty());
        assert_eq!(config.packet_encoding, "");
        assert!(!config.global_padding);
        assert!(!config.authenticated_length);
        assert!(config.fallbacks.is_none());
        assert!(config.fallback.is_none());
        assert!(config.fallback_for_alpn.is_none());
        assert!(!config.ignore_client_bandwidth);
        assert!(config.masquerade.is_none());
        assert_eq!(config.udp_relay_mode, "");
        assert!(!config.udp_over_stream);
        assert!(config.padding_scheme.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.custom_outbounds.is_empty());
        assert!(config.custom_routes.is_empty());
        assert_eq!(
            config
                .cert_config
                .as_ref()
                .expect("cert config")
                .cert_mode(),
            "file"
        );
    }

    #[test]
    fn accepts_string_ports_in_node_config_response() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": "443",
            "tls_settings": {
                "serverPort": "8443"
            },
            "reality_settings": {
                "server_port": "7443"
            }
        }))
        .expect("parse config");

        assert_eq!(config.server_port, 443);
        assert_eq!(config.tls_settings.server_port, 8443);
        assert_eq!(config.reality_settings.server_port, 7443);
    }

    #[test]
    fn ech_fields_mark_remote_config_as_ech_enabled() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "network": "tcp",
            "networkSettings": {
                "header": {
                    "type": "none"
                }
            },
            "server_name": "node.example.com",
            "tls_settings": {
                "server_name": "node.example.com",
                "allow_insecure": false,
                "ech": {
                    "enabled": false,
                    "config_path": "/etc/anytls/ech.json"
                }
            },
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            }
        }))
        .expect("parse config");

        assert!(config.tls_settings.ech.is_enabled());
        assert_eq!(config.network, "tcp");
        assert_eq!(
            config.network_settings,
            Some(serde_json::json!({
                "header": {
                    "type": "none"
                }
            }))
        );
        assert_eq!(
            config
                .cert_config
                .as_ref()
                .expect("cert config")
                .cert_mode(),
            "file"
        );
    }

    #[test]
    fn cert_config_accepts_inline_pem_aliases() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "inline",
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cert_mode(), "inline");
        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn cert_config_accepts_acme_aliases_and_defaults() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "acme",
                "cert_path": "/var/lib/noders/anytls/node.example.com/fullchain.pem",
                "key_path": "/var/lib/noders/anytls/node.example.com/privkey.pem",
                "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "http01_listen": "127.0.0.1:8080",
                "acme_account_key_path": "/var/lib/noders/anytls/node.example.com/account.pem"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cert_mode(), "acme");
        assert_eq!(
            cert.directory_url(),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(cert.challenge_listen(), "127.0.0.1:8080");
        assert_eq!(
            cert.account_key_path(),
            "/var/lib/noders/anytls/node.example.com/account.pem"
        );
        assert_eq!(cert.renew_before_days(), 30);
    }

    #[test]
    fn cert_config_preserves_extra_dns_fields_and_domains_aliases() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "mode": "dns",
                "domains": ["example.com", "*.example.com", "example.com"],
                "provider": "cloudflare",
                "zone_id": "zone-123",
                "env": {
                    "CF_DNS_API_TOKEN": "token-abc"
                },
                "propagation_timeout": 240,
                "propagation_interval": 7
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cert_mode(), "dns");
        assert_eq!(
            cert.domains(),
            vec!["example.com".to_string(), "*.example.com".to_string()]
        );
        assert_eq!(cert.dns_provider().as_deref(), Some("cloudflare"));
        assert_eq!(cert.dns_zone_id().as_deref(), Some("zone-123"));
        assert_eq!(
            cert.extra_string(&[&["env", "CF_DNS_API_TOKEN"]])
                .as_deref(),
            Some("token-abc")
        );
        assert_eq!(cert.dns_propagation_timeout_secs(), 240);
        assert_eq!(cert.dns_propagation_interval_secs(), 7);
    }

    #[test]
    fn cert_config_resolves_dns_provider_credentials_and_challenge_aliases() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "acme",
                "challenge_type": "dns-01",
                "provider": "cloudflare",
                "env": {
                    "CF_DNS_API_TOKEN": "token-abc",
                    "ALICLOUD_ACCESS_KEY_ID": "ali-id",
                    "ALICLOUD_ACCESS_KEY_SECRET": "ali-secret"
                },
                "cloudflare_api_key": "cf-key",
                "cloudflare_email": "dns@example.com"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.acme_challenge().as_deref(), Some("dns-01"));
        assert_eq!(cert.cloudflare_api_token().as_deref(), Some("token-abc"));
        assert_eq!(cert.cloudflare_api_key().as_deref(), Some("cf-key"));
        assert_eq!(
            cert.cloudflare_api_email().as_deref(),
            Some("dns@example.com")
        );
        assert_eq!(cert.alidns_access_key_id().as_deref(), Some("ali-id"));
        assert_eq!(
            cert.alidns_access_key_secret().as_deref(),
            Some("ali-secret")
        );
    }

    #[test]
    fn cert_config_resolves_dns_provider_credentials_from_env_text_block() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "dns",
                "provider": "cloudflare",
                "env": "CF_API_TOKEN=token-abc\nexport CF_API_EMAIL=dns@example.com\n# ignored\nALICLOUD_ACCESS_KEY_ID=ali-id\r\nALICLOUD_ACCESS_KEY_SECRET='ali-secret'"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cloudflare_api_token().as_deref(), Some("token-abc"));
        assert_eq!(
            cert.cloudflare_api_email().as_deref(),
            Some("dns@example.com")
        );
        assert_eq!(cert.alidns_access_key_id().as_deref(), Some("ali-id"));
        assert_eq!(
            cert.alidns_access_key_secret().as_deref(),
            Some("ali-secret")
        );
    }

    #[test]
    fn cert_config_resolves_dns_provider_credentials_from_nested_env_block() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
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
                    "environment_variables": "CF_API_TOKEN=token-abc\nCF_API_EMAIL=dns@example.com"
                },
                "dns": {
                    "credentials": {
                        "ALICLOUD_ACCESS_KEY_ID": "ali-id",
                        "ALICLOUD_ACCESS_KEY_SECRET": "ali-secret"
                    }
                }
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(cert.cloudflare_api_token().as_deref(), Some("token-abc"));
        assert_eq!(
            cert.cloudflare_api_email().as_deref(),
            Some("dns@example.com")
        );
        assert_eq!(cert.alidns_access_key_id().as_deref(), Some("ali-id"));
        assert_eq!(
            cert.alidns_access_key_secret().as_deref(),
            Some("ali-secret")
        );
    }

    #[test]
    fn cert_config_resolves_extended_cert_material_aliases() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "server_name": "node.example.com",
            "padding_scheme": [],
            "routes": [],
            "cert_config": {
                "cert_mode": "dns",
                "certificate_path": "/etc/ssl/fullchain.pem",
                "private_key_path": "/etc/ssl/privkey.pem",
                "cert_content": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "key_content": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
            }
        }))
        .expect("parse config");

        let cert = config.cert_config.expect("cert config");
        assert_eq!(
            cert.resolved_cert_path().as_deref(),
            Some("/etc/ssl/fullchain.pem")
        );
        assert_eq!(
            cert.resolved_key_path().as_deref(),
            Some("/etc/ssl/privkey.pem")
        );
        assert!(
            cert.resolved_cert_pem()
                .expect("cert pem")
                .contains("BEGIN CERTIFICATE")
        );
        assert!(
            cert.resolved_key_pem()
                .expect("key pem")
                .contains("BEGIN PRIVATE KEY")
        );
    }

    #[test]
    fn accepts_nulls_in_route_and_user_defaults() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 9,
            "match": null,
            "action": null,
            "action_value": null
        }))
        .expect("parse route");
        assert_eq!(route.action, "");
        assert_eq!(route.action_value, "");

        let user: PanelUser = serde_json::from_value(serde_json::json!({
            "id": 1,
            "uuid": null,
            "password": null,
            "alterId": null,
            "speed_limit": null,
            "device_limit": null
        }))
        .expect("parse user");
        assert_eq!(user.uuid, "");
        assert_eq!(user.password, "");
        assert_eq!(user.alter_id, 0);
        assert_eq!(user.speed_limit, 0);
        assert_eq!(user.device_limit, 0);
    }

    #[test]
    fn accepts_vmess_field_aliases() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vmess",
            "listenIp": "0.0.0.0",
            "serverPort": 443,
            "serverName": "node.example.com",
            "security": "aes-128-gcm",
            "tlsSettings": {
                "serverName": "tls.example.com",
                "serverPort": "8443"
            },
            "globalPadding": true,
            "authenticatedLength": true,
            "packetEncoding": "xudp",
            "fallbackForAlpn": {
                "h2": {
                    "server": "127.0.0.1",
                    "server_port": 8443
                }
            },
            "customOutbounds": [{ "tag": "direct" }],
            "customRoutes": [{ "match": "domain:example.com", "outbound": "direct" }],
            "certConfig": {
                "certMode": "file",
                "certificatePath": "/tmp/fullchain.pem",
                "privateKeyPath": "/tmp/privkey.pem"
            },
            "baseConfig": {
                "pushInterval": "120",
                "pullInterval": 30
            },
            "padding_scheme": [],
            "routes": []
        }))
        .expect("parse config");

        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.server_port, 443);
        assert_eq!(config.server_name, "node.example.com");
        assert_eq!(config.cipher, "aes-128-gcm");
        assert_eq!(config.tls_settings.server_name, "tls.example.com");
        assert_eq!(config.tls_settings.server_port, 8443);
        assert!(config.global_padding);
        assert!(config.authenticated_length);
        assert_eq!(config.packet_encoding, "xudp");
        assert!(config.fallback_for_alpn.is_some());
        assert_eq!(config.custom_outbounds.len(), 1);
        assert_eq!(config.custom_routes.len(), 1);
        assert_eq!(config.cert_config.as_ref().unwrap().cert_mode(), "file");
        let base_config = config.base_config.as_ref().expect("base config");
        assert_eq!(base_config.push_interval_seconds(), Some(120));
        assert_eq!(base_config.pull_interval_seconds(), Some(30));

        let user: PanelUser = serde_json::from_value(serde_json::json!({
            "id": 7,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "alterId": 0,
            "speedLimit": 1024,
            "deviceLimit": 2
        }))
        .expect("parse user");
        assert_eq!(user.alter_id, 0);
        assert_eq!(user.speed_limit, 1024);
        assert_eq!(user.device_limit, 2);
    }

    #[test]
    fn parses_protocol_extension_fields_and_aliases() {
        let config: NodeConfigResponse = serde_json::from_str(
            r#"{
                "protocol": "tuic",
                "listen_ip": "0.0.0.0",
                "server_port": 443,
                "network": "tcp",
                "networkSettings": {
                    "ws": false
                },
                "server_name": "node.example.com",
                "tls": {
                    "enabled": true
                },
                "tls_settings": {
                    "server_name": "node.example.com",
                    "allow_insecure": false
                },
                "multiplex": {
                    "enabled": true
                },
                "host": "trojan.example.com",
                "cipher": "2022-blake3-aes-128-gcm",
                "pluginOpts": "obfs=http",
                "plugin": "obfs-local",
                "server_key": "secret",
                "flow": "xtls-rprx-vision",
                "decryption": "none",
                "version": 2,
                "upMbps": 100,
                "downMbps": "200",
                "obfs": {
                    "type": "salamander"
                },
                "obfs-password": "cry_me_a_r1ver",
                "congestion_control": "bbr",
                "auth_timeout": "3s",
                "zero_rtt_handshake": true,
                "heartbeat": "10s",
                "transport": {
                    "type": "udp"
                },
                "trafficPattern": "h3",
                "alpn": ["h2", "http/1.1"],
                "packet_encoding": "xudp",
                "fallbacks": [{
                    "dest": 80
                }],
                "fallback": {
                    "server": "127.0.0.1",
                    "server_port": 8080
                },
                "fallback_for_alpn": {
                    "h2": {
                        "server": "127.0.0.1",
                        "server_port": 8443
                    }
                },
                "ignoreClientBandwidth": true,
                "masquerade": {
                    "type": "proxy",
                    "url": "https://example.com"
                },
                "udpRelayMode": "native",
                "udpOverStream": true,
                "padding_scheme": [],
                "routes": []
            }"#,
        )
        .expect("parse protocol extensions");

        assert_eq!(config.protocol, "tuic");
        assert_eq!(config.host, "trojan.example.com");
        assert_eq!(config.cipher, "2022-blake3-aes-128-gcm");
        assert_eq!(config.plugin, "obfs-local");
        assert_eq!(config.plugin_opts, "obfs=http");
        assert_eq!(config.server_key, "secret");
        assert_eq!(config.flow, "xtls-rprx-vision");
        assert_eq!(config.decryption, "none");
        assert_eq!(config.version, Some(serde_json::json!(2)));
        assert_eq!(config.up_mbps, Some(serde_json::json!(100)));
        assert_eq!(config.down_mbps, Some(serde_json::json!("200")));
        assert_eq!(
            config.obfs,
            Some(serde_json::json!({ "type": "salamander" }))
        );
        assert_eq!(config.obfs_password, "cry_me_a_r1ver");
        assert_eq!(config.congestion_control, "bbr");
        assert_eq!(config.auth_timeout, "3s");
        assert!(config.zero_rtt_handshake);
        assert_eq!(config.heartbeat, "10s");
        assert_eq!(config.transport, Some(serde_json::json!({ "type": "udp" })));
        assert_eq!(config.traffic_pattern, "h3");
        assert_eq!(config.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(config.packet_encoding, "xudp");
        assert_eq!(config.fallbacks, Some(serde_json::json!([{ "dest": 80 }])));
        assert_eq!(
            config.fallback,
            Some(serde_json::json!({
                "server": "127.0.0.1",
                "server_port": 8080
            }))
        );
        assert_eq!(
            config.fallback_for_alpn,
            Some(serde_json::json!({
                "h2": {
                    "server": "127.0.0.1",
                    "server_port": 8443
                }
            }))
        );
        assert!(config.ignore_client_bandwidth);
        assert_eq!(
            config.masquerade,
            Some(serde_json::json!({
                "type": "proxy",
                "url": "https://example.com"
            }))
        );
        assert_eq!(config.udp_relay_mode, "native");
        assert!(config.udp_over_stream);
    }

    #[test]
    fn interprets_tls_mode_and_disabled_multiplex_objects() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vmess",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "tls": 0,
            "multiplex": {
                "enabled": false,
                "protocol": "yamux"
            },
            "tls_settings": {
                "server_name": null,
                "allow_insecure": false
            }
        }))
        .expect("parse config");

        assert_eq!(config.tls_mode(), 0);
        assert!(!config.multiplex_enabled());
        assert!(!config.tls_settings.is_configured());

        let enabled: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "tls": {
                "enabled": true
            },
            "multiplex": true
        }))
        .expect("parse enabled config");

        assert_eq!(enabled.tls_mode(), 1);
        assert!(enabled.multiplex_enabled());
    }

    #[test]
    fn parses_alpn_from_string_lists() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "server_port": 443,
            "alpn": "h2, http/1.1\nh3"
        }))
        .expect("parse alpn list");

        assert_eq!(
            config.alpn,
            vec!["h2".to_string(), "http/1.1".to_string(), "h3".to_string()]
        );
    }

    #[test]
    fn falls_back_to_tls_settings_for_reality_mode() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "server_port": 443,
            "tls": 2,
            "tls_settings": {
                "server_name": "reality.example.com",
                "allow_insecure": true,
                "server_port": 8443,
                "public_key": "pub",
                "private_key": "priv",
                "short_id": "abcd"
            }
        }))
        .expect("parse reality config");

        let reality = config.effective_reality_settings();
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(reality.server_port, 8443);
        assert_eq!(reality.public_key, "pub");
        assert_eq!(reality.private_key, "priv");
        assert_eq!(reality.short_id, "abcd");
        assert!(reality.allow_insecure);
        assert!(config.tls_settings.is_configured());
        assert!(!config.reality_settings.is_configured());
    }

    #[test]
    fn prefers_explicit_reality_settings_when_present() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "server_port": 443,
            "tls": 2,
            "tls_settings": {
                "server_name": "tls.example.com",
                "public_key": "tls-pub"
            },
            "reality_settings": {
                "server_name": "reality.example.com",
                "server_port": 7443,
                "public_key": "reality-pub",
                "short_id": "beef"
            }
        }))
        .expect("parse explicit reality config");

        let reality = config.effective_reality_settings();
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(reality.server_port, 7443);
        assert_eq!(reality.public_key, "reality-pub");
        assert_eq!(reality.short_id, "beef");
    }

    #[test]
    fn merges_partial_reality_settings_with_tls_reality_fields() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "server_port": 443,
            "tls": 2,
            "tls_settings": {
                "server_name": "tls.example.com",
                "allow_insecure": true,
                "server_port": 8443,
                "public_key": "tls-pub",
                "private_key": "tls-priv",
                "short_id": "abcd"
            },
            "reality_settings": {
                "server_name": "reality.example.com",
                "public_key": "reality-pub"
            }
        }))
        .expect("parse partial reality config");

        let reality = config.effective_reality_settings();
        assert_eq!(reality.server_name, "reality.example.com");
        assert_eq!(reality.server_port, 8443);
        assert_eq!(reality.public_key, "reality-pub");
        assert_eq!(reality.private_key, "tls-priv");
        assert_eq!(reality.short_id, "abcd");
        assert!(reality.allow_insecure);
    }

    #[test]
    fn accepts_lowercase_shortid_alias_in_reality_fields() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "server_port": 443,
            "tls": 2,
            "tls_settings": {
                "server_name": "tls.example.com",
                "public_key": "tls-pub",
                "private_key": "tls-priv",
                "shortid": "abcd"
            },
            "reality_settings": {
                "server_name": "reality.example.com",
                "public_key": "reality-pub",
                "private_key": "reality-priv",
                "shortid": "beef"
            }
        }))
        .expect("parse shortid alias config");

        let reality = config.effective_reality_settings();
        assert_eq!(reality.short_id, "beef");
    }

    #[test]
    fn parses_machine_nodes_response() {
        let response: MachineNodesResponse = serde_json::from_value(serde_json::json!({
            "nodes": [
                {
                    "id": 1,
                    "type": "anytls",
                    "name": "alpha"
                }
            ],
            "base_config": {
                "push_interval": 60,
                "pull_interval": 30
            }
        }))
        .expect("parse machine nodes");

        assert_eq!(response.nodes.len(), 1);
        assert_eq!(response.nodes[0].node_type, "anytls");
        assert_eq!(
            response.base_config.unwrap().pull_interval_seconds(),
            Some(30)
        );
    }

    #[test]
    fn websocket_url_uses_machine_credentials() {
        let panel = MachinePanelClient::new(&PanelConfig {
            api: "https://xboard.example.com".to_string(),
            key: "replace-me".to_string(),
            machine_id: 9,
        })
        .expect("panel client");

        let ws_url = panel
            .websocket_url("wss://panel.example.com:8076")
            .expect("websocket url");

        assert!(ws_url.contains("machine_id=9"));
        assert!(ws_url.contains("token=replace-me"));
    }

    #[test]
    fn websocket_url_accepts_http_scheme_from_panel() {
        let panel = MachinePanelClient::new(&PanelConfig {
            api: "https://xboard.example.com".to_string(),
            key: "replace-me".to_string(),
            machine_id: 9,
        })
        .expect("panel client");

        let ws_url = panel
            .websocket_url("https://panel.example.com/ws")
            .expect("websocket url");

        assert!(ws_url.starts_with("wss://panel.example.com/ws"));
        assert!(ws_url.contains("machine_id=9"));
        assert!(ws_url.contains("token=replace-me"));
    }

    #[test]
    fn classifies_traffic_status_by_certainty() {
        assert!(classify_traffic_status(StatusCode::OK).is_ok());
        assert!(matches!(
            classify_traffic_status(StatusCode::BAD_REQUEST),
            Err(TrafficReportError::Definite(_))
        ));
        assert!(matches!(
            classify_traffic_status(StatusCode::INTERNAL_SERVER_ERROR),
            Err(TrafficReportError::Uncertain(_))
        ));
    }
}
