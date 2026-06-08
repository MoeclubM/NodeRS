use anyhow::{Context, anyhow, bail, ensure};
use serde_json::Value;
use std::collections::HashSet;

use crate::accounting::UserEntry;
use crate::panel::{NodeConfigResponse, PanelUser};
use crate::protocols::shared::{effective_listen_ip, routing};

use super::crypto::{Method, UserCredential};
use super::{
    EffectiveNodeConfig, EnabledNetworks, MultiplexConfig, PluginConfig, SingMuxProtocol, aead2022,
    crypto,
};

impl EffectiveNodeConfig {
    pub fn from_remote(remote: &NodeConfigResponse) -> anyhow::Result<Self> {
        validate_remote_support(remote)?;
        let method = parse_method(remote)?;
        let networks = parse_networks(&remote.network, &method)?;
        Ok(Self {
            listen_ip: effective_listen_ip(remote),
            server_port: remote.server_port,
            method,
            server_key: remote.server_key.trim().to_string(),
            networks,
            plugin: parse_plugin(remote)?,
            multiplex: parse_multiplex(remote)?,
            routing: routing::RoutingTable::from_remote(
                &remote.routes,
                &remote.custom_outbounds,
                &remote.custom_routes,
            )
            .context("compile Xboard routing")?,
        })
    }
}

impl EnabledNetworks {
    pub(super) fn any(self) -> bool {
        self.tcp || self.udp
    }
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: SingMuxProtocol::Yamux,
            padding: false,
        }
    }
}

pub(super) fn build_users(
    method: &Method,
    server_key: &str,
    users: &[PanelUser],
) -> anyhow::Result<Vec<UserCredential>> {
    let credentials = match method {
        Method::Aead2022(kind) => {
            let server_secret = aead2022::decode_server_psk(server_key, *kind)
                .context("decode Shadowsocks 2022 server_key")?;
            ensure!(
                !matches!(kind, crypto::Aead2022Method::ChaCha20Poly1305) || users.len() <= 1,
                "Shadowsocks 2022 chacha20-poly1305 does not support multi-user"
            );
            if users.len() == 1 {
                return Ok(vec![UserCredential {
                    user: UserEntry::from_panel_user(&users[0]),
                    method: method.clone(),
                    identity_hash: aead2022::identity_hash(&server_secret),
                    server_secret: server_secret.clone(),
                    secret: server_secret,
                }]);
            }
            users
                .iter()
                .map(|user| {
                    let secret = aead2022::derive_user_psk(user, *kind)?;
                    Ok(UserCredential {
                        user: UserEntry::from_panel_user(user),
                        method: method.clone(),
                        identity_hash: aead2022::identity_hash(&secret),
                        server_secret: server_secret.clone(),
                        secret,
                    })
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        }
        _ => users
            .iter()
            .map(|user| UserCredential::from_panel_user(user, method.clone()))
            .collect::<Result<Vec<_>, _>>()?,
    };

    if method.is_none() {
        ensure!(
            credentials.len() <= 1,
            "Shadowsocks none cipher does not support multi-user"
        );
    }

    let mut seen = HashSet::new();
    for credential in &credentials {
        ensure!(
            seen.insert(credential.secret.clone()),
            "duplicate Shadowsocks credentials for user {}",
            credential.user.id
        );
    }
    Ok(credentials)
}

fn parse_method(remote: &NodeConfigResponse) -> anyhow::Result<Method> {
    let cipher = remote.cipher.trim();
    if cipher.is_empty() {
        bail!("XBoard cipher is required for Shadowsocks nodes");
    }
    let method =
        Method::parse(cipher).ok_or_else(|| anyhow!("unsupported Shadowsocks cipher {cipher}"))?;
    if matches!(method, Method::Aead2022(_)) {
        ensure!(
            !remote.server_key.trim().is_empty(),
            "XBoard server_key is required for Shadowsocks 2022 nodes"
        );
    }
    Ok(method)
}

fn parse_networks(network: &str, method: &Method) -> anyhow::Result<EnabledNetworks> {
    let network = network.trim();
    if network.is_empty() {
        if matches!(method, Method::Aead2022(_)) {
            return Ok(EnabledNetworks {
                tcp: true,
                udp: true,
            });
        }
        return Ok(EnabledNetworks {
            tcp: true,
            udp: false,
        });
    }

    let mut networks = EnabledNetworks {
        tcp: false,
        udp: false,
    };
    for item in network.split(|ch: char| ch == ',' || ch.is_ascii_whitespace()) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.eq_ignore_ascii_case("tcp") {
            networks.tcp = true;
        } else if item.eq_ignore_ascii_case("udp") {
            networks.udp = true;
        } else {
            bail!("unsupported Shadowsocks network {item}");
        }
    }
    ensure!(networks.any(), "no Shadowsocks network enabled");
    Ok(networks)
}

fn parse_plugin(remote: &NodeConfigResponse) -> anyhow::Result<Option<PluginConfig>> {
    let command = remote.plugin.trim();
    let opts = remote.plugin_opts.trim();
    if command.is_empty() && opts.is_empty() {
        return Ok(None);
    }
    ensure!(
        !command.is_empty(),
        "Xboard plugin is required when plugin_opts is set"
    );
    Ok(Some(PluginConfig {
        command: command.to_string(),
        opts: opts.to_string(),
    }))
}

fn parse_multiplex(remote: &NodeConfigResponse) -> anyhow::Result<MultiplexConfig> {
    let Some(value) = remote.multiplex.as_ref() else {
        return Ok(MultiplexConfig::default());
    };
    if !crate::panel::json_value_is_enabled(value) {
        return Ok(MultiplexConfig::default());
    }
    match value {
        Value::Object(object) => {
            let protocol = object
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("yamux")
                .trim();
            ensure!(
                protocol.is_empty() || protocol.eq_ignore_ascii_case("yamux"),
                "only Shadowsocks yamux multiplex is implemented"
            );
            Ok(MultiplexConfig {
                enabled: true,
                protocol: SingMuxProtocol::Yamux,
                padding: object
                    .get("padding")
                    .is_some_and(crate::panel::json_value_is_enabled),
            })
        }
        _ => Ok(MultiplexConfig {
            enabled: true,
            ..Default::default()
        }),
    }
}

fn validate_remote_support(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if remote.tls.is_some()
        || remote.tls_settings.is_configured()
        || remote.tls_settings.has_reality_key_material()
        || remote.reality_settings.is_configured()
        || remote.cert_config.is_some()
    {
        bail!("Xboard tls/reality settings are not supported for Shadowsocks nodes");
    }
    if remote
        .network_settings
        .as_ref()
        .is_some_and(network_settings_enabled)
    {
        bail!("XBoard networkSettings is not supported by NodeRS Shadowsocks server");
    }
    parse_plugin(remote)?;
    parse_multiplex(remote)?;
    if remote.transport.as_ref().is_some_and(value_enabled) {
        bail!("Shadowsocks transport is not supported");
    }
    Ok(())
}

fn network_settings_enabled(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => {
            number.as_i64().is_some_and(|value| value != 0)
                || number.as_u64().is_some_and(|value| value != 0)
                || number.as_f64().is_some_and(|value| value != 0.0)
        }
        Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            !matches!(
                normalized.as_str(),
                "" | "0" | "false" | "off" | "no" | "none" | "disabled"
            )
        }
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => {
            if object.is_empty() {
                return false;
            }
            if let Some(enabled) = object.get("enabled") {
                return value_enabled(enabled);
            }
            object.iter().any(|(key, value)| {
                let normalized = normalize_option_key(key);
                if normalized == "acceptproxyprotocol" {
                    return false;
                }
                value_enabled(value)
            })
        }
    }
}

fn normalize_option_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn value_enabled(value: &Value) -> bool {
    crate::panel::json_value_is_enabled(value)
}
