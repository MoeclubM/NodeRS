use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::panel::{NodeConfigResponse, PanelUser};

use super::{BuiltServerConfig, is_disabled, listen_addr};

#[derive(Clone, Copy)]
enum ShadowsocksCipher {
    None,
    Legacy,
    Aead2022 {
        key_len: usize,
        supports_multi_user: bool,
    },
}

struct EnabledNetworks {
    tcp: bool,
    udp: bool,
}

struct UserMaterial<'a> {
    user: &'a PanelUser,
    credential: String,
}

struct ShadowsocksMaterials<'a> {
    password: String,
    server_users: Vec<String>,
    core_users: Vec<UserMaterial<'a>>,
}

pub(super) fn build_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    validate_remote(remote)?;
    let cipher = parse_cipher(remote)?;
    let networks = parse_networks(&remote.network, cipher)?;
    let materials = user_materials(cipher, remote, users)?;
    ensure!(
        !(networks.tcp && !materials.server_users.is_empty()),
        "Aerion Shadowsocks TCP multi-user accounting requires authenticated user exposure from the shadowsocks crate"
    );

    Ok(BuiltServerConfig::Shadowsocks(
        ::aerion::ShadowsocksServerConfig {
            listen: listen_addr(remote)?,
            method: canonical_cipher(remote)?,
            password: materials.password,
            users: materials.server_users,
            tcp: networks.tcp,
            udp: networks.udp,
            udp_over_tcp: shadowsocks_udp_over_tcp(remote),
        },
    ))
}

pub(super) fn core_users(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<Vec<::aerion::core::CoreUser>> {
    let cipher = parse_cipher(remote)?;
    let materials = user_materials(cipher, remote, users)?;
    Ok(materials
        .core_users
        .into_iter()
        .map(|material| {
            let mut entry = ::aerion::core::CoreUser::password(
                material.user.id.to_string(),
                material.credential,
            );
            let rate = speed_limit_bytes_per_second(material.user.speed_limit);
            entry.upload_limit_bps = rate;
            entry.download_limit_bps = rate;
            entry.max_online_ips = u64::try_from(material.user.device_limit)
                .ok()
                .filter(|limit| *limit > 0);
            entry
        })
        .collect())
}

fn validate_remote(remote: &NodeConfigResponse) -> anyhow::Result<()> {
    if remote.tls.is_some()
        || remote.tls_settings.is_configured()
        || remote.tls_settings.has_reality_key_material()
        || remote.reality_settings.is_configured()
        || remote.cert_config.is_some()
    {
        bail!("Xboard tls/reality settings are not supported for Shadowsocks nodes");
    }
    ensure!(
        remote
            .network_settings
            .as_ref()
            .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
        "Xboard networkSettings is not supported by Aerion Shadowsocks server"
    );
    ensure!(
        remote.plugin.trim().is_empty() && remote.plugin_opts.trim().is_empty(),
        "Aerion Shadowsocks server does not support SIP003 plugin configuration"
    );
    ensure!(
        !remote.multiplex_enabled(),
        "Aerion Shadowsocks server does not support sing-mux multiplex"
    );
    ensure!(
        remote
            .transport
            .as_ref()
            .is_none_or(|value| !crate::panel::json_value_is_enabled(value)),
        "Aerion Shadowsocks server does not support Xboard transport extension"
    );
    Ok(())
}

fn parse_cipher(remote: &NodeConfigResponse) -> anyhow::Result<ShadowsocksCipher> {
    Ok(match normalized_cipher(remote)?.as_str() {
        "none" | "plain" => ShadowsocksCipher::None,
        "aes128gcm"
        | "aeadaes128gcm"
        | "aes192gcm"
        | "aeadaes192gcm"
        | "aes256gcm"
        | "aeadaes256gcm"
        | "chacha20poly1305"
        | "aeadchacha20poly1305"
        | "chacha20ietfpoly1305"
        | "aeadchacha20ietfpoly1305"
        | "xchacha20poly1305"
        | "aeadxchacha20poly1305"
        | "xchacha20ietfpoly1305"
        | "aeadxchacha20ietfpoly1305" => ShadowsocksCipher::Legacy,
        "2022blake3aes128gcm" => ShadowsocksCipher::Aead2022 {
            key_len: 16,
            supports_multi_user: true,
        },
        "2022blake3aes256gcm" => ShadowsocksCipher::Aead2022 {
            key_len: 32,
            supports_multi_user: true,
        },
        "2022blake3chacha20poly1305" => ShadowsocksCipher::Aead2022 {
            key_len: 32,
            supports_multi_user: false,
        },
        _ => bail!("unsupported Shadowsocks cipher {}", remote.cipher.trim()),
    })
}

fn canonical_cipher(remote: &NodeConfigResponse) -> anyhow::Result<String> {
    Ok(match normalized_cipher(remote)?.as_str() {
        "none" | "plain" => "none",
        "aes128gcm" | "aeadaes128gcm" => "aes-128-gcm",
        "aes192gcm" | "aeadaes192gcm" => "aes-192-gcm",
        "aes256gcm" | "aeadaes256gcm" => "aes-256-gcm",
        "chacha20poly1305"
        | "aeadchacha20poly1305"
        | "chacha20ietfpoly1305"
        | "aeadchacha20ietfpoly1305" => "chacha20-ietf-poly1305",
        "xchacha20poly1305"
        | "aeadxchacha20poly1305"
        | "xchacha20ietfpoly1305"
        | "aeadxchacha20ietfpoly1305" => "xchacha20-ietf-poly1305",
        "2022blake3aes128gcm" => "2022-blake3-aes-128-gcm",
        "2022blake3aes256gcm" => "2022-blake3-aes-256-gcm",
        "2022blake3chacha20poly1305" => "2022-blake3-chacha20-poly1305",
        _ => bail!("unsupported Shadowsocks cipher {}", remote.cipher.trim()),
    }
    .to_string())
}

fn normalized_cipher(remote: &NodeConfigResponse) -> anyhow::Result<String> {
    let cipher = remote.cipher.trim();
    ensure!(
        !cipher.is_empty(),
        "Xboard cipher is required for Shadowsocks nodes"
    );
    Ok(cipher
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect())
}

fn parse_networks(network: &str, cipher: ShadowsocksCipher) -> anyhow::Result<EnabledNetworks> {
    let network = network.trim();
    if network.is_empty() {
        return Ok(match cipher {
            ShadowsocksCipher::Aead2022 { .. } => EnabledNetworks {
                tcp: true,
                udp: true,
            },
            ShadowsocksCipher::None | ShadowsocksCipher::Legacy => EnabledNetworks {
                tcp: true,
                udp: false,
            },
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
    ensure!(
        networks.tcp || networks.udp,
        "no Shadowsocks network enabled"
    );
    Ok(networks)
}

fn user_materials<'a>(
    cipher: ShadowsocksCipher,
    remote: &NodeConfigResponse,
    users: &'a [PanelUser],
) -> anyhow::Result<ShadowsocksMaterials<'a>> {
    match cipher {
        ShadowsocksCipher::None | ShadowsocksCipher::Legacy => {
            ensure!(
                users.len() == 1,
                "Aerion Shadowsocks legacy/none multi-user requires Shadowsocks 2022 EIH"
            );
            let user = &users[0];
            let password = effective_password(user)
                .ok_or_else(|| {
                    anyhow::anyhow!("Shadowsocks user {} is missing password/uuid", user.id)
                })?
                .to_string();
            Ok(ShadowsocksMaterials {
                password: password.clone(),
                server_users: Vec::new(),
                core_users: vec![UserMaterial {
                    user,
                    credential: password,
                }],
            })
        }
        ShadowsocksCipher::Aead2022 {
            key_len,
            supports_multi_user,
        } => {
            let password = normalize_psk(
                &remote.server_key,
                key_len,
                "decode Shadowsocks 2022 server_key",
            )?;
            if users.len() == 1 {
                return Ok(ShadowsocksMaterials {
                    password: password.clone(),
                    server_users: Vec::new(),
                    core_users: vec![UserMaterial {
                        user: &users[0],
                        credential: password,
                    }],
                });
            }

            ensure!(
                supports_multi_user,
                "Shadowsocks 2022 chacha20-poly1305 does not support multi-user"
            );
            let mut server_users = Vec::with_capacity(users.len());
            let mut core_users = Vec::with_capacity(users.len());
            for user in users {
                let key = shadowsocks_2022_user_key(user, key_len)?;
                server_users.push(format!("{}:{key}", user.id));
                core_users.push(UserMaterial {
                    user,
                    credential: key,
                });
            }
            Ok(ShadowsocksMaterials {
                password,
                server_users,
                core_users,
            })
        }
    }
}

fn shadowsocks_2022_user_key(user: &PanelUser, key_len: usize) -> anyhow::Result<String> {
    if !user.password.trim().is_empty() {
        return normalize_psk(
            &user.password,
            key_len,
            &format!("decode Shadowsocks 2022 user {} key", user.id),
        );
    }
    if !user.uuid.trim().is_empty() {
        return normalize_psk(
            &user.uuid,
            key_len,
            &format!("decode Shadowsocks 2022 user {} key", user.id),
        );
    }
    bail!("Shadowsocks 2022 user {} is missing password/uuid", user.id)
}

fn normalize_psk(value: &str, key_len: usize, context: &str) -> anyhow::Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "Shadowsocks 2022 key is required");
    let decoded = STANDARD.decode(value).context(context.to_string())?;
    ensure!(
        decoded.len() == key_len,
        "Shadowsocks 2022 key must be exactly {key_len} bytes"
    );
    Ok(STANDARD.encode(decoded))
}

fn effective_password(user: &PanelUser) -> Option<&str> {
    let password = user.password.trim();
    if !password.is_empty() {
        return Some(password);
    }
    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return Some(uuid);
    }
    None
}

fn shadowsocks_udp_over_tcp(remote: &NodeConfigResponse) -> bool {
    if remote.udp_over_stream {
        return true;
    }
    matches!(
        remote
            .udp_relay_mode
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str(),
        "uot" | "udpovertcp" | "stream"
    ) && !is_disabled(&remote.udp_relay_mode)
}

fn speed_limit_bytes_per_second(speed_limit: i64) -> Option<u64> {
    u64::try_from(speed_limit)
        .ok()
        .filter(|limit| *limit > 0)
        .map(|limit| limit.saturating_mul(125_000))
}
