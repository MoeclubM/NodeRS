use anyhow::{Context, ensure};
use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};
use std::path::PathBuf;

use super::tls;
use crate::acme;
use crate::panel::{CertConfig, NodeConfigResponse};

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
    let ech = &remote.tls_settings.ech;
    if !ech.is_enabled() {
        return Ok(None);
    }
    if !ech.key_path.trim().is_empty() {
        return Ok(Some(tls::EchConfigSource::Files {
            key_path: ech.key_path.trim().into(),
        }));
    }
    if !ech.key.trim().is_empty() {
        return Ok(Some(tls::EchConfigSource::Inline {
            key: ech.key.trim().as_bytes().to_vec(),
        }));
    }
    Ok(None)
}

pub(crate) fn aerion_ech_keys(
    tls: &EffectiveTlsConfig,
    reality: bool,
) -> anyhow::Result<Option<::aerion::TlsEchServerKeys>> {
    if reality {
        ensure!(
            tls.ech.is_none(),
            "ECH cannot be combined with REALITY on Aerion-backed nodes"
        );
        return Ok(None);
    }
    let Some(source) = tls.ech.as_ref() else {
        return Ok(None);
    };
    Ok(Some(match source {
        tls::EchConfigSource::Files { key_path } => ::aerion::tls_ech::tls_ech_from_path(key_path),
        tls::EchConfigSource::Inline { key } => {
            let inline = String::from_utf8(key.clone())
                .context("Xboard inline ECH key material must be UTF-8")?;
            ::aerion::tls_ech::tls_ech_from_compat_reference(inline.trim())
        }
    }))
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

#[cfg(test)]
mod tests;
