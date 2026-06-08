use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

use super::value_to_u64;

const DEFAULT_ACME_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const DEFAULT_ACME_CHALLENGE_LISTEN: &str = "0.0.0.0:80";
const DEFAULT_ACME_RENEW_BEFORE_DAYS: u64 = 30;
const DEFAULT_DNS_PROPAGATION_TIMEOUT_SECS: u64 = 180;
const DEFAULT_DNS_PROPAGATION_INTERVAL_SECS: u64 = 5;
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct CertConfig {
    #[serde(
        default,
        alias = "mode",
        alias = "certMode",
        deserialize_with = "super::deserialize_default_on_null"
    )]
    pub cert_mode: String,
    #[serde(
        default,
        alias = "certificate_path",
        alias = "certificatePath",
        alias = "fullchain_path",
        alias = "fullchainPath",
        alias = "fullchain",
        deserialize_with = "super::deserialize_default_on_null"
    )]
    pub cert_path: String,
    #[serde(
        default,
        alias = "private_key_path",
        alias = "privateKeyPath",
        alias = "privkey_path",
        alias = "privkeyPath",
        alias = "privkey",
        deserialize_with = "super::deserialize_default_on_null"
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
        deserialize_with = "super::deserialize_default_on_null"
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
        deserialize_with = "super::deserialize_default_on_null"
    )]
    pub key_pem: String,
    #[serde(default, deserialize_with = "super::deserialize_default_on_null")]
    pub domain: String,
    #[serde(default, deserialize_with = "super::deserialize_default_on_null")]
    pub email: String,
    #[serde(
        default,
        alias = "directory",
        alias = "acme_directory_url",
        alias = "directoryUrl",
        alias = "acmeDirectoryUrl",
        deserialize_with = "super::deserialize_default_on_null"
    )]
    pub directory_url: String,
    #[serde(
        default,
        alias = "http01_listen",
        alias = "http01Listen",
        alias = "acme_challenge_listen",
        alias = "acmeChallengeListen",
        deserialize_with = "super::deserialize_default_on_null"
    )]
    pub challenge_listen: String,
    #[serde(default, alias = "renewBeforeDays")]
    pub renew_before_days: Option<u64>,
    #[serde(
        default,
        alias = "acme_account_key_path",
        alias = "acmeAccountKeyPath",
        alias = "accountKeyPath",
        deserialize_with = "super::deserialize_default_on_null"
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

pub(super) fn value_to_split_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values.iter().flat_map(value_to_split_strings).collect(),
        Value::String(text) => split_list_values(text).collect(),
        Value::Null => Vec::new(),
        other => value_to_trimmed_string(other).into_iter().collect(),
    }
}
