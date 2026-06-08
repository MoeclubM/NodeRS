use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Client;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha1::Sha1;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{DnsChallengeRecord, DnsProviderConfig, unix_now};

type HmacSha1 = Hmac<Sha1>;

const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const ALIDNS_API_ENDPOINT: &str = "https://alidns.aliyuncs.com/";
const ALIDNS_API_VERSION: &str = "2015-01-09";
const ALIDNS_QUERY_ESCAPE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

static NEXT_ALIDNS_NONCE: AtomicU64 = AtomicU64::new(1);
#[derive(Debug)]
pub(super) enum DnsRecordHandle {
    Cloudflare { zone_id: String, record_id: String },
    AliDns { record_id: String },
}

#[derive(Debug, Clone)]
pub(super) enum DnsProvider {
    Cloudflare(CloudflareDnsProvider),
    AliDns(AliDnsProvider),
}

impl DnsProvider {
    pub(super) fn new(client: Client, config: DnsProviderConfig) -> Self {
        match config {
            DnsProviderConfig::Cloudflare {
                api_token,
                api_key,
                api_email,
                zone_id,
                zone_name,
                ttl,
            } => Self::Cloudflare(CloudflareDnsProvider {
                client,
                api_token,
                api_key,
                api_email,
                zone_id,
                zone_name,
                ttl,
            }),
            DnsProviderConfig::AliDns {
                access_key_id,
                access_key_secret,
                zone_name,
                ttl,
            } => Self::AliDns(AliDnsProvider {
                client,
                access_key_id,
                access_key_secret,
                zone_name,
                ttl,
            }),
        }
    }

    pub(super) async fn create_txt_record(
        &self,
        record: &DnsChallengeRecord,
    ) -> anyhow::Result<DnsRecordHandle> {
        match self {
            Self::Cloudflare(provider) => provider.create_txt_record(record).await,
            Self::AliDns(provider) => provider.create_txt_record(record).await,
        }
    }

    pub(super) async fn delete_record(&self, handle: DnsRecordHandle) -> anyhow::Result<()> {
        match (self, handle) {
            (Self::Cloudflare(provider), DnsRecordHandle::Cloudflare { zone_id, record_id }) => {
                provider.delete_record(&zone_id, &record_id).await
            }
            (Self::AliDns(provider), DnsRecordHandle::AliDns { record_id }) => {
                provider.delete_record(&record_id).await
            }
            (Self::Cloudflare(_), other) => {
                bail!("Cloudflare DNS provider received mismatched record handle {other:?}")
            }
            (Self::AliDns(_), other) => {
                bail!("AliDNS provider received mismatched record handle {other:?}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CloudflareDnsProvider {
    client: Client,
    api_token: Option<String>,
    api_key: Option<String>,
    api_email: Option<String>,
    zone_id: Option<String>,
    zone_name: Option<String>,
    ttl: Option<u64>,
}

impl CloudflareDnsProvider {
    pub(super) async fn create_txt_record(
        &self,
        record: &DnsChallengeRecord,
    ) -> anyhow::Result<DnsRecordHandle> {
        let zone_id = self.resolve_zone_id(&record.fqdn).await?;
        let response: anyhow::Result<CloudflareDnsRecord> = self
            .cloudflare_json(
                self.client
                    .post(format!("{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records"))
                    .json(&json!({
                        "type": "TXT",
                        "name": record.fqdn.trim_end_matches('.'),
                        "content": record.value,
                        "ttl": self.ttl.unwrap_or(60).max(1),
                    })),
                "create DNS record",
            )
            .await;

        let response = match response {
            Ok(response) => response,
            Err(error) if is_cloudflare_duplicate_record_error(&error) => {
                let record_id = self
                    .find_existing_txt_record_id(&zone_id, record)
                    .await?
                    .ok_or(error)?;
                return Ok(DnsRecordHandle::Cloudflare { zone_id, record_id });
            }
            Err(error) => return Err(error),
        };
        Ok(DnsRecordHandle::Cloudflare {
            zone_id,
            record_id: response.id,
        })
    }

    async fn find_existing_txt_record_id(
        &self,
        zone_id: &str,
        record: &DnsChallengeRecord,
    ) -> anyhow::Result<Option<String>> {
        let records: Vec<CloudflareDnsRecordDetail> = self
            .cloudflare_json(
                self.client
                    .get(format!("{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records"))
                    .query(&[
                        ("type", "TXT"),
                        ("name", record.fqdn.trim_end_matches('.')),
                        ("page", "1"),
                        ("per_page", "100"),
                    ]),
                "lookup DNS record",
            )
            .await?;
        Ok(records
            .into_iter()
            .find(|item| item.content == record.value)
            .map(|item| item.id))
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
        let _: Value = self
            .cloudflare_json(
                self.client.delete(format!(
                    "{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
                )),
                "delete DNS record",
            )
            .await?;
        Ok(())
    }

    async fn resolve_zone_id(&self, fqdn: &str) -> anyhow::Result<String> {
        if let Some(zone_id) = &self.zone_id {
            return Ok(zone_id.clone());
        }

        let mut candidates = Vec::new();
        if let Some(zone_name) = &self.zone_name {
            candidates.push(zone_name.clone());
        }
        for candidate in zone_candidates_from_name(fqdn) {
            if !candidates
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&candidate))
            {
                candidates.push(candidate);
            }
        }

        for zone_name in candidates {
            let zones: Vec<CloudflareZone> = self
                .cloudflare_json(
                    self.client
                        .get(format!("{CLOUDFLARE_API_BASE}/zones"))
                        .query(&[
                            ("name", zone_name.as_str()),
                            ("page", "1"),
                            ("per_page", "1"),
                        ]),
                    "lookup zone",
                )
                .await?;
            if let Some(zone) = zones.into_iter().next() {
                return Ok(zone.id);
            }
        }

        bail!("unable to resolve Cloudflare zone for {fqdn}")
    }

    fn apply_auth(
        &self,
        request: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::RequestBuilder> {
        if let Some(api_token) = &self.api_token {
            Ok(request.bearer_auth(api_token))
        } else if let (Some(api_email), Some(api_key)) = (&self.api_email, &self.api_key) {
            Ok(request
                .header("X-Auth-Email", api_email)
                .header("X-Auth-Key", api_key))
        } else {
            bail!("Cloudflare dns-01 requires api_token or api_key + api_email")
        }
    }

    async fn cloudflare_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        context: &str,
    ) -> anyhow::Result<T> {
        let response = self
            .apply_auth(request)?
            .send()
            .await
            .with_context(|| format!("Cloudflare {context}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("read Cloudflare {context} response"))?;
        let value: Value = serde_json::from_str(&body)
            .with_context(|| format!("decode Cloudflare {context} response"))?;
        let success = value
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(status.is_success());
        if !status.is_success() || !success {
            bail!(
                "Cloudflare {context} failed: {}",
                summarize_cloudflare_error_value(&value)
            );
        }
        serde_json::from_value(value.get("result").cloned().unwrap_or(Value::Null))
            .with_context(|| format!("decode Cloudflare {context} result"))
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsRecord {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsRecordDetail {
    id: String,
    #[serde(default)]
    content: String,
}

fn is_cloudflare_duplicate_record_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("81058") || message.contains("An identical record already exists")
}

#[derive(Debug, Clone)]
pub(super) struct AliDnsProvider {
    client: Client,
    access_key_id: String,
    access_key_secret: String,
    zone_name: Option<String>,
    ttl: Option<u64>,
}

impl AliDnsProvider {
    pub(super) async fn create_txt_record(
        &self,
        record: &DnsChallengeRecord,
    ) -> anyhow::Result<DnsRecordHandle> {
        let zone_name = self.resolve_zone_name(&record.fqdn).await?;
        let rr = relative_record_name(&record.fqdn, &zone_name)?;
        let response = self
            .signed_request(
                "AddDomainRecord",
                &[
                    ("DomainName", zone_name),
                    ("RR", rr),
                    ("Type", "TXT".to_string()),
                    ("Value", record.value.clone()),
                    ("TTL", self.ttl.unwrap_or(600).to_string()),
                ],
            )
            .await?;
        let record_id = response
            .get("RecordId")
            .and_then(json_value_to_string)
            .context("AliDNS AddDomainRecord response did not include RecordId")?;
        Ok(DnsRecordHandle::AliDns { record_id })
    }

    async fn delete_record(&self, record_id: &str) -> anyhow::Result<()> {
        let _ = self
            .signed_request("DeleteDomainRecord", &[("RecordId", record_id.to_string())])
            .await?;
        Ok(())
    }

    async fn resolve_zone_name(&self, fqdn: &str) -> anyhow::Result<String> {
        if let Some(zone_name) = &self.zone_name {
            return Ok(zone_name.clone());
        }

        for candidate in zone_candidates_from_name(fqdn) {
            match self
                .signed_request("DescribeDomainInfo", &[("DomainName", candidate.clone())])
                .await
            {
                Ok(_) => return Ok(candidate),
                Err(error) if is_alidns_missing_domain_error(&error) => continue,
                Err(error) => return Err(error),
            }
        }

        bail!("unable to resolve AliDNS zone for {fqdn}")
    }

    async fn signed_request(
        &self,
        action: &str,
        extra_params: &[(impl AsRef<str>, String)],
    ) -> anyhow::Result<Value> {
        let mut params = BTreeMap::new();
        params.insert("AccessKeyId".to_string(), self.access_key_id.clone());
        params.insert("Action".to_string(), action.to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureNonce".to_string(), next_alidns_nonce());
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert(
            "Timestamp".to_string(),
            OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .context("format AliDNS timestamp")?,
        );
        params.insert("Version".to_string(), ALIDNS_API_VERSION.to_string());
        for (key, value) in extra_params {
            params.insert(key.as_ref().to_string(), value.clone());
        }

        let canonicalized = params
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}={}",
                    alidns_percent_encode(key),
                    alidns_percent_encode(value)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("GET&%2F&{}", alidns_percent_encode(&canonicalized));
        let signature = alidns_signature(&self.access_key_secret, &string_to_sign)?;
        params.insert("Signature".to_string(), signature);

        let response = self
            .client
            .get(ALIDNS_API_ENDPOINT)
            .query(&params)
            .send()
            .await
            .with_context(|| format!("AliDNS {action}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("read AliDNS {action} response"))?;
        let value: Value = serde_json::from_str(&body)
            .with_context(|| format!("decode AliDNS {action} response"))?;
        if let Some(code) = value.get("Code").and_then(Value::as_str) {
            let message = value
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            bail!("AliDNS {action} failed with {code}: {message}");
        }
        if !status.is_success() {
            bail!("AliDNS {action} request failed with {status}: {body}");
        }
        Ok(value)
    }
}

fn is_alidns_missing_domain_error(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("InvalidDomainName.NoExist")
        || text.contains("DomainRecordNotBelongToUser")
        || text.contains("Forbidden.DomainNotBelongToUser")
}
pub(super) fn zone_candidates_from_name(name: &str) -> Vec<String> {
    let labels = name
        .trim()
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() < 2 {
        return Vec::new();
    }

    let start = if labels
        .first()
        .is_some_and(|label| label.eq_ignore_ascii_case("_acme-challenge"))
    {
        1
    } else {
        0
    };

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for index in start..labels.len() - 1 {
        let candidate = labels[index..].join(".");
        if candidate.contains('.') && seen.insert(candidate.to_ascii_lowercase()) {
            candidates.push(candidate);
        }
    }
    candidates
}

pub(super) fn relative_record_name(fqdn: &str, zone_name: &str) -> anyhow::Result<String> {
    let fqdn = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
    let zone_name = zone_name.trim().trim_end_matches('.').to_ascii_lowercase();
    if fqdn == zone_name {
        return Ok("@".to_string());
    }
    let suffix = format!(".{zone_name}");
    if let Some(relative) = fqdn.strip_suffix(&suffix) {
        return Ok(relative.to_string());
    }
    bail!("record {fqdn} does not belong to zone {zone_name}")
}

fn summarize_cloudflare_error_value(value: &Value) -> String {
    if let Some(errors) = value.get("errors").and_then(Value::as_array) {
        let summary = errors
            .iter()
            .map(|error| {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                match error.get("code").and_then(Value::as_i64) {
                    Some(code) => format!("{code}: {message}"),
                    None => message.to_string(),
                }
            })
            .collect::<Vec<_>>();
        if !summary.is_empty() {
            return summary.join("; ");
        }
    }
    value.to_string()
}

fn json_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn alidns_percent_encode(text: &str) -> String {
    utf8_percent_encode(text, &ALIDNS_QUERY_ESCAPE_SET).to_string()
}

fn alidns_signature(secret: &str, string_to_sign: &str) -> anyhow::Result<String> {
    let mut mac = HmacSha1::new_from_slice(format!("{secret}&").as_bytes())
        .context("initialize AliDNS HMAC")?;
    mac.update(string_to_sign.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

fn next_alidns_nonce() -> String {
    format!(
        "noders-{}-{}",
        unix_now(),
        NEXT_ALIDNS_NONCE.fetch_add(1, Ordering::Relaxed)
    )
}
