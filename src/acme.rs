use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use boring::nid::Nid;
use boring::x509::X509;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, LOCATION, RETRY_AFTER};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::warn;
mod dns;
mod dns_provider;
use dns::lookup_txt_records;
use dns_provider::{DnsProvider, DnsRecordHandle};
#[cfg(test)]
use dns_provider::{relative_record_name, zone_candidates_from_name};
const ACME_CONTENT_TYPE: &str = "application/jose+json";
const ACME_JWS_ALGORITHM: &str = "ES256";
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_POLL_ATTEMPTS: usize = 90;
const HTTP_BUFFER_SIZE: usize = 8192;
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_PROPAGATION_RESOLVERS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub email: String,
    pub domains: Vec<String>,
    pub renew_before_days: u64,
    pub account_key_path: PathBuf,
    pub challenge: AcmeChallengeConfig,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeChallengeConfig {
    Http01 { listen: String },
    Dns01(Dns01Config),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns01Config {
    pub provider: DnsProviderConfig,
    pub propagation_timeout_secs: u64,
    pub propagation_interval_secs: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProviderConfig {
    Cloudflare {
        api_token: Option<String>,
        api_key: Option<String>,
        api_email: Option<String>,
        zone_id: Option<String>,
        zone_name: Option<String>,
        ttl: Option<u64>,
    },
    AliDns {
        access_key_id: String,
        access_key_secret: String,
        zone_name: Option<String>,
        ttl: Option<u64>,
    },
}
pub async fn ensure_certificate(
    config: &AcmeConfig,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<bool> {
    let domains = normalize_domains(&config.domains);
    ensure!(
        !domains.is_empty(),
        "ACME domains must not be empty when ACME mode is used"
    );
    if !needs_renewal(cert_path, key_path, &domains, config.renew_before_days).await? {
        return Ok(false);
    }
    let client = Client::builder()
        .user_agent(format!("NodeRS/{} ACME", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build ACME HTTP client")?;
    let directory = fetch_directory(&client, &config.directory_url).await?;
    let account_key = load_or_create_account_key(&config.account_key_path).await?;
    let acme = AcmeClient::new(client, directory, account_key)?;
    let account = acme.ensure_account(&config.email).await?;
    let mut order = acme.new_order(&account.kid, &domains).await?;
    authorize_order(
        &acme,
        &account.kid,
        &config.challenge,
        &order.authorizations,
    )
    .await?;
    let domain_key = load_or_create_domain_key(key_path).await?;
    let csr_der = build_certificate_signing_request(&domain_key, &domains)?;
    order = acme
        .finalize_order(&account.kid, &order.url, &order.finalize, &csr_der)
        .await?;
    if order.status != "valid" {
        order = acme.poll_order_valid(&account.kid, &order.url).await?;
    }
    let certificate_url = order
        .certificate
        .context("ACME order became valid without a certificate URL")?;
    let certificate_pem = acme
        .download_certificate(&account.kid, &certificate_url)
        .await?;
    write_domain_key(key_path, &domain_key).await?;
    write_atomic(cert_path, certificate_pem.as_bytes()).await?;
    Ok(true)
}
async fn needs_renewal(
    cert_path: &Path,
    key_path: &Path,
    domains: &[String],
    renew_before_days: u64,
) -> anyhow::Result<bool> {
    if tokio::fs::metadata(cert_path).await.is_err() || tokio::fs::metadata(key_path).await.is_err()
    {
        return Ok(true);
    }
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("read certificate {}", cert_path.display()))?;
    if !certificate_matches_domains(&cert_pem, domains)? {
        return Ok(true);
    }
    let not_after = match first_certificate_not_after(&cert_pem) {
        Ok(timestamp) => timestamp,
        Err(_) => return Ok(true),
    };
    let renew_after = not_after.saturating_sub(renew_before_days.saturating_mul(24 * 60 * 60));
    Ok(unix_now() >= renew_after)
}
fn certificate_matches_domains(cert_pem: &[u8], domains: &[String]) -> anyhow::Result<bool> {
    let certificate = X509::stack_from_pem(cert_pem)
        .context("parse certificate PEM")?
        .into_iter()
        .next()
        .context("certificate PEM did not include any certificates")?;
    let mut actual = HashSet::new();
    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        for name in subject_alt_names {
            if let Some(dns_name) = name.dnsname() {
                actual.insert(dns_name.trim().trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    if actual.is_empty() {
        for entry in certificate.subject_name().entries_by_nid(Nid::COMMONNAME) {
            if let Ok(common_name) = entry.data().as_utf8() {
                actual.insert(
                    common_name
                        .to_string()
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                );
            }
        }
    }
    Ok(domains
        .iter()
        .all(|domain| actual.contains(&domain.trim().trim_end_matches('.').to_ascii_lowercase())))
}
async fn fetch_directory(client: &Client, directory_url: &str) -> anyhow::Result<AcmeDirectory> {
    client
        .get(directory_url)
        .send()
        .await
        .with_context(|| format!("request ACME directory {directory_url}"))?
        .error_for_status()
        .context("ACME directory request failed")?
        .json::<AcmeDirectory>()
        .await
        .context("decode ACME directory")
}
async fn authorize_order(
    acme: &AcmeClient,
    kid: &str,
    challenge: &AcmeChallengeConfig,
    authorization_urls: &[String],
) -> anyhow::Result<()> {
    let mut authorizations = Vec::with_capacity(authorization_urls.len());
    for authorization_url in authorization_urls {
        let authorization = acme.fetch_authorization(kid, authorization_url).await?;
        authorizations.push((authorization_url.clone(), authorization));
    }
    match challenge {
        AcmeChallengeConfig::Http01 { listen } => {
            authorize_http01(acme, kid, listen, &authorizations).await
        }
        AcmeChallengeConfig::Dns01(config) => {
            authorize_dns01(acme, kid, config, &authorizations).await
        }
    }
}
async fn authorize_http01(
    acme: &AcmeClient,
    kid: &str,
    listen: &str,
    authorizations: &[(String, AuthorizationBody)],
) -> anyhow::Result<()> {
    let mut responses = HashMap::new();
    let mut pending = Vec::new();
    for (authorization_url, authorization) in authorizations {
        if authorization.status == "valid" {
            continue;
        }
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == "http-01")
            .cloned()
            .with_context(|| {
                format!(
                    "ACME authorization for {} did not expose an http-01 challenge",
                    authorization.identifier.value
                )
            })?;
        responses.insert(
            challenge.token.clone(),
            build_key_authorization(&challenge.token, acme.jwk_thumbprint()),
        );
        pending.push(Http01PendingChallenge {
            authorization_url: authorization_url.clone(),
            challenge_url: challenge.url,
            challenge_status: challenge.status,
        });
    }
    if pending.is_empty() {
        return Ok(());
    }
    let server = Http01ChallengeServer::start(listen, responses).await?;
    let challenge_result = async {
        for pending_challenge in &pending {
            if pending_challenge.challenge_status != "valid" {
                acme.trigger_challenge(kid, &pending_challenge.challenge_url)
                    .await?;
            }
        }
        for pending_challenge in &pending {
            acme.poll_authorization_valid(kid, &pending_challenge.authorization_url)
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.stop();
    challenge_result
}
async fn authorize_dns01(
    acme: &AcmeClient,
    kid: &str,
    config: &Dns01Config,
    authorizations: &[(String, AuthorizationBody)],
) -> anyhow::Result<()> {
    let provider = DnsProvider::new(acme.client.clone(), config.provider.clone());
    let mut pending = Vec::new();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for (authorization_url, authorization) in authorizations {
        if authorization.status == "valid" {
            continue;
        }
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == "dns-01")
            .cloned()
            .with_context(|| {
                format!(
                    "ACME authorization for {} did not expose a dns-01 challenge",
                    authorization.identifier.value
                )
            })?;
        let record = DnsChallengeRecord {
            fqdn: build_dns01_record_name(&authorization.identifier.value),
            value: build_dns01_txt_value(&challenge.token, acme.jwk_thumbprint()),
        };
        if seen.insert((record.fqdn.to_ascii_lowercase(), record.value.clone())) {
            records.push(record.clone());
        }
        pending.push(Dns01PendingChallenge {
            authorization_url: authorization_url.clone(),
            challenge_url: challenge.url,
            challenge_status: challenge.status,
        });
    }
    if pending.is_empty() {
        return Ok(());
    }
    let mut handles = Vec::with_capacity(records.len());
    for record in &records {
        handles.push(provider.create_txt_record(record).await?);
    }
    let challenge_result = async {
        wait_for_dns_propagation(
            &records,
            config.propagation_timeout_secs,
            config.propagation_interval_secs,
        )
        .await?;
        for pending_challenge in &pending {
            if pending_challenge.challenge_status != "valid" {
                acme.trigger_challenge(kid, &pending_challenge.challenge_url)
                    .await?;
            }
        }
        for pending_challenge in &pending {
            acme.poll_authorization_valid(kid, &pending_challenge.authorization_url)
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup_result = cleanup_dns_records(&provider, handles).await;
    match challenge_result {
        Ok(()) => cleanup_result,
        Err(error) => {
            if let Err(cleanup_error) = cleanup_result {
                warn!(%cleanup_error, "cleanup ACME dns-01 records failed");
            }
            Err(error)
        }
    }
}
async fn cleanup_dns_records(
    provider: &DnsProvider,
    handles: Vec<DnsRecordHandle>,
) -> anyhow::Result<()> {
    for handle in handles {
        provider.delete_record(handle).await?;
    }
    Ok(())
}
async fn wait_for_dns_propagation(
    records: &[DnsChallengeRecord],
    timeout_secs: u64,
    interval_secs: u64,
) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let interval = Duration::from_secs(interval_secs.max(1));
    let started_at = tokio::time::Instant::now();
    loop {
        let mut missing = Vec::new();
        for record in records {
            if !txt_record_visible(record).await {
                missing.push(format!("{}={}", record.fqdn, record.value));
            }
        }
        if missing.is_empty() {
            return Ok(());
        }
        if started_at.elapsed() >= timeout {
            bail!(
                "timed out waiting for DNS propagation for {}",
                missing.join(", ")
            );
        }
        tokio::time::sleep(interval).await;
    }
}
async fn txt_record_visible(record: &DnsChallengeRecord) -> bool {
    for resolver in DNS_PROPAGATION_RESOLVERS {
        match lookup_txt_records(&record.fqdn, resolver).await {
            Ok(values) if values.iter().any(|value| value == &record.value) => return true,
            Ok(_) => {}
            Err(_) => {}
        }
    }
    false
}
struct AcmeClient {
    client: Client,
    directory: AcmeDirectory,
    account_key: SigningKey,
    jwk_header: Value,
    jwk_thumbprint: String,
}
#[derive(Debug, Deserialize, Clone)]
struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}
#[derive(Debug, Deserialize)]
struct OrderBody {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}
#[derive(Debug)]
struct OrderState {
    url: String,
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}
#[derive(Debug, Deserialize, Clone)]
struct AuthorizationBody {
    status: String,
    identifier: AuthorizationIdentifier,
    challenges: Vec<AuthorizationChallenge>,
}
#[derive(Debug, Deserialize, Clone)]
struct AuthorizationIdentifier {
    value: String,
}
#[derive(Debug, Deserialize, Clone)]
struct AuthorizationChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
    #[serde(default)]
    status: String,
}
#[derive(Debug)]
struct AccountHandle {
    kid: String,
}
impl AcmeClient {
    fn new(
        client: Client,
        directory: AcmeDirectory,
        account_key: SigningKey,
    ) -> anyhow::Result<Self> {
        let jwk_header = build_jwk(&account_key);
        let jwk_thumbprint = jwk_thumbprint(&account_key)?;
        Ok(Self {
            client,
            directory,
            account_key,
            jwk_header,
            jwk_thumbprint,
        })
    }
    fn jwk_thumbprint(&self) -> &str {
        &self.jwk_thumbprint
    }
    async fn ensure_account(&self, email: &str) -> anyhow::Result<AccountHandle> {
        let payload = if email.trim().is_empty() {
            json!({                "termsOfServiceAgreed": true,            })
        } else {
            json!({                "termsOfServiceAgreed": true,                "contact": [format!("mailto:{email}")],            })
        };
        let response = self
            .signed_request(&self.directory.new_account, None, Some(&payload))
            .await?;
        let location = header_value(response.headers(), LOCATION)
            .context("ACME account response did not include Location header")?;
        Ok(AccountHandle { kid: location })
    }
    async fn new_order(&self, kid: &str, domains: &[String]) -> anyhow::Result<OrderState> {
        let identifiers = domains            .iter()            .map(|domain| {                json!({                    "type": "dns",                    "value": domain,                })            })            .collect::<Vec<_>>();
        let payload = json!({            "identifiers": identifiers,        });
        let response = self
            .signed_request(&self.directory.new_order, Some(kid), Some(&payload))
            .await?;
        let location = header_value(response.headers(), LOCATION)
            .context("ACME order response did not include Location header")?;
        let body = response
            .json::<OrderBody>()
            .await
            .context("decode ACME order")?;
        Ok(OrderState::from_body(location, body))
    }
    async fn fetch_authorization(
        &self,
        kid: &str,
        authorization_url: &str,
    ) -> anyhow::Result<AuthorizationBody> {
        self.signed_request(authorization_url, Some(kid), None)
            .await?
            .json::<AuthorizationBody>()
            .await
            .context("decode ACME authorization")
    }
    async fn trigger_challenge(&self, kid: &str, challenge_url: &str) -> anyhow::Result<()> {
        let payload = json!({});
        self.signed_request(challenge_url, Some(kid), Some(&payload))
            .await?
            .error_for_status_ref()
            .context("submit ACME challenge response")?;
        Ok(())
    }
    async fn poll_authorization_valid(
        &self,
        kid: &str,
        authorization_url: &str,
    ) -> anyhow::Result<AuthorizationBody> {
        for _ in 0..MAX_POLL_ATTEMPTS {
            let response = self
                .signed_request(authorization_url, Some(kid), None)
                .await?;
            let delay = retry_after(response.headers());
            let authorization = response
                .json::<AuthorizationBody>()
                .await
                .context("decode ACME authorization poll")?;
            match authorization.status.as_str() {
                "valid" => return Ok(authorization),
                "pending" | "processing" => tokio::time::sleep(delay).await,
                "invalid" => {
                    bail!(
                        "ACME authorization became invalid for {}",
                        authorization.identifier.value
                    )
                }
                status => bail!("unexpected ACME authorization status {status}"),
            }
        }
        bail!("timed out while polling ACME authorization")
    }
    async fn finalize_order(
        &self,
        kid: &str,
        order_url: &str,
        finalize_url: &str,
        csr_der: &[u8],
    ) -> anyhow::Result<OrderState> {
        let payload = json!({            "csr": base64url(csr_der),        });
        self.signed_request(finalize_url, Some(kid), Some(&payload))
            .await?
            .error_for_status_ref()
            .context("submit ACME finalize request")?;
        self.poll_order_valid(kid, order_url).await
    }
    async fn poll_order_valid(&self, kid: &str, order_url: &str) -> anyhow::Result<OrderState> {
        for _ in 0..MAX_POLL_ATTEMPTS {
            let response = self.signed_request(order_url, Some(kid), None).await?;
            let delay = retry_after(response.headers());
            let body = response
                .json::<OrderBody>()
                .await
                .context("decode ACME order poll")?;
            let order = OrderState::from_body(order_url.to_string(), body);
            match order.status.as_str() {
                "valid" => return Ok(order),
                "pending" | "processing" | "ready" => tokio::time::sleep(delay).await,
                "invalid" => bail!("ACME order became invalid for {}", order.url),
                status => bail!("unexpected ACME order status {status}"),
            }
        }
        bail!("timed out while polling ACME order")
    }
    async fn download_certificate(
        &self,
        kid: &str,
        certificate_url: &str,
    ) -> anyhow::Result<String> {
        let response = self
            .signed_request(certificate_url, Some(kid), None)
            .await?;
        response
            .error_for_status_ref()
            .context("request ACME certificate chain")?;
        response.text().await.context("read ACME certificate chain")
    }
    async fn signed_request(
        &self,
        url: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> anyhow::Result<reqwest::Response> {
        for _ in 0..2 {
            let nonce = self.fetch_nonce().await?;
            let body = self.signed_payload(url, &nonce, kid, payload)?;
            let response = self
                .client
                .post(url)
                .header(CONTENT_TYPE, ACME_CONTENT_TYPE)
                .body(body)
                .send()
                .await
                .with_context(|| format!("send ACME POST to {url}"))?;
            if response.status().is_success() {
                return Ok(response);
            }
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if body.contains("badNonce") {
                continue;
            }
            bail!(
                "ACME request to {url} failed with {status}: {}",
                summarize_problem(&body)
            );
        }
        bail!("ACME request to {url} kept failing with badNonce")
    }
    async fn fetch_nonce(&self) -> anyhow::Result<String> {
        let response = self
            .client
            .head(&self.directory.new_nonce)
            .send()
            .await
            .with_context(|| format!("request ACME nonce {}", self.directory.new_nonce))?
            .error_for_status()
            .context("ACME nonce request failed")?;
        header_value(response.headers(), "Replay-Nonce")
            .context("ACME nonce response did not include Replay-Nonce header")
    }
    fn signed_payload(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> anyhow::Result<Vec<u8>> {
        let protected = if let Some(kid) = kid {
            json!({                "alg": ACME_JWS_ALGORITHM,                "kid": kid,                "nonce": nonce,                "url": url,            })
        } else {
            json!({                "alg": ACME_JWS_ALGORITHM,                "jwk": self.jwk_header,                "nonce": nonce,                "url": url,            })
        };
        let protected_b64 =
            base64url(&serde_json::to_vec(&protected).context("encode ACME protected header")?);
        let payload_b64 = match payload {
            Some(payload) => {
                base64url(&serde_json::to_vec(payload).context("encode ACME payload")?)
            }
            None => String::new(),
        };
        let signature_input = format!("{protected_b64}.{payload_b64}");
        let signature_b64 = sign_base64url(&self.account_key, signature_input.as_bytes())?;
        serde_json::to_vec(&json!({            "protected": protected_b64,            "payload": payload_b64,            "signature": signature_b64,        }))        .context("encode ACME JWS body")
    }
}
impl OrderState {
    fn from_body(url: String, body: OrderBody) -> Self {
        Self {
            url,
            status: body.status,
            authorizations: body.authorizations,
            finalize: body.finalize,
            certificate: body.certificate,
        }
    }
}
#[derive(Debug)]
struct Http01PendingChallenge {
    authorization_url: String,
    challenge_url: String,
    challenge_status: String,
}
#[derive(Debug, Clone)]
struct DnsChallengeRecord {
    fqdn: String,
    value: String,
}
#[derive(Debug)]
struct Dns01PendingChallenge {
    authorization_url: String,
    challenge_url: String,
    challenge_status: String,
}
fn build_dns01_record_name(identifier: &str) -> String {
    let domain = identifier
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("*.");
    format!("_acme-challenge.{domain}")
}
fn build_dns01_txt_value(token: &str, thumbprint: &str) -> String {
    let key_authorization = build_key_authorization(token, thumbprint);
    base64url(Sha256::digest(key_authorization.as_bytes()))
}
struct Http01ChallengeServer {
    handle: JoinHandle<()>,
}
impl Http01ChallengeServer {
    async fn start(listen: &str, responses: HashMap<String, String>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind ACME http-01 listener on {listen}"))?;
        let responses = Arc::new(
            responses
                .into_iter()
                .map(|(token, body)| (format!("/.well-known/acme-challenge/{token}"), body))
                .collect::<HashMap<_, _>>(),
        );
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let responses = responses.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_http_request(stream, responses).await {
                        tracing::debug!(%error, "serve ACME http-01 request failed");
                    }
                });
            }
        });
        Ok(Self { handle })
    }
    fn stop(self) {
        self.handle.abort();
    }
}
async fn serve_http_request(
    mut stream: tokio::net::TcpStream,
    responses: Arc<HashMap<String, String>>,
) -> anyhow::Result<()> {
    let request = tokio::time::timeout(HTTP_REQUEST_TIMEOUT, async {
        let mut buffer = Vec::with_capacity(1024);
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await.context("read HTTP request")?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n")
                || buffer.len() >= HTTP_BUFFER_SIZE
            {
                break;
            }
        }
        Ok::<_, anyhow::Error>(String::from_utf8_lossy(&buffer).into_owned())
    })
    .await
    .context("ACME HTTP-01 request timed out")??;
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1));
    let (status_line, body) = match path.and_then(|path| responses.get(path)) {
        Some(body) => ("HTTP/1.1 200 OK", body.as_str()),
        None => ("HTTP/1.1 404 Not Found", "not found"),
    };
    let response = format!(
        "{status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write HTTP challenge response")?;
    stream
        .flush()
        .await
        .context("flush HTTP challenge response")?;
    Ok(())
}
async fn load_or_create_account_key(path: &Path) -> anyhow::Result<SigningKey> {
    if let Ok(existing) = tokio::fs::read_to_string(path).await
        && let Ok(key) = parse_account_key(existing).await
    {
        return Ok(key);
    }
    let key = tokio::task::spawn_blocking(|| SigningKey::random(&mut OsRng))
        .await
        .context("join P-256 account key generation")?;
    write_account_key(path, &key).await?;
    Ok(key)
}
async fn parse_account_key(pem: String) -> anyhow::Result<SigningKey> {
    tokio::task::spawn_blocking(move || {
        SigningKey::from_pkcs8_pem(&pem).context("parse PKCS#8 P-256 account key")
    })
    .await
    .context("join P-256 account key parser")?
}
async fn write_account_key(path: &Path, key: &SigningKey) -> anyhow::Result<()> {
    let key = key.clone();
    let pem = tokio::task::spawn_blocking(move || {
        key.to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .context("encode PKCS#8 account key")
    })
    .await
    .context("join account key encoder")??;
    write_atomic(path, pem.as_bytes()).await
}
async fn load_or_create_domain_key(path: &Path) -> anyhow::Result<KeyPair> {
    if let Ok(existing) = tokio::fs::read_to_string(path).await
        && let Ok(key) = parse_domain_key(existing).await
    {
        return Ok(key);
    }
    let key = tokio::task::spawn_blocking(|| {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate P-256 domain key")
    })
    .await
    .context("join P-256 domain key generation")??;
    write_domain_key(path, &key).await?;
    Ok(key)
}
async fn parse_domain_key(pem: String) -> anyhow::Result<KeyPair> {
    tokio::task::spawn_blocking(move || KeyPair::from_pem(&pem).context("parse P-256 domain key"))
        .await
        .context("join P-256 domain key parser")?
}
async fn write_domain_key(path: &Path, key: &KeyPair) -> anyhow::Result<()> {
    let pem = key.serialize_pem();
    write_atomic(path, pem.as_bytes()).await
}
async fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let temp_path = temp_path(path);
    tokio::fs::write(&temp_path, bytes)
        .await
        .with_context(|| format!("write temporary file {}", temp_path.display()))?;
    if tokio::fs::metadata(path).await.is_ok() {
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("remove existing file {}", path.display()))?;
    }
    tokio::fs::rename(&temp_path, path)
        .await
        .with_context(|| format!("move {} to {}", temp_path.display(), path.display()))
}
fn temp_path(path: &Path) -> PathBuf {
    let suffix = format!("{}.tmp", unix_now());
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(extension) if !extension.is_empty() => {
            path.with_extension(format!("{extension}.{suffix}"))
        }
        _ => path.with_extension(suffix),
    }
}
fn build_key_authorization(token: &str, thumbprint: &str) -> String {
    format!("{token}.{thumbprint}")
}
fn build_jwk(key: &SigningKey) -> Value {
    let public_key = key.verifying_key().to_encoded_point(false);
    let x = public_key.x().expect("uncompressed P-256 point has x");
    let y = public_key.y().expect("uncompressed P-256 point has y");
    json!({        "crv": "P-256",        "kty": "EC",        "x": base64url(x),        "y": base64url(y),    })
}
fn jwk_thumbprint(key: &SigningKey) -> anyhow::Result<String> {
    let public_key = key.verifying_key().to_encoded_point(false);
    let x = public_key.x().expect("uncompressed P-256 point has x");
    let y = public_key.y().expect("uncompressed P-256 point has y");
    let jwk = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        base64url(x),
        base64url(y),
    );
    Ok(base64url(Sha256::digest(jwk.as_bytes())))
}
fn sign_base64url(key: &SigningKey, message: &[u8]) -> anyhow::Result<String> {
    let signature: p256::ecdsa::Signature = key.sign(message);
    Ok(base64url(signature.to_bytes()))
}
fn build_certificate_signing_request(
    private_key: &KeyPair,
    domains: &[String],
) -> anyhow::Result<Vec<u8>> {
    let domains = normalize_domains(domains);
    ensure!(!domains.is_empty(), "ACME CSR domains must not be empty");
    let mut params =
        CertificateParams::new(domains.clone()).context("build ACME certificate parameters")?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, &domains[0]);
    params.distinguished_name = distinguished_name;
    let csr = params
        .serialize_request(private_key)
        .context("serialize P-256 certificate signing request")?;
    Ok(csr.der().as_ref().to_vec())
}
fn normalize_domains(domains: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for domain in domains {
        let domain = domain.trim().trim_end_matches('.');
        if domain.is_empty() {
            continue;
        }
        let key = domain.to_ascii_lowercase();
        if seen.insert(key) {
            normalized.push(domain.to_string());
        }
    }
    normalized
}
fn first_certificate_not_after(cert_pem: &[u8]) -> anyhow::Result<u64> {
    let certificate = CertificateDer::pem_slice_iter(cert_pem)
        .next()
        .transpose()
        .context("parse certificate PEM")?
        .context("certificate PEM did not include any certificates")?;
    parse_certificate_not_after(certificate.as_ref())
}
fn parse_certificate_not_after(certificate_der: &[u8]) -> anyhow::Result<u64> {
    let mut certificate = DerReader::new(certificate_der);
    let cert_sequence = certificate.read_tag(0x30)?;
    ensure!(certificate.is_empty(), "trailing bytes after certificate");
    let mut cert_fields = DerReader::new(cert_sequence);
    let tbs_certificate = cert_fields.read_tag(0x30)?;
    let mut tbs = DerReader::new(tbs_certificate);
    if tbs.peek_tag() == Some(0xa0) {
        let _ = tbs.read_tag(0xa0)?;
    }
    let _ = tbs.read_tag(0x02)?;
    let _ = tbs.read_tag(0x30)?;
    let _ = tbs.read_tag(0x30)?;
    let validity = tbs.read_tag(0x30)?;
    let mut validity_fields = DerReader::new(validity);
    let _ = validity_fields.read_any()?;
    let not_after = validity_fields.read_any()?;
    parse_der_time(not_after.tag, not_after.content)
}
fn parse_der_time(tag: u8, bytes: &[u8]) -> anyhow::Result<u64> {
    let text = std::str::from_utf8(bytes).context("decode certificate time")?;
    match tag {
        0x17 => parse_time_string(text, false),
        0x18 => parse_time_string(text, true),
        _ => bail!("unsupported certificate time tag {tag:#x}"),
    }
}
fn parse_time_string(text: &str, generalized: bool) -> anyhow::Result<u64> {
    ensure!(text.ends_with('Z'), "certificate time must end with Z");
    let body = &text[..text.len() - 1];
    let (year, rest) = if generalized {
        ensure!(body.len() == 14, "invalid GeneralizedTime length");
        (body[0..4].parse::<i32>()?, &body[4..])
    } else {
        ensure!(body.len() == 12, "invalid UTCTime length");
        let short_year = body[0..2].parse::<i32>()?;
        let full_year = if short_year >= 50 {
            1900 + short_year
        } else {
            2000 + short_year
        };
        (full_year, &body[2..])
    };
    let month = rest[0..2].parse::<u32>()?;
    let day = rest[2..4].parse::<u32>()?;
    let hour = rest[4..6].parse::<u32>()?;
    let minute = rest[6..8].parse::<u32>()?;
    let second = rest[8..10].parse::<u32>()?;
    unix_timestamp(year, month, day, hour, minute, second)
}
fn unix_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> anyhow::Result<u64> {
    ensure!((1..=12).contains(&month), "invalid month {month}");
    ensure!((1..=31).contains(&day), "invalid day {day}");
    ensure!(hour < 24, "invalid hour {hour}");
    ensure!(minute < 60, "invalid minute {minute}");
    ensure!(second < 60, "invalid second {second}");
    let days = days_from_civil(year, month as i32, day as i32);
    let epoch_days = days_from_civil(1970, 1, 1);
    let seconds = (days - epoch_days) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second);
    ensure!(seconds >= 0, "certificate time predates UNIX epoch");
    Ok(seconds as u64)
}
fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era * 146097 + doe)
}
fn header_value(
    headers: &reqwest::header::HeaderMap,
    name: impl reqwest::header::AsHeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}
fn retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
}
fn summarize_problem(body: &str) -> String {
    #[derive(Deserialize)]
    struct ProblemBody {
        #[serde(rename = "type")]
        typ: Option<String>,
        detail: Option<String>,
    }
    serde_json::from_str::<ProblemBody>(body)
        .ok()
        .map(|problem| match (problem.typ, problem.detail) {
            (Some(typ), Some(detail)) => format!("{typ}: {detail}"),
            (Some(typ), None) => typ,
            (None, Some(detail)) => detail,
            (None, None) => body.to_string(),
        })
        .unwrap_or_else(|| body.to_string())
}
fn base64url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
struct DerReader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }
    fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
    fn read_tag(&mut self, expected_tag: u8) -> anyhow::Result<&'a [u8]> {
        let element = self.read_any()?;
        ensure!(
            element.tag == expected_tag,
            "expected DER tag {expected_tag:#x}, got {:#x}",
            element.tag
        );
        Ok(element.content)
    }
    fn read_any(&mut self) -> anyhow::Result<DerElement<'a>> {
        let tag = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| anyhow!("unexpected end of DER input"))?;
        self.position += 1;
        let length = self.read_length()?;
        let end = self.position + length;
        ensure!(end <= self.bytes.len(), "DER length exceeds input");
        let content = &self.bytes[self.position..end];
        self.position = end;
        Ok(DerElement { tag, content })
    }
    fn read_length(&mut self) -> anyhow::Result<usize> {
        let first = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| anyhow!("unexpected end of DER length"))?;
        self.position += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        ensure!(
            count > 0 && count <= 8,
            "unsupported DER length size {count}"
        );
        ensure!(
            self.position + count <= self.bytes.len(),
            "truncated DER length"
        );
        let mut length = 0usize;
        for byte in &self.bytes[self.position..self.position + count] {
            length = (length << 8) | (*byte as usize);
        }
        self.position += count;
        Ok(length)
    }
}
struct DerElement<'a> {
    tag: u8,
    content: &'a [u8],
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tokio::net::{TcpListener, TcpStream};
    #[test]
    fn builds_key_authorization() {
        assert_eq!(build_key_authorization("token", "thumb"), "token.thumb");
    }
    #[test]
    fn builds_dns01_record_name_and_value() {
        assert_eq!(
            build_dns01_record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert!(!build_dns01_txt_value("token", "thumb").is_empty());
    }
    #[test]
    fn parses_utc_time() {
        assert_eq!(parse_der_time(0x17, b"260308000000Z").unwrap(), 1772928000);
    }
    #[test]
    fn parses_generalized_time() {
        assert_eq!(
            parse_der_time(0x18, b"20260308000000Z").unwrap(),
            1772928000
        );
    }
    #[test]
    fn zone_candidates_skip_acme_label() {
        assert_eq!(
            zone_candidates_from_name("_acme-challenge.foo.example.com"),
            vec!["foo.example.com".to_string(), "example.com".to_string()]
        );
    }
    #[test]
    fn relative_record_name_strips_zone() {
        assert_eq!(
            relative_record_name("_acme-challenge.example.com", "example.com").unwrap(),
            "_acme-challenge"
        );
    }
    #[test]
    fn acme_jws_header_uses_es256_for_p256_account_keys() {
        let account_key = SigningKey::random(&mut OsRng);
        let client = AcmeClient::new(
            Client::new(),
            AcmeDirectory {
                new_nonce: "https://example.invalid/new-nonce".to_string(),
                new_account: "https://example.invalid/new-account".to_string(),
                new_order: "https://example.invalid/new-order".to_string(),
            },
            account_key,
        )
        .unwrap();
        let signed = client
            .signed_payload(
                "https://example.invalid/new-account",
                "nonce-1",
                None,
                Some(&json!({ "termsOfServiceAgreed": true })),
            )
            .unwrap();
        let envelope: Value = serde_json::from_slice(&signed).unwrap();
        let protected = envelope["protected"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(protected).unwrap();
        let header: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(header["alg"], ACME_JWS_ALGORITHM);
        assert_eq!(header["nonce"], "nonce-1");
        assert_eq!(header["url"], "https://example.invalid/new-account");
        assert!(header.get("jwk").is_some());
    }
    #[tokio::test]
    async fn serves_http01_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let server = Http01ChallengeServer::start(
            &address.to_string(),
            HashMap::from([("abc".to_string(), "abc.thumb".to_string())]),
        )
        .await
        .unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        server.stop();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("abc.thumb"));
    }
}
