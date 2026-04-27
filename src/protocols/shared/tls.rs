use anyhow::{Context, ensure};
use base64::Engine as _;
use boring::hpke::HpkeKey;
use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslEchKeys, SslMethod, SslOptions, SslVersion};
use boring::x509::X509;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

use crate::acme;

pub use super::reality::RealityTlsConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMaterialSource {
    Files {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    Inline {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
    SelfSigned {
        subject_alt_names: Vec<String>,
    },
    Acme {
        cert_path: PathBuf,
        key_path: PathBuf,
        config: acme::AcmeConfig,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchConfigSource {
    Files {
        key_path: PathBuf,
        config_path: Option<PathBuf>,
    },
    Inline {
        key: Vec<u8>,
        config: Option<Vec<u8>>,
    },
}

#[derive(Clone)]
pub struct LoadedTlsMaterials {
    source: TlsMaterialSource,
    ech_source: Option<EchConfigSource>,
    reality: Option<RealityTlsConfig>,
    alpn_protocols: Vec<String>,
    cert_digest: [u8; 32],
    key_digest: [u8; 32],
    ech_key_digest: Option<[u8; 32]>,
    ech_config_digest: Option<[u8; 32]>,
    acceptor: Arc<SslAcceptor>,
}

impl LoadedTlsMaterials {
    pub fn acceptor(&self) -> Arc<SslAcceptor> {
        self.acceptor.clone()
    }

    pub fn matches_source(
        &self,
        source: &TlsMaterialSource,
        ech_source: Option<&EchConfigSource>,
        reality: Option<&RealityTlsConfig>,
        alpn_protocols: &[String],
    ) -> bool {
        self.source == *source
            && self.ech_source.as_ref() == ech_source
            && self.reality.as_ref() == reality
            && self.alpn_protocols == alpn_protocols
    }
}

pub async fn load_tls_materials(
    source: &TlsMaterialSource,
    ech_source: Option<&EchConfigSource>,
    reality: Option<&RealityTlsConfig>,
    alpn_protocols: &[String],
) -> anyhow::Result<LoadedTlsMaterials> {
    let source = source.clone();
    let ech_source = ech_source.cloned();
    let reality = reality.cloned();
    let alpn_protocols = alpn_protocols.to_vec();
    let (cert_pem, key_pem) = if reality.is_some() {
        (Vec::new(), Vec::new())
    } else {
        load_source_materials(&source).await?
    };
    let ech_materials = match ech_source.as_ref() {
        Some(ech_source) => Some(load_ech_source_materials(ech_source).await?),
        None => None,
    };
    let acceptor = build_acceptor(
        cert_pem.clone(),
        key_pem.clone(),
        ech_materials.as_ref(),
        reality.as_ref(),
        &alpn_protocols,
    )
    .await?;
    Ok(LoadedTlsMaterials {
        source,
        ech_source,
        reality,
        alpn_protocols,
        cert_digest: digest(&cert_pem),
        key_digest: digest(&key_pem),
        ech_key_digest: ech_materials.as_ref().map(|(key, _)| digest(key)),
        ech_config_digest: ech_materials
            .as_ref()
            .and_then(|(_, config)| config.as_ref().map(|config| digest(config))),
        acceptor,
    })
}

pub async fn reload_if_changed(
    materials: &mut LoadedTlsMaterials,
) -> anyhow::Result<Option<Arc<SslAcceptor>>> {
    if !is_reloadable_tls_source(&materials.source)
        && !matches!(materials.ech_source, Some(EchConfigSource::Files { .. }))
    {
        return Ok(None);
    }

    let (cert_pem, key_pem) = if materials.reality.is_some() {
        (Vec::new(), Vec::new())
    } else {
        load_source_materials(&materials.source).await?
    };
    let ech_materials = match materials.ech_source.as_ref() {
        Some(ech_source) => Some(load_ech_source_materials(ech_source).await?),
        None => None,
    };

    let cert_digest = digest(&cert_pem);
    let key_digest = digest(&key_pem);
    let ech_key_digest = ech_materials.as_ref().map(|(key, _)| digest(key));
    let ech_config_digest = ech_materials
        .as_ref()
        .and_then(|(_, config)| config.as_ref().map(|config| digest(config)));

    if cert_digest == materials.cert_digest
        && key_digest == materials.key_digest
        && ech_key_digest == materials.ech_key_digest
        && ech_config_digest == materials.ech_config_digest
    {
        return Ok(None);
    }

    let acceptor = build_acceptor(
        cert_pem,
        key_pem,
        ech_materials.as_ref(),
        materials.reality.as_ref(),
        &materials.alpn_protocols,
    )
    .await?;
    materials.cert_digest = cert_digest;
    materials.key_digest = key_digest;
    materials.ech_key_digest = ech_key_digest;
    materials.ech_config_digest = ech_config_digest;
    materials.acceptor = acceptor.clone();
    Ok(Some(acceptor))
}

fn is_reloadable_tls_source(source: &TlsMaterialSource) -> bool {
    !matches!(
        source,
        TlsMaterialSource::Inline { .. } | TlsMaterialSource::SelfSigned { .. }
    )
}

async fn load_source_materials(source: &TlsMaterialSource) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    match source {
        TlsMaterialSource::Files {
            cert_path,
            key_path,
        } => {
            let cert_pem = tokio::fs::read(cert_path)
                .await
                .with_context(|| format!("read certificate PEM {}", cert_path.display()))?;
            let key_pem = tokio::fs::read(key_path)
                .await
                .with_context(|| format!("read private key PEM {}", key_path.display()))?;
            Ok((cert_pem, key_pem))
        }
        TlsMaterialSource::Inline { cert_pem, key_pem } => Ok((cert_pem.clone(), key_pem.clone())),
        TlsMaterialSource::SelfSigned { subject_alt_names } => {
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(subject_alt_names.clone())
                    .context("generate self-signed certificate")?;
            Ok((
                cert.pem().into_bytes(),
                signing_key.serialize_pem().into_bytes(),
            ))
        }
        TlsMaterialSource::Acme {
            cert_path,
            key_path,
            config,
        } => {
            acme::ensure_certificate(config, cert_path, key_path)
                .await
                .context("ensure ACME certificate")?;
            let cert_pem = tokio::fs::read(cert_path)
                .await
                .with_context(|| format!("read ACME certificate PEM {}", cert_path.display()))?;
            let key_pem = tokio::fs::read(key_path)
                .await
                .with_context(|| format!("read ACME private key PEM {}", key_path.display()))?;
            Ok((cert_pem, key_pem))
        }
    }
}

async fn load_ech_source_materials(
    source: &EchConfigSource,
) -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
    match source {
        EchConfigSource::Files {
            key_path,
            config_path,
        } => {
            let key = tokio::fs::read(key_path)
                .await
                .with_context(|| format!("read ECH key {}", key_path.display()))?;
            let config = match config_path {
                Some(config_path) => Some(
                    tokio::fs::read(config_path)
                        .await
                        .with_context(|| format!("read ECH config {}", config_path.display()))?,
                ),
                None => None,
            };
            Ok((key, config))
        }
        EchConfigSource::Inline { key, config } => Ok((key.clone(), config.clone())),
    }
}

async fn build_acceptor(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    ech_materials: Option<&(Vec<u8>, Option<Vec<u8>>)>,
    reality: Option<&RealityTlsConfig>,
    alpn_protocols: &[String],
) -> anyhow::Result<Arc<SslAcceptor>> {
    let ech_materials = ech_materials.cloned();
    let reality = reality.cloned();
    let alpn_wire = encode_alpn_protocols(alpn_protocols)?;
    tokio::task::spawn_blocking(move || -> anyhow::Result<Arc<SslAcceptor>> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .context("build BoringSSL acceptor")?;

        if reality.is_some() {
            builder.set_options(SslOptions::NO_TICKET);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .context("set REALITY minimum TLS version")?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .context("set REALITY maximum TLS version")?;
            builder
                .set_sigalgs_list("ed25519")
                .context("set REALITY signature algorithms")?;
        } else {
            let mut certs = X509::stack_from_pem(&cert_pem).context("read certificate PEM")?;
            ensure!(
                !certs.is_empty(),
                "certificate PEM did not contain any certificates"
            );
            let leaf = certs.remove(0);
            builder
                .set_certificate(&leaf)
                .context("set leaf certificate")?;
            for cert in certs {
                builder
                    .add_extra_chain_cert(cert)
                    .context("add extra chain certificate")?;
            }

            let key = PKey::private_key_from_pem(&key_pem).context("read private key PEM")?;
            builder.set_private_key(&key).context("set private key")?;
            builder.check_private_key().context("check private key")?;
        }

        if let Some((ech_key, ech_config)) = ech_materials.as_ref() {
            let ech_keys =
                build_ech_keys(ech_key, ech_config.as_deref()).context("build ECH keys")?;
            builder.set_ech_keys(&ech_keys).context("set ECH keys")?;
        }

        if reality.is_none() && !alpn_wire.is_empty() {
            builder
                .set_alpn_protos(&alpn_wire)
                .context("set ALPN protocols")?;
            let server_protocols = alpn_wire.clone();
            builder.set_alpn_select_callback(move |_, client| {
                let mut server_pos = 0;
                while server_pos < server_protocols.len() {
                    let server_len = server_protocols[server_pos] as usize;
                    let server_start = server_pos + 1;
                    let server_end = server_start + server_len;
                    let server_protocol = &server_protocols[server_start..server_end];

                    let mut client_pos = 0;
                    while client_pos < client.len() {
                        let client_len = client[client_pos] as usize;
                        let client_start = client_pos + 1;
                        let client_end = client_start + client_len;
                        if client_end > client.len() {
                            return Err(AlpnError::NOACK);
                        }
                        if &client[client_start..client_end] == server_protocol {
                            return Ok(&client[client_start..client_end]);
                        }
                        client_pos = client_end;
                    }

                    server_pos = server_end;
                }
                Err(AlpnError::NOACK)
            });
        }

        Ok(Arc::new(builder.build()))
    })
    .await
    .context("join BoringSSL builder")?
}

pub(crate) fn encode_alpn_protocols(protocols: &[String]) -> anyhow::Result<Vec<u8>> {
    let protocols = parse_alpn_protocols(protocols)?;
    let mut encoded = Vec::new();
    for protocol in protocols {
        encoded.push(protocol.len() as u8);
        encoded.extend_from_slice(&protocol);
    }
    Ok(encoded)
}

pub(crate) fn parse_alpn_protocols(protocols: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut parsed = Vec::with_capacity(protocols.len());
    for protocol in protocols {
        let protocol = protocol.trim();
        ensure!(
            !protocol.is_empty(),
            "ALPN protocols cannot contain empty values"
        );
        ensure!(
            protocol.is_ascii(),
            "ALPN protocol {protocol:?} must be ASCII"
        );
        ensure!(
            protocol.len() <= u8::MAX as usize,
            "ALPN protocol {protocol:?} is too long"
        );
        parsed.push(protocol.as_bytes().to_vec());
    }
    Ok(parsed)
}

fn build_ech_keys(
    key_material: &[u8],
    config_material: Option<&[u8]>,
) -> anyhow::Result<SslEchKeys> {
    let decoded_key = decode_pem_or_raw(key_material, "ECH KEYS").context("decode ECH key")?;
    let embedded = parse_xboard_ech_key_payload(&decoded_key).ok();
    let private_key = match embedded.as_ref() {
        Some((private_key, _)) => private_key.clone(),
        None => parse_raw_ech_private_key(&decoded_key)?,
    };
    let configs = match config_material {
        Some(config_material) => {
            let decoded_config =
                decode_pem_or_raw(config_material, "ECH CONFIGS").context("decode ECH config")?;
            parse_ech_configs(&decoded_config)?
        }
        None => match embedded {
            Some((_, config)) => vec![config],
            None => {
                anyhow::bail!("ECH config is required when key does not contain embedded config")
            }
        },
    };

    let mut builder = SslEchKeys::builder().context("allocate ECH keys")?;
    for config in configs {
        let hpke_key =
            HpkeKey::dhkem_p256_sha256(&private_key).context("initialize ECH HPKE key")?;
        builder
            .add_key(true, &config, hpke_key)
            .context("register ECH retry config")?;
    }
    Ok(builder.build())
}

fn parse_raw_ech_private_key(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    if bytes.len() == 32 {
        Ok(bytes.to_vec())
    } else {
        anyhow::bail!("ECH private key must be 32 bytes or an Xboard ECH KEYS payload")
    }
}

fn parse_xboard_ech_key_payload(bytes: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let key_len = read_be_u16(bytes, 0, "ECH key length")? as usize;
    let key_start = 2;
    let key_end = key_start + key_len;
    ensure!(key_end + 2 <= bytes.len(), "truncated ECH key payload");
    let config_len = read_be_u16(bytes, key_end, "ECH config length")? as usize;
    let config_start = key_end + 2;
    let config_end = config_start + config_len;
    ensure!(config_end == bytes.len(), "invalid ECH key payload length");
    Ok((
        bytes[key_start..key_end].to_vec(),
        bytes[config_start..config_end].to_vec(),
    ))
}

fn parse_ech_configs(bytes: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    if bytes.len() >= 4 && bytes[0] == 0xfe && bytes[1] == 0x0d {
        let content_len = read_be_u16(bytes, 2, "ECH config content length")? as usize;
        ensure!(
            bytes.len() == content_len + 4,
            "ECH config length does not match payload"
        );
        return Ok(vec![bytes.to_vec()]);
    }

    let total_len = read_be_u16(bytes, 0, "ECH config list length")? as usize;
    ensure!(
        bytes.len() == total_len + 2,
        "ECH config list length does not match payload"
    );

    let mut configs = Vec::new();
    let mut offset = 2;
    while offset < bytes.len() {
        ensure!(offset + 4 <= bytes.len(), "truncated ECH config entry");
        let content_len = read_be_u16(bytes, offset + 2, "ECH config content length")? as usize;
        let end = offset + content_len + 4;
        ensure!(end <= bytes.len(), "truncated ECH config entry body");
        configs.push(bytes[offset..end].to_vec());
        offset = end;
    }
    ensure!(!configs.is_empty(), "ECH config list is empty");
    Ok(configs)
}

fn decode_pem_or_raw(raw: &[u8], label: &str) -> anyhow::Result<Vec<u8>> {
    let raw = trim_ascii_whitespace(raw);
    ensure!(!raw.is_empty(), "empty {label} payload");

    if raw.starts_with(b"-----BEGIN ") {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let text =
            std::str::from_utf8(raw).with_context(|| format!("parse {label} PEM as UTF-8"))?;
        let start = text
            .find(&begin)
            .with_context(|| format!("missing {begin}"))?
            + begin.len();
        let body = &text[start..];
        let end_at = body.find(&end).with_context(|| format!("missing {end}"))?;
        let compact = body[..end_at]
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>();
        return base64::engine::general_purpose::STANDARD
            .decode(compact)
            .with_context(|| format!("decode {label} PEM base64"));
    }

    let compact = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.len() % 4 == 0
        && compact.iter().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='
            )
        })
    {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&compact) {
            return Ok(decoded);
        }
    }
    Ok(compact)
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn read_be_u16(bytes: &[u8], offset: usize, label: &str) -> anyhow::Result<u16> {
    ensure!(offset + 2 <= bytes.len(), "truncated {label}");
    Ok(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::pkey::Id;

    fn build_xboard_ech_payloads(public_name: &str) -> (Vec<u8>, Vec<u8>) {
        let key = PKey::generate(Id::X25519).expect("generate X25519");
        let mut private_key = vec![0; key.raw_private_key_len().expect("private key length")];
        let private_key = key
            .raw_private_key(&mut private_key)
            .expect("private key bytes")
            .to_vec();
        let mut public_key = vec![0; key.raw_public_key_len().expect("public key length")];
        let public_key = key
            .raw_public_key(&mut public_key)
            .expect("public key bytes")
            .to_vec();

        let mut contents = Vec::new();
        contents.push(7);
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        contents.extend_from_slice(&8u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0003u16.to_be_bytes());
        contents.push(0);
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut ech_config = Vec::new();
        ech_config.extend_from_slice(&0xfe0du16.to_be_bytes());
        ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        ech_config.extend_from_slice(&contents);

        let mut ech_config_list = Vec::new();
        ech_config_list.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
        ech_config_list.extend_from_slice(&ech_config);

        let mut ech_keys = Vec::new();
        ech_keys.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
        ech_keys.extend_from_slice(&private_key);
        ech_keys.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
        ech_keys.extend_from_slice(&ech_config);

        (
            pem_block("ECH KEYS", &ech_keys),
            pem_block("ECH CONFIGS", &ech_config_list),
        )
    }

    fn pem_block(label: &str, bytes: &[u8]) -> Vec<u8> {
        let mut pem = format!("-----BEGIN {label}-----\n").into_bytes();
        for chunk in base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .as_bytes()
            .chunks(64)
        {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(format!("-----END {label}-----").as_bytes());
        pem
    }

    #[test]
    fn digest_changes_with_content() {
        assert_ne!(digest(b"a"), digest(b"b"));
    }

    #[test]
    fn parses_xboard_ech_key_payload() {
        let (key_pem, _) = build_xboard_ech_payloads("ech.example.com");
        let decoded = decode_pem_or_raw(&key_pem, "ECH KEYS").expect("decode key");
        let (private_key, config) = parse_xboard_ech_key_payload(&decoded).expect("parse payload");
        assert_eq!(private_key.len(), 32);
        assert!(config.starts_with(&0xfe0du16.to_be_bytes()));
    }

    #[tokio::test]
    async fn loads_self_signed_materials() {
        let (cert_pem, key_pem) = load_source_materials(&TlsMaterialSource::SelfSigned {
            subject_alt_names: vec!["node.example.com".to_string()],
        })
        .await
        .expect("self-signed materials");

        let cert_pem = String::from_utf8(cert_pem).expect("certificate utf8");
        let key_pem = String::from_utf8(key_pem).expect("private key utf8");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn self_signed_materials_do_not_reload() {
        let mut materials = load_tls_materials(
            &TlsMaterialSource::SelfSigned {
                subject_alt_names: vec!["node.example.com".to_string()],
            },
            None,
            None,
            &[],
        )
        .await
        .expect("self-signed materials");

        assert!(
            reload_if_changed(&mut materials)
                .await
                .expect("reload")
                .is_none()
        );
    }

    #[tokio::test]
    async fn reality_materials_track_alpn_when_matching_source() {
        let reality = RealityTlsConfig {
            server_name: "reality.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: [7; 32],
            short_ids: vec![[0; 8]],
        };
        let materials = load_tls_materials(
            &TlsMaterialSource::SelfSigned {
                subject_alt_names: vec!["node.example.com".to_string()],
            },
            None,
            Some(&reality),
            &["h2".to_string()],
        )
        .await
        .expect("reality materials");

        let other_alpn = vec!["http/1.1".to_string()];
        assert!(!materials.matches_source(
            &TlsMaterialSource::SelfSigned {
                subject_alt_names: vec!["node.example.com".to_string()],
            },
            None,
            Some(&reality),
            &other_alpn,
        ));
    }

    #[tokio::test]
    async fn loads_xboard_ech_from_embedded_key_payload() {
        let (ech_key, _) = build_xboard_ech_payloads("ech.example.com");
        let materials = load_tls_materials(
            &TlsMaterialSource::SelfSigned {
                subject_alt_names: vec!["node.example.com".to_string()],
            },
            Some(&EchConfigSource::Inline {
                key: ech_key,
                config: None,
            }),
            None,
            &[],
        )
        .await
        .expect("load ECH");

        let _ = materials.acceptor();
    }

    #[tokio::test]
    async fn loads_xboard_ech_from_separate_config_payload() {
        let (ech_key, ech_config) = build_xboard_ech_payloads("ech.example.com");
        let materials = load_tls_materials(
            &TlsMaterialSource::SelfSigned {
                subject_alt_names: vec!["node.example.com".to_string()],
            },
            Some(&EchConfigSource::Inline {
                key: ech_key,
                config: Some(ech_config),
            }),
            None,
            &[],
        )
        .await
        .expect("load ECH");

        let _ = materials.acceptor();
    }

    #[test]
    fn encodes_alpn_protocols_in_wire_format() {
        let encoded = encode_alpn_protocols(&["h2".to_string(), "http/1.1".to_string()])
            .expect("encode alpn");
        assert_eq!(encoded, b"\x02h2\x08http/1.1");
    }

    #[test]
    fn rejects_empty_alpn_protocol_values() {
        let error = encode_alpn_protocols(&[String::new()]).expect_err("empty alpn");
        assert!(error.to_string().contains("empty values"));
    }
}
