use anyhow::Context;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::path::PathBuf;

use crate::acme;

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
    Files { key_path: PathBuf },
    Inline { key: Vec<u8> },
}

pub(crate) async fn load_source_materials(
    source: &TlsMaterialSource,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
