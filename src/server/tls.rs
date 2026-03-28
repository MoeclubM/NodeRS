use anyhow::{Context, ensure};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct LoadedTlsMaterials {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_digest: [u8; 32],
    key_digest: [u8; 32],
    server_config: Arc<ServerConfig>,
}

impl LoadedTlsMaterials {
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }
}

pub async fn load_tls_materials(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<LoadedTlsMaterials> {
    let cert_path = cert_path.to_path_buf();
    let key_path = key_path.to_path_buf();
    let cert_pem = tokio::fs::read(&cert_path)
        .await
        .with_context(|| format!("read certificate PEM {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(&key_path)
        .await
        .with_context(|| format!("read private key PEM {}", key_path.display()))?;
    let server_config = parse_server_config(cert_pem.clone(), key_pem.clone()).await?;
    Ok(LoadedTlsMaterials {
        cert_path,
        key_path,
        cert_digest: digest(&cert_pem),
        key_digest: digest(&key_pem),
        server_config,
    })
}

pub async fn reload_if_changed(
    materials: &mut LoadedTlsMaterials,
) -> anyhow::Result<Option<Arc<ServerConfig>>> {
    let cert_pem = tokio::fs::read(&materials.cert_path)
        .await
        .with_context(|| format!("read certificate PEM {}", materials.cert_path.display()))?;
    let key_pem = tokio::fs::read(&materials.key_path)
        .await
        .with_context(|| format!("read private key PEM {}", materials.key_path.display()))?;
    let cert_digest = digest(&cert_pem);
    let key_digest = digest(&key_pem);
    if cert_digest == materials.cert_digest && key_digest == materials.key_digest {
        return Ok(None);
    }
    let server_config = parse_server_config(cert_pem, key_pem).await?;
    materials.cert_digest = cert_digest;
    materials.key_digest = key_digest;
    materials.server_config = server_config.clone();
    Ok(Some(server_config))
}

async fn parse_server_config(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
) -> anyhow::Result<Arc<ServerConfig>> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Arc<ServerConfig>> {
        let certs = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .context("read certificate PEM")?;
        ensure!(
            !certs.is_empty(),
            "certificate PEM did not contain any certificates"
        );
        let key = PrivateKeyDer::from_pem_slice(&key_pem).context("read private key PEM")?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("build rustls server config")?;
        Ok(Arc::new(config))
    })
    .await
    .context("join PEM loader")?
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_changes_with_content() {
        assert_ne!(digest(b"a"), digest(b"b"));
    }
}
