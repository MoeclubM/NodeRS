use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};

use crate::panel::PanelUser;

use super::super::crypto::Aead2022Method;

pub(crate) fn decode_server_psk(value: &str, method: Aead2022Method) -> anyhow::Result<Vec<u8>> {
    decode_psk(value, method.key_len())
}

pub(crate) fn derive_user_psk(user: &PanelUser, method: Aead2022Method) -> anyhow::Result<Vec<u8>> {
    let key_len = method.key_len();
    let password = user.password.trim();
    if !password.is_empty() {
        return decode_psk(password, key_len)
            .with_context(|| format!("decode Shadowsocks 2022 user {} key", user.id));
    }

    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return decode_psk(uuid, key_len)
            .with_context(|| format!("decode Shadowsocks 2022 user {} key", user.id));
    }

    bail!("Shadowsocks 2022 user {} is missing password/uuid", user.id)
}

pub(crate) fn identity_hash(psk: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(psk);
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&hash.as_bytes()[..16]);
    truncated
}

fn decode_psk(value: &str, key_len: usize) -> anyhow::Result<Vec<u8>> {
    let value = value.trim();
    ensure!(!value.is_empty(), "Shadowsocks 2022 key is required");
    let decoded = STANDARD
        .decode(value)
        .context("decode Shadowsocks 2022 key")?;
    normalize_psk(&decoded, key_len)
}

fn normalize_psk(value: &[u8], key_len: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(
        value.len() >= key_len,
        "Shadowsocks 2022 key is shorter than {key_len} bytes"
    );
    if value.len() == key_len {
        return Ok(value.to_vec());
    }
    let mut hasher = Sha256::new();
    hasher.update(value);
    let digest = hasher.finalize();
    Ok(digest[..key_len].to_vec())
}
