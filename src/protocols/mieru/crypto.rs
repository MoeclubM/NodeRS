use anyhow::{Context, anyhow, ensure};
use boring::aead::{AeadCtx, Algorithm};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
pub const REPLAY_WINDOW: Duration = Duration::from_secs(360);

const KEY_ITERATIONS: u32 = 64;
const USER_HINT_PREFIX_LEN: usize = 16;
const USER_HINT_SUFFIX_LEN: usize = 4;

#[derive(Clone)]
pub struct CipherState {
    key: [u8; KEY_LEN],
    nonce: Option<[u8; NONCE_LEN]>,
    user_name: Option<String>,
}

impl CipherState {
    pub fn new(key: [u8; KEY_LEN], user_name: Option<String>) -> Self {
        Self {
            key,
            nonce: None,
            user_name,
        }
    }

    pub fn from_received(
        key: [u8; KEY_LEN],
        nonce: [u8; NONCE_LEN],
        user_name: Option<String>,
    ) -> Self {
        Self {
            key,
            nonce: Some(nonce),
            user_name,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let include_nonce = self.nonce.is_none();
        let mut nonce = if let Some(current) = self.nonce.as_mut() {
            increment_nonce(current);
            *current
        } else {
            let mut nonce = random_nonce()?;
            if let Some(user_name) = self.user_name.as_deref() {
                apply_user_hint(&mut nonce, user_name);
            }
            self.nonce = Some(nonce);
            nonce
        };
        if !include_nonce {
            nonce = self
                .nonce
                .expect("nonce must be initialized after implicit increment");
        }

        let encrypted = seal(&self.key, &nonce, plaintext)?;
        if include_nonce {
            let mut frame = nonce.to_vec();
            frame.extend_from_slice(&encrypted);
            return Ok(frame);
        }
        Ok(encrypted)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (nonce, ciphertext) = if let Some(current) = self.nonce.as_mut() {
            increment_nonce(current);
            (*current, ciphertext)
        } else {
            ensure!(
                ciphertext.len() >= NONCE_LEN + TAG_LEN,
                "Mieru frame too short: {}",
                ciphertext.len()
            );
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
            self.nonce = Some(nonce);
            (nonce, &ciphertext[NONCE_LEN..])
        };
        open(&self.key, &nonce, ciphertext)
    }

    pub fn expects_nonce(&self) -> bool {
        self.nonce.is_none()
    }
}

pub fn hash_password(user_name: &str, password: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + 1 + user_name.len());
    input.extend_from_slice(password.as_bytes());
    input.push(0);
    input.extend_from_slice(user_name.as_bytes());
    Sha256::digest(input).into()
}

pub fn derive_keys(hashed_password: &[u8; 32], now: SystemTime) -> anyhow::Result<[[u8; 32]; 3]> {
    let unix = now
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let rounded = ((unix + KEY_REFRESH_INTERVAL.as_secs() / 2) / KEY_REFRESH_INTERVAL.as_secs())
        * KEY_REFRESH_INTERVAL.as_secs();

    let mut keys = [[0u8; 32]; 3];
    for (index, timestamp) in [
        rounded.saturating_sub(KEY_REFRESH_INTERVAL.as_secs()),
        rounded,
        rounded + KEY_REFRESH_INTERVAL.as_secs(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut salt_input = [0u8; 8];
        salt_input.copy_from_slice(&timestamp.to_be_bytes());
        let salt: [u8; 32] = Sha256::digest(salt_input).into();
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(hashed_password, &salt, KEY_ITERATIONS, &mut key);
        keys[index] = key;
    }
    Ok(keys)
}

pub fn user_hint_matches(user_name: &str, nonce: &[u8; NONCE_LEN]) -> bool {
    let mut input = Vec::with_capacity(user_name.len() + USER_HINT_PREFIX_LEN);
    input.extend_from_slice(user_name.as_bytes());
    input.extend_from_slice(&nonce[..USER_HINT_PREFIX_LEN]);
    let digest: [u8; 32] = Sha256::digest(input).into();
    digest[..USER_HINT_SUFFIX_LEN] == nonce[NONCE_LEN - USER_HINT_SUFFIX_LEN..]
}

pub fn decrypt_first_frame(
    key: [u8; KEY_LEN],
    frame: &[u8],
) -> anyhow::Result<([u8; NONCE_LEN], Vec<u8>)> {
    ensure!(
        frame.len() >= NONCE_LEN + TAG_LEN,
        "Mieru first frame too short: {}",
        frame.len()
    );
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&frame[..NONCE_LEN]);
    let plaintext = open(&key, &nonce, &frame[NONCE_LEN..])?;
    Ok((nonce, plaintext))
}

fn apply_user_hint(nonce: &mut [u8; NONCE_LEN], user_name: &str) {
    let mut input = Vec::with_capacity(user_name.len() + USER_HINT_PREFIX_LEN);
    input.extend_from_slice(user_name.as_bytes());
    input.extend_from_slice(&nonce[..USER_HINT_PREFIX_LEN]);
    let digest: [u8; 32] = Sha256::digest(input).into();
    nonce[NONCE_LEN - USER_HINT_SUFFIX_LEN..].copy_from_slice(&digest[..USER_HINT_SUFFIX_LEN]);
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn random_nonce() -> anyhow::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    boring::rand::rand_bytes(&mut nonce).context("generate Mieru nonce")?;
    Ok(nonce)
}

fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let algorithm = Algorithm::xchacha20_poly1305();
    let ctx = AeadCtx::new_default_tag(&algorithm, key).context("init Mieru cipher")?;
    let mut buffer = plaintext.to_vec();
    let mut tag = vec![0u8; algorithm.max_overhead()];
    let tag = ctx
        .seal_in_place(nonce, &mut buffer, &mut tag, &[])
        .context("encrypt Mieru frame")?;
    buffer.extend_from_slice(tag);
    Ok(buffer)
}

fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= TAG_LEN,
        "Mieru ciphertext too short: {}",
        ciphertext.len()
    );
    let algorithm = Algorithm::xchacha20_poly1305();
    let ctx = AeadCtx::new_default_tag(&algorithm, key).context("init Mieru cipher")?;
    let split = ciphertext.len() - algorithm.max_overhead();
    let (data, tag) = ciphertext.split_at(split);
    let mut buffer = data.to_vec();
    ctx.open_in_place(nonce, &mut buffer, tag, &[])
        .map_err(|_| anyhow!("decrypt Mieru frame failed"))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_matching_user_hint() {
        let mut nonce = [7u8; NONCE_LEN];
        apply_user_hint(&mut nonce, "user");
        assert!(user_hint_matches("user", &nonce));
        assert!(!user_hint_matches("other", &nonce));
    }

    #[test]
    fn roundtrips_implicit_nonce_cipher() {
        let key = [3u8; KEY_LEN];
        let mut send = CipherState::new(key, Some("user".to_string()));
        let mut recv = CipherState::new(key, None);
        let first = send.encrypt(b"metadata").expect("encrypt first");
        let second = send.encrypt(b"payload").expect("encrypt second");
        assert_eq!(recv.decrypt(&first).expect("decrypt first"), b"metadata");
        assert_eq!(recv.decrypt(&second).expect("decrypt second"), b"payload");
    }
}
