use std::fmt;

use anyhow::{Context, bail, ensure};
use boring::aead::{AeadCtx, Algorithm};
use boring::symm::{Cipher, Crypter, Mode};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const AUTH_ID_ENCRYPTION_KEY_SALT: &str = "AES Auth ID Encryption";
const AEAD_RESPONSE_HEADER_LENGTH_KEY_SALT: &str = "AEAD Resp Header Len Key";
const AEAD_RESPONSE_HEADER_LENGTH_IV_SALT: &str = "AEAD Resp Header Len IV";
const AEAD_RESPONSE_HEADER_PAYLOAD_KEY_SALT: &str = "AEAD Resp Header Key";
const AEAD_RESPONSE_HEADER_PAYLOAD_IV_SALT: &str = "AEAD Resp Header IV";
const VMESS_AEAD_KDF_SALT: &[u8] = b"VMess AEAD KDF";
const VMESS_HEADER_PAYLOAD_KEY_SALT: &str = "VMess Header AEAD Key";
const VMESS_HEADER_PAYLOAD_IV_SALT: &str = "VMess Header AEAD Nonce";
const VMESS_HEADER_LENGTH_KEY_SALT: &str = "VMess Header AEAD Key_Length";
const VMESS_HEADER_LENGTH_IV_SALT: &str = "VMess Header AEAD Nonce_Length";
const AUTHENTICATED_LENGTH_SALT: &str = "auth_len";
const MAX_PADDING_LEN: usize = 64;
const AEAD_TAG_LEN: usize = 16;
const MAX_CHUNK_PLAIN_LEN: usize = 16 * 1024;
const HMAC_BLOCK_SIZE: usize = 64;
const CHACHA_KEY_LEN: usize = 32;
const SECURITY_TYPE_AES128_GCM: u8 = 0x03;
const SECURITY_TYPE_CHACHA20_POLY1305: u8 = 0x04;
const SECURITY_TYPE_NONE: u8 = 0x05;
const SECURITY_TYPE_ZERO: u8 = 0x06;
const REQUEST_OPTION_CHUNK_STREAM: u8 = 0x01;
const REQUEST_OPTION_CONNECTION_REUSE: u8 = 0x02;
const REQUEST_OPTION_CHUNK_MASKING: u8 = 0x04;
const REQUEST_OPTION_GLOBAL_PADDING: u8 = 0x08;
const REQUEST_OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
const SUPPORTED_OPTION_BITS: u8 = REQUEST_OPTION_CHUNK_STREAM
    | REQUEST_OPTION_CONNECTION_REUSE
    | REQUEST_OPTION_CHUNK_MASKING
    | REQUEST_OPTION_GLOBAL_PADDING
    | REQUEST_OPTION_AUTHENTICATED_LENGTH;
const KECCAKF_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
const KECCAKF_ROTATION: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAKF_PERMUTATION: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
    Zero,
}

impl SecurityType {
    pub fn from_raw(raw: u8) -> anyhow::Result<Self> {
        match raw {
            SECURITY_TYPE_AES128_GCM => Ok(Self::Aes128Gcm),
            SECURITY_TYPE_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            SECURITY_TYPE_NONE => Ok(Self::None),
            SECURITY_TYPE_ZERO => Ok(Self::Zero),
            0x01 => bail!("VMess legacy security is not supported"),
            0x02 => bail!("VMess auto security must not appear on the wire"),
            other => bail!("unsupported VMess security type: {other}"),
        }
    }

    pub fn from_remote(value: &str) -> anyhow::Result<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "" | "auto" => Ok(Self::auto_for_platform()),
            "none" => Ok(Self::None),
            "zero" => Ok(Self::Zero),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            other => bail!("unsupported VMess security setting: {other}"),
        }
    }

    pub fn auto_for_platform() -> Self {
        match std::env::consts::ARCH {
            "x86_64" | "aarch64" | "s390x" => Self::Aes128Gcm,
            _ => Self::ChaCha20Poly1305,
        }
    }

    pub fn normalized(self) -> Self {
        match self {
            Self::Zero => Self::None,
            other => other,
        }
    }

    pub fn payload_overhead(self) -> usize {
        match self.normalized() {
            Self::None => 0,
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => AEAD_TAG_LEN,
            Self::Zero => 0,
        }
    }
}

impl fmt::Display for SecurityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "aes-128-gcm"),
            Self::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
            Self::None => write!(f, "none"),
            Self::Zero => write!(f, "zero"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequestOptions(u8);

impl RequestOptions {
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn supported_mask() -> u8 {
        SUPPORTED_OPTION_BITS
    }

    pub const fn chunk_stream(self) -> bool {
        self.0 & REQUEST_OPTION_CHUNK_STREAM != 0
    }

    pub const fn chunk_masking(self) -> bool {
        self.0 & REQUEST_OPTION_CHUNK_MASKING != 0
    }

    pub const fn global_padding(self) -> bool {
        self.0 & REQUEST_OPTION_GLOBAL_PADDING != 0
    }

    pub const fn authenticated_length(self) -> bool {
        self.0 & REQUEST_OPTION_AUTHENTICATED_LENGTH != 0
    }

    pub const fn has_unknown_bits(self) -> bool {
        self.0 & !SUPPORTED_OPTION_BITS != 0
    }

    pub fn set_chunk_stream(&mut self) {
        self.0 |= REQUEST_OPTION_CHUNK_STREAM;
    }

    pub fn set_chunk_masking(&mut self) {
        self.0 |= REQUEST_OPTION_CHUNK_MASKING;
    }

    pub fn set_global_padding(&mut self) {
        self.0 |= REQUEST_OPTION_GLOBAL_PADDING;
    }

    pub fn set_authenticated_length(&mut self) {
        self.0 |= REQUEST_OPTION_AUTHENTICATED_LENGTH;
    }

    pub fn clear_chunk_stream(&mut self) {
        self.0 &= !REQUEST_OPTION_CHUNK_STREAM;
    }

    pub fn clear_chunk_masking(&mut self) {
        self.0 &= !REQUEST_OPTION_CHUNK_MASKING;
    }
}

impl fmt::Display for RequestOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chunk_stream={}, chunk_masking={}, global_padding={}, authenticated_length={}",
            self.chunk_stream(),
            self.chunk_masking(),
            self.global_padding(),
            self.authenticated_length()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyConfig {
    security: SecurityType,
    options: RequestOptions,
    payload_key: [u8; 16],
    payload_iv: [u8; 16],
    length_key: [u8; 16],
    length_iv: [u8; 16],
}

impl BodyConfig {
    pub fn new_request(
        security: SecurityType,
        options: RequestOptions,
        key: [u8; 16],
        iv: [u8; 16],
    ) -> anyhow::Result<Self> {
        Self::new(security, options, key, iv, key, iv)
    }

    pub fn new_response(
        security: SecurityType,
        options: RequestOptions,
        request_key: [u8; 16],
        request_iv: [u8; 16],
    ) -> anyhow::Result<Self> {
        Self::new(
            security,
            options,
            response_body_key(&request_key),
            response_body_iv(&request_iv),
            request_key,
            request_iv,
        )
    }

    pub fn new(
        security: SecurityType,
        options: RequestOptions,
        payload_key: [u8; 16],
        payload_iv: [u8; 16],
        length_key: [u8; 16],
        length_iv: [u8; 16],
    ) -> anyhow::Result<Self> {
        let security = security.normalized();
        ensure!(
            !options.has_unknown_bits(),
            "unsupported VMess request option bits: 0x{:02x}",
            options.bits() & !SUPPORTED_OPTION_BITS
        );
        if !options.chunk_stream() {
            ensure!(
                !options.chunk_masking()
                    && !options.global_padding()
                    && !options.authenticated_length(),
                "VMess non-chunked body cannot enable chunk masking, global padding, or authenticated length"
            );
            ensure!(
                security == SecurityType::None,
                "encrypted VMess security {security} requires chunk stream"
            );
        }
        if options.global_padding() {
            ensure!(
                options.chunk_stream(),
                "VMess global padding requires chunk stream"
            );
            ensure!(
                options.chunk_masking() || options.authenticated_length(),
                "VMess global padding requires chunk masking or authenticated length"
            );
        }
        if options.chunk_masking() {
            ensure!(
                options.chunk_stream(),
                "VMess chunk masking requires chunk stream"
            );
        }
        if options.authenticated_length() {
            ensure!(
                options.chunk_stream(),
                "VMess authenticated length requires chunk stream"
            );
        }
        Ok(Self {
            security,
            options,
            payload_key,
            payload_iv,
            length_key,
            length_iv,
        })
    }
    pub fn raw_mode(self) -> bool {
        self.security == SecurityType::None && !self.options.chunk_stream()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAuthId {
    pub timestamp: i64,
    pub random: u32,
    pub checksum: u32,
}

pub fn parse_uuid(value: &str) -> anyhow::Result<[u8; 16]> {
    let normalized: String = value.chars().filter(|ch| *ch != '-').collect();
    ensure!(
        normalized.len() == 32,
        "invalid UUID length for VMess user id: {}",
        value
    );
    let mut out = [0u8; 16];
    hex::decode_to_slice(normalized, &mut out).context("decode VMess UUID")?;
    Ok(out)
}

pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut levels: Vec<&[u8]> = Vec::with_capacity(2 + path.len());
    levels.push(VMESS_AEAD_KDF_SALT);
    levels.push(salt.as_bytes());
    levels.extend_from_slice(path);
    nested_hmac_hash(&levels, key)
}

pub fn kdf16(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, salt, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64) -> anyhow::Result<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    random_bytes_into(&mut plain[8..12]).context("generate VMess auth id random bytes")?;
    let checksum = crc32_ieee(&plain[..12]);
    plain[12..16].copy_from_slice(&checksum.to_be_bytes());
    let key = kdf16(cmd_key, AUTH_ID_ENCRYPTION_KEY_SALT, &[]);
    aes_128_ecb_crypt(&key, &plain, Mode::Encrypt).context("encrypt VMess auth id")
}

pub fn decode_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> anyhow::Result<DecodedAuthId> {
    let key = kdf16(cmd_key, AUTH_ID_ENCRYPTION_KEY_SALT, &[]);
    let decrypted =
        aes_128_ecb_crypt(&key, auth_id, Mode::Decrypt).context("decrypt VMess auth id")?;
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&decrypted[..8]);
    let timestamp = i64::from_be_bytes(timestamp_bytes);
    let mut random_bytes = [0u8; 4];
    random_bytes.copy_from_slice(&decrypted[8..12]);
    let random = u32::from_be_bytes(random_bytes);
    let mut checksum_bytes = [0u8; 4];
    checksum_bytes.copy_from_slice(&decrypted[12..16]);
    let checksum = u32::from_be_bytes(checksum_bytes);
    let actual_checksum = crc32_ieee(&decrypted[..12]);
    ensure!(
        checksum == actual_checksum,
        "invalid VMess auth id checksum: expected 0x{checksum:08x}, got 0x{actual_checksum:08x}"
    );
    Ok(DecodedAuthId {
        timestamp,
        random,
        checksum,
    })
}

pub fn auth_id_is_fresh(decoded: &DecodedAuthId, now: i64, skew_secs: i64) -> bool {
    let lower = now.saturating_sub(skew_secs);
    let upper = now.saturating_add(skew_secs);
    decoded.timestamp >= lower && decoded.timestamp <= upper
}

pub async fn open_vmess_aead_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
) -> anyhow::Result<Vec<u8>> {
    let mut encrypted_length = [0u8; 2 + AEAD_TAG_LEN];
    reader
        .read_exact(&mut encrypted_length)
        .await
        .context("read VMess AEAD header length")?;
    let mut connection_nonce = [0u8; 8];
    reader
        .read_exact(&mut connection_nonce)
        .await
        .context("read VMess AEAD header nonce")?;

    let length_key = kdf16(
        cmd_key,
        VMESS_HEADER_LENGTH_KEY_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    let length_nonce = kdf(
        cmd_key,
        VMESS_HEADER_LENGTH_IV_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    let length_plain = decrypt_aes_gcm(
        &length_key,
        &length_nonce[..12],
        &encrypted_length,
        auth_id,
        "VMess AEAD header length",
    )?;
    ensure!(
        length_plain.len() == 2,
        "invalid VMess header length payload size: {}",
        length_plain.len()
    );
    let header_length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;

    let mut encrypted_payload = vec![0u8; header_length + AEAD_TAG_LEN];
    reader
        .read_exact(&mut encrypted_payload)
        .await
        .context("read VMess AEAD header payload")?;
    let payload_key = kdf16(
        cmd_key,
        VMESS_HEADER_PAYLOAD_KEY_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    let payload_nonce = kdf(
        cmd_key,
        VMESS_HEADER_PAYLOAD_IV_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    decrypt_aes_gcm(
        &payload_key,
        &payload_nonce[..12],
        &encrypted_payload,
        auth_id,
        "VMess AEAD header payload",
    )
}

pub fn response_body_key(request_body_key: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn response_body_iv(request_body_iv: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn generate_chunk_nonce(base: &[u8], counter: u16, nonce_len: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; nonce_len];
    let copy_len = nonce_len.min(base.len());
    nonce[..copy_len].copy_from_slice(&base[..copy_len]);
    if nonce_len >= 2 {
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
    }
    nonce
}

pub fn generate_chacha20_poly1305_key(value: &[u8]) -> [u8; CHACHA_KEY_LEN] {
    let first = Md5::digest(value);
    let second = Md5::digest(&first);
    let mut out = [0u8; CHACHA_KEY_LEN];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

pub fn encode_response_header(
    response_header: u8,
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
) -> anyhow::Result<Vec<u8>> {
    let response_key = response_body_key(request_body_key);
    let response_iv = response_body_iv(request_body_iv);
    let header_plain = [response_header, 0, 0, 0];

    let length_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_LENGTH_KEY_SALT, &[]);
    let length_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_LENGTH_IV_SALT, &[]);
    let payload_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_PAYLOAD_KEY_SALT, &[]);
    let payload_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_PAYLOAD_IV_SALT, &[]);

    let mut out = encrypt_aes_gcm(
        &length_key,
        &length_nonce[..12],
        &(header_plain.len() as u16).to_be_bytes(),
        &[],
        "VMess response header length",
    )?;
    out.extend_from_slice(&encrypt_aes_gcm(
        &payload_key,
        &payload_nonce[..12],
        &header_plain,
        &[],
        "VMess response header payload",
    )?);
    Ok(out)
}

pub struct BodyReader<R> {
    inner: R,
    state: ChunkState,
    pending: Vec<u8>,
    pending_pos: usize,
    finished: bool,
}

impl<R: AsyncRead + Unpin> BodyReader<R> {
    pub fn new(inner: R, config: BodyConfig) -> anyhow::Result<Self> {
        Ok(Self {
            inner,
            state: ChunkState::new(config),
            pending: Vec::new(),
            pending_pos: 0,
            finished: false,
        })
    }

    pub async fn read_plain(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.state.raw_mode() {
            let n = self.inner.read(buf).await.context("read raw VMess body")?;
            return Ok(n);
        }
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
            if self.finished {
                return Ok(0);
            }
            self.read_next_chunk().await?;
            if self.pending.is_empty() {
                return Ok(0);
            }
        }
        let remaining = self.pending.len() - self.pending_pos;
        let to_copy = remaining.min(buf.len());
        buf[..to_copy].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + to_copy]);
        self.pending_pos += to_copy;
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        Ok(to_copy)
    }

    pub async fn read_packet(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        ensure!(
            !self.state.raw_mode(),
            "VMess packet transfer requires chunk stream"
        );
        ensure!(
            self.pending_pos >= self.pending.len(),
            "VMess packet transfer cannot continue after partial stream reads"
        );
        if self.finished {
            return Ok(None);
        }
        self.pending.clear();
        self.pending_pos = 0;
        self.read_next_chunk().await?;
        if self.finished {
            return Ok(None);
        }
        Ok(Some(std::mem::take(&mut self.pending)))
    }

    async fn read_next_chunk(&mut self) -> anyhow::Result<()> {
        let mut size_bytes = vec![0u8; self.state.size_field_len()];
        self.inner
            .read_exact(&mut size_bytes)
            .await
            .context("read VMess chunk size")?;
        let padding_len = if self.state.padding_before_size_decode() {
            self.state.next_padding_len()
        } else {
            0
        };
        let encoded_size = self.state.decode_size(&size_bytes)? as usize;
        let padding_len = if self.state.padding_before_size_decode() {
            padding_len
        } else {
            self.state.next_padding_len()
        };
        ensure!(
            encoded_size >= padding_len,
            "invalid VMess chunk size {encoded_size} smaller than padding {padding_len}"
        );
        let payload_len = encoded_size - padding_len;
        ensure!(
            payload_len >= self.state.payload_overhead(),
            "invalid VMess chunk payload size {payload_len} below overhead {}",
            self.state.payload_overhead()
        );
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.inner
                .read_exact(&mut payload)
                .await
                .context("read VMess chunk payload")?;
        }
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            self.inner
                .read_exact(&mut padding)
                .await
                .context("read VMess chunk padding")?;
        }
        let plaintext = self.state.decrypt_payload(&payload)?;
        if payload_len == self.state.payload_overhead() {
            if plaintext.is_empty() {
                self.finished = true;
                self.pending.clear();
                self.pending_pos = 0;
                return Ok(());
            }
        }
        self.pending = plaintext;
        self.pending_pos = 0;
        Ok(())
    }
}

pub struct BodyWriter<W> {
    inner: W,
    state: ChunkState,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> BodyWriter<W> {
    pub fn new(inner: W, config: BodyConfig) -> anyhow::Result<Self> {
        Ok(Self {
            inner,
            state: ChunkState::new(config),
            finished: false,
        })
    }

    pub async fn write_all_plain(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        ensure!(!self.finished, "VMess body writer already finished");
        if self.state.raw_mode() {
            self.inner
                .write_all(data)
                .await
                .context("write raw VMess body")?;
            return Ok(());
        }
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + MAX_CHUNK_PLAIN_LEN).min(data.len());
            self.write_chunk(&data[offset..end]).await?;
            offset = end;
        }
        Ok(())
    }

    pub async fn write_packet_plain(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        ensure!(!self.finished, "VMess body writer already finished");
        ensure!(
            !self.state.raw_mode(),
            "VMess packet transfer requires chunk stream"
        );
        self.write_chunk(data).await
    }

    pub async fn finish(&mut self) -> anyhow::Result<()> {
        if self.finished {
            return Ok(());
        }
        if !self.state.raw_mode() {
            self.write_chunk(&[]).await?;
        }
        self.inner.shutdown().await.context("shutdown VMess body")?;
        self.finished = true;
        Ok(())
    }

    async fn write_chunk(&mut self, plaintext: &[u8]) -> anyhow::Result<()> {
        let padding_len = self.state.next_padding_len();
        let ciphertext = self.state.encrypt_payload(plaintext)?;
        let total_len = ciphertext.len() + padding_len;
        ensure!(
            total_len <= u16::MAX as usize,
            "VMess chunk too large: {total_len}"
        );
        let size_bytes = self.state.encode_size(total_len as u16)?;
        self.inner
            .write_all(&size_bytes)
            .await
            .context("write VMess chunk size")?;
        if !ciphertext.is_empty() {
            self.inner
                .write_all(&ciphertext)
                .await
                .context("write VMess chunk payload")?;
        }
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            random_bytes_into(&mut padding).context("generate VMess chunk padding")?;
            self.inner
                .write_all(&padding)
                .await
                .context("write VMess chunk padding")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ChunkState {
    config: BodyConfig,
    size_shake: Option<Shake128>,
    padding_shake: Option<Shake128>,
    padding_from_size_shake: bool,
    size_counter: u16,
    payload_counter: u16,
}

impl ChunkState {
    fn new(config: BodyConfig) -> Self {
        let mut size_shake = None;
        let mut padding_shake = None;
        let mut padding_from_size_shake = false;
        if config.options.chunk_stream() {
            if config.options.authenticated_length() {
                if config.options.global_padding() {
                    let mut shake = Shake128::default();
                    shake.absorb(&config.payload_iv);
                    shake.finalize();
                    padding_shake = Some(shake);
                }
            } else if config.options.chunk_masking() {
                let mut shake = Shake128::default();
                shake.absorb(&config.payload_iv);
                shake.finalize();
                if config.options.global_padding() {
                    padding_from_size_shake = true;
                }
                size_shake = Some(shake);
            }
        }
        Self {
            config,
            size_shake,
            padding_shake,
            padding_from_size_shake,
            size_counter: 0,
            payload_counter: 0,
        }
    }

    fn raw_mode(&self) -> bool {
        self.config.raw_mode()
    }

    fn size_field_len(&self) -> usize {
        if self.config.options.authenticated_length() {
            2 + AEAD_TAG_LEN
        } else {
            2
        }
    }

    fn payload_overhead(&self) -> usize {
        self.config.security.payload_overhead()
    }

    fn padding_before_size_decode(&self) -> bool {
        self.padding_from_size_shake
    }

    fn next_padding_len(&mut self) -> usize {
        if self.padding_from_size_shake {
            self.size_shake
                .as_mut()
                .map(Shake128::next_padding_len)
                .unwrap_or(0)
        } else {
            self.padding_shake
                .as_mut()
                .map(Shake128::next_padding_len)
                .unwrap_or(0)
        }
    }

    fn decode_size(&mut self, encoded: &[u8]) -> anyhow::Result<u16> {
        ensure!(
            encoded.len() == self.size_field_len(),
            "invalid VMess encoded chunk size length: {}",
            encoded.len()
        );
        let decoded = if self.config.options.authenticated_length() {
            let plain = self.open_length_chunk(encoded)?;
            ensure!(plain.len() == 2, "invalid VMess AEAD length payload size");
            u16::from_be_bytes([plain[0], plain[1]]).wrapping_add(AEAD_TAG_LEN as u16)
        } else if let Some(shake) = self.size_shake.as_mut() {
            let mask = shake.next_u16();
            mask ^ u16::from_be_bytes([encoded[0], encoded[1]])
        } else {
            u16::from_be_bytes([encoded[0], encoded[1]])
        };
        Ok(decoded)
    }

    fn encode_size(&mut self, size: u16) -> anyhow::Result<Vec<u8>> {
        let output = if self.config.options.authenticated_length() {
            let adjusted = size.wrapping_sub(AEAD_TAG_LEN as u16);
            self.seal_length_chunk(&adjusted.to_be_bytes())?
        } else if let Some(shake) = self.size_shake.as_mut() {
            let masked = shake.next_u16() ^ size;
            masked.to_be_bytes().to_vec()
        } else {
            size.to_be_bytes().to_vec()
        };
        Ok(output)
    }

    fn decrypt_payload(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.config.security {
            SecurityType::None => Ok(payload.to_vec()),
            SecurityType::Aes128Gcm => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter, 12);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                decrypt_aes_gcm(
                    &self.config.payload_key,
                    &nonce,
                    payload,
                    &[],
                    "VMess AES-128-GCM payload",
                )
            }
            SecurityType::ChaCha20Poly1305 => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter, 12);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                decrypt_chacha20_poly1305(
                    &generate_chacha20_poly1305_key(&self.config.payload_key),
                    &nonce,
                    payload,
                    &[],
                    "VMess ChaCha20-Poly1305 payload",
                )
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }

    fn encrypt_payload(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.config.security {
            SecurityType::None => Ok(plaintext.to_vec()),
            SecurityType::Aes128Gcm => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter, 12);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                encrypt_aes_gcm(
                    &self.config.payload_key,
                    &nonce,
                    plaintext,
                    &[],
                    "VMess AES-128-GCM payload",
                )
            }
            SecurityType::ChaCha20Poly1305 => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter, 12);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                encrypt_chacha20_poly1305(
                    &generate_chacha20_poly1305_key(&self.config.payload_key),
                    &nonce,
                    plaintext,
                    &[],
                    "VMess ChaCha20-Poly1305 payload",
                )
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }

    fn open_length_chunk(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = kdf16(&self.config.length_key, AUTHENTICATED_LENGTH_SALT, &[]);
        let nonce = generate_chunk_nonce(&self.config.length_iv, self.size_counter, 12);
        self.size_counter = self.size_counter.wrapping_add(1);
        match self.config.security {
            SecurityType::ChaCha20Poly1305 => decrypt_chacha20_poly1305(
                &generate_chacha20_poly1305_key(&key),
                &nonce,
                ciphertext,
                &[],
                "VMess authenticated length",
            ),
            SecurityType::Aes128Gcm | SecurityType::None => {
                decrypt_aes_gcm(&key, &nonce, ciphertext, &[], "VMess authenticated length")
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }

    fn seal_length_chunk(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = kdf16(&self.config.length_key, AUTHENTICATED_LENGTH_SALT, &[]);
        let nonce = generate_chunk_nonce(&self.config.length_iv, self.size_counter, 12);
        self.size_counter = self.size_counter.wrapping_add(1);
        match self.config.security {
            SecurityType::ChaCha20Poly1305 => encrypt_chacha20_poly1305(
                &generate_chacha20_poly1305_key(&key),
                &nonce,
                plaintext,
                &[],
                "VMess authenticated length",
            ),
            SecurityType::Aes128Gcm | SecurityType::None => {
                encrypt_aes_gcm(&key, &nonce, plaintext, &[], "VMess authenticated length")
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Shake128 {
    state: [u64; 25],
    absorb_pos: usize,
    squeeze_pos: usize,
    finalized: bool,
}

impl Default for Shake128 {
    fn default() -> Self {
        Self {
            state: [0u64; 25],
            absorb_pos: 0,
            squeeze_pos: 0,
            finalized: false,
        }
    }
}

impl Shake128 {
    const RATE: usize = 168;

    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.finalized, "cannot absorb after SHAKE128 finalization");
        for &byte in data {
            self.xor_byte(self.absorb_pos, byte);
            self.absorb_pos += 1;
            if self.absorb_pos == Self::RATE {
                keccakf(&mut self.state);
                self.absorb_pos = 0;
            }
        }
    }

    pub fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        self.xor_byte(self.absorb_pos, 0x1f);
        self.xor_byte(Self::RATE - 1, 0x80);
        keccakf(&mut self.state);
        self.squeeze_pos = 0;
        self.finalized = true;
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.finalized {
            self.finalize();
        }
        for byte in out {
            if self.squeeze_pos == Self::RATE {
                keccakf(&mut self.state);
                self.squeeze_pos = 0;
            }
            *byte = self.byte_at(self.squeeze_pos);
            self.squeeze_pos += 1;
        }
    }

    pub fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.squeeze(&mut buf);
        u16::from_be_bytes(buf)
    }

    pub fn next_padding_len(&mut self) -> usize {
        (self.next_u16() as usize) % MAX_PADDING_LEN
    }

    fn xor_byte(&mut self, pos: usize, byte: u8) {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        self.state[lane] ^= (byte as u64) << shift;
    }

    fn byte_at(&self, pos: usize) -> u8 {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        ((self.state[lane] >> shift) & 0xff) as u8
    }
}

fn keccakf(state: &mut [u64; 25]) {
    for round_constant in KECCAKF_ROUND_CONSTANTS {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut current = state[1];
        for idx in 0..24 {
            let target = KECCAKF_PERMUTATION[idx];
            let tmp = state[target];
            state[target] = current.rotate_left(KECCAKF_ROTATION[idx]);
            current = tmp;
        }

        for y in 0..5 {
            let row = [
                state[5 * y],
                state[5 * y + 1],
                state[5 * y + 2],
                state[5 * y + 3],
                state[5 * y + 4],
            ];
            for x in 0..5 {
                state[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        state[0] ^= round_constant;
    }
}

fn nested_hmac_hash(levels: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if let Some((last, rest)) = levels.split_last() {
        hmac_with_custom_hash(last, data, |input| {
            if rest.is_empty() {
                sha256_hash(input)
            } else {
                nested_hmac_hash(rest, input)
            }
        })
    } else {
        sha256_hash(data)
    }
}

fn hmac_with_custom_hash<F>(key: &[u8], data: &[u8], hash_fn: F) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        key_block[..32].copy_from_slice(&hash_fn(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Vec::with_capacity(HMAC_BLOCK_SIZE + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = hash_fn(&inner);

    let mut outer = Vec::with_capacity(HMAC_BLOCK_SIZE + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    hash_fn(&outer)
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn encrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut tag = [0u8; AEAD_TAG_LEN];
    let mut ciphertext = boring::symm::encrypt_aead(
        Cipher::aes_128_gcm(),
        key,
        Some(nonce),
        aad,
        plaintext,
        &mut tag,
    )
    .with_context(|| format!("encrypt {name}"))?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= AEAD_TAG_LEN,
        "ciphertext too short for {name}: {}",
        ciphertext.len()
    );
    let split = ciphertext.len() - AEAD_TAG_LEN;
    let (data, tag) = ciphertext.split_at(split);
    boring::symm::decrypt_aead(Cipher::aes_128_gcm(), key, Some(nonce), aad, data, tag)
        .with_context(|| format!("decrypt {name}"))
}

fn encrypt_chacha20_poly1305(
    key: &[u8; CHACHA_KEY_LEN],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    let ctx = AeadCtx::new_default_tag(&Algorithm::chacha20_poly1305(), key)
        .with_context(|| format!("init {name}"))?;
    let mut buffer = plaintext.to_vec();
    let mut tag = vec![0u8; AEAD_TAG_LEN];
    let tag = ctx
        .seal_in_place(nonce, &mut buffer, &mut tag, aad)
        .with_context(|| format!("encrypt {name}"))?;
    buffer.extend_from_slice(tag);
    Ok(buffer)
}

fn decrypt_chacha20_poly1305(
    key: &[u8; CHACHA_KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= AEAD_TAG_LEN,
        "ciphertext too short for {name}: {}",
        ciphertext.len()
    );
    let ctx = AeadCtx::new_default_tag(&Algorithm::chacha20_poly1305(), key)
        .with_context(|| format!("init {name}"))?;
    let split = ciphertext.len() - AEAD_TAG_LEN;
    let (data, tag) = ciphertext.split_at(split);
    let mut buffer = data.to_vec();
    ctx.open_in_place(nonce, &mut buffer, tag, aad)
        .with_context(|| format!("decrypt {name}"))?;
    Ok(buffer)
}

fn aes_128_ecb_crypt(key: &[u8], block: &[u8; 16], mode: Mode) -> anyhow::Result<[u8; 16]> {
    let mut crypter =
        Crypter::new(Cipher::aes_128_ecb(), mode, key, None).context("init aes-128-ecb")?;
    crypter.pad(false);

    let mut out = [0u8; 32];
    let mut count = crypter
        .update(block, &mut out)
        .context("update aes-128-ecb")?;
    count += crypter
        .finalize(&mut out[count..])
        .context("finalize aes-128-ecb")?;

    ensure!(count == 16, "unexpected aes-128-ecb output length: {count}");
    let mut result = [0u8; 16];
    result.copy_from_slice(&out[..16]);
    Ok(result)
}

fn random_bytes_into(buf: &mut [u8]) -> anyhow::Result<()> {
    boring::rand::rand_bytes(buf).context("generate random bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake128_matches_known_vector_prefix() {
        let mut shake = Shake128::default();
        shake.finalize();
        let mut out = [0u8; 16];
        shake.squeeze(&mut out);
        assert_eq!(hex::encode(out), "7f9c2ba4e88f827d616045507605853e");
    }

    #[test]
    fn kdf_matches_xray_vector() {
        let key = b"Demo Key for Auth ID Test";
        let out = kdf(
            key,
            "Demo Path for Auth ID Test",
            &[b"Demo Path 2", b"Demo Path 3"],
        );
        assert_eq!(
            hex::encode(out),
            "04330362c2d751437ba06447fa626f8315e72aeafc836be44f9a95fdf0a7feca"
        );
    }

    #[test]
    fn auth_id_roundtrip() {
        let uuid = parse_uuid("a3482e88-686a-4a58-8126-99c9df64b7bf").unwrap();
        let key = cmd_key(&uuid);
        let auth_id = create_auth_id(&key, 1_700_000_000).unwrap();
        let decoded = decode_auth_id(&key, &auth_id).unwrap();
        assert_eq!(decoded.timestamp, 1_700_000_000);
    }

    #[test]
    fn generate_chacha_key_matches_reference() {
        let key = generate_chacha20_poly1305_key(b"0123456789abcdef");
        assert_eq!(
            hex::encode(key),
            "4032af8d61035123906e58e067140cc567304ba676a616064c4340059e1b6370"
        );
    }

    #[test]
    fn response_header_uses_plain_aead_payload() {
        let request_key = [0x11; 16];
        let request_iv = [0x22; 16];
        let encoded = encode_response_header(0x7f, &request_key, &request_iv).unwrap();
        let response_key = response_body_key(&request_key);
        let response_iv = response_body_iv(&request_iv);

        let length_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_LENGTH_KEY_SALT, &[]);
        let length_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_LENGTH_IV_SALT, &[]);
        let payload_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_PAYLOAD_KEY_SALT, &[]);
        let payload_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_PAYLOAD_IV_SALT, &[]);

        let length_plain = decrypt_aes_gcm(
            &length_key,
            &length_nonce[..12],
            &encoded[..2 + AEAD_TAG_LEN],
            &[],
            "test response header length",
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([length_plain[0], length_plain[1]]), 4);

        let payload_plain = decrypt_aes_gcm(
            &payload_key,
            &payload_nonce[..12],
            &encoded[2 + AEAD_TAG_LEN..],
            &[],
            "test response header payload",
        )
        .unwrap();
        assert_eq!(payload_plain, [0x7f, 0, 0, 0]);
    }

    #[tokio::test]
    async fn packet_roundtrip_preserves_datagram_boundaries() {
        let mut options = RequestOptions::default();
        options.set_chunk_stream();
        let config = BodyConfig::new(
            SecurityType::None,
            options,
            [0x11; 16],
            [0x22; 16],
            [0x11; 16],
            [0x22; 16],
        )
        .unwrap();
        let (reader_io, writer_io) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let mut writer = BodyWriter::new(writer_io, config).unwrap();
            writer.write_packet_plain(b"one").await.unwrap();
            writer.write_packet_plain(b"two-two").await.unwrap();
            writer.finish().await.unwrap();
        });

        let mut reader = BodyReader::new(reader_io, config).unwrap();
        assert_eq!(reader.read_packet().await.unwrap(), Some(b"one".to_vec()));
        assert_eq!(
            reader.read_packet().await.unwrap(),
            Some(b"two-two".to_vec())
        );
        assert_eq!(reader.read_packet().await.unwrap(), None);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn global_padding_and_chunk_masking_roundtrip_multiple_chunks() {
        let mut options = RequestOptions::default();
        options.set_chunk_stream();
        options.set_chunk_masking();
        options.set_global_padding();
        let config = BodyConfig::new(
            SecurityType::None,
            options,
            [0x33; 16],
            [0x44; 16],
            [0x33; 16],
            [0x44; 16],
        )
        .unwrap();
        let (reader_io, writer_io) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let mut writer = BodyWriter::new(writer_io, config).unwrap();
            writer.write_packet_plain(b"alpha").await.unwrap();
            writer.write_packet_plain(b"beta").await.unwrap();
            writer.write_packet_plain(b"gamma").await.unwrap();
            writer.finish().await.unwrap();
        });

        let mut reader = BodyReader::new(reader_io, config).unwrap();
        assert_eq!(reader.read_packet().await.unwrap(), Some(b"alpha".to_vec()));
        assert_eq!(reader.read_packet().await.unwrap(), Some(b"beta".to_vec()));
        assert_eq!(reader.read_packet().await.unwrap(), Some(b"gamma".to_vec()));
        assert_eq!(reader.read_packet().await.unwrap(), None);
        writer.await.unwrap();
    }
}
