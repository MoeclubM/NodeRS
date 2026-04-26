use anyhow::{Context, anyhow, bail, ensure};
use boring::aead::{AeadCtx, Algorithm};
use boring::symm::{self, Cipher};
use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::accounting::{SessionControl, UserEntry};
use crate::panel::PanelUser;
use crate::protocols::anytls::socksaddr::SocksAddr;

const LEGACY_TAG_LEN: usize = 16;
const LEGACY_LENGTH_CHUNK_LEN: usize = 2 + LEGACY_TAG_LEN;
const MAX_TCP_CHUNK_LEN: usize = 0x3fff;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    None,
    Legacy(LegacyAeadMethod),
    Aead2022(Aead2022Method),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyAeadMethod {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead2022Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone)]
pub struct UserCredential {
    pub user: UserEntry,
    pub method: Method,
    pub(crate) secret: Vec<u8>,
    pub(crate) server_secret: Vec<u8>,
    pub(crate) identity_hash: [u8; 16],
}

pub struct AcceptedTcpReader<R> {
    credential: UserCredential,
    state: TcpReaderState<R>,
}

enum TcpReaderState<R> {
    None {
        inner: R,
    },
    Legacy {
        inner: PrefixedReader<R>,
        kind: LegacyAeadMethod,
        subkey: Vec<u8>,
        next_nonce: u64,
        next_payload_len: usize,
    },
}

pub struct DecodedUdpPacket {
    pub credential: UserCredential,
    pub destination: SocksAddr,
    pub payload: Vec<u8>,
    pub wire_len: usize,
}

struct PrefixedReader<R> {
    inner: R,
    prefetched: VecDeque<u8>,
}

impl Method {
    pub fn parse(cipher: &str) -> Option<Self> {
        match cipher.trim().to_ascii_lowercase().as_str() {
            "none" | "plain" => Some(Self::None),
            "aes-128-gcm" | "aead_aes_128_gcm" => Some(Self::Legacy(LegacyAeadMethod::Aes128Gcm)),
            "aes-192-gcm" | "aead_aes_192_gcm" => Some(Self::Legacy(LegacyAeadMethod::Aes192Gcm)),
            "aes-256-gcm" | "aead_aes_256_gcm" => Some(Self::Legacy(LegacyAeadMethod::Aes256Gcm)),
            "chacha20-poly1305" | "aead_chacha20_poly1305" | "chacha20-ietf-poly1305" => {
                Some(Self::Legacy(LegacyAeadMethod::ChaCha20Poly1305))
            }
            "xchacha20-poly1305" | "aead_xchacha20_poly1305" | "xchacha20-ietf-poly1305" => {
                Some(Self::Legacy(LegacyAeadMethod::XChaCha20Poly1305))
            }
            "2022-blake3-aes-128-gcm" => Some(Self::Aead2022(Aead2022Method::Aes128Gcm)),
            "2022-blake3-aes-256-gcm" => Some(Self::Aead2022(Aead2022Method::Aes256Gcm)),
            "2022-blake3-chacha20-poly1305" => {
                Some(Self::Aead2022(Aead2022Method::ChaCha20Poly1305))
            }
            _ => None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    fn salt_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Legacy(kind) => kind.salt_len(),
            Self::Aead2022(kind) => kind.key_len(),
        }
    }
}

impl LegacyAeadMethod {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
            Self::XChaCha20Poly1305 => 32,
        }
    }

    fn salt_len(self) -> usize {
        self.key_len()
    }

    fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
}

impl Aead2022Method {
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }
}

impl UserCredential {
    pub fn from_panel_user(user: &PanelUser, method: Method) -> anyhow::Result<Self> {
        let password = effective_password(user)
            .ok_or_else(|| anyhow!("Shadowsocks user {} is missing password/uuid", user.id))?;
        Ok(Self {
            user: UserEntry::from_panel_user(user),
            secret: derive_secret(&method, password)?,
            server_secret: Vec::new(),
            identity_hash: [0u8; 16],
            method,
        })
    }
}

impl<R> AcceptedTcpReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn credential(&self) -> &UserCredential {
        &self.credential
    }

    pub async fn accept(mut inner: R, users: &[UserCredential]) -> anyhow::Result<Self> {
        ensure!(!users.is_empty(), "no Shadowsocks users configured");
        if let Some(user) = users.iter().find(|user| user.method.is_none()) {
            ensure!(
                users.len() == 1,
                "Shadowsocks none cipher does not support multi-user"
            );
            return Ok(Self {
                credential: user.clone(),
                state: TcpReaderState::None { inner },
            });
        }

        let max_salt_len = users
            .iter()
            .map(|user| user.method.salt_len())
            .max()
            .unwrap_or_default();
        let mut prefix = vec![0u8; max_salt_len + LEGACY_LENGTH_CHUNK_LEN];
        inner
            .read_exact(&mut prefix)
            .await
            .context("read Shadowsocks TCP prefix")?;

        for user in users {
            let Method::Legacy(kind) = user.method else {
                continue;
            };
            let salt_len = kind.salt_len();
            let salt = &prefix[..salt_len];
            let length_ciphertext = &prefix[salt_len..salt_len + LEGACY_LENGTH_CHUNK_LEN];
            let subkey = derive_legacy_subkey(&user.secret, salt, salt_len)?;
            let length_plaintext =
                match decrypt_legacy(kind, &subkey, &legacy_nonce(kind, 0), length_ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(_) => continue,
                };
            if length_plaintext.len() != 2 {
                continue;
            }
            let next_payload_len =
                u16::from_be_bytes([length_plaintext[0], length_plaintext[1]]) as usize;
            if next_payload_len > MAX_TCP_CHUNK_LEN {
                continue;
            }
            return Ok(Self {
                credential: user.clone(),
                state: TcpReaderState::Legacy {
                    inner: PrefixedReader::new(
                        inner,
                        prefix[salt_len + LEGACY_LENGTH_CHUNK_LEN..].to_vec(),
                    ),
                    kind,
                    subkey,
                    next_nonce: 1,
                    next_payload_len,
                },
            });
        }

        bail!("failed to match Shadowsocks TCP user")
    }

    pub async fn pump_to_plain<W>(
        self,
        mut writer: W,
        control: Arc<SessionControl>,
    ) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self.state {
            TcpReaderState::None { mut inner } => {
                pump_raw_stream(&mut inner, &mut writer, control).await
            }
            TcpReaderState::Legacy {
                mut inner,
                kind,
                subkey,
                mut next_nonce,
                mut next_payload_len,
            } => loop {
                let payload_ciphertext = inner
                    .read_exact(payload_len_with_tag(next_payload_len))
                    .await
                    .with_context(|| {
                        format!("read Shadowsocks TCP payload chunk ({next_payload_len} bytes)")
                    })?;
                let payload = decrypt_legacy(
                    kind,
                    &subkey,
                    &legacy_nonce(kind, next_nonce),
                    &payload_ciphertext,
                )
                .context("decrypt Shadowsocks TCP payload chunk")?;
                next_nonce += 1;
                if !payload.is_empty() {
                    tokio::select! {
                        _ = control.cancelled() => return Ok(()),
                        result = writer.write_all(&payload) => result.context("write decrypted Shadowsocks TCP payload")?,
                    }
                }

                let Some(length_ciphertext) =
                    inner.read_exact_or_eof(LEGACY_LENGTH_CHUNK_LEN).await?
                else {
                    let _ = writer.shutdown().await;
                    return Ok(());
                };
                let length_plaintext = decrypt_legacy(
                    kind,
                    &subkey,
                    &legacy_nonce(kind, next_nonce),
                    &length_ciphertext,
                )
                .context("decrypt Shadowsocks TCP length chunk")?;
                next_nonce += 1;
                ensure!(
                    length_plaintext.len() == 2,
                    "invalid Shadowsocks TCP length chunk size {}",
                    length_plaintext.len()
                );
                next_payload_len =
                    u16::from_be_bytes([length_plaintext[0], length_plaintext[1]]) as usize;
                ensure!(
                    next_payload_len <= MAX_TCP_CHUNK_LEN,
                    "Shadowsocks TCP payload length {next_payload_len} exceeds limit {MAX_TCP_CHUNK_LEN}"
                );
            },
        }
    }
}

impl<R> PrefixedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(inner: R, prefetched: Vec<u8>) -> Self {
        Self {
            inner,
            prefetched: prefetched.into_iter().collect(),
        }
    }

    async fn read_exact(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            if let Some(byte) = self.prefetched.pop_front() {
                data.push(byte);
                continue;
            }
            let remaining = len - data.len();
            let mut tail = vec![0u8; remaining];
            self.inner
                .read_exact(&mut tail)
                .await
                .context("read Shadowsocks TCP continuation")?;
            data.extend_from_slice(&tail);
        }
        Ok(data)
    }

    async fn read_exact_or_eof(&mut self, len: usize) -> anyhow::Result<Option<Vec<u8>>> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            if let Some(byte) = self.prefetched.pop_front() {
                data.push(byte);
                continue;
            }
            let mut tail = vec![0u8; len - data.len()];
            match self.inner.read(&mut tail).await {
                Ok(0) if data.is_empty() => return Ok(None),
                Ok(0) => bail!(
                    "unexpected EOF while reading Shadowsocks TCP chunk: wanted {len}, got {}",
                    data.len()
                ),
                Ok(read) => data.extend_from_slice(&tail[..read]),
                Err(error) => return Err(error).context("read Shadowsocks TCP chunk"),
            }
        }
        Ok(Some(data))
    }
}

pub async fn pump_plain_to_tcp<R, W>(
    credential: &UserCredential,
    mut reader: R,
    mut writer: W,
    control: Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match credential.method {
        Method::None => pump_raw_stream(&mut reader, &mut writer, control).await,
        Method::Legacy(kind) => {
            let salt = random_bytes(kind.salt_len())?;
            let subkey = derive_legacy_subkey(&credential.secret, &salt, kind.key_len())?;
            let mut next_nonce = 0u64;
            let mut sent_header = false;
            let mut buffer = vec![0u8; MAX_TCP_CHUNK_LEN];
            loop {
                let read = tokio::select! {
                    _ = control.cancelled() => return Ok(()),
                    read = reader.read(&mut buffer) => read.context("read Shadowsocks plain response")?,
                };
                if read == 0 {
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
                let length_plaintext = (read as u16).to_be_bytes();
                let length_ciphertext = encrypt_legacy(
                    kind,
                    &subkey,
                    &legacy_nonce(kind, next_nonce),
                    &length_plaintext,
                )
                .context("encrypt Shadowsocks TCP length chunk")?;
                next_nonce += 1;
                let payload_ciphertext = encrypt_legacy(
                    kind,
                    &subkey,
                    &legacy_nonce(kind, next_nonce),
                    &buffer[..read],
                )
                .context("encrypt Shadowsocks TCP payload chunk")?;
                next_nonce += 1;
                let mut output = Vec::with_capacity(
                    usize::from(!sent_header) * salt.len()
                        + length_ciphertext.len()
                        + payload_ciphertext.len(),
                );
                if !sent_header {
                    output.extend_from_slice(&salt);
                    sent_header = true;
                }
                output.extend_from_slice(&length_ciphertext);
                output.extend_from_slice(&payload_ciphertext);
                tokio::select! {
                    _ = control.cancelled() => return Ok(()),
                    result = writer.write_all(&output) => result.context("write encrypted Shadowsocks TCP response")?,
                }
            }
        }
        Method::Aead2022(_) => bail!("Shadowsocks 2022 TCP encoder must be handled separately"),
    }
}

pub fn decode_udp_packet(
    packet: &[u8],
    users: &[UserCredential],
) -> anyhow::Result<DecodedUdpPacket> {
    ensure!(!users.is_empty(), "no Shadowsocks users configured");
    if let Some(user) = users.iter().find(|user| user.method.is_none()) {
        ensure!(
            users.len() == 1,
            "Shadowsocks none cipher does not support multi-user"
        );
        let (destination, offset) = parse_socks_addr(packet)?;
        return Ok(DecodedUdpPacket {
            credential: user.clone(),
            destination,
            payload: packet[offset..].to_vec(),
            wire_len: packet.len(),
        });
    }

    for user in users {
        let Method::Legacy(kind) = user.method else {
            continue;
        };
        let salt_len = kind.salt_len();
        if packet.len() <= salt_len + LEGACY_TAG_LEN {
            continue;
        }
        let salt = &packet[..salt_len];
        let subkey = derive_legacy_subkey(&user.secret, salt, salt_len)?;
        let plaintext =
            match decrypt_legacy(kind, &subkey, &legacy_nonce(kind, 0), &packet[salt_len..]) {
                Ok(plaintext) => plaintext,
                Err(_) => continue,
            };
        let (destination, offset) = parse_socks_addr(&plaintext)?;
        return Ok(DecodedUdpPacket {
            credential: user.clone(),
            destination,
            payload: plaintext[offset..].to_vec(),
            wire_len: packet.len(),
        });
    }

    bail!("failed to match Shadowsocks UDP user")
}

pub fn encode_udp_packet(
    credential: &UserCredential,
    destination: &SocksAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut plain = Vec::with_capacity(address_wire_len(destination) + payload.len());
    write_socks_addr(&mut plain, destination)?;
    plain.extend_from_slice(payload);

    match credential.method {
        Method::None => Ok(plain),
        Method::Legacy(kind) => {
            let salt = random_bytes(kind.salt_len())?;
            let subkey = derive_legacy_subkey(&credential.secret, &salt, kind.key_len())?;
            let ciphertext = encrypt_legacy(kind, &subkey, &legacy_nonce(kind, 0), &plain)
                .context("encrypt Shadowsocks UDP packet")?;
            let mut encoded = salt;
            encoded.extend_from_slice(&ciphertext);
            Ok(encoded)
        }
        Method::Aead2022(_) => bail!("Shadowsocks 2022 UDP encoder must be handled separately"),
    }
}

pub fn effective_password(user: &PanelUser) -> Option<&str> {
    let password = user.password.trim();
    if !password.is_empty() {
        return Some(password);
    }
    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return Some(uuid);
    }
    None
}

fn derive_secret(method: &Method, password: &str) -> anyhow::Result<Vec<u8>> {
    Ok(match method {
        Method::None => Vec::new(),
        Method::Legacy(kind) => password_to_cipher_key(password.as_bytes(), kind.key_len()),
        Method::Aead2022(_) => {
            bail!("Shadowsocks 2022 users must be built with explicit server/user keys")
        }
    })
}

fn derive_legacy_subkey(secret: &[u8], salt: &[u8], out_len: usize) -> anyhow::Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), secret);
    let mut subkey = vec![0u8; out_len];
    hkdf.expand(b"ss-subkey", &mut subkey)
        .map_err(|_| anyhow!("derive Shadowsocks subkey"))?;
    Ok(subkey)
}

fn encrypt_legacy(
    kind: LegacyAeadMethod,
    subkey: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match kind {
        LegacyAeadMethod::Aes128Gcm => encrypt_boring_symm(
            Cipher::aes_128_gcm(),
            subkey,
            nonce,
            plaintext,
            "aes-128-gcm",
        ),
        LegacyAeadMethod::Aes192Gcm => encrypt_boring_symm(
            Cipher::aes_192_gcm(),
            subkey,
            nonce,
            plaintext,
            "aes-192-gcm",
        ),
        LegacyAeadMethod::Aes256Gcm => encrypt_boring_symm(
            Cipher::aes_256_gcm(),
            subkey,
            nonce,
            plaintext,
            "aes-256-gcm",
        ),
        LegacyAeadMethod::ChaCha20Poly1305 => encrypt_boring_aead(
            Algorithm::chacha20_poly1305(),
            subkey,
            nonce,
            plaintext,
            "chacha20-ietf-poly1305",
        ),
        LegacyAeadMethod::XChaCha20Poly1305 => encrypt_boring_aead(
            Algorithm::xchacha20_poly1305(),
            subkey,
            nonce,
            plaintext,
            "xchacha20-ietf-poly1305",
        ),
    }
}

fn decrypt_legacy(
    kind: LegacyAeadMethod,
    subkey: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match kind {
        LegacyAeadMethod::Aes128Gcm => decrypt_boring_symm(
            Cipher::aes_128_gcm(),
            subkey,
            nonce,
            ciphertext,
            "aes-128-gcm",
        ),
        LegacyAeadMethod::Aes192Gcm => decrypt_boring_symm(
            Cipher::aes_192_gcm(),
            subkey,
            nonce,
            ciphertext,
            "aes-192-gcm",
        ),
        LegacyAeadMethod::Aes256Gcm => decrypt_boring_symm(
            Cipher::aes_256_gcm(),
            subkey,
            nonce,
            ciphertext,
            "aes-256-gcm",
        ),
        LegacyAeadMethod::ChaCha20Poly1305 => decrypt_boring_aead(
            Algorithm::chacha20_poly1305(),
            subkey,
            nonce,
            ciphertext,
            "chacha20-ietf-poly1305",
        ),
        LegacyAeadMethod::XChaCha20Poly1305 => decrypt_boring_aead(
            Algorithm::xchacha20_poly1305(),
            subkey,
            nonce,
            ciphertext,
            "xchacha20-ietf-poly1305",
        ),
    }
}

fn encrypt_boring_symm(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut tag = [0u8; LEGACY_TAG_LEN];
    let mut ciphertext = symm::encrypt_aead(cipher, key, Some(nonce), &[], plaintext, &mut tag)
        .with_context(|| format!("encrypt {name}"))?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_boring_symm(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= LEGACY_TAG_LEN,
        "ciphertext too short for {name}: {}",
        ciphertext.len()
    );
    let split = ciphertext.len() - LEGACY_TAG_LEN;
    let (data, tag) = ciphertext.split_at(split);
    symm::decrypt_aead(cipher, key, Some(nonce), &[], data, tag)
        .with_context(|| format!("decrypt {name}"))
}

fn encrypt_boring_aead(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    let ctx = AeadCtx::new_default_tag(&algorithm, key).with_context(|| format!("init {name}"))?;
    let mut buffer = plaintext.to_vec();
    let mut tag = vec![0u8; algorithm.max_overhead()];
    let tag = ctx
        .seal_in_place(nonce, &mut buffer, &mut tag, &[])
        .with_context(|| format!("encrypt {name}"))?;
    buffer.extend_from_slice(tag);
    Ok(buffer)
}

fn decrypt_boring_aead(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    let ctx = AeadCtx::new_default_tag(&algorithm, key).with_context(|| format!("init {name}"))?;
    let tag_len = algorithm.max_overhead();
    ensure!(
        ciphertext.len() >= tag_len,
        "ciphertext too short for {name}: {}",
        ciphertext.len()
    );
    let split = ciphertext.len() - tag_len;
    let (data, tag) = ciphertext.split_at(split);
    let mut buffer = data.to_vec();
    ctx.open_in_place(nonce, &mut buffer, tag, &[])
        .with_context(|| format!("decrypt {name}"))?;
    Ok(buffer)
}

fn legacy_nonce(kind: LegacyAeadMethod, counter: u64) -> Vec<u8> {
    let mut nonce = vec![0u8; kind.nonce_len()];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn payload_len_with_tag(payload_len: usize) -> usize {
    payload_len + LEGACY_TAG_LEN
}

pub(crate) fn random_bytes(len: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    boring::rand::rand_bytes(&mut bytes).context("generate random bytes")?;
    Ok(bytes)
}

pub(crate) fn parse_socks_addr(packet: &[u8]) -> anyhow::Result<(SocksAddr, usize)> {
    ensure!(!packet.is_empty(), "missing Shadowsocks address type");
    match packet[0] {
        ATYP_IPV4 => {
            ensure!(packet.len() >= 7, "short Shadowsocks IPv4 address");
            let ip = Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]);
            let port = u16::from_be_bytes([packet[5], packet[6]]);
            Ok((SocksAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        ATYP_IPV6 => {
            ensure!(packet.len() >= 19, "short Shadowsocks IPv6 address");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[1..17]);
            let port = u16::from_be_bytes([packet[17], packet[18]]);
            Ok((
                SocksAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        ATYP_DOMAIN => {
            ensure!(packet.len() >= 2, "short Shadowsocks domain header");
            let len = packet[1] as usize;
            ensure!(
                packet.len() >= 2 + len + 2,
                "short Shadowsocks domain address"
            );
            let host = String::from_utf8(packet[2..2 + len].to_vec())
                .context("decode Shadowsocks domain")?;
            let port = u16::from_be_bytes([packet[2 + len], packet[3 + len]]);
            Ok((SocksAddr::Domain(host, port), 2 + len + 2))
        }
        other => bail!("unsupported Shadowsocks address type {other:#x}"),
    }
}

pub(crate) fn write_socks_addr(
    buffer: &mut Vec<u8>,
    destination: &SocksAddr,
) -> anyhow::Result<()> {
    match destination {
        SocksAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buffer.push(ATYP_IPV4);
                buffer.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buffer.push(ATYP_IPV6);
                buffer.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain(host, _) => {
            let host = host.as_bytes();
            ensure!(
                host.len() <= u8::MAX as usize,
                "Shadowsocks domain too long"
            );
            buffer.push(ATYP_DOMAIN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host);
        }
    }
    let port = match destination {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

pub(crate) fn address_wire_len(destination: &SocksAddr) -> usize {
    match destination {
        SocksAddr::Ip(addr) if addr.is_ipv4() => 1 + 4 + 2,
        SocksAddr::Ip(_) => 1 + 16 + 2,
        SocksAddr::Domain(host, _) => 1 + 1 + host.len() + 2,
    }
}

fn password_to_cipher_key(password: &[u8], key_len: usize) -> Vec<u8> {
    if key_len == 0 {
        return Vec::new();
    }

    let mut key = Vec::with_capacity(key_len);
    let mut last = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        if !last.is_empty() {
            hasher.update(&last);
        }
        hasher.update(password);
        last = hasher.finalize().to_vec();
        key.extend_from_slice(&last);
    }
    key.truncate(key_len);
    key
}

async fn pump_raw_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => match read {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
                Err(error) => return Err(error).context("read raw Shadowsocks stream"),
            },
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&buffer[..read]) => match result {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) => return Ok(()),
                Err(error) => return Err(error).context("write raw Shadowsocks stream"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::PanelUser;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn build_user(method: Method) -> UserCredential {
        UserCredential::from_panel_user(
            &PanelUser {
                id: 1,
                password: "test-password".to_string(),
                ..Default::default()
            },
            method,
        )
        .expect("build user")
    }

    fn encode_tcp_request(
        credential: &UserCredential,
        destination: &SocksAddr,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut plain = Vec::new();
        write_socks_addr(&mut plain, destination)?;
        plain.extend_from_slice(payload);
        match credential.method {
            Method::None => Ok(plain),
            Method::Legacy(kind) => {
                let salt = vec![7u8; kind.salt_len()];
                let subkey = derive_legacy_subkey(&credential.secret, &salt, kind.key_len())?;
                let mut packet = salt;
                let len = (plain.len() as u16).to_be_bytes();
                packet.extend_from_slice(&encrypt_legacy(
                    kind,
                    &subkey,
                    &legacy_nonce(kind, 0),
                    &len,
                )?);
                packet.extend_from_slice(&encrypt_legacy(
                    kind,
                    &subkey,
                    &legacy_nonce(kind, 1),
                    &plain,
                )?);
                Ok(packet)
            }
            Method::Aead2022(_) => bail!("test helper does not support Shadowsocks 2022"),
        }
    }

    #[test]
    fn parses_supported_methods() {
        assert_eq!(Method::parse("none"), Some(Method::None));
        assert_eq!(Method::parse("plain"), Some(Method::None));
        assert_eq!(
            Method::parse("aes-128-gcm"),
            Some(Method::Legacy(LegacyAeadMethod::Aes128Gcm))
        );
        assert_eq!(
            Method::parse("aead_aes_128_gcm"),
            Some(Method::Legacy(LegacyAeadMethod::Aes128Gcm))
        );
        assert_eq!(
            Method::parse("chacha20-ietf-poly1305"),
            Some(Method::Legacy(LegacyAeadMethod::ChaCha20Poly1305))
        );
        assert_eq!(
            Method::parse("chacha20-poly1305"),
            Some(Method::Legacy(LegacyAeadMethod::ChaCha20Poly1305))
        );
        assert_eq!(
            Method::parse("xchacha20-poly1305"),
            Some(Method::Legacy(LegacyAeadMethod::XChaCha20Poly1305))
        );
        assert_eq!(
            Method::parse("2022-blake3-aes-128-gcm"),
            Some(Method::Aead2022(Aead2022Method::Aes128Gcm))
        );
        assert_eq!(
            Method::parse("2022-blake3-chacha20-poly1305"),
            Some(Method::Aead2022(Aead2022Method::ChaCha20Poly1305))
        );
    }

    #[test]
    fn udp_roundtrip_for_aead_cipher() {
        let user = build_user(Method::Legacy(LegacyAeadMethod::Aes128Gcm));
        let encoded = encode_udp_packet(
            &user,
            &SocksAddr::Domain("example.com".to_string(), 443),
            b"hello",
        )
        .expect("encode udp");
        let decoded = decode_udp_packet(&encoded, &[user]).expect("decode udp");
        assert_eq!(
            decoded.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn udp_roundtrip_for_none_cipher() {
        let user = build_user(Method::None);
        let encoded = encode_udp_packet(
            &user,
            &SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 53))),
            b"abc",
        )
        .expect("encode udp");
        let decoded = decode_udp_packet(&encoded, &[user]).expect("decode udp");
        assert_eq!(
            decoded.destination,
            SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 53)))
        );
        assert_eq!(decoded.payload, b"abc");
    }

    #[tokio::test]
    async fn accepts_and_decrypts_tcp_request() {
        let user = build_user(Method::Legacy(LegacyAeadMethod::ChaCha20Poly1305));
        let request = encode_tcp_request(
            &user,
            &SocksAddr::Domain("example.com".to_string(), 80),
            b"payload",
        )
        .expect("encode tcp");

        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(&request).await.expect("write request");
        client.shutdown().await.expect("shutdown client");

        let accepted = AcceptedTcpReader::accept(server, &[user])
            .await
            .expect("accept tcp");
        let control = SessionControl::new();
        let (mut plain_reader, plain_writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            accepted
                .pump_to_plain(plain_writer, control)
                .await
                .expect("pump plain");
        });

        let destination = SocksAddr::read_from(&mut plain_reader)
            .await
            .expect("read destination");
        assert_eq!(
            destination,
            SocksAddr::Domain("example.com".to_string(), 80)
        );
        let mut payload = Vec::new();
        plain_reader
            .read_to_end(&mut payload)
            .await
            .expect("read payload");
        assert_eq!(payload, b"payload");
    }
}
