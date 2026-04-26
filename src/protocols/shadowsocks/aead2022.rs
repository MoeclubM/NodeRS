use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::aead::{AeadCtx, Algorithm};
use boring::symm::{self, Cipher, Crypter, Mode};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::accounting::SessionControl;
use crate::panel::PanelUser;
use crate::protocols::anytls::socksaddr::SocksAddr;

use super::crypto::{
    Aead2022Method, UserCredential, address_wire_len, parse_socks_addr, random_bytes,
    write_socks_addr,
};

const TAG_LEN: usize = 16;
const MAX_TCP_CHUNK_LEN: usize = 0xffff;
const UDP_CHACHA_NONCE_LEN: usize = 24;
const REQUEST_FIXED_HEADER_LEN: usize = 1 + 8 + 2;
const HEADER_TYPE_CLIENT: u8 = 0;
const HEADER_TYPE_SERVER: u8 = 1;
const TIMESTAMP_TOLERANCE_SECS: i64 = 30;
const TCP_REPLAY_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub(crate) struct TcpResponseContext {
    pub(crate) request_salt: Vec<u8>,
}

#[derive(Clone, Default)]
pub(crate) struct TcpReplayCache {
    inner: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
}

pub(crate) struct AcceptedTcpReader<R> {
    credential: UserCredential,
    inner: R,
    method: Aead2022Method,
    session_key: Vec<u8>,
    next_nonce: u64,
    plain_prefix: Vec<u8>,
    response_context: TcpResponseContext,
}

#[derive(Debug, Clone)]
pub(crate) struct UdpIdentification {
    pub(crate) credential: UserCredential,
    packet_header: [u8; 16],
    pub(crate) client_session_id: u64,
    client_packet_id: u64,
    pub(crate) wire_len: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedUdpPacket {
    pub(crate) destination: SocksAddr,
    pub(crate) payload: Vec<u8>,
    pub(crate) wire_len: usize,
}

pub(crate) struct UdpSession {
    pub(crate) credential: UserCredential,
    pub(crate) client_session_id: u64,
    server_session_id: u64,
    inbound_key: Vec<u8>,
    outbound_key: Vec<u8>,
    replay_window: SlidingWindow,
    next_server_packet_id: u64,
}

struct SlidingWindow {
    last: u64,
    ring: [u64; 128],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0u64; 128],
        }
    }
}

pub(crate) fn decode_server_psk(value: &str, method: Aead2022Method) -> anyhow::Result<Vec<u8>> {
    decode_psk(value, method.key_len())
}

pub(crate) fn derive_user_psk(user: &PanelUser, method: Aead2022Method) -> anyhow::Result<Vec<u8>> {
    let key_len = method.key_len();
    let password = user.password.trim();
    if !password.is_empty() {
        if let Ok(decoded) = STANDARD.decode(password) {
            if decoded.len() >= key_len {
                return Ok(normalize_psk(&decoded, key_len)?);
            }
        }

        return Ok(fixed_length_raw_key(password.as_bytes(), key_len));
    }

    let uuid = user.uuid.trim();
    if !uuid.is_empty() {
        return Ok(fixed_length_raw_key(uuid.as_bytes(), key_len));
    }

    bail!("Shadowsocks 2022 user {} is missing password/uuid", user.id)
}

pub(crate) fn identity_hash(psk: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(psk);
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&hash.as_bytes()[..16]);
    truncated
}

fn has_identity_header(users: &[UserCredential], method: Aead2022Method) -> bool {
    let _ = users;
    !matches!(method, Aead2022Method::ChaCha20Poly1305)
}

impl TcpReplayCache {
    pub(crate) fn accept(&self, salt: &[u8]) -> bool {
        let now = Instant::now();
        let mut guard = self
            .inner
            .lock()
            .expect("Shadowsocks 2022 TCP replay cache lock poisoned");
        guard.retain(|_, seen_at| now.duration_since(*seen_at) <= TCP_REPLAY_TTL);
        if guard.contains_key(salt) {
            return false;
        }
        guard.insert(salt.to_vec(), now);
        true
    }
}

impl<R> AcceptedTcpReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn credential(&self) -> &UserCredential {
        &self.credential
    }

    pub(crate) fn response_context(&self) -> TcpResponseContext {
        self.response_context.clone()
    }

    pub(crate) async fn accept(
        mut inner: R,
        users: &[UserCredential],
        replay: &TcpReplayCache,
    ) -> anyhow::Result<Self> {
        ensure!(!users.is_empty(), "no Shadowsocks users configured");
        let method = match users[0].method {
            super::crypto::Method::Aead2022(method) => method,
            _ => bail!("internal Shadowsocks 2022 method mismatch"),
        };
        let key_len = method.key_len();
        let identity_len = usize::from(has_identity_header(users, method)) * 16;
        let prefix_len = key_len + identity_len + REQUEST_FIXED_HEADER_LEN + TAG_LEN;
        let mut prefix = vec![0u8; prefix_len];
        inner
            .read_exact(&mut prefix)
            .await
            .context("read Shadowsocks 2022 TCP prefix")?;

        let salt = &prefix[..key_len];
        ensure!(
            replay.accept(salt),
            "duplicate Shadowsocks 2022 request salt"
        );
        let (credential, encrypted_identity_len) = if has_identity_header(users, method) {
            let encrypted_identity = &prefix[key_len..key_len + 16];
            let server_secret = &users[0].server_secret;
            ensure!(
                !server_secret.is_empty(),
                "Shadowsocks 2022 server key is not configured"
            );
            let identity = decrypt_identity_header(server_secret, salt, encrypted_identity)
                .context("decrypt Shadowsocks 2022 identity header")?;
            let credential = users
                .iter()
                .find(|user| user.identity_hash == identity)
                .cloned()
                .ok_or_else(|| anyhow!("failed to match Shadowsocks 2022 TCP user"))?;
            (credential, 16usize)
        } else {
            (users[0].clone(), 0usize)
        };

        let session_key = session_subkey(&credential.secret, salt, key_len);
        let fixed_plain = decrypt_tcp_chunk(
            method,
            &session_key,
            0,
            &prefix[key_len + encrypted_identity_len..],
            "Shadowsocks 2022 TCP fixed header",
        )?;
        ensure!(
            fixed_plain.len() == REQUEST_FIXED_HEADER_LEN,
            "invalid Shadowsocks 2022 TCP fixed header length {}",
            fixed_plain.len()
        );
        ensure!(
            fixed_plain[0] == HEADER_TYPE_CLIENT,
            "unexpected Shadowsocks 2022 TCP header type {}",
            fixed_plain[0]
        );
        let timestamp = u64::from_be_bytes(fixed_plain[1..9].try_into().expect("timestamp slice"));
        validate_timestamp(timestamp)?;
        let variable_len =
            u16::from_be_bytes(fixed_plain[9..11].try_into().expect("length slice")) as usize;
        let mut variable_ciphertext = vec![0u8; variable_len + TAG_LEN];
        inner
            .read_exact(&mut variable_ciphertext)
            .await
            .with_context(|| {
                format!("read Shadowsocks 2022 TCP variable header ({variable_len} bytes)")
            })?;
        let variable_plain = decrypt_tcp_chunk(
            method,
            &session_key,
            1,
            &variable_ciphertext,
            "Shadowsocks 2022 TCP variable header",
        )?;
        let (destination, offset) = parse_socks_addr(&variable_plain)?;
        ensure!(
            variable_plain.len() >= offset + 2,
            "short Shadowsocks 2022 TCP padding length"
        );
        let padding_len = u16::from_be_bytes(
            variable_plain[offset..offset + 2]
                .try_into()
                .expect("padding length slice"),
        ) as usize;
        ensure!(
            variable_plain.len() >= offset + 2 + padding_len,
            "short Shadowsocks 2022 TCP padding"
        );
        let initial_payload = &variable_plain[offset + 2 + padding_len..];
        ensure!(
            padding_len > 0 || !initial_payload.is_empty(),
            "Shadowsocks 2022 TCP request header requires payload or padding"
        );

        let mut plain_prefix =
            Vec::with_capacity(address_wire_len(&destination) + initial_payload.len());
        write_socks_addr(&mut plain_prefix, &destination)?;
        plain_prefix.extend_from_slice(initial_payload);

        Ok(Self {
            credential,
            inner,
            method,
            session_key,
            next_nonce: 2,
            plain_prefix,
            response_context: TcpResponseContext {
                request_salt: salt.to_vec(),
            },
        })
    }

    pub(crate) async fn pump_to_plain<W>(
        mut self,
        mut writer: W,
        control: Arc<SessionControl>,
    ) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if !self.plain_prefix.is_empty() {
            tokio::select! {
                _ = control.cancelled() => return Ok(()),
                result = writer.write_all(&self.plain_prefix) => result.context("write decrypted Shadowsocks 2022 TCP header")?,
            }
        }

        loop {
            let Some(length_ciphertext) = read_exact_or_eof(&mut self.inner, 2 + TAG_LEN).await?
            else {
                let _ = writer.shutdown().await;
                return Ok(());
            };
            let length_plain = decrypt_tcp_chunk(
                self.method,
                &self.session_key,
                self.next_nonce,
                &length_ciphertext,
                "Shadowsocks 2022 TCP length chunk",
            )?;
            self.next_nonce += 1;
            ensure!(
                length_plain.len() == 2,
                "invalid Shadowsocks 2022 TCP length chunk size {}",
                length_plain.len()
            );
            let payload_len =
                u16::from_be_bytes(length_plain[..2].try_into().expect("length bytes")) as usize;
            ensure!(
                payload_len <= MAX_TCP_CHUNK_LEN,
                "Shadowsocks 2022 TCP payload length {payload_len} exceeds limit {MAX_TCP_CHUNK_LEN}"
            );
            let mut payload_ciphertext = vec![0u8; payload_len + TAG_LEN];
            self.inner
                .read_exact(&mut payload_ciphertext)
                .await
                .with_context(|| {
                    format!("read Shadowsocks 2022 TCP payload chunk ({payload_len} bytes)")
                })?;
            let payload = decrypt_tcp_chunk(
                self.method,
                &self.session_key,
                self.next_nonce,
                &payload_ciphertext,
                "Shadowsocks 2022 TCP payload chunk",
            )?;
            self.next_nonce += 1;
            if !payload.is_empty() {
                tokio::select! {
                    _ = control.cancelled() => return Ok(()),
                    result = writer.write_all(&payload) => result.context("write decrypted Shadowsocks 2022 TCP payload")?,
                }
            }
        }
    }
}

pub(crate) async fn pump_plain_to_tcp<R, W>(
    credential: &UserCredential,
    response_context: &TcpResponseContext,
    mut reader: R,
    mut writer: W,
    control: Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let method = match credential.method {
        super::crypto::Method::Aead2022(method) => method,
        _ => bail!("internal Shadowsocks 2022 method mismatch"),
    };
    let key_len = method.key_len();
    let response_salt = random_bytes(key_len)?;
    let session_key = session_subkey(&credential.secret, &response_salt, key_len);
    let mut next_nonce = 0u64;
    let mut sent_header = false;
    let mut buffer = vec![0u8; MAX_TCP_CHUNK_LEN];

    loop {
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => read.context("read Shadowsocks 2022 plain response")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }

        if !sent_header {
            let mut fixed_plain =
                Vec::with_capacity(1 + 8 + response_context.request_salt.len() + 2);
            fixed_plain.push(HEADER_TYPE_SERVER);
            fixed_plain.extend_from_slice(&(current_unix_time()? as u64).to_be_bytes());
            fixed_plain.extend_from_slice(&response_context.request_salt);
            fixed_plain.extend_from_slice(&(read as u16).to_be_bytes());

            let mut output = Vec::with_capacity(
                response_salt.len() + fixed_plain.len() + TAG_LEN + read + TAG_LEN,
            );
            output.extend_from_slice(&response_salt);
            output.extend_from_slice(&encrypt_tcp_chunk(
                method,
                &session_key,
                next_nonce,
                &fixed_plain,
                "Shadowsocks 2022 TCP response fixed header",
            )?);
            next_nonce += 1;
            output.extend_from_slice(&encrypt_tcp_chunk(
                method,
                &session_key,
                next_nonce,
                &buffer[..read],
                "Shadowsocks 2022 TCP response first payload",
            )?);
            next_nonce += 1;
            tokio::select! {
                _ = control.cancelled() => return Ok(()),
                result = writer.write_all(&output) => result.context("write Shadowsocks 2022 TCP response header")?,
            }
            sent_header = true;
            continue;
        }

        let length_ciphertext = encrypt_tcp_chunk(
            method,
            &session_key,
            next_nonce,
            &(read as u16).to_be_bytes(),
            "Shadowsocks 2022 TCP response length chunk",
        )?;
        next_nonce += 1;
        let payload_ciphertext = encrypt_tcp_chunk(
            method,
            &session_key,
            next_nonce,
            &buffer[..read],
            "Shadowsocks 2022 TCP response payload chunk",
        )?;
        next_nonce += 1;
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&length_ciphertext) => result.context("write Shadowsocks 2022 TCP response length chunk")?,
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&payload_ciphertext) => result.context("write Shadowsocks 2022 TCP response payload chunk")?,
        }
    }
}

pub(crate) fn identify_udp_request(
    packet: &[u8],
    users: &[UserCredential],
) -> anyhow::Result<UdpIdentification> {
    ensure!(!users.is_empty(), "no Shadowsocks users configured");
    let method = match users[0].method {
        super::crypto::Method::Aead2022(method) => method,
        _ => bail!("internal Shadowsocks 2022 method mismatch"),
    };
    match method {
        Aead2022Method::ChaCha20Poly1305 => identify_udp_request_chacha(packet, users),
        _ => identify_udp_request_aes(packet, users),
    }
}

impl UdpSession {
    pub(crate) fn new(identified: &UdpIdentification) -> anyhow::Result<Self> {
        let method = match identified.credential.method {
            super::crypto::Method::Aead2022(method) => method,
            _ => bail!("internal Shadowsocks 2022 method mismatch"),
        };
        let server_session_id = u64::from_be_bytes(
            random_bytes(8)?
                .as_slice()
                .try_into()
                .expect("server session id bytes"),
        );
        Ok(Self {
            credential: identified.credential.clone(),
            client_session_id: identified.client_session_id,
            server_session_id,
            inbound_key: if matches!(method, Aead2022Method::ChaCha20Poly1305) {
                identified.credential.secret.clone()
            } else {
                session_subkey(
                    &identified.credential.secret,
                    &identified.client_session_id.to_be_bytes(),
                    method.key_len(),
                )
            },
            outbound_key: if matches!(method, Aead2022Method::ChaCha20Poly1305) {
                identified.credential.secret.clone()
            } else {
                session_subkey(
                    &identified.credential.secret,
                    &server_session_id.to_be_bytes(),
                    method.key_len(),
                )
            },
            replay_window: SlidingWindow::default(),
            next_server_packet_id: 0,
        })
    }
}

pub(crate) fn decode_udp_request_body(
    packet: &[u8],
    identified: &UdpIdentification,
    session: &mut UdpSession,
) -> anyhow::Result<DecodedUdpPacket> {
    ensure!(
        session.client_session_id == identified.client_session_id,
        "Shadowsocks 2022 UDP session id mismatch"
    );
    ensure!(
        session.credential.user.id == identified.credential.user.id,
        "Shadowsocks 2022 UDP user mismatch"
    );
    ensure!(
        session.replay_window.check(identified.client_packet_id),
        "duplicate Shadowsocks 2022 UDP packet id {}",
        identified.client_packet_id
    );

    let method = match session.credential.method {
        super::crypto::Method::Aead2022(method) => method,
        _ => bail!("internal Shadowsocks 2022 method mismatch"),
    };
    let plain = match method {
        Aead2022Method::ChaCha20Poly1305 => decrypt_packet_body(
            method,
            &session.credential.secret,
            &packet[..UDP_CHACHA_NONCE_LEN],
            &packet[UDP_CHACHA_NONCE_LEN..],
            "decrypt Shadowsocks 2022 UDP payload",
        )?,
        _ => decrypt_packet_body(
            method,
            &session.inbound_key,
            &identified.packet_header[4..16],
            &packet[32..],
            "decrypt Shadowsocks 2022 UDP payload",
        )?,
    };
    ensure!(
        plain.len() >= 1 + 8 + 2,
        "short Shadowsocks 2022 UDP payload"
    );
    let (header, destination_bytes) = match method {
        Aead2022Method::ChaCha20Poly1305 => {
            ensure!(
                plain.len() >= 16 + 1 + 8 + 2,
                "short Shadowsocks 2022 UDP payload"
            );
            (&plain[16..], &plain[27..])
        }
        _ => (&plain[..], &plain[11..]),
    };
    ensure!(
        header[0] == HEADER_TYPE_CLIENT,
        "unexpected Shadowsocks 2022 UDP header type {}",
        header[0]
    );
    let timestamp = u64::from_be_bytes(header[1..9].try_into().expect("timestamp"));
    validate_timestamp(timestamp)?;
    let padding_len =
        u16::from_be_bytes(header[9..11].try_into().expect("padding length")) as usize;
    ensure!(
        destination_bytes.len() >= padding_len,
        "short Shadowsocks 2022 UDP padding"
    );
    let (destination, offset) = parse_socks_addr(&destination_bytes[padding_len..])?;
    let payload = destination_bytes[padding_len + offset..].to_vec();
    session.replay_window.add(identified.client_packet_id);
    Ok(DecodedUdpPacket {
        destination,
        payload,
        wire_len: identified.wire_len,
    })
}

pub(crate) fn encode_udp_response(
    session: &mut UdpSession,
    destination: &SocksAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let method = match session.credential.method {
        super::crypto::Method::Aead2022(method) => method,
        _ => bail!("internal Shadowsocks 2022 method mismatch"),
    };
    let packet_id = session.next_server_packet_id;
    session.next_server_packet_id = session.next_server_packet_id.wrapping_add(1);

    if matches!(method, Aead2022Method::ChaCha20Poly1305) {
        return encode_udp_response_chacha(session, destination, payload);
    }

    let mut header_plain = [0u8; 16];
    header_plain[..8].copy_from_slice(&session.server_session_id.to_be_bytes());
    header_plain[8..].copy_from_slice(&packet_id.to_be_bytes());
    let encrypted_header = ecb_crypt(
        &session.credential.secret,
        &header_plain,
        true,
        "encrypt Shadowsocks 2022 UDP response header",
    )?;

    let mut body_plain =
        Vec::with_capacity(1 + 8 + 8 + 2 + address_wire_len(destination) + payload.len());
    body_plain.push(HEADER_TYPE_SERVER);
    body_plain.extend_from_slice(&(current_unix_time()? as u64).to_be_bytes());
    body_plain.extend_from_slice(&session.client_session_id.to_be_bytes());
    body_plain.extend_from_slice(&0u16.to_be_bytes());
    write_socks_addr(&mut body_plain, destination)?;
    body_plain.extend_from_slice(payload);

    let body = encrypt_packet_body(
        method,
        &session.outbound_key,
        &header_plain[4..16],
        &body_plain,
        "encrypt Shadowsocks 2022 UDP response payload",
    )?;

    let mut packet = Vec::with_capacity(encrypted_header.len() + body.len());
    packet.extend_from_slice(&encrypted_header);
    packet.extend_from_slice(&body);
    Ok(packet)
}

impl SlidingWindow {
    fn check(&self, counter: u64) -> bool {
        const BLOCK_BITS: u64 = 64;
        const RING_BLOCKS: u64 = 128;
        const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS;

        if counter > self.last {
            return true;
        }
        if self.last - counter > WINDOW_SIZE {
            return false;
        }

        let block_index = ((counter >> 6) & (RING_BLOCKS - 1)) as usize;
        let bit_index = (counter & (BLOCK_BITS - 1)) as usize;
        (self.ring[block_index] >> bit_index) & 1 == 0
    }

    fn add(&mut self, counter: u64) {
        const BLOCK_BITS: u64 = 64;
        const RING_BLOCKS: u64 = 128;
        const RING_MASK: u64 = RING_BLOCKS - 1;

        let block_index = counter >> 6;
        if counter > self.last {
            let mut last_block_index = self.last >> 6;
            let mut diff = block_index.saturating_sub(last_block_index);
            if diff > RING_BLOCKS {
                diff = RING_BLOCKS;
            }
            for _ in 0..diff {
                last_block_index = (last_block_index + 1) & RING_MASK;
                self.ring[last_block_index as usize] = 0;
            }
            self.last = counter;
        }
        let ring_index = (block_index & RING_MASK) as usize;
        let bit_index = (counter & (BLOCK_BITS - 1)) as usize;
        self.ring[ring_index] |= 1u64 << bit_index;
    }
}

fn decode_psk(value: &str, key_len: usize) -> anyhow::Result<Vec<u8>> {
    let value = value.trim();
    ensure!(!value.is_empty(), "Shadowsocks 2022 key is required");
    let decoded = STANDARD
        .decode(value)
        .context("decode Shadowsocks 2022 key")?;
    normalize_psk(&decoded, key_len)
}

fn identify_udp_request_aes(
    packet: &[u8],
    users: &[UserCredential],
) -> anyhow::Result<UdpIdentification> {
    let method = match users[0].method {
        super::crypto::Method::Aead2022(method) => method,
        _ => bail!("internal Shadowsocks 2022 method mismatch"),
    };
    ensure!(!matches!(method, Aead2022Method::ChaCha20Poly1305));
    let has_identity = has_identity_header(users, method);
    let min_len = 16 + usize::from(has_identity) * 16 + TAG_LEN;
    ensure!(packet.len() > min_len, "short Shadowsocks 2022 UDP packet");

    let server_secret = &users[0].server_secret;
    ensure!(
        !server_secret.is_empty(),
        "Shadowsocks 2022 server key is not configured"
    );

    let mut packet_header = [0u8; 16];
    packet_header.copy_from_slice(&packet[..16]);
    packet_header = ecb_crypt(
        server_secret,
        &packet_header,
        false,
        "decrypt Shadowsocks 2022 UDP header",
    )?;

    let credential = if has_identity {
        let mut encrypted_identity = [0u8; 16];
        encrypted_identity.copy_from_slice(&packet[16..32]);
        let mut identity = ecb_crypt(
            server_secret,
            &encrypted_identity,
            false,
            "decrypt Shadowsocks 2022 UDP identity header",
        )?;
        xor_in_place(&mut identity, &packet_header);
        users
            .iter()
            .find(|user| user.identity_hash == identity)
            .cloned()
            .ok_or_else(|| anyhow!("failed to match Shadowsocks 2022 UDP user"))?
    } else {
        users[0].clone()
    };
    let client_session_id = u64::from_be_bytes(packet_header[..8].try_into().expect("session id"));
    let client_packet_id = u64::from_be_bytes(packet_header[8..].try_into().expect("packet id"));

    Ok(UdpIdentification {
        credential,
        packet_header,
        client_session_id,
        client_packet_id,
        wire_len: packet.len(),
    })
}

fn identify_udp_request_chacha(
    packet: &[u8],
    users: &[UserCredential],
) -> anyhow::Result<UdpIdentification> {
    ensure!(
        packet.len() > UDP_CHACHA_NONCE_LEN + TAG_LEN,
        "short Shadowsocks 2022 UDP packet"
    );
    ensure!(
        users.len() == 1,
        "Shadowsocks 2022 chacha20-poly1305 does not support multi-user"
    );

    let credential = users[0].clone();
    let method = match credential.method {
        super::crypto::Method::Aead2022(method) => method,
        _ => bail!("internal Shadowsocks 2022 method mismatch"),
    };
    ensure!(matches!(method, Aead2022Method::ChaCha20Poly1305));

    let plain = decrypt_packet_body(
        method,
        &credential.secret,
        &packet[..UDP_CHACHA_NONCE_LEN],
        &packet[UDP_CHACHA_NONCE_LEN..],
        "decrypt Shadowsocks 2022 UDP payload",
    )?;
    ensure!(plain.len() >= 16, "short Shadowsocks 2022 UDP payload");

    let client_session_id = u64::from_be_bytes(plain[..8].try_into().expect("session id"));
    let client_packet_id = u64::from_be_bytes(plain[8..16].try_into().expect("packet id"));
    let mut packet_header = [0u8; 16];
    packet_header.copy_from_slice(&plain[..16]);

    Ok(UdpIdentification {
        credential,
        packet_header,
        client_session_id,
        client_packet_id,
        wire_len: packet.len(),
    })
}

fn fixed_length_raw_key(bytes: &[u8], key_len: usize) -> Vec<u8> {
    let mut raw = vec![0u8; key_len];
    let copy_len = bytes.len().min(key_len);
    raw[..copy_len].copy_from_slice(&bytes[..copy_len]);
    raw
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

fn decrypt_identity_header(
    server_secret: &[u8],
    salt: &[u8],
    encrypted_identity: &[u8],
) -> anyhow::Result<[u8; 16]> {
    let key = identity_subkey(server_secret, salt, server_secret.len());
    let mut block = [0u8; 16];
    block.copy_from_slice(encrypted_identity);
    ecb_crypt(
        &key,
        &block,
        false,
        "decrypt Shadowsocks 2022 identity header",
    )
}

fn session_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key("shadowsocks 2022 session subkey", &material);
    derived[..key_len].to_vec()
}

fn identity_subkey(server_psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(server_psk.len() + salt.len());
    material.extend_from_slice(server_psk);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
    derived[..key_len].to_vec()
}

fn validate_timestamp(timestamp: u64) -> anyhow::Result<()> {
    let now = current_unix_time()?;
    let diff = now.abs_diff(timestamp as i64);
    ensure!(
        diff <= TIMESTAMP_TOLERANCE_SECS as u64,
        "invalid Shadowsocks 2022 timestamp {timestamp}"
    );
    Ok(())
}

fn current_unix_time() -> anyhow::Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs() as i64)
}

fn decrypt_tcp_chunk(
    method: Aead2022Method,
    key: &[u8],
    nonce_counter: u64,
    ciphertext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    decrypt_packet_body(method, key, &nonce(nonce_counter), ciphertext, context)
}

fn encrypt_tcp_chunk(
    method: Aead2022Method,
    key: &[u8],
    nonce_counter: u64,
    plaintext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    encrypt_packet_body(method, key, &nonce(nonce_counter), plaintext, context)
}

fn encrypt_packet_body(
    method: Aead2022Method,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    match method {
        Aead2022Method::Aes128Gcm => {
            encrypt_boring_symm(Cipher::aes_128_gcm(), key, nonce, plaintext, context)
        }
        Aead2022Method::Aes256Gcm => {
            encrypt_boring_symm(Cipher::aes_256_gcm(), key, nonce, plaintext, context)
        }
        Aead2022Method::ChaCha20Poly1305 => {
            let algorithm = match nonce.len() {
                12 => Algorithm::chacha20_poly1305(),
                24 => Algorithm::xchacha20_poly1305(),
                other => {
                    bail!("unsupported chacha nonce length {other} for {context}");
                }
            };
            encrypt_boring_aead(algorithm, key, nonce, plaintext, context)
        }
    }
}

fn decrypt_packet_body(
    method: Aead2022Method,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    match method {
        Aead2022Method::Aes128Gcm => {
            decrypt_boring_symm(Cipher::aes_128_gcm(), key, nonce, ciphertext, context)
        }
        Aead2022Method::Aes256Gcm => {
            decrypt_boring_symm(Cipher::aes_256_gcm(), key, nonce, ciphertext, context)
        }
        Aead2022Method::ChaCha20Poly1305 => {
            let algorithm = match nonce.len() {
                12 => Algorithm::chacha20_poly1305(),
                24 => Algorithm::xchacha20_poly1305(),
                other => {
                    bail!("unsupported chacha nonce length {other} for {context}");
                }
            };
            decrypt_boring_aead(algorithm, key, nonce, ciphertext, context)
        }
    }
}

fn encrypt_boring_symm(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut tag = [0u8; TAG_LEN];
    let mut ciphertext = symm::encrypt_aead(cipher, key, Some(nonce), &[], plaintext, &mut tag)
        .with_context(|| context.to_string())?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_boring_symm(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= TAG_LEN,
        "ciphertext too short for {context}: {}",
        ciphertext.len()
    );
    let split = ciphertext.len() - TAG_LEN;
    let (data, tag) = ciphertext.split_at(split);
    symm::decrypt_aead(cipher, key, Some(nonce), &[], data, tag)
        .with_context(|| context.to_string())
}

fn encrypt_boring_aead(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    let ctx = AeadCtx::new_default_tag(&algorithm, key).with_context(|| context.to_string())?;
    let mut buffer = plaintext.to_vec();
    let mut tag = vec![0u8; algorithm.max_overhead()];
    let tag = ctx
        .seal_in_place(nonce, &mut buffer, &mut tag, &[])
        .with_context(|| context.to_string())?;
    buffer.extend_from_slice(tag);
    Ok(buffer)
}

fn decrypt_boring_aead(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    context: &str,
) -> anyhow::Result<Vec<u8>> {
    let ctx = AeadCtx::new_default_tag(&algorithm, key).with_context(|| context.to_string())?;
    let tag_len = algorithm.max_overhead();
    ensure!(
        ciphertext.len() >= tag_len,
        "ciphertext too short for {context}: {}",
        ciphertext.len()
    );
    let split = ciphertext.len() - tag_len;
    let (data, tag) = ciphertext.split_at(split);
    let mut buffer = data.to_vec();
    ctx.open_in_place(nonce, &mut buffer, tag, &[])
        .with_context(|| context.to_string())?;
    Ok(buffer)
}

fn encode_udp_response_chacha(
    session: &mut UdpSession,
    destination: &SocksAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let nonce = random_bytes(UDP_CHACHA_NONCE_LEN)?;
    let packet_id = session.next_server_packet_id;
    session.next_server_packet_id = session.next_server_packet_id.wrapping_add(1);

    let mut body_plain =
        Vec::with_capacity(8 + 8 + 1 + 8 + 8 + 2 + address_wire_len(destination) + payload.len());
    body_plain.extend_from_slice(&session.server_session_id.to_be_bytes());
    body_plain.extend_from_slice(&packet_id.to_be_bytes());
    body_plain.push(HEADER_TYPE_SERVER);
    body_plain.extend_from_slice(&(current_unix_time()? as u64).to_be_bytes());
    body_plain.extend_from_slice(&session.client_session_id.to_be_bytes());
    body_plain.extend_from_slice(&0u16.to_be_bytes());
    write_socks_addr(&mut body_plain, destination)?;
    body_plain.extend_from_slice(payload);

    let body = encrypt_packet_body(
        Aead2022Method::ChaCha20Poly1305,
        &session.credential.secret,
        &nonce,
        &body_plain,
        "encrypt Shadowsocks 2022 UDP response payload",
    )?;
    let mut packet = nonce;
    packet.extend_from_slice(&body);
    Ok(packet)
}

fn ecb_crypt(
    key: &[u8],
    input: &[u8; 16],
    encrypt: bool,
    context: &str,
) -> anyhow::Result<[u8; 16]> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_ecb(),
        32 => Cipher::aes_256_ecb(),
        other => bail!("unsupported Shadowsocks 2022 ECB key length {other}"),
    };
    let mode = if encrypt {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };
    let mut crypter = Crypter::new(cipher, mode, key, None).with_context(|| context.to_string())?;
    crypter.pad(false);
    let mut output = [0u8; 32];
    let mut written = crypter
        .update(input, &mut output)
        .with_context(|| context.to_string())?;
    written += crypter
        .finalize(&mut output[written..])
        .with_context(|| context.to_string())?;
    ensure!(
        written == 16,
        "unexpected Shadowsocks 2022 ECB output size {written}"
    );
    let mut block = [0u8; 16];
    block.copy_from_slice(&output[..16]);
    Ok(block)
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn xor_in_place(target: &mut [u8; 16], other: &[u8; 16]) {
    for (byte, other) in target.iter_mut().zip(other.iter()) {
        *byte ^= *other;
    }
}

async fn read_exact_or_eof<R>(reader: &mut R, len: usize) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut data = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match reader.read(&mut data[filled..]).await {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                bail!(
                    "unexpected EOF while reading Shadowsocks 2022 TCP chunk: wanted {len}, got {filled}"
                )
            }
            Ok(read) => filled += read,
            Err(error) => return Err(error).context("read Shadowsocks 2022 TCP chunk"),
        }
    }
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::UserEntry;
    use crate::protocols::shadowsocks::crypto::Method;

    fn sample_credential(method: Aead2022Method) -> UserCredential {
        let secret = derive_user_psk(
            &PanelUser {
                id: 1,
                password: "12345678-1234-1234-1234-123456789abc".to_string(),
                uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
                ..Default::default()
            },
            method,
        )
        .expect("user psk");
        let server_psk = match method {
            Aead2022Method::Aes128Gcm => "QUJDREVGR0hJSktMTU5PUA==",
            Aead2022Method::Aes256Gcm | Aead2022Method::ChaCha20Poly1305 => {
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
            }
        };
        UserCredential {
            user: UserEntry {
                id: 1,
                uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
                password_sha256: [0u8; 32],
                device_limit: 0,
            },
            method: super::super::crypto::Method::Aead2022(method),
            secret: secret.clone(),
            server_secret: decode_server_psk(server_psk, method).expect("server psk"),
            identity_hash: identity_hash(&secret),
        }
    }

    #[test]
    fn derives_user_key_from_uuid_prefix() {
        let key = derive_user_psk(
            &PanelUser {
                id: 1,
                uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
                ..Default::default()
            },
            Aead2022Method::Aes128Gcm,
        )
        .expect("key");
        assert_eq!(key, b"12345678-1234-12");
    }

    #[test]
    fn derives_user_key_from_password_prefix_when_present() {
        let key = derive_user_psk(
            &PanelUser {
                id: 1,
                password: "password-based-key-material".to_string(),
                uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
                ..Default::default()
            },
            Aead2022Method::Aes128Gcm,
        )
        .expect("key");
        assert_eq!(key, b"password-based-k");
    }

    #[test]
    fn derives_user_key_from_base64_password() {
        let key = derive_user_psk(
            &PanelUser {
                id: 1,
                password: "MTIzNDU2Nzg5MEFCQ0RFRg==".to_string(),
                ..Default::default()
            },
            Aead2022Method::Aes128Gcm,
        )
        .expect("key");
        assert_eq!(key, b"1234567890ABCDEF");
    }

    #[test]
    fn treats_uuid_as_raw_material_instead_of_base64() {
        let key = derive_user_psk(
            &PanelUser {
                id: 1,
                uuid: "1234567890abcdef1234567890abcdef".to_string(),
                ..Default::default()
            },
            Aead2022Method::Aes128Gcm,
        )
        .expect("key");
        assert_eq!(key, b"1234567890abcdef");
    }

    #[test]
    fn accepts_large_tcp_chunk_lengths() {
        assert_eq!(MAX_TCP_CHUNK_LEN, u16::MAX as usize);
    }

    #[test]
    fn sliding_window_rejects_duplicate_counter() {
        let mut window = SlidingWindow::default();
        assert!(window.check(7));
        window.add(7);
        assert!(!window.check(7));
        assert!(window.check(8));
    }

    #[test]
    fn udp_response_packet_has_expected_header_shape() {
        let credential = sample_credential(Aead2022Method::Aes128Gcm);
        let identified = UdpIdentification {
            credential: credential.clone(),
            packet_header: [0u8; 16],
            client_session_id: 9,
            client_packet_id: 0,
            wire_len: 0,
        };
        let mut session = UdpSession::new(&identified).expect("session");
        let packet = encode_udp_response(
            &mut session,
            &SocksAddr::Domain("example.com".to_string(), 443),
            b"hello",
        )
        .expect("packet");
        assert!(packet.len() > 16 + TAG_LEN);
    }

    #[test]
    fn chacha_udp_identification_uses_nonce_prefixed_single_user_format() {
        let credential = sample_credential(Aead2022Method::ChaCha20Poly1305);
        let client_session_id = 9u64;
        let client_packet_id = 2u64;
        let nonce = vec![7u8; UDP_CHACHA_NONCE_LEN];

        let mut body_plain = Vec::new();
        body_plain.extend_from_slice(&client_session_id.to_be_bytes());
        body_plain.extend_from_slice(&client_packet_id.to_be_bytes());
        body_plain.push(HEADER_TYPE_CLIENT);
        body_plain.extend_from_slice(&(current_unix_time().expect("time") as u64).to_be_bytes());
        body_plain.extend_from_slice(&0u16.to_be_bytes());
        write_socks_addr(
            &mut body_plain,
            &SocksAddr::Domain("example.com".to_string(), 443),
        )
        .expect("addr");
        body_plain.extend_from_slice(b"hello");
        let body = encrypt_packet_body(
            Aead2022Method::ChaCha20Poly1305,
            &credential.secret,
            &nonce,
            &body_plain,
            "encrypt test udp body",
        )
        .expect("body");

        let mut packet = nonce;
        packet.extend_from_slice(&body);
        let identified =
            identify_udp_request(&packet, std::slice::from_ref(&credential)).expect("identify");
        assert_eq!(identified.client_session_id, client_session_id);
        assert_eq!(identified.client_packet_id, client_packet_id);
        assert_eq!(identified.credential.user.id, credential.user.id);
    }

    #[test]
    fn chacha_udp_response_uses_nonce_prefixed_format() {
        let credential = sample_credential(Aead2022Method::ChaCha20Poly1305);
        let identified = UdpIdentification {
            credential: credential.clone(),
            packet_header: [0u8; 16],
            client_session_id: 9,
            client_packet_id: 0,
            wire_len: 0,
        };
        let mut session = UdpSession::new(&identified).expect("session");
        let packet = encode_udp_response(
            &mut session,
            &SocksAddr::Domain("example.com".to_string(), 443),
            b"hello",
        )
        .expect("packet");
        assert!(packet.len() > UDP_CHACHA_NONCE_LEN + TAG_LEN);
    }

    #[test]
    fn chacha_tcp_accept_uses_single_user_format_without_identity_header() {
        let credential = sample_credential(Aead2022Method::ChaCha20Poly1305);
        let request_salt = vec![7u8; credential.secret.len()];
        let session_key =
            session_subkey(&credential.secret, &request_salt, credential.secret.len());

        let mut variable_plain = Vec::new();
        write_socks_addr(
            &mut variable_plain,
            &SocksAddr::Domain("example.com".to_string(), 443),
        )
        .expect("addr");
        variable_plain.extend_from_slice(&0u16.to_be_bytes());
        variable_plain.extend_from_slice(b"hello");
        let fixed_plain = {
            let mut bytes = Vec::new();
            bytes.push(HEADER_TYPE_CLIENT);
            bytes.extend_from_slice(&(current_unix_time().expect("time") as u64).to_be_bytes());
            bytes.extend_from_slice(&(variable_plain.len() as u16).to_be_bytes());
            bytes
        };

        let mut request = request_salt.clone();
        request.extend_from_slice(
            &encrypt_tcp_chunk(
                Aead2022Method::ChaCha20Poly1305,
                &session_key,
                0,
                &fixed_plain,
                "encrypt fixed",
            )
            .expect("fixed"),
        );
        request.extend_from_slice(
            &encrypt_tcp_chunk(
                Aead2022Method::ChaCha20Poly1305,
                &session_key,
                1,
                &variable_plain,
                "encrypt variable",
            )
            .expect("variable"),
        );

        let replay = TcpReplayCache::default();
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let accepted = runtime
            .block_on(AcceptedTcpReader::accept(
                std::io::Cursor::new(request),
                std::slice::from_ref(&credential),
                &replay,
            ))
            .expect("accept");
        assert_eq!(accepted.credential().user.id, credential.user.id);
    }

    #[test]
    fn parses_chacha_method() {
        assert!(matches!(
            Method::parse("2022-blake3-chacha20-poly1305"),
            Some(Method::Aead2022(Aead2022Method::ChaCha20Poly1305))
        ));
    }
}
