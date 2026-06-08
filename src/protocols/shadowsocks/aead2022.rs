mod keys;
mod replay;
mod udp;

use anyhow::{Context, anyhow, bail, ensure};
use boring::aead::{AeadCtx, Algorithm};
use boring::symm::{self, Cipher, Crypter, Mode};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::accounting::SessionControl;
use crate::protocols::shared::socksaddr::SocksAddr;

use super::crypto::{
    Aead2022Method, UserCredential, address_wire_len, parse_socks_addr, random_bytes,
    write_socks_addr,
};
pub(crate) use keys::{decode_server_psk, derive_user_psk, identity_hash};
use replay::SlidingWindow;
pub(crate) use replay::TcpReplayCache;
pub(crate) use udp::{decode_udp_request_body, encode_udp_response, identify_udp_request};

const TAG_LEN: usize = 16;
const MAX_TCP_CHUNK_LEN: usize = 0xffff;
const UDP_CHACHA_NONCE_LEN: usize = 24;
const REQUEST_FIXED_HEADER_LEN: usize = 1 + 8 + 2;
const HEADER_TYPE_CLIENT: u8 = 0;
const HEADER_TYPE_SERVER: u8 = 1;
const HEADER_TYPE_CLIENT_ENCRYPTED: u8 = 10;
const HEADER_TYPE_SERVER_ENCRYPTED: u8 = 11;
const TLS_RECORD_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TIMESTAMP_TOLERANCE_SECS: i64 = 30;

#[derive(Debug, Clone)]
pub(crate) struct TcpResponseContext {
    pub(crate) request_salt: Vec<u8>,
    encrypted_protocol: bool,
}

pub(crate) struct AcceptedTcpReader<R> {
    credential: UserCredential,
    inner: R,
    method: Aead2022Method,
    session_key: Vec<u8>,
    next_nonce: u64,
    plain_prefix: Vec<u8>,
    encrypted_protocol: bool,
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

fn has_identity_header(users: &[UserCredential], method: Aead2022Method) -> bool {
    users.len() > 1 && !matches!(method, Aead2022Method::ChaCha20Poly1305)
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
        let encrypted_protocol = match fixed_plain[0] {
            HEADER_TYPE_CLIENT => false,
            HEADER_TYPE_CLIENT_ENCRYPTED => true,
            other => bail!("unexpected Shadowsocks 2022 TCP header type {other}"),
        };
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
            encrypted_protocol,
            response_context: TcpResponseContext {
                request_salt: salt.to_vec(),
                encrypted_protocol,
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
        if self.encrypted_protocol {
            self.pump_encrypted_to_plain(&mut writer, control).await?;
            return Ok(());
        }

        if !self.plain_prefix.is_empty() {
            tokio::select! {
                _ = control.cancelled() => return Ok(()),
                result = writer.write_all(&self.plain_prefix) => result.context("write decrypted Shadowsocks 2022 TCP header")?,
            }
        }

        loop {
            let chunk = tokio::select! {
                _ = control.cancelled() => return Ok(()),
                chunk = self.read_plain_chunk() => chunk?,
            };
            let Some(payload) = chunk else {
                let _ = writer.shutdown().await;
                return Ok(());
            };
            if !payload.is_empty() {
                tokio::select! {
                    _ = control.cancelled() => return Ok(()),
                    result = writer.write_all(&payload) => result.context("write decrypted Shadowsocks 2022 TCP payload")?,
                }
            }
        }
    }
}

impl<R> AcceptedTcpReader<R>
where
    R: AsyncRead + Unpin,
{
    async fn read_plain_chunk(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(length_ciphertext) = read_exact_or_eof(&mut self.inner, 2 + TAG_LEN).await? else {
            return Ok(None);
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
        Ok(Some(payload))
    }

    async fn pump_encrypted_to_plain<W>(
        &mut self,
        writer: &mut W,
        control: Arc<SessionControl>,
    ) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if !self.plain_prefix.is_empty() {
            tokio::select! {
                _ = control.cancelled() => return Ok(()),
                result = writer.write_all(&self.plain_prefix) => result.context("write decrypted Shadowsocks 2022 encrypted TCP prefix")?,
            }
            self.plain_prefix.clear();
        }

        loop {
            let chunk = tokio::select! {
                _ = control.cancelled() => return Ok(()),
                chunk = self.read_plain_chunk() => chunk?,
            };
            let Some(record_header) = chunk else {
                let _ = writer.shutdown().await;
                return Ok(());
            };
            ensure!(
                record_header.len() == TLS_RECORD_HEADER_LEN,
                "invalid Shadowsocks 2022 encrypted TCP TLS record header length {}",
                record_header.len()
            );
            let record_type = record_header[0];
            let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
            tokio::select! {
                _ = control.cancelled() => return Ok(()),
                result = writer.write_all(&record_header) => result.context("write decrypted Shadowsocks 2022 encrypted TCP TLS record header")?,
            }

            if record_type == TLS_RECORD_TYPE_APPLICATION_DATA {
                let mut raw_payload = vec![0u8; record_len];
                tokio::select! {
                    _ = control.cancelled() => return Ok(()),
                    result = self.inner.read_exact(&mut raw_payload) => result.context("read Shadowsocks 2022 encrypted TCP raw TLS application payload")?,
                };
                tokio::select! {
                    _ = control.cancelled() => return Ok(()),
                    result = writer.write_all(&raw_payload) => result.context("write decrypted Shadowsocks 2022 encrypted TCP raw TLS application payload")?,
                }
                continue;
            }

            let chunk = tokio::select! {
                _ = control.cancelled() => return Ok(()),
                chunk = self.read_plain_chunk() => chunk?,
            };
            let Some(payload) = chunk else {
                bail!(
                    "unexpected EOF while reading Shadowsocks 2022 encrypted TCP TLS record body"
                );
            };
            ensure!(
                payload.len() == record_len,
                "invalid Shadowsocks 2022 encrypted TCP TLS record body length {} expected {}",
                payload.len(),
                record_len
            );
            tokio::select! {
                _ = control.cancelled() => return Ok(()),
                result = writer.write_all(&payload) => result.context("write decrypted Shadowsocks 2022 encrypted TCP TLS record body")?,
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

    if response_context.encrypted_protocol {
        return pump_plain_to_encrypted_tcp(
            response_context,
            method,
            response_salt,
            session_key,
            next_nonce,
            reader,
            writer,
            control,
        )
        .await;
    }

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

async fn pump_plain_to_encrypted_tcp<R, W>(
    response_context: &TcpResponseContext,
    method: Aead2022Method,
    response_salt: Vec<u8>,
    session_key: Vec<u8>,
    mut next_nonce: u64,
    mut reader: R,
    mut writer: W,
    control: Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(mut record_header) = read_exact_or_eof(&mut reader, TLS_RECORD_HEADER_LEN).await?
    else {
        let _ = writer.shutdown().await;
        return Ok(());
    };

    let mut fixed_plain = Vec::with_capacity(1 + 8 + response_context.request_salt.len() + 2);
    fixed_plain.push(HEADER_TYPE_SERVER_ENCRYPTED);
    fixed_plain.extend_from_slice(&(current_unix_time()? as u64).to_be_bytes());
    fixed_plain.extend_from_slice(&response_context.request_salt);
    fixed_plain.extend_from_slice(&0u16.to_be_bytes());

    let mut output = Vec::with_capacity(response_salt.len() + fixed_plain.len() + TAG_LEN);
    output.extend_from_slice(&response_salt);
    output.extend_from_slice(&encrypt_tcp_chunk(
        method,
        &session_key,
        next_nonce,
        &fixed_plain,
        "Shadowsocks 2022 encrypted TCP response fixed header",
    )?);
    next_nonce += 1;
    tokio::select! {
        _ = control.cancelled() => return Ok(()),
        result = writer.write_all(&output) => result.context("write Shadowsocks 2022 encrypted TCP response header")?,
    }

    loop {
        write_tls_record_to_encrypted_tcp(
            method,
            &session_key,
            &mut next_nonce,
            record_header,
            &mut reader,
            &mut writer,
            &control,
        )
        .await?;

        let next = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            record_header = read_exact_or_eof(&mut reader, TLS_RECORD_HEADER_LEN) => record_header?,
        };
        let Some(next) = next else {
            let _ = writer.shutdown().await;
            return Ok(());
        };
        record_header = next;
    }
}

async fn write_tls_record_to_encrypted_tcp<R, W>(
    method: Aead2022Method,
    session_key: &[u8],
    next_nonce: &mut u64,
    record_header: Vec<u8>,
    reader: &mut R,
    writer: &mut W,
    control: &Arc<SessionControl>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    ensure!(
        record_header.len() == TLS_RECORD_HEADER_LEN,
        "invalid Shadowsocks 2022 encrypted TCP TLS record header length {}",
        record_header.len()
    );
    let record_type = record_header[0];
    let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    write_tcp_stream_chunk(
        method,
        session_key,
        next_nonce,
        &record_header,
        writer,
        control,
        "Shadowsocks 2022 encrypted TCP TLS record header",
    )
    .await?;

    let mut record_payload = vec![0u8; record_len];
    tokio::select! {
        _ = control.cancelled() => return Ok(()),
        result = reader.read_exact(&mut record_payload) => result.context("read Shadowsocks 2022 encrypted TCP TLS record body")?,
    };
    if record_type == TLS_RECORD_TYPE_APPLICATION_DATA {
        tokio::select! {
            _ = control.cancelled() => return Ok(()),
            result = writer.write_all(&record_payload) => result.context("write Shadowsocks 2022 encrypted TCP raw TLS application payload")?,
        }
    } else {
        write_tcp_stream_chunk(
            method,
            session_key,
            next_nonce,
            &record_payload,
            writer,
            control,
            "Shadowsocks 2022 encrypted TCP TLS record body",
        )
        .await?;
    }
    Ok(())
}

async fn write_tcp_stream_chunk<W>(
    method: Aead2022Method,
    session_key: &[u8],
    next_nonce: &mut u64,
    payload: &[u8],
    writer: &mut W,
    control: &Arc<SessionControl>,
    context: &str,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        payload.len() <= MAX_TCP_CHUNK_LEN,
        "Shadowsocks 2022 TCP payload length {} exceeds limit {}",
        payload.len(),
        MAX_TCP_CHUNK_LEN
    );
    let length_ciphertext = encrypt_tcp_chunk(
        method,
        session_key,
        *next_nonce,
        &(payload.len() as u16).to_be_bytes(),
        "Shadowsocks 2022 TCP length chunk",
    )?;
    *next_nonce += 1;
    let payload_ciphertext = encrypt_tcp_chunk(method, session_key, *next_nonce, payload, context)?;
    *next_nonce += 1;
    tokio::select! {
        _ = control.cancelled() => return Ok(()),
        result = writer.write_all(&length_ciphertext) => result.context("write Shadowsocks 2022 TCP length chunk")?,
    }
    tokio::select! {
        _ = control.cancelled() => return Ok(()),
        result = writer.write_all(&payload_ciphertext) => result.with_context(|| format!("write {context}"))?,
    }
    Ok(())
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
mod tests;
