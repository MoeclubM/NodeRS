use anyhow::{Context, ensure};
use boring::asn1::{Asn1Integer, Asn1Time};
use boring::bn::BigNum;
use boring::derive::Deriver;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private, Public};
use boring::symm::{Cipher, decrypt_aead};
use boring::x509::{X509, X509NameBuilder};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityTlsConfig {
    pub server_name: String,
    pub server_port: u16,
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
}

pub struct RealityCertificateState {
    key: PKey<Private>,
    public_key: [u8; 32],
    certificate_template: Vec<u8>,
    signature_offset: usize,
}

impl RealityCertificateState {
    pub fn private_key(&self) -> &PKey<Private> {
        &self.key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawClientHello {
    pub prefix: Vec<u8>,
    pub handshake: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedClientHello {
    pub server_name: String,
    pub client_version: [u8; 4],
    pub client_time: u32,
    pub short_id: [u8; 8],
    pub auth_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloDetails {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub key_shares: Vec<ClientKeyShare>,
    pub alpn_protocols: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyShare {
    pub group: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedServerHello {
    pub prefix: Vec<u8>,
    pub cipher_suite: u16,
    pub key_share_group: u16,
    handshake: Vec<u8>,
    key_share_range: (usize, usize),
}

impl ObservedServerHello {
    pub fn curves_list(&self) -> Option<&'static str> {
        match self.key_share_group {
            29 => Some("X25519"),
            0x6399 => Some("X25519Kyber768Draft00"),
            0x11ec => Some("X25519MLKEM768"),
            _ => None,
        }
    }

    pub fn rewrite_key_share(&self, server_share: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (start, end) = self.key_share_range;
        ensure!(
            end >= start,
            "REALITY observed ServerHello key_share range is invalid"
        );
        ensure!(
            end <= self.handshake.len(),
            "REALITY observed ServerHello key_share range exceeds handshake"
        );
        ensure!(
            end - start == server_share.len(),
            "REALITY observed ServerHello key_share length mismatch"
        );
        let mut handshake = self.handshake.clone();
        handshake[start..end].copy_from_slice(server_share);
        Ok(handshake)
    }
}

pub async fn read_client_hello<R>(reader: &mut R) -> anyhow::Result<RawClientHello>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = Vec::new();
    let mut handshake = Vec::new();
    let mut total_handshake_len = None;

    loop {
        let mut record_header = [0u8; 5];
        reader
            .read_exact(&mut record_header)
            .await
            .context("read REALITY TLS record header")?;
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let mut record_payload = vec![0u8; record_len];
        reader
            .read_exact(&mut record_payload)
            .await
            .context("read REALITY TLS record payload")?;

        prefix.extend_from_slice(&record_header);
        prefix.extend_from_slice(&record_payload);

        ensure!(
            record_header[0] == 22,
            "REALITY expected initial TLS handshake record"
        );

        let mut payload = record_payload.as_slice();
        while !payload.is_empty() {
            let expected_len = match total_handshake_len {
                Some(expected_len) => expected_len,
                None => {
                    ensure!(
                        payload.len() >= 4,
                        "truncated REALITY ClientHello handshake header"
                    );
                    ensure!(
                        payload[0] == 1,
                        "REALITY expected ClientHello handshake message"
                    );
                    let declared_len = read_be_u24(payload, 1, "REALITY ClientHello length")?;
                    handshake.extend_from_slice(&payload[..4]);
                    payload = &payload[4..];
                    let expected_len = declared_len as usize + 4;
                    total_handshake_len = Some(expected_len);
                    expected_len
                }
            };

            let missing = expected_len.saturating_sub(handshake.len());
            let take = missing.min(payload.len());
            handshake.extend_from_slice(&payload[..take]);
            payload = &payload[take..];

            if handshake.len() == expected_len {
                return Ok(RawClientHello { prefix, handshake });
            }
        }
    }
}

pub async fn read_server_hello<R>(reader: &mut R) -> anyhow::Result<ObservedServerHello>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = Vec::new();
    let mut handshake = Vec::new();
    let mut total_handshake_len = None;

    loop {
        let mut record_header = [0u8; 5];
        reader
            .read_exact(&mut record_header)
            .await
            .context("read REALITY target TLS record header")?;
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let mut record_payload = vec![0u8; record_len];
        reader
            .read_exact(&mut record_payload)
            .await
            .context("read REALITY target TLS record payload")?;

        prefix.extend_from_slice(&record_header);
        prefix.extend_from_slice(&record_payload);

        ensure!(
            record_header[0] == 22,
            "REALITY target expected initial TLS handshake record"
        );

        let mut payload = record_payload.as_slice();
        while !payload.is_empty() {
            let expected_len = match total_handshake_len {
                Some(expected_len) => expected_len,
                None => {
                    ensure!(
                        payload.len() >= 4,
                        "truncated REALITY target ServerHello handshake header"
                    );
                    ensure!(
                        payload[0] == 2,
                        "REALITY target expected ServerHello handshake message"
                    );
                    let declared_len =
                        read_be_u24(payload, 1, "REALITY target ServerHello length")?;
                    handshake.extend_from_slice(&payload[..4]);
                    payload = &payload[4..];
                    let expected_len = declared_len as usize + 4;
                    total_handshake_len = Some(expected_len);
                    expected_len
                }
            };

            let missing = expected_len.saturating_sub(handshake.len());
            let take = missing.min(payload.len());
            handshake.extend_from_slice(&payload[..take]);
            payload = &payload[take..];

            if handshake.len() == expected_len {
                return parse_server_hello(prefix, &handshake);
            }
        }
    }
}

pub fn authenticate_client_hello(
    client_hello: &RawClientHello,
    config: &RealityTlsConfig,
) -> anyhow::Result<AuthenticatedClientHello> {
    let parsed = parse_client_hello(&client_hello.handshake)?;
    ensure!(
        server_name_allowed(config, &parsed.server_name),
        "REALITY ClientHello SNI {} does not match configured server_names {}",
        parsed.server_name,
        config.server_names.join(",")
    );

    let peer_public_key = parse_peer_public_key(parsed.key_share)?;
    let shared_key = derive_shared_key(config.private_key, peer_public_key)?;

    let hkdf = Hkdf::<Sha256>::new(Some(&parsed.random[..20]), &shared_key);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("derive REALITY auth key failed"))?;

    let mut aad = client_hello.handshake.clone();
    aad[parsed.session_start..parsed.session_start + parsed.session_id.len()].fill(0);

    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        &auth_key,
        Some(&parsed.random[20..]),
        &aad,
        &parsed.session_id[..16],
        &parsed.session_id[16..],
    )
    .context("decrypt REALITY session id")?;
    ensure!(
        plain.len() == 16,
        "REALITY decrypted session id prefix must be 16 bytes"
    );

    let mut client_version = [0u8; 4];
    client_version.copy_from_slice(&plain[..4]);
    let client_time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plain[8..16]);
    ensure!(
        config.short_ids.contains(&short_id),
        "REALITY ClientHello short_id {} does not match configured short_id",
        hex::encode(short_id)
    );

    Ok(AuthenticatedClientHello {
        server_name: parsed.server_name,
        client_version,
        client_time,
        short_id,
        auth_key,
    })
}

pub fn client_hello_details(client_hello: &RawClientHello) -> anyhow::Result<ClientHelloDetails> {
    let parsed = parse_client_hello(&client_hello.handshake)?;
    Ok(ClientHelloDetails {
        random: parsed.random,
        session_id: parsed.session_id.to_vec(),
        key_shares: parse_key_share_entries(parsed.key_share)?,
        alpn_protocols: match parsed.alpn {
            Some(alpn) => parse_alpn_protocols_extension(alpn)?,
            None => Vec::new(),
        },
    })
}

pub fn build_certificate_state() -> anyhow::Result<RealityCertificateState> {
    let key = PKey::generate(boring::pkey::Id::ED25519).context("generate REALITY Ed25519 key")?;
    let mut public_key = [0u8; 32];
    key.raw_public_key(&mut public_key)
        .context("read REALITY Ed25519 public key")?;

    let name = X509NameBuilder::new().context("create REALITY certificate name")?;
    let name = name.build();
    let serial_bn = BigNum::from_u32(0).context("REALITY serial")?;
    let serial = Asn1Integer::from_bn(&serial_bn).context("set REALITY serial")?;
    let not_before = Asn1Time::from_unix(0).context("set REALITY not_before")?;
    let not_after = Asn1Time::from_str("99991231235959Z").context("set REALITY not_after")?;

    let mut certificate = X509::builder().context("create REALITY certificate")?;
    certificate.set_version(2).context("set REALITY version")?;
    certificate
        .set_serial_number(&serial)
        .context("set REALITY serial")?;
    certificate
        .set_issuer_name(&name)
        .context("set REALITY issuer")?;
    certificate
        .set_subject_name(&name)
        .context("set REALITY subject")?;
    certificate
        .set_not_before(&not_before)
        .context("set REALITY not_before")?;
    certificate
        .set_not_after(&not_after)
        .context("set REALITY not_after")?;
    certificate
        .set_pubkey(&key)
        .context("set REALITY public key")?;
    let digest = unsafe { MessageDigest::from_ptr(std::ptr::null()) };
    certificate
        .sign(&key, digest)
        .context("sign REALITY certificate template")?;
    let certificate = certificate.build();
    let template_signature = certificate.signature().as_slice();
    let certificate_template = certificate
        .to_der()
        .context("encode REALITY certificate template")?;
    let signature_offset = certificate_template
        .windows(template_signature.len())
        .rposition(|window| window == template_signature)
        .context("find REALITY certificate signature offset")?;

    Ok(RealityCertificateState {
        key,
        public_key,
        certificate_template,
        signature_offset,
    })
}

pub fn build_server_certificate(
    cert_state: &RealityCertificateState,
    auth_key: &[u8; 32],
) -> anyhow::Result<X509> {
    let mut hmac =
        Hmac::<Sha512>::new_from_slice(auth_key).context("initialize REALITY certificate HMAC")?;
    hmac.update(&cert_state.public_key);
    let signature = hmac.finalize().into_bytes();

    let mut certificate = cert_state.certificate_template.clone();
    ensure!(
        cert_state.signature_offset + signature.len() <= certificate.len(),
        "REALITY certificate template is too short"
    );
    certificate[cert_state.signature_offset..cert_state.signature_offset + signature.len()]
        .copy_from_slice(&signature);
    X509::from_der(&certificate).context("parse REALITY certificate")
}

fn parse_server_hello(prefix: Vec<u8>, raw: &[u8]) -> anyhow::Result<ObservedServerHello> {
    ensure!(
        raw.len() >= 4 + 2 + 32 + 1,
        "truncated REALITY target ServerHello"
    );
    ensure!(
        raw[0] == 2,
        "REALITY target expected ServerHello handshake message"
    );
    let declared_len = read_be_u24(raw, 1, "REALITY target ServerHello length")? as usize;
    ensure!(
        declared_len + 4 == raw.len(),
        "REALITY target ServerHello length does not match payload"
    );

    let mut offset = 4;
    let legacy_version = read_be_u16(raw, offset, "REALITY target ServerHello legacy_version")?;
    ensure!(
        legacy_version == 0x0303,
        "REALITY target ServerHello legacy_version must be TLS 1.2"
    );
    offset += 2;

    ensure!(
        offset + 32 <= raw.len(),
        "truncated REALITY target ServerHello random"
    );
    offset += 32;

    ensure!(
        offset < raw.len(),
        "truncated REALITY target ServerHello session id length"
    );
    let session_len = raw[offset] as usize;
    offset += 1;
    ensure!(
        offset + session_len <= raw.len(),
        "truncated REALITY target ServerHello session id"
    );
    offset += session_len;

    let cipher_suite = read_be_u16(raw, offset, "REALITY target ServerHello cipher suite")?;
    ensure!(
        matches!(cipher_suite, 0x1301 | 0x1302 | 0x1303),
        "REALITY target selected unsupported TLS 1.3 cipher suite 0x{cipher_suite:04x}"
    );
    offset += 2;

    ensure!(
        offset < raw.len(),
        "truncated REALITY target ServerHello compression method"
    );
    ensure!(
        raw[offset] == 0,
        "REALITY target ServerHello compression method must be null"
    );
    offset += 1;

    let extensions_len =
        read_be_u16(raw, offset, "REALITY target ServerHello extensions length")? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    ensure!(
        extensions_end == raw.len(),
        "REALITY target ServerHello extensions length does not match payload"
    );

    let mut supports_tls13 = false;
    let mut key_share_group = None;
    let mut key_share_range = None;
    while offset < extensions_end {
        let extension_type = read_be_u16(raw, offset, "REALITY target ServerHello extension type")?;
        let extension_len = read_be_u16(
            raw,
            offset + 2,
            "REALITY target ServerHello extension length",
        )? as usize;
        let data_start = offset + 4;
        let data_end = data_start + extension_len;
        ensure!(
            data_end <= extensions_end,
            "truncated REALITY target ServerHello extension"
        );
        let data = &raw[data_start..data_end];

        match extension_type {
            43 => {
                supports_tls13 = parse_server_supported_versions_extension(data)?;
            }
            51 => {
                let (group, range) = parse_server_key_share_extension(data, data_start)?;
                key_share_group = Some(group);
                key_share_range = Some(range);
            }
            _ => {}
        }

        offset = data_end;
    }

    ensure!(
        supports_tls13,
        "REALITY target ServerHello must negotiate TLS 1.3"
    );

    Ok(ObservedServerHello {
        prefix,
        cipher_suite,
        key_share_group: key_share_group.context("REALITY target ServerHello missing key_share")?,
        handshake: raw.to_vec(),
        key_share_range: key_share_range.context("REALITY target ServerHello missing key_share")?,
    })
}

struct ParsedClientHello<'a> {
    server_name: String,
    random: [u8; 32],
    session_id: &'a [u8],
    session_start: usize,
    key_share: &'a [u8],
    alpn: Option<&'a [u8]>,
}

fn parse_client_hello(raw: &[u8]) -> anyhow::Result<ParsedClientHello<'_>> {
    ensure!(raw.len() >= 4 + 2 + 32 + 1, "truncated REALITY ClientHello");
    ensure!(
        raw[0] == 1,
        "REALITY expected ClientHello handshake message"
    );
    let declared_len = read_be_u24(raw, 1, "REALITY ClientHello length")? as usize;
    ensure!(
        declared_len + 4 == raw.len(),
        "REALITY ClientHello length does not match payload"
    );

    let mut offset = 4;
    let _legacy_version = read_be_u16(raw, offset, "REALITY ClientHello legacy_version")?;
    offset += 2;

    ensure!(
        offset + 32 <= raw.len(),
        "truncated REALITY ClientHello random"
    );
    let mut random = [0u8; 32];
    random.copy_from_slice(&raw[offset..offset + 32]);
    offset += 32;

    ensure!(
        offset < raw.len(),
        "truncated REALITY ClientHello session id length"
    );
    let session_len = raw[offset] as usize;
    offset += 1;
    let session_start = offset;
    let session_end = session_start + session_len;
    ensure!(
        session_end <= raw.len(),
        "truncated REALITY ClientHello session id"
    );
    let session_id = &raw[session_start..session_end];
    ensure!(
        session_id.len() == 32,
        "REALITY ClientHello session id must be 32 bytes"
    );
    offset = session_end;

    let cipher_suites_len =
        read_be_u16(raw, offset, "REALITY ClientHello cipher suites length")? as usize;
    offset += 2;
    ensure!(
        offset + cipher_suites_len <= raw.len(),
        "truncated REALITY ClientHello cipher suites"
    );
    offset += cipher_suites_len;

    ensure!(
        offset < raw.len(),
        "truncated REALITY ClientHello compression methods length"
    );
    let compression_methods_len = raw[offset] as usize;
    offset += 1;
    ensure!(
        offset + compression_methods_len <= raw.len(),
        "truncated REALITY ClientHello compression methods"
    );
    offset += compression_methods_len;

    let extensions_len =
        read_be_u16(raw, offset, "REALITY ClientHello extensions length")? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    ensure!(
        extensions_end == raw.len(),
        "REALITY ClientHello extensions length does not match payload"
    );

    let mut server_name = None;
    let mut key_share = None;
    let mut alpn = None;
    let mut supports_tls13 = false;
    while offset < extensions_end {
        let extension_type = read_be_u16(raw, offset, "REALITY ClientHello extension type")?;
        let extension_len =
            read_be_u16(raw, offset + 2, "REALITY ClientHello extension length")? as usize;
        let data_start = offset + 4;
        let data_end = data_start + extension_len;
        ensure!(
            data_end <= extensions_end,
            "truncated REALITY ClientHello extension"
        );
        let data = &raw[data_start..data_end];

        match extension_type {
            0 => {
                server_name = Some(parse_server_name_extension(data)?);
            }
            43 => {
                supports_tls13 = parse_supported_versions_extension(data)?;
            }
            13 => {
                parse_signature_algorithms_extension(data)?;
            }
            16 => {
                alpn = Some(data);
            }
            51 => {
                key_share = Some(data);
            }
            _ => {}
        }

        offset = data_end;
    }

    ensure!(supports_tls13, "REALITY ClientHello must support TLS 1.3");

    Ok(ParsedClientHello {
        server_name: server_name.context("REALITY ClientHello missing SNI")?,
        random,
        session_id,
        session_start,
        key_share: key_share.context("REALITY ClientHello missing key_share")?,
        alpn,
    })
}

fn parse_server_name_extension(bytes: &[u8]) -> anyhow::Result<String> {
    let list_len = read_be_u16(bytes, 0, "REALITY server_name list length")? as usize;
    ensure!(
        list_len + 2 == bytes.len(),
        "REALITY server_name list length does not match payload"
    );
    let mut offset = 2;
    while offset < bytes.len() {
        ensure!(
            offset + 3 <= bytes.len(),
            "truncated REALITY server_name entry"
        );
        let name_type = bytes[offset];
        let name_len = read_be_u16(bytes, offset + 1, "REALITY server_name length")? as usize;
        let name_start = offset + 3;
        let name_end = name_start + name_len;
        ensure!(
            name_end <= bytes.len(),
            "truncated REALITY server_name bytes"
        );
        if name_type == 0 {
            let server_name = std::str::from_utf8(&bytes[name_start..name_end])
                .context("decode REALITY server_name as UTF-8")?;
            ensure!(
                !server_name.is_empty(),
                "REALITY ClientHello SNI cannot be empty"
            );
            return Ok(server_name.to_string());
        }
        offset = name_end;
    }
    anyhow::bail!("REALITY ClientHello missing host_name SNI entry")
}

fn parse_supported_versions_extension(bytes: &[u8]) -> anyhow::Result<bool> {
    ensure!(
        !bytes.is_empty(),
        "truncated REALITY supported_versions extension"
    );
    let declared_len = bytes[0] as usize;
    ensure!(
        declared_len + 1 == bytes.len(),
        "REALITY supported_versions length does not match payload"
    );
    ensure!(
        declared_len % 2 == 0,
        "REALITY supported_versions payload must contain whole versions"
    );
    Ok(bytes[1..]
        .chunks_exact(2)
        .any(|version| version == [0x03, 0x04]))
}

fn parse_signature_algorithms_extension(bytes: &[u8]) -> anyhow::Result<()> {
    let declared_len = read_be_u16(bytes, 0, "REALITY signature_algorithms length")? as usize;
    ensure!(
        declared_len + 2 == bytes.len(),
        "REALITY signature_algorithms length does not match payload"
    );
    ensure!(
        declared_len % 2 == 0,
        "REALITY signature_algorithms payload must contain whole schemes"
    );
    Ok(())
}

fn parse_key_share_entries(key_share: &[u8]) -> anyhow::Result<Vec<ClientKeyShare>> {
    let declared_len = read_be_u16(key_share, 0, "REALITY key_share list length")? as usize;
    ensure!(
        declared_len + 2 == key_share.len(),
        "REALITY key_share list length does not match payload"
    );

    let mut offset = 2;
    let mut entries = Vec::new();
    while offset < key_share.len() {
        ensure!(
            offset + 4 <= key_share.len(),
            "truncated REALITY key_share entry"
        );
        let group = u16::from_be_bytes([key_share[offset], key_share[offset + 1]]);
        let data_len = u16::from_be_bytes([key_share[offset + 2], key_share[offset + 3]]) as usize;
        let data_start = offset + 4;
        let data_end = data_start + data_len;
        ensure!(
            data_end <= key_share.len(),
            "truncated REALITY key_share data"
        );
        entries.push(ClientKeyShare {
            group,
            data: key_share[data_start..data_end].to_vec(),
        });
        offset = data_end;
    }

    Ok(entries)
}

fn parse_alpn_protocols_extension(bytes: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let declared_len = read_be_u16(bytes, 0, "REALITY ALPN protocol list length")? as usize;
    ensure!(
        declared_len + 2 == bytes.len(),
        "REALITY ALPN protocol list length does not match payload"
    );
    ensure!(
        declared_len > 0,
        "REALITY ALPN protocol list cannot be empty"
    );

    let mut offset = 2;
    let mut protocols = Vec::new();
    while offset < bytes.len() {
        ensure!(
            offset < bytes.len(),
            "truncated REALITY ALPN protocol length"
        );
        let protocol_len = bytes[offset] as usize;
        offset += 1;
        ensure!(protocol_len > 0, "REALITY ALPN protocol cannot be empty");
        let protocol_end = offset + protocol_len;
        ensure!(
            protocol_end <= bytes.len(),
            "truncated REALITY ALPN protocol bytes"
        );
        protocols.push(bytes[offset..protocol_end].to_vec());
        offset = protocol_end;
    }

    Ok(protocols)
}

fn parse_server_supported_versions_extension(bytes: &[u8]) -> anyhow::Result<bool> {
    ensure!(
        bytes.len() == 2,
        "REALITY target supported_versions must be 2 bytes"
    );
    Ok(bytes == [0x03, 0x04])
}

fn parse_server_key_share_extension(
    bytes: &[u8],
    payload_offset: usize,
) -> anyhow::Result<(u16, (usize, usize))> {
    let group = read_be_u16(bytes, 0, "REALITY target key_share group")?;
    let key_len = read_be_u16(bytes, 2, "REALITY target key_share length")? as usize;
    ensure!(
        key_len + 4 == bytes.len(),
        "REALITY target key_share length does not match payload"
    );
    ensure!(key_len > 0, "REALITY target key_share cannot be empty");
    Ok((group, (payload_offset + 4, payload_offset + 4 + key_len)))
}

fn server_name_allowed(config: &RealityTlsConfig, server_name: &str) -> bool {
    config
        .server_names
        .iter()
        .any(|expected| expected == server_name)
}

fn derive_shared_key(private_key: [u8; 32], peer_public_key: &[u8]) -> anyhow::Result<[u8; 32]> {
    let private_key =
        x25519_private_key_from_raw(private_key).context("load REALITY X25519 private key")?;
    let peer_public_key =
        x25519_public_key_from_raw(peer_public_key).context("load REALITY X25519 peer key")?;
    let mut deriver = Deriver::new(&private_key).context("initialize REALITY X25519 derive")?;
    deriver
        .set_peer(&peer_public_key)
        .context("set REALITY X25519 peer key")?;
    let shared = deriver
        .derive_to_vec()
        .context("derive REALITY X25519 shared key")?;
    ensure!(
        shared.len() == 32,
        "REALITY X25519 shared key length mismatch"
    );
    let mut shared_key = [0u8; 32];
    shared_key.copy_from_slice(&shared);
    Ok(shared_key)
}

fn x25519_private_key_from_raw(raw: [u8; 32]) -> anyhow::Result<PKey<Private>> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04,
        0x20,
    ]);
    der.extend_from_slice(&raw);
    PKey::private_key_from_der(&der).context("decode X25519 private key DER")
}

fn x25519_public_key_from_raw(raw: &[u8]) -> anyhow::Result<PKey<Public>> {
    ensure!(
        raw.len() == 32,
        "REALITY X25519 public key must be 32 bytes"
    );
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ]);
    der.extend_from_slice(raw);
    PKey::public_key_from_der(&der).context("decode X25519 public key DER")
}

fn parse_peer_public_key(key_share: &[u8]) -> anyhow::Result<&[u8]> {
    let declared_len = read_be_u16(key_share, 0, "REALITY key_share list length")? as usize;
    ensure!(
        declared_len + 2 == key_share.len(),
        "REALITY key_share list length does not match payload"
    );

    let mut offset = 2;
    let mut hybrid_public_key = None;
    while offset < key_share.len() {
        ensure!(
            offset + 4 <= key_share.len(),
            "truncated REALITY key_share entry"
        );
        let group = u16::from_be_bytes([key_share[offset], key_share[offset + 1]]);
        let data_len = u16::from_be_bytes([key_share[offset + 2], key_share[offset + 3]]) as usize;
        let data_start = offset + 4;
        let data_end = data_start + data_len;
        ensure!(
            data_end <= key_share.len(),
            "truncated REALITY key_share data"
        );
        let data = &key_share[data_start..data_end];
        if group == 29 && data.len() == 32 {
            return Ok(data);
        }
        if group == 0x6399 && data.len() >= 32 {
            hybrid_public_key = Some(&data[..32]);
        }
        if group == 0x11ec && data.len() >= 32 {
            hybrid_public_key = Some(&data[data.len() - 32..]);
        }
        offset = data_end;
    }

    hybrid_public_key.context("REALITY ClientHello missing X25519 key_share")
}

fn read_be_u16(bytes: &[u8], offset: usize, label: &str) -> anyhow::Result<u16> {
    ensure!(offset + 2 <= bytes.len(), "truncated {label}");
    Ok(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_be_u24(bytes: &[u8], offset: usize, label: &str) -> anyhow::Result<u32> {
    ensure!(offset + 3 <= bytes.len(), "truncated {label}");
    Ok(((bytes[offset] as u32) << 16)
        | ((bytes[offset + 1] as u32) << 8)
        | (bytes[offset + 2] as u32))
}

#[cfg(test)]
mod tests;
