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
pub struct ObservedServerHello {
    pub prefix: Vec<u8>,
    pub cipher_suite: u16,
    pub key_share_group: u16,
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
                key_share_group = Some(parse_server_key_share_extension(data)?);
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
    })
}

struct ParsedClientHello<'a> {
    server_name: String,
    random: [u8; 32],
    session_id: &'a [u8],
    session_start: usize,
    key_share: &'a [u8],
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
    let mut supports_tls13 = false;
    let mut supports_ed25519 = false;
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
                supports_ed25519 = parse_signature_algorithms_extension(data)?;
            }
            51 => {
                key_share = Some(data);
            }
            _ => {}
        }

        offset = data_end;
    }

    ensure!(supports_tls13, "REALITY ClientHello must support TLS 1.3");
    ensure!(
        supports_ed25519,
        "REALITY ClientHello does not advertise Ed25519 signature support"
    );

    Ok(ParsedClientHello {
        server_name: server_name.context("REALITY ClientHello missing SNI")?,
        random,
        session_id,
        session_start,
        key_share: key_share.context("REALITY ClientHello missing key_share")?,
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

fn parse_signature_algorithms_extension(bytes: &[u8]) -> anyhow::Result<bool> {
    let declared_len = read_be_u16(bytes, 0, "REALITY signature_algorithms length")? as usize;
    ensure!(
        declared_len + 2 == bytes.len(),
        "REALITY signature_algorithms length does not match payload"
    );
    ensure!(
        declared_len % 2 == 0,
        "REALITY signature_algorithms payload must contain whole schemes"
    );
    Ok(bytes[2..]
        .chunks_exact(2)
        .any(|scheme| scheme == [0x08, 0x07]))
}

fn parse_server_supported_versions_extension(bytes: &[u8]) -> anyhow::Result<bool> {
    ensure!(
        bytes.len() == 2,
        "REALITY target supported_versions must be 2 bytes"
    );
    Ok(bytes == [0x03, 0x04])
}

fn parse_server_key_share_extension(bytes: &[u8]) -> anyhow::Result<u16> {
    let group = read_be_u16(bytes, 0, "REALITY target key_share group")?;
    let key_len = read_be_u16(bytes, 2, "REALITY target key_share length")? as usize;
    ensure!(
        key_len + 4 == bytes.len(),
        "REALITY target key_share length does not match payload"
    );
    ensure!(key_len > 0, "REALITY target key_share cannot be empty");
    Ok(group)
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
mod tests {
    use super::*;
    use boring::pkey::Id;
    use boring::symm::encrypt_aead;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn builds_certificate_with_hmac_signature() {
        let state = build_certificate_state().expect("certificate state");
        let auth_key = [7u8; 32];
        let certificate = build_server_certificate(&state, &auth_key).expect("certificate");

        let mut hmac = Hmac::<Sha512>::new_from_slice(&auth_key).expect("hmac");
        hmac.update(&state.public_key);
        let signature = hmac.finalize().into_bytes();
        assert_eq!(certificate.signature().as_slice(), &signature[..]);
    }

    #[test]
    fn extracts_x25519_key_share() {
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&36u16.to_be_bytes());
        key_share.extend_from_slice(&29u16.to_be_bytes());
        key_share.extend_from_slice(&32u16.to_be_bytes());
        key_share.extend_from_slice(&[5u8; 32]);

        let public_key = parse_peer_public_key(&key_share).expect("public key");
        assert_eq!(public_key, [5u8; 32].as_slice());
    }

    #[test]
    fn reality_server_name_matching_is_exact() {
        let config = RealityTlsConfig {
            server_name: "target.example.com".to_string(),
            server_port: 443,
            server_names: vec!["Example.com".to_string()],
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
        };

        assert!(server_name_allowed(&config, "Example.com"));
        assert!(!server_name_allowed(&config, "example.com"));
    }

    #[test]
    fn extracts_x25519_from_hybrid_key_shares() {
        let mut kyber_key_share = Vec::new();
        kyber_key_share.extend_from_slice(&40u16.to_be_bytes());
        kyber_key_share.extend_from_slice(&0x6399u16.to_be_bytes());
        kyber_key_share.extend_from_slice(&36u16.to_be_bytes());
        kyber_key_share.extend_from_slice(&[6u8; 32]);
        kyber_key_share.extend_from_slice(&[7u8; 4]);
        assert_eq!(
            parse_peer_public_key(&kyber_key_share).expect("kyber x25519 key"),
            [6u8; 32].as_slice()
        );

        let mut mlkem_key_share = Vec::new();
        mlkem_key_share.extend_from_slice(&40u16.to_be_bytes());
        mlkem_key_share.extend_from_slice(&0x11ecu16.to_be_bytes());
        mlkem_key_share.extend_from_slice(&36u16.to_be_bytes());
        mlkem_key_share.extend_from_slice(&[8u8; 4]);
        mlkem_key_share.extend_from_slice(&[9u8; 32]);
        assert_eq!(
            parse_peer_public_key(&mlkem_key_share).expect("mlkem x25519 key"),
            [9u8; 32].as_slice()
        );
    }

    #[test]
    fn derives_x25519_shared_key_from_raw_keys() {
        let alice = PKey::generate(Id::X25519).expect("alice key");
        let bob = PKey::generate(Id::X25519).expect("bob key");
        let mut alice_private = [0u8; 32];
        let mut bob_public = [0u8; 32];
        alice
            .raw_private_key(&mut alice_private)
            .expect("alice private key");
        bob.raw_public_key(&mut bob_public).expect("bob public key");

        let shared = derive_shared_key(alice_private, &bob_public).expect("shared key");

        let mut deriver = Deriver::new(&alice).expect("deriver");
        deriver.set_peer(&bob).expect("peer key");
        let expected = deriver.derive_to_vec().expect("expected shared key");
        assert_eq!(shared.as_slice(), expected.as_slice());
    }

    #[test]
    fn authenticates_valid_client_hello() {
        let server_key = PKey::generate(Id::X25519).expect("server key");
        let client_key = PKey::generate(Id::X25519).expect("client key");
        let mut server_private = [0u8; 32];
        let mut client_public = [0u8; 32];
        server_key
            .raw_private_key(&mut server_private)
            .expect("server private key");
        client_key
            .raw_public_key(&mut client_public)
            .expect("client public key");

        let config = RealityTlsConfig {
            server_name: "target.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: server_private,
            short_ids: vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]],
        };

        let handshake = build_test_client_hello(
            &config,
            &client_public,
            "reality.example.com",
            [1, 2, 3, 0],
            0x01020304,
            [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
            true,
        );
        let authenticated = authenticate_client_hello(
            &RawClientHello {
                prefix: Vec::new(),
                handshake,
            },
            &config,
        )
        .expect("authenticate REALITY client hello");

        assert_eq!(authenticated.server_name, "reality.example.com");
        assert_eq!(authenticated.client_version, [1, 2, 3, 0]);
        assert_eq!(authenticated.client_time, 0x01020304);
        assert_eq!(authenticated.short_id, [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn reads_client_hello_from_tls_record_prefix() {
        let server_key = PKey::generate(Id::X25519).expect("server key");
        let client_key = PKey::generate(Id::X25519).expect("client key");
        let mut server_private = [0u8; 32];
        let mut client_public = [0u8; 32];
        server_key
            .raw_private_key(&mut server_private)
            .expect("server private key");
        client_key
            .raw_public_key(&mut client_public)
            .expect("client public key");

        let config = RealityTlsConfig {
            server_name: "target.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: server_private,
            short_ids: vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]],
        };
        let handshake = build_test_client_hello(
            &config,
            &client_public,
            "reality.example.com",
            [1, 2, 3, 0],
            0x01020304,
            [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
            true,
        );

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        let expected_record = record.clone();

        let (mut client, mut server) = tokio::io::duplex(4096);
        let write_task = tokio::spawn(async move {
            client.write_all(&record).await.expect("write client hello");
        });

        let raw = read_client_hello(&mut server)
            .await
            .expect("read raw client hello");
        write_task.await.expect("join write task");

        assert_eq!(raw.handshake, handshake);
        assert_eq!(raw.prefix, expected_record);
    }

    #[tokio::test]
    async fn reads_server_hello_from_tls_record_prefix() {
        let handshake = build_test_server_hello(0x1301, 29);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0303u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        let expected_record = record.clone();

        let (mut client, mut server) = tokio::io::duplex(4096);
        let write_task = tokio::spawn(async move {
            client.write_all(&record).await.expect("write server hello");
        });

        let observed = read_server_hello(&mut server)
            .await
            .expect("read REALITY target server hello");
        write_task.await.expect("join write task");

        assert_eq!(observed.prefix, expected_record);
        assert_eq!(observed.cipher_suite, 0x1301);
        assert_eq!(observed.key_share_group, 29);
        assert_eq!(observed.curves_list(), Some("X25519"));
    }

    #[test]
    fn maps_hybrid_server_groups_to_boringssl_curve_names() {
        assert_eq!(
            ObservedServerHello {
                prefix: Vec::new(),
                cipher_suite: 0x1301,
                key_share_group: 0x6399,
            }
            .curves_list(),
            Some("X25519Kyber768Draft00")
        );
        assert_eq!(
            ObservedServerHello {
                prefix: Vec::new(),
                cipher_suite: 0x1301,
                key_share_group: 0x11ec,
            }
            .curves_list(),
            Some("X25519MLKEM768")
        );
    }

    #[test]
    fn rejects_client_hello_without_ed25519_support() {
        let server_key = PKey::generate(Id::X25519).expect("server key");
        let client_key = PKey::generate(Id::X25519).expect("client key");
        let mut server_private = [0u8; 32];
        let mut client_public = [0u8; 32];
        server_key
            .raw_private_key(&mut server_private)
            .expect("server private key");
        client_key
            .raw_public_key(&mut client_public)
            .expect("client public key");

        let config = RealityTlsConfig {
            server_name: "target.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: server_private,
            short_ids: vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]],
        };
        let handshake = build_test_client_hello(
            &config,
            &client_public,
            "reality.example.com",
            [1, 2, 3, 0],
            0x01020304,
            [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
            false,
        );

        let error = authenticate_client_hello(
            &RawClientHello {
                prefix: Vec::new(),
                handshake,
            },
            &config,
        )
        .expect_err("missing ed25519 support should fail");
        assert!(error.to_string().contains("Ed25519"));
    }

    fn build_test_client_hello(
        config: &RealityTlsConfig,
        client_public: &[u8; 32],
        server_name: &str,
        client_version: [u8; 4],
        client_time: u32,
        short_id: [u8; 8],
        include_ed25519: bool,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        body.push(32);
        let session_start = body.len();
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&encode_server_name_extension(server_name));
        extensions.extend_from_slice(&encode_supported_versions_extension());
        extensions.extend_from_slice(&encode_signature_algorithms_extension(include_ed25519));
        extensions.extend_from_slice(&encode_key_share_extension(client_public));
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let shared_key = derive_shared_key(config.private_key, client_public).expect("shared key");
        let hkdf = Hkdf::<Sha256>::new(Some(&body[2..22]), &shared_key);
        let mut auth_key = [0u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key)
            .expect("expand REALITY auth key");

        let mut plaintext = Vec::with_capacity(16);
        plaintext.extend_from_slice(&client_version);
        plaintext.extend_from_slice(&client_time.to_be_bytes());
        plaintext.extend_from_slice(&short_id);
        let mut tag = [0u8; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &auth_key,
            Some(&body[22..34]),
            &handshake,
            &plaintext,
            &mut tag,
        )
        .expect("encrypt REALITY session id");
        handshake[4 + session_start..4 + session_start + 16].copy_from_slice(&ciphertext);
        handshake[4 + session_start + 16..4 + session_start + 32].copy_from_slice(&tag);
        handshake
    }

    fn encode_server_name_extension(server_name: &str) -> Vec<u8> {
        let server_name = server_name.as_bytes();
        let mut payload = Vec::new();
        let list_len = 1 + 2 + server_name.len();
        payload.extend_from_slice(&(list_len as u16).to_be_bytes());
        payload.push(0);
        payload.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        payload.extend_from_slice(server_name);

        let mut extension = Vec::new();
        extension.extend_from_slice(&0u16.to_be_bytes());
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }

    fn encode_supported_versions_extension() -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend_from_slice(&43u16.to_be_bytes());
        extension.extend_from_slice(&3u16.to_be_bytes());
        extension.push(2);
        extension.extend_from_slice(&0x0304u16.to_be_bytes());
        extension
    }

    fn encode_signature_algorithms_extension(include_ed25519: bool) -> Vec<u8> {
        let mut payload = Vec::new();
        let schemes: &[[u8; 2]] = if include_ed25519 {
            &[[0x04, 0x03], [0x08, 0x04], [0x08, 0x07]]
        } else {
            &[[0x04, 0x03], [0x08, 0x04]]
        };
        payload.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
        for scheme in schemes {
            payload.extend_from_slice(scheme);
        }

        let mut extension = Vec::new();
        extension.extend_from_slice(&13u16.to_be_bytes());
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }

    fn encode_key_share_extension(client_public: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&36u16.to_be_bytes());
        payload.extend_from_slice(&29u16.to_be_bytes());
        payload.extend_from_slice(&32u16.to_be_bytes());
        payload.extend_from_slice(client_public);

        let mut extension = Vec::new();
        extension.extend_from_slice(&51u16.to_be_bytes());
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }

    fn build_test_server_hello(cipher_suite: u16, group: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ]);
        body.push(32);
        body.extend_from_slice(&[0x55; 32]);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&encode_server_supported_versions_extension());
        extensions.extend_from_slice(&encode_server_key_share_extension(group));
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(2);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn encode_server_supported_versions_extension() -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend_from_slice(&43u16.to_be_bytes());
        extension.extend_from_slice(&2u16.to_be_bytes());
        extension.extend_from_slice(&0x0304u16.to_be_bytes());
        extension
    }

    fn encode_server_key_share_extension(group: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        let key_share = match group {
            29 => vec![0x44; 32],
            0x11ec => vec![0x33; 32 + 1088],
            _ => vec![0x22; 32],
        };
        payload.extend_from_slice(&group.to_be_bytes());
        payload.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        payload.extend_from_slice(&key_share);

        let mut extension = Vec::new();
        extension.extend_from_slice(&51u16.to_be_bytes());
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }
}
