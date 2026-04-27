use anyhow::{Context, ensure};
use boring::asn1::{Asn1Integer, Asn1Time};
use boring::bn::BigNum;
use boring::derive::Deriver;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private, Public};
use boring::ssl::{ClientHello, ExtensionType, NameType};
use boring::symm::{Cipher, decrypt_aead};
use boring::x509::{X509, X509NameBuilder};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityTlsConfig {
    pub server_name: String,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
}

pub(super) struct RealityCertificateState {
    key: PKey<Private>,
    public_key: [u8; 32],
    certificate_template: Vec<u8>,
    signature_offset: usize,
}

pub(super) fn build_certificate_state() -> anyhow::Result<RealityCertificateState> {
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

pub(super) fn configure_certificate(
    client_hello: &mut ClientHello<'_>,
    config: &RealityTlsConfig,
    cert_state: &RealityCertificateState,
) -> anyhow::Result<()> {
    let auth_key = derive_auth_key(client_hello, config)?;
    let certificate = build_certificate(cert_state, &auth_key)?;
    let ssl = client_hello.ssl_mut();
    ssl.set_certificate(&certificate)
        .context("set REALITY certificate")?;
    ssl.set_private_key(&cert_state.key)
        .context("set REALITY private key")?;
    Ok(())
}

fn derive_auth_key(
    client_hello: &ClientHello<'_>,
    config: &RealityTlsConfig,
) -> anyhow::Result<[u8; 32]> {
    let server_name = client_hello
        .servername(NameType::HOST_NAME)
        .context("REALITY ClientHello missing SNI")?;
    ensure!(
        server_name == config.server_name,
        "REALITY ClientHello SNI {server_name} does not match {}",
        config.server_name
    );

    let random = client_hello.random();
    ensure!(
        random.len() == 32,
        "REALITY ClientHello random must be 32 bytes"
    );

    let client_hello_raw = client_hello.as_bytes();
    let (session_id, session_start) = parse_client_hello_session_id(client_hello_raw)?;
    ensure!(
        session_id.len() == 32,
        "REALITY ClientHello session id must be 32 bytes"
    );

    let key_share = client_hello
        .get_extension(ExtensionType::KEY_SHARE)
        .context("REALITY ClientHello missing key_share")?;
    let peer_public_key = parse_peer_public_key(key_share)?;

    let shared_key = derive_shared_key(config.private_key, peer_public_key)?;

    let hkdf = Hkdf::<Sha256>::new(Some(&random[..20]), &shared_key);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("derive REALITY auth key failed"))?;

    let mut aad = Vec::with_capacity(client_hello_raw.len() + 4);
    aad.push(1);
    aad.push((client_hello_raw.len() >> 16) as u8);
    aad.push((client_hello_raw.len() >> 8) as u8);
    aad.push(client_hello_raw.len() as u8);
    aad.extend_from_slice(client_hello_raw);
    aad[4 + session_start..4 + session_start + session_id.len()].fill(0);

    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        &auth_key,
        Some(&random[20..]),
        &aad,
        &session_id[..16],
        &session_id[16..],
    )
    .context("decrypt REALITY session id")?;
    ensure!(
        plain.len() == 16,
        "REALITY decrypted session id prefix must be 16 bytes"
    );
    let mut received_short_id = [0u8; 8];
    received_short_id.copy_from_slice(&plain[8..16]);
    ensure!(
        config.short_ids.contains(&received_short_id),
        "REALITY ClientHello short_id {} does not match configured short_id",
        hex::encode(received_short_id)
    );

    Ok(auth_key)
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

fn parse_client_hello_session_id(bytes: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    ensure!(
        bytes.len() >= 35,
        "truncated REALITY ClientHello before session id"
    );
    let session_start = 35;
    let session_len = bytes[34] as usize;
    let session_end = session_start + session_len;
    ensure!(
        session_end <= bytes.len(),
        "truncated REALITY ClientHello session id"
    );
    Ok((&bytes[session_start..session_end], session_start))
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

fn build_certificate(
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

fn read_be_u16(bytes: &[u8], offset: usize, label: &str) -> anyhow::Result<u16> {
    ensure!(offset + 2 <= bytes.len(), "truncated {label}");
    Ok(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_certificate_with_hmac_signature() {
        let state = build_certificate_state().expect("certificate state");
        let auth_key = [7u8; 32];
        let certificate = build_certificate(&state, &auth_key).expect("certificate");

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
        let alice = PKey::generate(boring::pkey::Id::X25519).expect("alice key");
        let bob = PKey::generate(boring::pkey::Id::X25519).expect("bob key");
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
}
