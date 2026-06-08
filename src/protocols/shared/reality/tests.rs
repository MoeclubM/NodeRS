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
            handshake: Vec::new(),
            key_share_range: (0, 0),
        }
        .curves_list(),
        Some("X25519Kyber768Draft00")
    );
    assert_eq!(
        ObservedServerHello {
            prefix: Vec::new(),
            cipher_suite: 0x1301,
            key_share_group: 0x11ec,
            handshake: Vec::new(),
            key_share_range: (0, 0),
        }
        .curves_list(),
        Some("X25519MLKEM768")
    );
}

#[test]
fn rewrites_observed_server_hello_key_share_in_place() {
    let handshake = build_test_server_hello(0x1301, 29);
    let observed = parse_server_hello(Vec::new(), &handshake).expect("parse server hello");

    let rewritten = observed
        .rewrite_key_share(&[0x99; 32])
        .expect("rewrite server hello key share");

    assert_eq!(rewritten.len(), handshake.len());
    assert_eq!(
        rewritten[..rewritten.len() - 32],
        handshake[..handshake.len() - 32]
    );
    assert_eq!(rewritten[rewritten.len() - 32..], [0x99; 32]);
}

#[test]
fn accepts_client_hello_without_ed25519_support() {
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

    let authenticated = authenticate_client_hello(
        &RawClientHello {
            prefix: Vec::new(),
            handshake,
        },
        &config,
    )
    .expect("authenticate client hello without ed25519");
    assert_eq!(authenticated.short_id, [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn extracts_client_hello_details_from_hybrid_groups() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    body.push(32);
    body.extend_from_slice(&[0x22; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&encode_server_name_extension("reality.example.com"));
    extensions.extend_from_slice(&encode_supported_versions_extension());
    extensions.extend_from_slice(&encode_signature_algorithms_extension(false));
    extensions.extend_from_slice(&encode_alpn_extension(&[b"h2", b"http/1.1"]));

    let mut key_share_payload = Vec::new();
    let mut entries = Vec::new();
    entries.extend_from_slice(&0x6399u16.to_be_bytes());
    entries.extend_from_slice(&1216u16.to_be_bytes());
    entries.extend_from_slice(&[0x33; 32]);
    entries.extend_from_slice(&[0x44; 1184]);
    entries.extend_from_slice(&0x11ecu16.to_be_bytes());
    entries.extend_from_slice(&1120u16.to_be_bytes());
    entries.extend_from_slice(&[0x55; 1088]);
    entries.extend_from_slice(&[0x66; 32]);
    key_share_payload.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    key_share_payload.extend_from_slice(&entries);

    let mut key_share_extension = Vec::new();
    key_share_extension.extend_from_slice(&51u16.to_be_bytes());
    key_share_extension.extend_from_slice(&(key_share_payload.len() as u16).to_be_bytes());
    key_share_extension.extend_from_slice(&key_share_payload);
    extensions.extend_from_slice(&key_share_extension);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    handshake.push(((body.len() >> 16) & 0xff) as u8);
    handshake.push(((body.len() >> 8) & 0xff) as u8);
    handshake.push((body.len() & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let details = client_hello_details(&RawClientHello {
        prefix: Vec::new(),
        handshake,
    })
    .expect("client hello details");

    assert_eq!(details.random, [0x11; 32]);
    assert_eq!(details.session_id, vec![0x22; 32]);
    assert_eq!(details.key_shares.len(), 2);
    assert_eq!(details.key_shares[0].group, 0x6399);
    assert_eq!(details.key_shares[0].data.len(), 32 + 1184);
    assert_eq!(details.key_shares[0].data[..32], [0x33; 32]);
    assert_eq!(details.key_shares[1].group, 0x11ec);
    assert_eq!(details.key_shares[1].data.len(), 1088 + 32);
    assert_eq!(details.key_shares[1].data[1088..], [0x66; 32]);
    assert_eq!(
        details.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
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
    build_test_client_hello_with_alpn(
        config,
        client_public,
        server_name,
        client_version,
        client_time,
        short_id,
        include_ed25519,
        &[],
    )
}

fn build_test_client_hello_with_alpn(
    config: &RealityTlsConfig,
    client_public: &[u8; 32],
    server_name: &str,
    client_version: [u8; 4],
    client_time: u32,
    short_id: [u8; 8],
    include_ed25519: bool,
    alpn_protocols: &[&[u8]],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
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
    if !alpn_protocols.is_empty() {
        extensions.extend_from_slice(&encode_alpn_extension(alpn_protocols));
    }
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

fn encode_alpn_extension(protocols: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    let list_len: usize = protocols.iter().map(|protocol| 1 + protocol.len()).sum();
    payload.extend_from_slice(&(list_len as u16).to_be_bytes());
    for protocol in protocols {
        payload.push(protocol.len() as u8);
        payload.extend_from_slice(protocol);
    }

    let mut extension = Vec::new();
    extension.extend_from_slice(&16u16.to_be_bytes());
    extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    extension.extend_from_slice(&payload);
    extension
}

fn build_test_server_hello(cipher_suite: u16, group: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
        8, 7, 6, 5, 4, 3, 2, 1, 0,
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
        0x6399 => vec![0x33; 32 + 1088],
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
