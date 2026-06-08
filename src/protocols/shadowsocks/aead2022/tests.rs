use super::*;
use crate::accounting::UserEntry;
use crate::panel::PanelUser;
use crate::protocols::shadowsocks::crypto::Method;
use sha2::{Digest as _, Sha256};

fn sample_credential(method: Aead2022Method) -> UserCredential {
    let server_psk = match method {
        Aead2022Method::Aes128Gcm => "QUJDREVGR0hJSktMTU5PUA==",
        Aead2022Method::Aes256Gcm | Aead2022Method::ChaCha20Poly1305 => {
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        }
    };
    let secret = derive_user_psk(
        &PanelUser {
            id: 1,
            password: server_psk.to_string(),
            ..Default::default()
        },
        method,
    )
    .expect("user psk");
    UserCredential {
        user: UserEntry {
            id: 1,
            uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
            password_sha256: [0u8; 32],
            speed_limit: 0,
            device_limit: 0,
        },
        method: super::super::crypto::Method::Aead2022(method),
        secret: secret.clone(),
        server_secret: decode_server_psk(server_psk, method).expect("server psk"),
        identity_hash: identity_hash(&secret),
    }
}

#[test]
fn derives_user_key_from_base64_uuid_when_password_is_missing() {
    let key = derive_user_psk(
        &PanelUser {
            id: 1,
            uuid: "MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
            ..Default::default()
        },
        Aead2022Method::Aes128Gcm,
    )
    .expect("key");
    assert_eq!(key, b"1234567890abcdef");
}

#[test]
fn derives_user_key_from_base64_password_when_present() {
    let key = derive_user_psk(
        &PanelUser {
            id: 1,
            password: "cGFzc3dvcmQtYmFzZWQta2V5LW1hdGVyaWFs".to_string(),
            uuid: "MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
            ..Default::default()
        },
        Aead2022Method::Aes128Gcm,
    )
    .expect("key");
    assert_eq!(
        key,
        Sha256::digest(b"password-based-key-material")[..16].to_vec()
    );
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
fn rejects_non_base64_user_key() {
    let error = derive_user_psk(
        &PanelUser {
            id: 1,
            uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
            ..Default::default()
        },
        Aead2022Method::Aes128Gcm,
    )
    .expect_err("raw uuid should fail");
    assert!(
        error
            .to_string()
            .contains("decode Shadowsocks 2022 user 1 key")
    );
}

#[test]
fn accepts_large_tcp_chunk_lengths() {
    assert_eq!(MAX_TCP_CHUNK_LEN, u16::MAX as usize);
}

fn append_tcp_stream_chunk(
    output: &mut Vec<u8>,
    method: Aead2022Method,
    session_key: &[u8],
    next_nonce: &mut u64,
    payload: &[u8],
) {
    output.extend_from_slice(
        &encrypt_tcp_chunk(
            method,
            session_key,
            *next_nonce,
            &(payload.len() as u16).to_be_bytes(),
            "encrypt length",
        )
        .expect("length"),
    );
    *next_nonce += 1;
    output.extend_from_slice(
        &encrypt_tcp_chunk(method, session_key, *next_nonce, payload, "encrypt payload")
            .expect("payload"),
    );
    *next_nonce += 1;
}

#[test]
fn decodes_tcp_encrypted_protocol_extension() {
    let credential = sample_credential(Aead2022Method::Aes128Gcm);
    let request_salt = vec![7u8; credential.secret.len()];
    let session_key = session_subkey(&credential.secret, &request_salt, credential.secret.len());
    let destination = SocksAddr::Domain("example.com".to_string(), 443);
    let mut variable_plain = Vec::new();
    write_socks_addr(&mut variable_plain, &destination).expect("addr");
    variable_plain.extend_from_slice(&1u16.to_be_bytes());
    variable_plain.push(0);
    let fixed_plain = {
        let mut bytes = Vec::new();
        bytes.push(HEADER_TYPE_CLIENT_ENCRYPTED);
        bytes.extend_from_slice(&(current_unix_time().expect("time") as u64).to_be_bytes());
        bytes.extend_from_slice(&(variable_plain.len() as u16).to_be_bytes());
        bytes
    };
    let mut request = request_salt.clone();
    request.extend_from_slice(
        &encrypt_tcp_chunk(
            Aead2022Method::Aes128Gcm,
            &session_key,
            0,
            &fixed_plain,
            "encrypt fixed",
        )
        .expect("fixed"),
    );
    request.extend_from_slice(
        &encrypt_tcp_chunk(
            Aead2022Method::Aes128Gcm,
            &session_key,
            1,
            &variable_plain,
            "encrypt variable",
        )
        .expect("variable"),
    );
    let mut next_nonce = 2u64;
    let handshake_header = [22, 3, 3, 0, 3];
    append_tcp_stream_chunk(
        &mut request,
        Aead2022Method::Aes128Gcm,
        &session_key,
        &mut next_nonce,
        &handshake_header,
    );
    append_tcp_stream_chunk(
        &mut request,
        Aead2022Method::Aes128Gcm,
        &session_key,
        &mut next_nonce,
        b"abc",
    );
    let application_header = [23, 3, 3, 0, 5];
    append_tcp_stream_chunk(
        &mut request,
        Aead2022Method::Aes128Gcm,
        &session_key,
        &mut next_nonce,
        &application_header,
    );
    request.extend_from_slice(b"hello");

    let replay = TcpReplayCache::default();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let accepted = AcceptedTcpReader::accept(
            std::io::Cursor::new(request),
            std::slice::from_ref(&credential),
            &replay,
        )
        .await
        .expect("accept");
        let (mut plain_reader, plain_writer) = tokio::io::duplex(4096);
        let pump = tokio::spawn(async move {
            accepted
                .pump_to_plain(plain_writer, SessionControl::new())
                .await
                .expect("pump");
        });
        let mut output = Vec::new();
        plain_reader
            .read_to_end(&mut output)
            .await
            .expect("read output");
        pump.await.expect("join pump");

        let mut expected = Vec::new();
        write_socks_addr(&mut expected, &destination).expect("addr");
        expected.extend_from_slice(&handshake_header);
        expected.extend_from_slice(b"abc");
        expected.extend_from_slice(&application_header);
        expected.extend_from_slice(b"hello");
        assert_eq!(output, expected);
    });
}

#[test]
fn encodes_tcp_encrypted_protocol_extension_response() {
    let credential = sample_credential(Aead2022Method::Aes128Gcm);
    let request_salt = vec![8u8; credential.secret.len()];
    let response_context = TcpResponseContext {
        request_salt: request_salt.clone(),
        encrypted_protocol: true,
    };
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let input = [b"\x17\x03\x03\x00\x05".as_slice(), b"hello".as_slice()].concat();
        let (mut response_reader, response_writer) = tokio::io::duplex(4096);
        let pump_credential = credential.clone();
        let pump = tokio::spawn(async move {
            pump_plain_to_tcp(
                &pump_credential,
                &response_context,
                std::io::Cursor::new(input),
                response_writer,
                SessionControl::new(),
            )
            .await
            .expect("pump response");
        });
        let mut output = Vec::new();
        response_reader
            .read_to_end(&mut output)
            .await
            .expect("read response");
        pump.await.expect("join response pump");

        let key_len = Aead2022Method::Aes128Gcm.key_len();
        let response_salt = &output[..key_len];
        let session_key = session_subkey(&credential.secret, response_salt, key_len);
        let fixed_len = 1 + 8 + key_len + 2;
        let fixed_start = key_len;
        let fixed_end = fixed_start + fixed_len + TAG_LEN;
        let fixed_plain = decrypt_tcp_chunk(
            Aead2022Method::Aes128Gcm,
            &session_key,
            0,
            &output[fixed_start..fixed_end],
            "decrypt fixed response",
        )
        .expect("fixed response");
        assert_eq!(fixed_plain[0], HEADER_TYPE_SERVER_ENCRYPTED);
        assert_eq!(&fixed_plain[9..9 + key_len], request_salt.as_slice());
        assert_eq!(
            u16::from_be_bytes([fixed_plain[9 + key_len], fixed_plain[10 + key_len]]),
            0
        );

        let mut offset = fixed_end;
        let length_plain = decrypt_tcp_chunk(
            Aead2022Method::Aes128Gcm,
            &session_key,
            1,
            &output[offset..offset + 2 + TAG_LEN],
            "decrypt response length",
        )
        .expect("length");
        assert_eq!(u16::from_be_bytes([length_plain[0], length_plain[1]]), 5);
        offset += 2 + TAG_LEN;
        let header_plain = decrypt_tcp_chunk(
            Aead2022Method::Aes128Gcm,
            &session_key,
            2,
            &output[offset..offset + 5 + TAG_LEN],
            "decrypt response header",
        )
        .expect("header");
        assert_eq!(header_plain, b"\x17\x03\x03\x00\x05");
        offset += 5 + TAG_LEN;
        assert_eq!(&output[offset..], b"hello");
    });
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
    let session_key = session_subkey(&credential.secret, &request_salt, credential.secret.len());

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
fn aes_tcp_accept_uses_single_user_format_without_identity_header() {
    let credential = sample_credential(Aead2022Method::Aes128Gcm);
    let request_salt = vec![7u8; credential.secret.len()];
    let session_key = session_subkey(&credential.secret, &request_salt, credential.secret.len());

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
            Aead2022Method::Aes128Gcm,
            &session_key,
            0,
            &fixed_plain,
            "encrypt fixed",
        )
        .expect("fixed"),
    );
    request.extend_from_slice(
        &encrypt_tcp_chunk(
            Aead2022Method::Aes128Gcm,
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
