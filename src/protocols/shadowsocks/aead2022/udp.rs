use anyhow::{anyhow, bail, ensure};
use std::convert::TryInto;

use crate::protocols::shared::socksaddr::SocksAddr;

use super::super::crypto::{
    Aead2022Method, UserCredential, address_wire_len, parse_socks_addr, random_bytes,
    write_socks_addr,
};
use super::replay::SlidingWindow;
use super::{
    DecodedUdpPacket, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER, TAG_LEN, UDP_CHACHA_NONCE_LEN,
    UdpIdentification, UdpSession, current_unix_time, decrypt_packet_body, ecb_crypt,
    encrypt_packet_body, has_identity_header, session_subkey, validate_timestamp, xor_in_place,
};

pub(crate) fn identify_udp_request(
    packet: &[u8],
    users: &[UserCredential],
) -> anyhow::Result<UdpIdentification> {
    ensure!(!users.is_empty(), "no Shadowsocks users configured");
    let method = match users[0].method {
        super::super::crypto::Method::Aead2022(method) => method,
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
            super::super::crypto::Method::Aead2022(method) => method,
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
        super::super::crypto::Method::Aead2022(method) => method,
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
        super::super::crypto::Method::Aead2022(method) => method,
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

fn identify_udp_request_aes(
    packet: &[u8],
    users: &[UserCredential],
) -> anyhow::Result<UdpIdentification> {
    let method = match users[0].method {
        super::super::crypto::Method::Aead2022(method) => method,
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
        super::super::crypto::Method::Aead2022(method) => method,
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
