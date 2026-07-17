use serde_json::json;

use super::*;

#[test]
fn builds_mieru_server_config() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8964,
        network: "tcp".to_string(),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "mieru-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Mieru(config) =
        build_mieru_config(&remote, &users).expect("build Mieru config")
    else {
        panic!("expected Mieru config");
    };
    assert_eq!(config.listen, "127.0.0.1:8964".parse().unwrap());
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.users[0].username, "mieru-secret");
    assert_eq!(config.users[0].password, "mieru-secret");
    assert_eq!(config.transport, ::aerion::MieruTransport::Tcp);
}

#[test]
fn builds_shadowsocks_legacy_server_config() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8388,
        cipher: "aead_aes_128_gcm".to_string(),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        password: "ss-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Shadowsocks(config) =
        shadowsocks::build_config(&remote, &users).expect("build Shadowsocks config")
    else {
        panic!("expected Shadowsocks config");
    };
    assert_eq!(config.listen, "127.0.0.1:8388".parse().unwrap());
    assert_eq!(config.method, "aes-128-gcm");
    assert_eq!(config.password, "ss-secret");
    assert!(config.users.is_empty());
    assert!(config.tcp);
    assert!(!config.udp);
}

#[test]
fn builds_shadowsocks_2022_udp_multi_user_config() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8388,
        network: "udp".to_string(),
        cipher: "2022-blake3-aes-128-gcm".to_string(),
        server_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
        ..Default::default()
    };
    let users = vec![
        PanelUser {
            id: 1001,
            password: "MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
            ..Default::default()
        },
        PanelUser {
            id: 1002,
            password: "YWJjZGVmMTIzNDU2Nzg5MA==".to_string(),
            ..Default::default()
        },
    ];

    let BuiltServerConfig::Shadowsocks(config) =
        shadowsocks::build_config(&remote, &users).expect("build Shadowsocks config")
    else {
        panic!("expected Shadowsocks config");
    };
    assert_eq!(config.password, "QUJDREVGR0hJSktMTU5PUA==");
    assert_eq!(
        config.users,
        vec![
            "1001:MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
            "1002:YWJjZGVmMTIzNDU2Nzg5MA==".to_string()
        ]
    );
    assert!(!config.tcp);
    assert!(config.udp);

    let core_users = shadowsocks::core_users(&remote, &users).expect("core users");
    assert_eq!(core_users[0].id, "1001");
    assert_eq!(core_users[0].credential, "MTIzNDU2Nzg5MGFiY2RlZg==");
    assert_eq!(core_users[1].id, "1002");
}

#[test]
fn rejects_shadowsocks_tcp_multi_user_accounting_gap() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8388,
        cipher: "2022-blake3-aes-128-gcm".to_string(),
        server_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
        ..Default::default()
    };
    let users = vec![
        PanelUser {
            id: 1001,
            password: "MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
            ..Default::default()
        },
        PanelUser {
            id: 1002,
            password: "YWJjZGVmMTIzNDU2Nzg5MA==".to_string(),
            ..Default::default()
        },
    ];

    let error = match shadowsocks::build_config(&remote, &users) {
        Ok(_) => panic!("tcp multi-user should fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("TCP multi-user accounting"));
}

#[test]
fn builds_mieru_server_config_ignores_xboard_tls_and_cert() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8964,
        network: "ws".to_string(),
        network_settings: Some(json!({ "path": "/ignored" })),
        tls: Some(json!(1)),
        tls_settings: crate::panel::NodeTlsSettings {
            server_name: "tls.example.com".to_string(),
            allow_insecure: true,
            ..Default::default()
        },
        reality_settings: crate::panel::NodeRealitySettings {
            server_name: "reality.example.com".to_string(),
            private_key: "ignored".to_string(),
            ..Default::default()
        },
        multiplex: Some(json!({ "enabled": true })),
        cert_config: Some(crate::panel::CertConfig {
            cert_mode: "acme".to_string(),
            domain: "tls.example.com".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "mieru-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Mieru(config) =
        build_mieru_config(&remote, &users).expect("build Mieru config")
    else {
        panic!("expected Mieru config");
    };
    assert_eq!(config.listen, "127.0.0.1:8964".parse().unwrap());
    assert_eq!(config.users[0].username, "mieru-secret");
}

#[tokio::test]
async fn builds_naive_server_config() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8443,
        network: "quic".to_string(),
        server_name: "naive.example.com".to_string(),
        congestion_control: "cubic".to_string(),
        udp_relay_mode: "native".to_string(),
        ..Default::default()
    };
    let users = vec![
        PanelUser {
            id: 1001,
            uuid: "alice".to_string(),
            password: "alice-pass".to_string(),
            ..Default::default()
        },
        PanelUser {
            id: 1002,
            uuid: "bob".to_string(),
            password: "bob-pass".to_string(),
            ..Default::default()
        },
    ];

    let BuiltServerConfig::Naive(config) = build_naive_config(&remote, &users)
        .await
        .expect("build Naive config")
    else {
        panic!("expected Naive config");
    };
    assert_eq!(config.listen, "127.0.0.1:8443".parse().unwrap());
    assert_eq!(config.username, "alice");
    assert_eq!(config.password, "alice-pass");
    assert_eq!(config.users, vec!["bob:bob-pass"]);
    assert!(config.udp_over_tcp);
    assert!(config.tcp);
    assert!(config.quic);
    assert_eq!(config.quic_congestion_control, "cubic");
}

#[tokio::test]
async fn builds_naive_server_config_from_uuid_only_user() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8443,
        server_name: "naive.example.com".to_string(),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "uuid-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Naive(config) = build_naive_config(&remote, &users)
        .await
        .expect("build Naive config")
    else {
        panic!("expected Naive config");
    };
    assert_eq!(config.username, "uuid-secret");
    assert_eq!(config.password, "uuid-secret");
}

#[tokio::test]
async fn builds_hysteria2_server_config_from_xboard_obfs_fields() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8444,
        network: "udp".to_string(),
        server_name: "hy2.example.com".to_string(),
        version: Some(json!(2)),
        up_mbps: Some(json!(100)),
        server_key: "xboard-obfs-secret".to_string(),
        is_obfs: true,
        auth_timeout: "3s".to_string(),
        congestion_control: "reno".to_string(),
        udp_relay_mode: "native".to_string(),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "uuid-secret".to_string(),
        password: "password-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Hysteria2(config) = build_hysteria2_config(&remote, &users)
        .await
        .expect("build Hysteria2 config")
    else {
        panic!("expected Hysteria2 config");
    };
    assert_eq!(config.listen, "127.0.0.1:8444".parse().unwrap());
    assert_eq!(config.users, vec!["password-secret", "uuid-secret"]);
    assert_eq!(config.obfs.as_deref(), Some("salamander"));
    assert_eq!(config.obfs_password.as_deref(), Some("xboard-obfs-secret"));
    assert_eq!(config.upload_bandwidth, Some(100));
    assert_eq!(config.cc_rx, "12500000");
    assert_eq!(config.congestion_control, "reno");
    assert_eq!(config.auth_timeout, Duration::from_secs(3));
    assert!(config.udp);
    assert_eq!(config.cert_path, PathBuf::new());
    assert!(config.key.is_some());
    assert_eq!(config.certificates.len(), 1);
}

#[test]
fn trojan_accepts_websocket_transport() {
    let remote = NodeConfigResponse {
        network: "ws".to_string(),
        network_settings: Some(json!({
            "path": "trojan",
            "headers": {
                "Host": "trojan.example.com"
            }
        })),
        ..Default::default()
    };

    validate_trojan_remote(&remote).expect("validate Trojan transport");
    let transport = vless_transport(&remote).expect("parse Trojan transport");
    assert_eq!(
        transport.kind,
        ::aerion::vless_transport::VlessTransportKind::WebSocket
    );
    assert_eq!(transport.path, "/trojan");
    assert_eq!(transport.host.as_deref(), Some("trojan.example.com"));
}

#[test]
fn transport_uses_top_level_host() {
    let remote = NodeConfigResponse {
        network: "ws".to_string(),
        network_settings: Some(json!({ "path": "/ws" })),
        host: "ws.example.com".to_string(),
        ..Default::default()
    };

    let transport = vless_transport(&remote).expect("parse WebSocket transport");
    assert_eq!(transport.host.as_deref(), Some("ws.example.com"));
}

#[test]
fn tuic_rejects_unimplemented_zero_rtt() {
    let remote = NodeConfigResponse {
        zero_rtt_handshake: true,
        ..Default::default()
    };

    let error = validate_tuic_remote(&remote).expect_err("reject TUIC 0-RTT");
    assert!(error.to_string().contains("0-RTT"));
}
