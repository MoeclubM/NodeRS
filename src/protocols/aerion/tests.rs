use serde_json::json;

use super::*;

#[tokio::test]
async fn builds_sudoku_with_distinct_users_and_dynamic_revoke() -> anyhow::Result<()> {
    let remote: NodeConfigResponse = serde_json::from_value(json!({
        "protocol":"sudoku", "listen_ip":"0.0.0.0", "server_port":8443,
        "sudoku":{"aead":"aes-128-gcm","table_type":"prefer_ascii","padding_min":0,"padding_max":0,"http_mask":true,"http_mask_mode":"ws","path_root":"edge"}
    }))?;
    let users = vec![
        PanelUser {
            id: 1,
            uuid: "alice-uuid".into(),
            speed_limit: 10,
            ..Default::default()
        },
        PanelUser {
            id: 2,
            uuid: "bob-uuid".into(),
            ..Default::default()
        },
    ];
    let BuiltServerConfig::Sudoku(config) =
        build_server_config(ProtocolKind::Sudoku, &remote, &users).await?
    else {
        panic!("expected Sudoku")
    };
    assert_eq!(config.listen.port(), 8443);
    assert_eq!(config.key, "alice-uuid");
    assert_eq!(config.users, ["bob-uuid"]);
    assert_eq!(config.options.http_mask_mode, "ws");
    assert_eq!(config.options.path_root, "edge");
    assert!(!protocol_requires_listener_user_reload(
        ProtocolKind::Sudoku
    ));
    let core = ::aerion::ProxyCore::empty();
    core.replace_users(core_users(ProtocolKind::Sudoku, &remote, &users)?)?;
    let bob = core.authenticate("bob-uuid").await?;
    assert_eq!(bob.user_id(), "2");
    core.replace_users(core_users(ProtocolKind::Sudoku, &remote, &users[..1])?)?;
    assert!(core.authenticate("bob-uuid").await.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(1), bob.cancelled()).await?;
    Ok(())
}

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
    assert_eq!(config.listen, "[::]:8964".parse().unwrap());
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.users[0].username, "mieru-secret");
    assert_eq!(config.users[0].password, "mieru-secret");
    assert_eq!(config.transport, ::aerion::MieruTransport::Tcp);
}

#[test]
fn builds_mieru_udp_underlay_from_network() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8964,
        network: "udp".to_string(),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "mieru-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Mieru(config) =
        build_mieru_config(&remote, &users).expect("build Mieru UDP config")
    else {
        panic!("expected Mieru config");
    };
    assert_eq!(config.transport, ::aerion::MieruTransport::Udp);
}

#[test]
fn builds_mieru_udp_underlay_from_transport_field() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8964,
        network: "tcp".to_string(),
        transport: Some(json!("udp")),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "mieru-secret".to_string(),
        ..Default::default()
    }];

    let BuiltServerConfig::Mieru(config) =
        build_mieru_config(&remote, &users).expect("build Mieru UDP config")
    else {
        panic!("expected Mieru config");
    };
    assert_eq!(config.transport, ::aerion::MieruTransport::Udp);
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
    assert_eq!(config.listen, "[::]:8388".parse().unwrap());
    assert_eq!(config.method, "aes-128-gcm");
    assert_eq!(config.password, "ss-secret");
    assert!(config.users.is_empty());
    assert!(config.tcp);
    assert!(!config.udp);
}

#[test]
fn builds_shadowsocks_server_config_ignoring_tls_fields() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8388,
        cipher: "aead_aes_128_gcm".to_string(),
        tls: Some(json!(1)),
        cert_config: Some(crate::panel::CertConfig {
            cert_mode: "acme".to_string(),
            domain: "ss.example.com".to_string(),
            ..Default::default()
        }),
        plugin: "obfs-local".to_string(),
        multiplex: Some(json!({ "enabled": true })),
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
    assert_eq!(config.method, "aes-128-gcm");
    assert_eq!(config.password, "ss-secret");
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
fn builds_shadowsocks_2022_tcp_multi_user_config() {
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

    let BuiltServerConfig::Shadowsocks(config) =
        shadowsocks::build_config(&remote, &users).expect("build TCP multi-user config")
    else {
        panic!("expected Shadowsocks config");
    };
    assert!(config.tcp);
    assert!(config.udp);
    assert_eq!(config.users.len(), 2);
}

#[test]
fn shadowsocks_2022_uuid_keys_stay_stable_when_user_count_changes() {
    for (cipher, server_key, user_key) in [
        (
            "2022-blake3-aes-128-gcm",
            "QUJDREVGR0hJSktMTU5PUA==",
            "YTM0ODJlODgtNjg2YS00YQ==",
        ),
        (
            "2022-blake3-aes-256-gcm",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=",
            "YTM0ODJlODgtNjg2YS00YTU4LTgxMjYtOTljOWRmNjQ=",
        ),
    ] {
        let remote = NodeConfigResponse {
            server_port: 8388,
            cipher: cipher.into(),
            server_key: server_key.into(),
            ..Default::default()
        };
        let users = vec![
            PanelUser {
                id: 1001,
                uuid: "a3482e88-686a-4a58-8126-99c9df64b7bf".into(),
                speed_limit: 10,
                device_limit: 2,
                ..Default::default()
            },
            PanelUser {
                id: 1002,
                uuid: "b4593f99-797b-5b69-9237-aa0de075c8cf".into(),
                ..Default::default()
            },
        ];
        for active in [&users[..], &users[..1]] {
            let BuiltServerConfig::Shadowsocks(config) =
                shadowsocks::build_config(&remote, active).expect("build UUID config")
            else {
                panic!("expected Shadowsocks config");
            };
            assert_eq!(config.password, server_key);
            assert_eq!(config.users[0], format!("1001:{user_key}"));
            let core_users = shadowsocks::core_users(&remote, active).expect("core UUID users");
            assert_eq!(core_users[0].credential, user_key);
            assert_eq!(core_users[0].upload_limit_bps, Some(1_250_000));
            assert_eq!(core_users[0].max_online_ips, Some(2));
        }
        assert!(shadowsocks::core_users(&remote, &[]).unwrap().is_empty());
    }
}

#[test]
fn shadowsocks_2022_chacha_supports_only_a_single_user() {
    let remote = NodeConfigResponse {
        server_port: 8388,
        cipher: "2022-blake3-chacha20-poly1305".into(),
        ..Default::default()
    };
    let user = PanelUser {
        id: 1001,
        password: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=".into(),
        ..Default::default()
    };
    let BuiltServerConfig::Shadowsocks(config) =
        shadowsocks::build_config(&remote, std::slice::from_ref(&user)).unwrap()
    else {
        panic!("expected Shadowsocks config");
    };
    assert_eq!(config.password, user.password);
    assert!(config.users.is_empty());
    let core_users = shadowsocks::core_users(&remote, std::slice::from_ref(&user)).unwrap();
    assert_eq!(core_users[0].credential, user.password);
    assert_eq!(core_users[0].id, "1001");
    let second_user = PanelUser {
        id: 1002,
        uuid: "b4593f99-797b-5b69-9237-aa0de075c8cf".into(),
        ..Default::default()
    };
    let users = [user, second_user];
    let error = shadowsocks::build_config(&remote, &users).err().unwrap();
    assert!(error.to_string().contains("supports only a single user"));
    assert!(shadowsocks::core_users(&remote, &users).is_err());
    assert!(shadowsocks::core_users(&remote, &[]).unwrap().is_empty());
}

#[test]
fn builds_mieru_server_config_ignoring_xboard_tls_ws_or_multiplex() {
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
    assert_eq!(config.listen, "[::]:8964".parse().unwrap());
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.transport, ::aerion::MieruTransport::Tcp);
}

#[test]
fn ignores_xboard_routing_and_fallback_fields() {
    let remote = NodeConfigResponse {
        custom_outbounds: vec![json!({ "tag": "ignored" })],
        fallback: Some(json!({ "dest": "127.0.0.1:80" })),
        ..Default::default()
    };

    ignore_unmapped_routing_and_fallbacks(ProtocolKind::Mieru.as_str(), &remote);
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
            email: "alice@example.com".to_string(),
            password: "alice-pass".to_string(),
            ..Default::default()
        },
        PanelUser {
            id: 1002,
            email: "bob@example.com".to_string(),
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
    assert_eq!(config.listen, "[::]:8443".parse().unwrap());
    assert_eq!(config.username, "alice@example.com");
    assert_eq!(config.password, "alice-pass");
    assert_eq!(config.users, vec!["bob@example.com:bob-pass"]);
    assert!(config.udp_over_tcp);
    assert!(config.tcp);
    assert!(config.quic);
    assert_eq!(config.quic_congestion_control, "cubic");
}

#[tokio::test]
async fn rejects_naive_server_config_without_email() {
    let remote = NodeConfigResponse {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 8443,
        server_name: "naive.example.com".to_string(),
        ..Default::default()
    };
    let users = vec![PanelUser {
        id: 1001,
        uuid: "uuid-secret".to_string(),
        password: "secret".to_string(),
        ..Default::default()
    }];

    let error = match build_naive_config(&remote, &users).await {
        Err(error) => error,
        Ok(_) => panic!("Naive without email must fail"),
    };
    assert!(error.to_string().contains("missing email"));
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
    assert_eq!(config.listen, "[::]:8444".parse().unwrap());
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
fn tuic_ignores_unimplemented_zero_rtt() {
    let remote = NodeConfigResponse {
        zero_rtt_handshake: true,
        ..Default::default()
    };

    validate_tuic_remote(&remote).expect("ignore TUIC 0-RTT");
}

#[test]
fn protocol_requires_listener_user_reload_identifies_static_listeners() {
    assert!(protocol_requires_listener_user_reload(ProtocolKind::Mieru));
    assert!(protocol_requires_listener_user_reload(ProtocolKind::Naive));
    assert!(protocol_requires_listener_user_reload(
        ProtocolKind::Shadowsocks
    ));
    assert!(protocol_requires_listener_user_reload(ProtocolKind::Tuic));
    assert!(protocol_requires_listener_user_reload(ProtocolKind::Vmess));

    assert!(!protocol_requires_listener_user_reload(
        ProtocolKind::Anytls
    ));
    assert!(!protocol_requires_listener_user_reload(
        ProtocolKind::Hysteria2
    ));
    assert!(!protocol_requires_listener_user_reload(
        ProtocolKind::Trojan
    ));
    assert!(!protocol_requires_listener_user_reload(ProtocolKind::Vless));
}

#[test]
fn credentials_changed_detects_user_modifications() {
    let remote = NodeConfigResponse {
        network: "tcp".to_string(),
        ..Default::default()
    };
    let base_users = vec![
        PanelUser {
            id: 1,
            uuid: "uuid-1".to_string(),
            speed_limit: 100,
            device_limit: 2,
            ..Default::default()
        },
        PanelUser {
            id: 2,
            uuid: "uuid-2".to_string(),
            speed_limit: 200,
            device_limit: 1,
            ..Default::default()
        },
    ];

    // Same users, same order -> false
    assert!(!credentials_changed(
        ProtocolKind::Mieru,
        &remote,
        &base_users,
        &base_users
    ));

    // Same users, swapped order -> false
    let reversed_users = vec![base_users[1].clone(), base_users[0].clone()];
    assert!(!credentials_changed(
        ProtocolKind::Mieru,
        &remote,
        &base_users,
        &reversed_users
    ));

    // Only speed limit or device limit changed -> false
    let mut limits_changed = base_users.clone();
    limits_changed[0].speed_limit = 500;
    limits_changed[1].device_limit = 5;
    assert!(!credentials_changed(
        ProtocolKind::Mieru,
        &remote,
        &base_users,
        &limits_changed
    ));

    // User added -> true
    let mut user_added = base_users.clone();
    user_added.push(PanelUser {
        id: 3,
        uuid: "uuid-3".to_string(),
        ..Default::default()
    });
    assert!(credentials_changed(
        ProtocolKind::Mieru,
        &remote,
        &base_users,
        &user_added
    ));

    // User removed -> true
    let user_removed = vec![base_users[0].clone()];
    assert!(credentials_changed(
        ProtocolKind::Mieru,
        &remote,
        &base_users,
        &user_removed
    ));

    // User credential changed -> true
    let mut credential_changed = base_users.clone();
    credential_changed[0].uuid = "new-uuid-1".to_string();
    assert!(credentials_changed(
        ProtocolKind::Mieru,
        &remote,
        &base_users,
        &credential_changed
    ));
}

#[tokio::test]
async fn builds_flux_xboard_and_pxboard_equivalently_and_dedups_listeners() -> anyhow::Result<()> {
    let priv_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let xboard_remote: NodeConfigResponse = serde_json::from_value(json!({
        "protocol": "flux",
        "host": "edge.example.com",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "tls": 2,
        "reality_settings": {
            "server_name": "www.microsoft.com",
            "server_port": 443,
            "private_key": priv_key,
            "short_id": "01020304"
        },
        "flux": {
            "ip_strategy": "dual",
            "standby_channels": 2,
            "rotation_interval_sec": 180,
            "rotation_bytes_mb": 96,
            "security": "reality",
            "obfs_key": "shared-obfs-secret-key",
            "channels": [
                {
                    "id": "ct-v4-relay",
                    "connect_host": "ct.example.com",
                    "connect_ports": "20443",
                    "listen_ports": "8443",
                    "transport": "tcp",
                    "security": "reality"
                },
                {
                    "id": "cu-v6-relay",
                    "connect_host": "cu6.example.com",
                    "connect_ports": "30443",
                    "listen_ports": "8443",
                    "transport": "tcp",
                    "security": "reality"
                },
                {
                    "id": "cdn-ws",
                    "connect_host": "cdn.example.com",
                    "connect_ports": "443",
                    "listen_ip": "127.0.0.1",
                    "listen_ports": "18080",
                    "transport": "http",
                    "http_mode": "ws",
                    "http_host": "cdn.example.com",
                    "http_path": "/flux-ws",
                    "security": "tls",
                    "cert_mode": "origin_plain"
                },
                {
                    "id": "udp-hop",
                    "connect_ports": "21000-21002",
                    "transport": "udp",
                    "security": "obfs",
                    "role": "backup",
                    "weight": 80
                }
            ]
        }
    }))?;

    let pxboard_remote = crate::pxboard::adapt_pxboard_node_config(json!({
        "protocol": "flux",
        "host": "edge.example.com",
        "listen": { "host": "0.0.0.0", "port": 443 },
        "transport": { "type": "tcp", "settings": {} },
        "security": {
            "mode": "reality",
            "serverName": "www.microsoft.com",
            "tlsSettings": {},
            "reality": {
                "serverName": "www.microsoft.com",
                "serverPort": 443,
                "privateKey": priv_key,
                "shortId": "01020304"
            },
            "certificate": null
        },
        "protocolOptions": {
            "ipStrategy": "dual",
            "standbyChannels": 2,
            "rotationIntervalSec": 180,
            "rotationBytesMb": 96,
            "obfsKey": "shared-obfs-secret-key",
            "channels": [
                {
                    "id": "ct-v4-relay",
                    "connectHost": "ct.example.com",
                    "connectPorts": "20443",
                    "listenPorts": "8443",
                    "transport": "tcp",
                    "security": "reality"
                },
                {
                    "id": "cu-v6-relay",
                    "connectHost": "cu6.example.com",
                    "connectPorts": "30443",
                    "listenPorts": "8443",
                    "transport": "tcp",
                    "security": "reality"
                },
                {
                    "id": "cdn-ws",
                    "connectHost": "cdn.example.com",
                    "connectPorts": "443",
                    "listenIp": "127.0.0.1",
                    "listenPorts": "18080",
                    "transport": "http",
                    "httpMode": "ws",
                    "httpHost": "cdn.example.com",
                    "httpPath": "/flux-ws",
                    "security": "tls",
                    "certMode": "origin_plain"
                },
                {
                    "id": "udp-hop",
                    "connectPorts": "21000-21002",
                    "transport": "udp",
                    "security": "obfs",
                    "role": "backup",
                    "weight": 80
                }
            ]
        }
    }))?;

    let users = vec![
        PanelUser {
            id: 1,
            uuid: "alice-flux-uuid".into(),
            ..Default::default()
        },
        PanelUser {
            id: 2,
            uuid: "bob-flux-uuid".into(),
            ..Default::default()
        },
    ];

    let BuiltServerConfig::Flux(xb_cfg) =
        build_server_config(ProtocolKind::Flux, &xboard_remote, &users).await?
    else {
        panic!("expected Flux config for Xboard")
    };
    let BuiltServerConfig::Flux(px_cfg) =
        build_server_config(ProtocolKind::Flux, &pxboard_remote, &users).await?
    else {
        panic!("expected Flux config for PxBoard")
    };

    assert!(!protocol_requires_listener_user_reload(ProtocolKind::Flux));
    assert_eq!(xb_cfg.key, "alice-flux-uuid");
    assert_eq!(xb_cfg.users, ["bob-flux-uuid"]);
    // 4 logical channels -> 3 physical listener groups because ct-v4-relay & cu-v6-relay share :: :8443/tcp
    assert_eq!(xb_cfg.listeners.len(), 3);
    assert_eq!(px_cfg.listeners.len(), 3);
    assert_eq!(xb_cfg.listeners[0].ports, vec![8443]);
    assert_eq!(xb_cfg.listeners[1].ports, vec![18080]);
    assert_eq!(xb_cfg.listeners[2].ports, vec![21000, 21001, 21002]);
    for (a, b) in xb_cfg.listeners.iter().zip(px_cfg.listeners.iter()) {
        assert_eq!(a.listen_ip, b.listen_ip);
        assert_eq!(a.ports, b.ports);
        assert_eq!(a.transport, b.transport);
        assert_eq!(a.http_mode, b.http_mode);
        assert_eq!(a.http_path, b.http_path);
        assert_eq!(a.security, b.security);
        assert_eq!(a.cert_mode, b.cert_mode);
        assert_eq!(a.reality, b.reality);
        assert_eq!(a.obfs_key, b.obfs_key);
    }

    // Conflicting security on the same local port must be rejected explicitly
    let conflict_remote: NodeConfigResponse = serde_json::from_value(json!({
        "protocol": "flux",
        "server_port": 443,
        "flux": {
            "obfs_key": "shared-obfs-secret-key",
            "channels": [
                {
                    "id": "ch1",
                    "listen_ports": "9443",
                    "transport": "tcp",
                    "security": "obfs"
                },
                {
                    "id": "ch2",
                    "listen_ports": "9443",
                    "transport": "http",
                    "http_mode": "ws",
                    "security": "obfs"
                }
            ]
        }
    }))?;
    assert!(
        build_server_config(ProtocolKind::Flux, &conflict_remote, &users)
            .await
            .is_err()
    );
    Ok(())
}
