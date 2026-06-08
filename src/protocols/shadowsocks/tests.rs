use super::*;
use crate::panel::NodeConfigResponse;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn dummy_plugin_path() -> PathBuf {
    std::env::current_exe()
        .expect("current exe")
        .with_file_name(if cfg!(windows) {
            "dummy_ss_plugin.bat"
        } else {
            "dummy_ss_plugin.sh"
        })
}

fn base_remote() -> NodeConfigResponse {
    NodeConfigResponse {
        protocol: "shadowsocks".to_string(),
        listen_ip: "0.0.0.0".to_string(),
        server_port: 8388,
        cipher: "aes-128-gcm".to_string(),
        ..Default::default()
    }
}

#[test]
fn legacy_defaults_to_tcp_only() {
    let config = EffectiveNodeConfig::from_remote(&base_remote()).expect("config");
    assert!(config.networks.tcp);
    assert!(!config.networks.udp);
}

#[test]
fn shadowsocks_2022_defaults_to_both_networks() {
    let remote = NodeConfigResponse {
        cipher: "2022-blake3-aes-128-gcm".to_string(),
        server_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
        ..base_remote()
    };
    let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
    assert!(config.networks.tcp);
    assert!(config.networks.udp);
}

#[test]
fn accepts_plugin_configuration() {
    let remote = NodeConfigResponse {
        plugin: "obfs-local".to_string(),
        plugin_opts: "obfs=http".to_string(),
        ..base_remote()
    };
    let config = EffectiveNodeConfig::from_remote(&remote).expect("plugin");
    let plugin = config.plugin.expect("plugin config");
    assert_eq!(plugin.command, "obfs-local");
    assert_eq!(plugin.opts, "obfs=http");
}

#[tokio::test]
async fn starts_sip003_plugin_and_loopback_tcp_listener() {
    let plugin_path = dummy_plugin_path();
    let script = if cfg!(windows) {
        "@echo off\r\n(\r\necho SS_REMOTE_HOST=%SS_REMOTE_HOST%\r\necho SS_REMOTE_PORT=%SS_REMOTE_PORT%\r\necho SS_LOCAL_HOST=%SS_LOCAL_HOST%\r\necho SS_LOCAL_PORT=%SS_LOCAL_PORT%\r\n) > \"%SS_PLUGIN_OPTIONS%\"\r\nping -n 6 127.0.0.1 > nul\r\n"
    } else {
        "#!/bin/sh\nprintf 'SS_REMOTE_HOST=%s\nSS_REMOTE_PORT=%s\nSS_LOCAL_HOST=%s\nSS_LOCAL_PORT=%s\n' \"$SS_REMOTE_HOST\" \"$SS_REMOTE_PORT\" \"$SS_LOCAL_HOST\" \"$SS_LOCAL_PORT\" > \"$SS_PLUGIN_OPTIONS\"\nsleep 5\n"
    };
    tokio::fs::write(&plugin_path, script)
        .await
        .expect("write plugin");
    #[cfg(unix)]
    tokio::fs::set_permissions(&plugin_path, std::fs::Permissions::from_mode(0o755))
        .await
        .expect("chmod plugin");

    let env_path = plugin_path.with_extension("env");
    let controller = ServerController::new(Accounting::new());
    controller
        .replace_users(&[PanelUser {
            id: 1,
            password: "secret".to_string(),
            ..Default::default()
        }])
        .expect("users");
    let config = EffectiveNodeConfig {
        listen_ip: "127.0.0.1".to_string(),
        server_port: 0,
        method: Method::Legacy(crypto::LegacyAeadMethod::Aes128Gcm),
        server_key: String::new(),
        networks: EnabledNetworks {
            tcp: true,
            udp: false,
        },
        plugin: Some(PluginConfig {
            command: plugin_path.to_string_lossy().to_string(),
            opts: env_path.to_string_lossy().to_string(),
        }),
        multiplex: MultiplexConfig::default(),
        routing: routing::RoutingTable::default(),
    };

    controller.apply_config(config).await.expect("apply config");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let env = tokio::fs::read_to_string(&env_path)
        .await
        .expect("read plugin env");
    assert!(env.contains("SS_REMOTE_HOST=127.0.0.1"));
    assert!(env.contains("SS_REMOTE_PORT=0"));
    assert!(env.contains("SS_LOCAL_HOST=127.0.0.1"));
    assert!(env.contains("SS_LOCAL_PORT="));
    controller.shutdown().await;
    let _ = tokio::fs::remove_file(&plugin_path).await;
    let _ = tokio::fs::remove_file(&env_path).await;
}

#[test]
fn parses_yamux_multiplex_configuration() {
    let remote = NodeConfigResponse {
        multiplex: Some(serde_json::json!({
            "enabled": true,
            "protocol": "yamux",
            "padding": true
        })),
        ..base_remote()
    };
    let config = EffectiveNodeConfig::from_remote(&remote).expect("multiplex");
    assert!(config.multiplex.enabled);
    assert_eq!(config.multiplex.protocol, SingMuxProtocol::Yamux);
    assert!(config.multiplex.padding);
}

#[test]
fn rejects_non_yamux_multiplex_configuration() {
    let remote = NodeConfigResponse {
        multiplex: Some(serde_json::json!({
            "enabled": true,
            "protocol": "h2mux"
        })),
        ..base_remote()
    };
    let error = EffectiveNodeConfig::from_remote(&remote).expect_err("multiplex");
    assert!(error.to_string().contains("yamux"));
}

#[test]
fn builds_users_from_password_or_uuid() {
    let users = build_users(
        &Method::Legacy(crypto::LegacyAeadMethod::Aes128Gcm),
        "",
        &[
            PanelUser {
                id: 1,
                password: "secret".to_string(),
                ..Default::default()
            },
            PanelUser {
                id: 2,
                uuid: "fallback-secret".to_string(),
                ..Default::default()
            },
        ],
    )
    .expect("users");
    assert_eq!(users.len(), 2);
}

#[test]
fn accepts_shadowsocks_2022_with_server_key() {
    let remote = NodeConfigResponse {
        cipher: "2022-blake3-aes-128-gcm".to_string(),
        server_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
        ..base_remote()
    };
    let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
    assert!(matches!(config.method, Method::Aead2022(_)));
}

#[test]
fn shadowsocks_2022_single_user_uses_server_key() {
    let users = build_users(
        &Method::Aead2022(crypto::Aead2022Method::Aes128Gcm),
        "QUJDREVGR0hJSktMTU5PUA==",
        &[PanelUser {
            id: 1,
            password: "user-password".to_string(),
            ..Default::default()
        }],
    )
    .expect("users");

    assert_eq!(users.len(), 1);
    assert_eq!(users[0].secret, b"ABCDEFGHIJKLMNOP");
}

#[test]
fn shadowsocks_2022_multi_user_decodes_base64_user_keys() {
    let users = build_users(
        &Method::Aead2022(crypto::Aead2022Method::Aes128Gcm),
        "QUJDREVGR0hJSktMTU5PUA==",
        &[
            PanelUser {
                id: 1,
                password: "MTIzNDU2Nzg5MGFiY2RlZg==".to_string(),
                ..Default::default()
            },
            PanelUser {
                id: 2,
                password: "YWJjZGVmMTIzNDU2Nzg5MA==".to_string(),
                ..Default::default()
            },
        ],
    )
    .expect("users");

    assert_eq!(users.len(), 2);
    assert_eq!(users[0].secret, b"1234567890abcdef");
    assert_eq!(users[1].secret, b"abcdef1234567890");
}

#[test]
fn rejects_shadowsocks_2022_multi_user_raw_key() {
    let error = build_users(
        &Method::Aead2022(crypto::Aead2022Method::Aes128Gcm),
        "QUJDREVGR0hJSktMTU5PUA==",
        &[
            PanelUser {
                id: 1,
                password: "not-base64-key".to_string(),
                ..Default::default()
            },
            PanelUser {
                id: 2,
                password: "YWJjZGVmMTIzNDU2Nzg5MA==".to_string(),
                ..Default::default()
            },
        ],
    )
    .expect_err("raw key should fail");
    assert!(
        error
            .to_string()
            .contains("decode Shadowsocks 2022 user 1 key")
    );
}

#[test]
fn accepts_shadowsocks_2022_chacha_method() {
    let remote = NodeConfigResponse {
        cipher: "2022-blake3-chacha20-poly1305".to_string(),
        server_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string(),
        ..base_remote()
    };
    let config = EffectiveNodeConfig::from_remote(&remote).expect("config");
    assert!(matches!(
        config.method,
        Method::Aead2022(crypto::Aead2022Method::ChaCha20Poly1305)
    ));
}

#[test]
fn rejects_shadowsocks_2022_chacha_multi_user() {
    let error = build_users(
        &Method::Aead2022(crypto::Aead2022Method::ChaCha20Poly1305),
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        &[
            PanelUser {
                id: 1,
                uuid: "user-1".to_string(),
                ..Default::default()
            },
            PanelUser {
                id: 2,
                uuid: "user-2".to_string(),
                ..Default::default()
            },
        ],
    )
    .expect_err("multi-user chacha");
    assert!(error.to_string().contains("does not support multi-user"));
}

#[test]
fn accepts_disabled_transport_extension_values() {
    let remote = NodeConfigResponse {
        network_settings: Some(serde_json::json!({ "enabled": false })),
        multiplex: Some(serde_json::json!({ "enabled": false })),
        transport: Some(serde_json::json!({ "enabled": false })),
        ..base_remote()
    };
    EffectiveNodeConfig::from_remote(&remote).expect("config");
}

#[test]
fn rejects_enabled_transport_extension_values() {
    let remote = NodeConfigResponse {
        network_settings: Some(serde_json::json!({ "ws": true })),
        ..base_remote()
    };
    let error = EffectiveNodeConfig::from_remote(&remote).expect_err("network settings");
    assert!(error.to_string().contains("networkSettings"));
}

#[test]
fn accepts_proxy_protocol_noise_in_network_settings() {
    let remote = NodeConfigResponse {
        network_settings: Some(serde_json::json!({ "acceptProxyProtocol": true })),
        ..base_remote()
    };
    EffectiveNodeConfig::from_remote(&remote).expect("config");
}
