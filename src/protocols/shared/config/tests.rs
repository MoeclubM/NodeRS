use super::*;
use crate::panel::{CertConfig, NodeConfigResponse, NodeEchSettings, NodeTlsSettings};
use crate::protocols::shared::tls;

const REALITY_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn base_remote() -> NodeConfigResponse {
    NodeConfigResponse {
        protocol: "vless".to_string(),
        listen_ip: "0.0.0.0".to_string(),
        server_port: 443,
        server_name: "node.example.com".to_string(),
        cert_config: Some(CertConfig {
            cert_mode: "file".to_string(),
            cert_path: "/etc/ssl/private/fullchain.pem".to_string(),
            key_path: "/etc/ssl/private/privkey.pem".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn self_signed_tls_includes_server_names_array() {
    let remote = NodeConfigResponse {
        cert_config: Some(CertConfig {
            cert_mode: "self_signed".to_string(),
            ..Default::default()
        }),
        tls_settings: NodeTlsSettings {
            server_name: "tls.example.com".to_string(),
            server_names: vec!["cdn.example.com".to_string(), "TLS.EXAMPLE.COM".to_string()],
            ..Default::default()
        },
        ..base_remote()
    };

    let effective = EffectiveTlsConfig::from_remote(&remote).expect("tls config");
    match effective.source {
        tls::TlsMaterialSource::SelfSigned { subject_alt_names } => {
            assert_eq!(
                subject_alt_names,
                vec![
                    "node.example.com".to_string(),
                    "tls.example.com".to_string(),
                    "cdn.example.com".to_string()
                ]
            );
        }
        _ => unreachable!("expected self-signed TLS source"),
    }
}

#[test]
fn acme_tls_includes_server_names_array_when_domains_are_empty() {
    let remote = NodeConfigResponse {
        cert_config: Some(CertConfig {
            cert_mode: "acme".to_string(),
            ..Default::default()
        }),
        tls_settings: NodeTlsSettings {
            server_names: vec!["cdn.example.com".to_string()],
            ..Default::default()
        },
        ..base_remote()
    };

    let effective = EffectiveTlsConfig::from_remote(&remote).expect("tls config");
    match effective.source {
        tls::TlsMaterialSource::Acme { config, .. } => {
            assert_eq!(
                config.domains,
                vec![
                    "node.example.com".to_string(),
                    "cdn.example.com".to_string()
                ]
            );
        }
        _ => unreachable!("expected ACME TLS source"),
    }
}

#[test]
fn tls_config_maps_xboard_ech_settings() {
    let remote = NodeConfigResponse {
        tls_settings: NodeTlsSettings {
            ech: NodeEchSettings {
                enabled: true,
                key_path: "/etc/anytls/ech.bin".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        ..base_remote()
    };

    let effective = EffectiveTlsConfig::from_remote(&remote).expect("tls config");
    assert!(effective.ech.is_some());
}

#[test]
fn rejects_reality_tls_mode_without_private_key() {
    let remote = NodeConfigResponse {
        tls: Some(serde_json::json!(2)),
        reality_settings: crate::panel::NodeRealitySettings {
            server_name: "reality.example.com".to_string(),
            public_key: REALITY_KEY_B64.to_string(),
            ..Default::default()
        },
        ..base_remote()
    };

    let error = effective_reality_config(&remote).expect_err("reality settings");
    assert!(error.to_string().contains("reality_settings.private_key"));
}

#[test]
fn rejects_reality_tls_mode_without_any_server_name() {
    let remote = NodeConfigResponse {
        tls: Some(serde_json::json!(2)),
        server_name: String::new(),
        reality_settings: crate::panel::NodeRealitySettings {
            public_key: REALITY_KEY_B64.to_string(),
            private_key: REALITY_KEY_B64.to_string(),
            ..Default::default()
        },
        ..base_remote()
    };

    let error = effective_reality_config(&remote).expect_err("reality server name");
    assert!(
        error
            .to_string()
            .contains("reality_settings.server_name or server_names")
    );
}

#[test]
fn parses_reality_config_from_tls_mode_two() {
    let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "tls": 2,
        "tls_settings": {
            "server_name": "reality.example.com",
            "server_port": 8443,
            "allow_insecure": true,
            "public_key": REALITY_KEY_B64,
            "private_key": REALITY_KEY_B64,
            "short_id": "a1b2"
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse remote");

    let reality = effective_reality_config(&remote)
        .expect("reality config")
        .expect("reality config present");
    assert_eq!(reality.server_name, "reality.example.com");
    assert_eq!(
        reality.server_names,
        vec!["reality.example.com".to_string()]
    );
    assert_eq!(reality.server_port, 8443);
    assert!(reality.allow_insecure);
    assert_eq!(reality.private_key, [0u8; 32]);
    assert_eq!(reality.short_ids, vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]]);
}

#[test]
fn reality_config_defaults_port_and_accepts_camel_case_fields() {
    let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 2443,
        "server_name": "node.example.com",
        "tls": 2,
        "realitySettings": {
            "server_name": "reality.example.com",
            "publicKey": REALITY_KEY_B64,
            "privateKey": REALITY_KEY_B64,
            "shortId": ""
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse remote");

    let reality = effective_reality_config(&remote)
        .expect("reality config")
        .expect("reality config present");
    assert_eq!(reality.server_port, 2443);
    assert_eq!(reality.short_ids, vec![[0u8; 8]]);
}

#[test]
fn reality_config_accepts_server_names_array() {
    let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 2443,
        "tls": 2,
        "realitySettings": {
            "serverName": "cas-bridge.xethub.hf.co",
            "serverNames": ["oracle-osa-01.telecom.moe", "cdn.example.com"],
            "publicKey": REALITY_KEY_B64,
            "privateKey": REALITY_KEY_B64,
            "shortIds": ["a1b2"]
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse remote");

    let reality = effective_reality_config(&remote)
        .expect("reality config")
        .expect("reality config present");
    assert_eq!(
        reality.server_names,
        vec![
            "cas-bridge.xethub.hf.co".to_string(),
            "oracle-osa-01.telecom.moe".to_string(),
            "cdn.example.com".to_string()
        ]
    );
}

#[test]
fn reality_config_accepts_missing_public_key_for_server_side() {
    let remote = NodeConfigResponse {
        tls: Some(serde_json::json!(2)),
        reality_settings: crate::panel::NodeRealitySettings {
            server_name: "reality.example.com".to_string(),
            private_key: REALITY_KEY_B64.to_string(),
            short_id: "a1b2".to_string(),
            ..Default::default()
        },
        ..base_remote()
    };

    let reality = effective_reality_config(&remote)
        .expect("reality config")
        .expect("reality config present");
    assert_eq!(reality.server_name, "reality.example.com");
    assert_eq!(reality.private_key, [0u8; 32]);
}

#[test]
fn parses_reality_short_ids_array() {
    let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 2443,
        "server_name": "node.example.com",
        "tls": 2,
        "realitySettings": {
            "serverName": "reality.example.com",
            "publicKey": REALITY_KEY_B64,
            "privateKey": REALITY_KEY_B64,
            "shortIds": ["a1b2", "c3d4"]
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse remote");

    let reality = effective_reality_config(&remote)
        .expect("reality config")
        .expect("reality config present");
    assert_eq!(
        reality.short_ids,
        vec![
            [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
            [0xc3, 0xd4, 0, 0, 0, 0, 0, 0]
        ]
    );
}

#[test]
fn rejects_invalid_reality_settings() {
    let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "tls": 2,
        "tls_settings": {
            "server_name": "reality.example.com",
            "public_key": REALITY_KEY_B64,
            "private_key": REALITY_KEY_B64,
            "short_id": "not-hex"
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse remote");

    let error = effective_reality_config(&remote).expect_err("invalid short id");
    assert!(error.to_string().contains("short_id"));

    let remote: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "tls": 2,
        "tls_settings": {
            "server_name": "reality.example.com",
            "public_key": REALITY_KEY_B64
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse remote");

    let error = effective_reality_config(&remote).expect_err("missing private key");
    assert!(error.to_string().contains("private_key"));
}
