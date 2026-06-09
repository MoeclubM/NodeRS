use super::*;
use crate::config::PanelConfig;

#[test]
fn parses_base_config_numbers() {
    let cfg = BaseConfig {
        push_interval: Some(serde_json::json!(120)),
        pull_interval: Some(serde_json::json!("30")),
    };
    assert_eq!(cfg.push_interval_seconds(), Some(120));
    assert_eq!(cfg.pull_interval_seconds(), Some(30));
}

#[test]
fn parses_route_match_from_string() {
    let route: RouteConfig = serde_json::from_value(serde_json::json!({
        "id": 1,
        "match": r" protocol:tcp , regexp:^example\.com$ ",
        "action": "block",
        "action_value": ""
    }))
    .expect("parse route");
    assert_eq!(
        route.match_value,
        Some(RouteMatch::String(
            r" protocol:tcp , regexp:^example\.com$ ".to_string()
        ))
    );
}

#[test]
fn parses_route_match_from_array() {
    let route: RouteConfig = serde_json::from_value(serde_json::json!({
        "id": 2,
        "match": [r"regexp:^example\.org$", "protocol:udp"],
        "action": "block",
        "action_value": ""
    }))
    .expect("parse route");
    assert_eq!(
        route.match_value,
        Some(RouteMatch::Strings(vec![
            r"regexp:^example\.org$".to_string(),
            "protocol:udp".to_string()
        ]))
    );
}

#[test]
fn accepts_nulls_in_node_config_response() {
    let config: NodeConfigResponse = serde_json::from_str(
        r#"{
            "protocol": "anytls",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "network": null,
            "networkSettings": null,
            "server_name": "node.example.com",
            "tls": null,
            "tls_settings": {
                "server_name": "node.example.com",
                "allow_insecure": false,
                "ech": null
            },
            "multiplex": null,
            "host": null,
            "cipher": null,
            "plugin": null,
            "plugin_opts": null,
            "server_key": null,
            "flow": null,
            "decryption": null,
            "version": null,
            "up_mbps": null,
            "down_mbps": null,
            "obfs": null,
            "obfs-password": null,
            "congestion_control": null,
            "auth_timeout": null,
            "zero_rtt_handshake": null,
            "heartbeat": null,
            "transport": null,
            "traffic_pattern": null,
            "nonce_pattern": null,
            "alpn": null,
            "packet_encoding": null,
            "global_padding": null,
            "authenticated_length": null,
            "fallbacks": null,
            "fallback": null,
            "fallback_for_alpn": null,
            "ignoreClientBandwidth": null,
            "masquerade": null,
            "udpRelayMode": null,
            "udpOverStream": null,
            "padding_scheme": null,
            "routes": null,
            "custom_outbounds": null,
            "custom_routes": null,
            "cert_config": {
                "cert_mode": "file",
                "cert_path": "/etc/ssl/private/fullchain.pem",
                "key_path": "/etc/ssl/private/privkey.pem"
            },
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60
            }
        }"#,
    )
    .expect("parse config");
    assert_eq!(config.listen_ip, "0.0.0.0");
    assert_eq!(config.server_name, "node.example.com");
    assert_eq!(config.network, "");
    assert!(config.network_settings.is_none());
    assert!(config.tls.is_none());
    assert!(config.multiplex.is_none());
    assert_eq!(config.host, "");
    assert_eq!(config.cipher, "");
    assert_eq!(config.plugin, "");
    assert_eq!(config.plugin_opts, "");
    assert_eq!(config.server_key, "");
    assert_eq!(config.flow, "");
    assert_eq!(config.decryption, "");
    assert!(config.version.is_none());
    assert!(config.up_mbps.is_none());
    assert!(config.down_mbps.is_none());
    assert!(config.obfs.is_none());
    assert_eq!(config.obfs_password, "");
    assert_eq!(config.congestion_control, "");
    assert_eq!(config.auth_timeout, "");
    assert!(!config.zero_rtt_handshake);
    assert_eq!(config.heartbeat, "");
    assert!(config.transport.is_none());
    assert_eq!(config.traffic_pattern, "");
    assert_eq!(config.nonce_pattern, "");
    assert!(config.alpn.is_empty());
    assert_eq!(config.packet_encoding, "");
    assert!(!config.global_padding);
    assert!(!config.authenticated_length);
    assert!(config.fallbacks.is_none());
    assert!(config.fallback.is_none());
    assert!(config.fallback_for_alpn.is_none());
    assert!(!config.ignore_client_bandwidth);
    assert!(config.masquerade.is_none());
    assert_eq!(config.udp_relay_mode, "");
    assert!(!config.udp_over_stream);
    assert!(config.padding_scheme.is_empty());
    assert!(config.routes.is_empty());
    assert!(config.custom_outbounds.is_empty());
    assert!(config.custom_routes.is_empty());
    assert_eq!(
        config
            .cert_config
            .as_ref()
            .expect("cert config")
            .cert_mode(),
        "file"
    );
}

#[test]
fn accepts_string_ports_in_node_config_response() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": "443",
        "tls_settings": {
            "serverPort": "8443"
        },
        "reality_settings": {
            "server_port": "7443"
        }
    }))
    .expect("parse config");

    assert_eq!(config.server_port, 443);
    assert_eq!(config.tls_settings.server_port, 8443);
    assert_eq!(config.reality_settings.server_port, 7443);
}

#[test]
fn ech_fields_mark_remote_config_as_ech_enabled() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "network": "tcp",
        "networkSettings": {
            "header": {
                "type": "none"
            }
        },
        "server_name": "node.example.com",
        "tls_settings": {
            "server_name": "node.example.com",
            "allow_insecure": false,
            "ech": {
                "enabled": false,
                "config_path": "/etc/anytls/ech.json"
            }
        },
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "mode": "file",
            "cert_path": "/etc/ssl/private/fullchain.pem",
            "key_path": "/etc/ssl/private/privkey.pem"
        }
    }))
    .expect("parse config");

    assert!(config.tls_settings.ech.is_enabled());
    assert_eq!(config.network, "tcp");
    assert_eq!(
        config.network_settings,
        Some(serde_json::json!({
            "header": {
                "type": "none"
            }
        }))
    );
    assert_eq!(
        config
            .cert_config
            .as_ref()
            .expect("cert config")
            .cert_mode(),
        "file"
    );
}

#[test]
fn ech_only_tls_settings_are_not_treated_as_configured() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls_settings": {
            "ech": {
                "enabled": true
            }
        }
    }))
    .expect("parse config");

    assert!(config.tls_settings.ech.is_enabled());
    assert!(!config.tls_settings.is_configured());
}

#[test]
fn cert_config_accepts_inline_pem_aliases() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "inline",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(cert.cert_mode(), "inline");
    assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(cert.key_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
fn cert_config_accepts_acme_aliases_and_defaults() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "acme",
            "cert_path": "/var/lib/noders/anytls/node.example.com/fullchain.pem",
            "key_path": "/var/lib/noders/anytls/node.example.com/privkey.pem",
            "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "http01_listen": "127.0.0.1:8080",
            "acme_account_key_path": "/var/lib/noders/anytls/node.example.com/account.pem"
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(cert.cert_mode(), "acme");
    assert_eq!(
        cert.directory_url(),
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(cert.challenge_listen(), "127.0.0.1:8080");
    assert_eq!(
        cert.account_key_path(),
        "/var/lib/noders/anytls/node.example.com/account.pem"
    );
    assert_eq!(cert.renew_before_days(), 30);
}

#[test]
fn cert_config_preserves_extra_dns_fields_and_domains_aliases() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "mode": "dns",
            "domains": ["example.com", "*.example.com", "example.com"],
            "provider": "cloudflare",
            "zone_id": "zone-123",
            "env": {
                "CF_DNS_API_TOKEN": "token-abc"
            },
            "propagation_timeout": 240,
            "propagation_interval": 7
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(cert.cert_mode(), "dns");
    assert_eq!(
        cert.domains(),
        vec!["example.com".to_string(), "*.example.com".to_string()]
    );
    assert_eq!(cert.dns_provider().as_deref(), Some("cloudflare"));
    assert_eq!(cert.dns_zone_id().as_deref(), Some("zone-123"));
    assert_eq!(
        cert.extra_string(&[&["env", "CF_DNS_API_TOKEN"]])
            .as_deref(),
        Some("token-abc")
    );
    assert_eq!(cert.dns_propagation_timeout_secs(), 240);
    assert_eq!(cert.dns_propagation_interval_secs(), 7);
}

#[test]
fn cert_config_resolves_dns_provider_credentials_and_challenge_aliases() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "acme",
            "challenge_type": "dns-01",
            "provider": "cloudflare",
            "env": {
                "CF_DNS_API_TOKEN": "token-abc",
                "ALICLOUD_ACCESS_KEY_ID": "ali-id",
                "ALICLOUD_ACCESS_KEY_SECRET": "ali-secret"
            },
            "cloudflare_api_key": "cf-key",
            "cloudflare_email": "dns@example.com"
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(cert.acme_challenge().as_deref(), Some("dns-01"));
    assert_eq!(cert.cloudflare_api_token().as_deref(), Some("token-abc"));
    assert_eq!(cert.cloudflare_api_key().as_deref(), Some("cf-key"));
    assert_eq!(
        cert.cloudflare_api_email().as_deref(),
        Some("dns@example.com")
    );
    assert_eq!(cert.alidns_access_key_id().as_deref(), Some("ali-id"));
    assert_eq!(
        cert.alidns_access_key_secret().as_deref(),
        Some("ali-secret")
    );
}

#[test]
fn cert_config_resolves_dns_provider_credentials_from_env_text_block() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "dns",
            "provider": "cloudflare",
            "env": "CF_API_TOKEN=token-abc\nexport CF_API_EMAIL=dns@example.com\n# ignored\nALICLOUD_ACCESS_KEY_ID=ali-id\r\nALICLOUD_ACCESS_KEY_SECRET='ali-secret'"
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(cert.cloudflare_api_token().as_deref(), Some("token-abc"));
    assert_eq!(
        cert.cloudflare_api_email().as_deref(),
        Some("dns@example.com")
    );
    assert_eq!(cert.alidns_access_key_id().as_deref(), Some("ali-id"));
    assert_eq!(
        cert.alidns_access_key_secret().as_deref(),
        Some("ali-secret")
    );
}

#[test]
fn cert_config_resolves_dns_provider_credentials_from_nested_env_block() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "dns",
            "provider": "cloudflare",
            "cloudflare": {
                "environment_variables": "CF_API_TOKEN=token-abc\nCF_API_EMAIL=dns@example.com"
            },
            "dns": {
                "credentials": {
                    "ALICLOUD_ACCESS_KEY_ID": "ali-id",
                    "ALICLOUD_ACCESS_KEY_SECRET": "ali-secret"
                }
            }
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(cert.cloudflare_api_token().as_deref(), Some("token-abc"));
    assert_eq!(
        cert.cloudflare_api_email().as_deref(),
        Some("dns@example.com")
    );
    assert_eq!(cert.alidns_access_key_id().as_deref(), Some("ali-id"));
    assert_eq!(
        cert.alidns_access_key_secret().as_deref(),
        Some("ali-secret")
    );
}

#[test]
fn cert_config_resolves_extended_cert_material_aliases() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "anytls",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "server_name": "node.example.com",
        "padding_scheme": [],
        "routes": [],
        "cert_config": {
            "cert_mode": "dns",
            "certificate_path": "/etc/ssl/fullchain.pem",
            "private_key_path": "/etc/ssl/privkey.pem",
            "cert_content": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "key_content": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
        }
    }))
    .expect("parse config");

    let cert = config.cert_config.expect("cert config");
    assert_eq!(
        cert.resolved_cert_path().as_deref(),
        Some("/etc/ssl/fullchain.pem")
    );
    assert_eq!(
        cert.resolved_key_path().as_deref(),
        Some("/etc/ssl/privkey.pem")
    );
    assert!(
        cert.resolved_cert_pem()
            .expect("cert pem")
            .contains("BEGIN CERTIFICATE")
    );
    assert!(
        cert.resolved_key_pem()
            .expect("key pem")
            .contains("BEGIN PRIVATE KEY")
    );
}

#[test]
fn accepts_nulls_in_route_and_user_defaults() {
    let route: RouteConfig = serde_json::from_value(serde_json::json!({
        "id": 9,
        "match": null,
        "action": null,
        "action_value": null
    }))
    .expect("parse route");
    assert_eq!(route.action, "");
    assert_eq!(route.action_value, "");

    let user: PanelUser = serde_json::from_value(serde_json::json!({
        "id": 1,
        "uuid": null,
        "password": null,
        "alterId": null,
        "speed_limit": null,
        "device_limit": null
    }))
    .expect("parse user");
    assert_eq!(user.uuid, "");
    assert_eq!(user.password, "");
    assert_eq!(user.alter_id, 0);
    assert_eq!(user.speed_limit, 0);
    assert_eq!(user.device_limit, 0);
}

#[test]
fn accepts_vmess_field_aliases() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vmess",
        "listenIp": "0.0.0.0",
        "serverPort": 443,
        "serverName": "node.example.com",
        "security": "aes-128-gcm",
        "tlsSettings": {
            "serverName": "tls.example.com",
            "serverPort": "8443"
        },
        "globalPadding": true,
        "authenticatedLength": true,
        "packetEncoding": "xudp",
        "fallbackForAlpn": {
            "h2": {
                "server": "127.0.0.1",
                "server_port": 8443
            }
        },
        "customOutbounds": [{ "tag": "direct" }],
        "customRoutes": [{ "match": "domain:example.com", "outbound": "direct" }],
        "certConfig": {
            "certMode": "file",
            "certificatePath": "/tmp/fullchain.pem",
            "privateKeyPath": "/tmp/privkey.pem"
        },
        "baseConfig": {
            "pushInterval": "120",
            "pullInterval": 30
        },
        "padding_scheme": [],
        "routes": []
    }))
    .expect("parse config");

    assert_eq!(config.listen_ip, "0.0.0.0");
    assert_eq!(config.server_port, 443);
    assert_eq!(config.server_name, "node.example.com");
    assert_eq!(config.cipher, "aes-128-gcm");
    assert_eq!(config.tls_settings.server_name, "tls.example.com");
    assert_eq!(config.tls_settings.server_port, 8443);
    assert!(config.global_padding);
    assert!(config.authenticated_length);
    assert_eq!(config.packet_encoding, "xudp");
    assert!(config.fallback_for_alpn.is_some());
    assert_eq!(config.custom_outbounds.len(), 1);
    assert_eq!(config.custom_routes.len(), 1);
    assert_eq!(config.cert_config.as_ref().unwrap().cert_mode(), "file");
    let base_config = config.base_config.as_ref().expect("base config");
    assert_eq!(base_config.push_interval_seconds(), Some(120));
    assert_eq!(base_config.pull_interval_seconds(), Some(30));

    let user: PanelUser = serde_json::from_value(serde_json::json!({
        "id": 7,
        "uuid": "00000000-0000-0000-0000-000000000001",
        "alterId": 0,
        "speedLimit": 1024,
        "deviceLimit": 2
    }))
    .expect("parse user");
    assert_eq!(user.alter_id, 0);
    assert_eq!(user.speed_limit, 1024);
    assert_eq!(user.device_limit, 2);
}

#[test]
fn parses_protocol_extension_fields_and_aliases() {
    let config: NodeConfigResponse = serde_json::from_str(
        r#"{
            "protocol": "tuic",
            "listen_ip": "0.0.0.0",
            "server_port": 443,
            "network": "tcp",
            "networkSettings": {
                "ws": false
            },
            "server_name": "node.example.com",
            "tls": {
                "enabled": true
            },
            "tls_settings": {
                "server_name": "node.example.com",
                "allow_insecure": false
            },
            "multiplex": {
                "enabled": true
            },
            "host": "trojan.example.com",
            "cipher": "2022-blake3-aes-128-gcm",
            "pluginOpts": "obfs=http",
            "plugin": "obfs-local",
            "server_key": "secret",
            "flow": "xtls-rprx-vision",
            "decryption": "none",
            "version": 2,
            "upMbps": 100,
            "downMbps": "200",
            "obfs": {
                "type": "salamander"
            },
            "is_obfs": true,
            "obfs-password": "cry_me_a_r1ver",
            "congestion_control": "bbr",
            "auth_timeout": "3s",
            "zero_rtt_handshake": true,
            "heartbeat": "10s",
            "transport": {
                "type": "udp"
            },
            "trafficPattern": "h3",
            "alpn": ["h2", "http/1.1"],
            "packet_encoding": "xudp",
            "fallbacks": [{
                "dest": 80
            }],
            "fallback": {
                "server": "127.0.0.1",
                "server_port": 8080
            },
            "fallback_for_alpn": {
                "h2": {
                    "server": "127.0.0.1",
                    "server_port": 8443
                }
            },
            "ignoreClientBandwidth": true,
            "masquerade": {
                "type": "proxy",
                "url": "https://example.com"
            },
            "udpRelayMode": "native",
            "udpOverStream": true,
            "padding_scheme": [],
            "routes": []
        }"#,
    )
    .expect("parse protocol extensions");

    assert_eq!(config.protocol, "tuic");
    assert_eq!(config.host, "trojan.example.com");
    assert_eq!(config.cipher, "2022-blake3-aes-128-gcm");
    assert_eq!(config.plugin, "obfs-local");
    assert_eq!(config.plugin_opts, "obfs=http");
    assert_eq!(config.server_key, "secret");
    assert_eq!(config.flow, "xtls-rprx-vision");
    assert_eq!(config.decryption, "none");
    assert_eq!(config.version, Some(serde_json::json!(2)));
    assert_eq!(config.up_mbps, Some(serde_json::json!(100)));
    assert_eq!(config.down_mbps, Some(serde_json::json!("200")));
    assert_eq!(
        config.obfs,
        Some(serde_json::json!({ "type": "salamander" }))
    );
    assert!(config.is_obfs);
    assert_eq!(config.obfs_password, "cry_me_a_r1ver");
    assert_eq!(config.congestion_control, "bbr");
    assert_eq!(config.auth_timeout, "3s");
    assert!(config.zero_rtt_handshake);
    assert_eq!(config.heartbeat, "10s");
    assert_eq!(config.transport, Some(serde_json::json!({ "type": "udp" })));
    assert_eq!(config.traffic_pattern, "h3");
    assert_eq!(config.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    assert_eq!(config.packet_encoding, "xudp");
    assert_eq!(config.fallbacks, Some(serde_json::json!([{ "dest": 80 }])));
    assert_eq!(
        config.fallback,
        Some(serde_json::json!({
            "server": "127.0.0.1",
            "server_port": 8080
        }))
    );
    assert_eq!(
        config.fallback_for_alpn,
        Some(serde_json::json!({
            "h2": {
                "server": "127.0.0.1",
                "server_port": 8443
            }
        }))
    );
    assert!(config.ignore_client_bandwidth);
    assert_eq!(
        config.masquerade,
        Some(serde_json::json!({
            "type": "proxy",
            "url": "https://example.com"
        }))
    );
    assert_eq!(config.udp_relay_mode, "native");
    assert!(config.udp_over_stream);
}

#[test]
fn interprets_tls_mode_and_disabled_multiplex_objects() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vmess",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "tls": 0,
        "multiplex": {
            "enabled": false,
            "protocol": "yamux"
        },
        "tls_settings": {
            "server_name": null,
            "allow_insecure": false
        }
    }))
    .expect("parse config");

    assert_eq!(config.tls_mode(), 0);
    assert!(!config.multiplex_enabled());
    assert!(!config.tls_settings.is_configured());

    let enabled: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "listen_ip": "0.0.0.0",
        "server_port": 443,
        "tls": {
            "enabled": true
        },
        "multiplex": true
    }))
    .expect("parse enabled config");

    assert_eq!(enabled.tls_mode(), 1);
    assert!(enabled.multiplex_enabled());

    let reality: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": "reality"
    }))
    .expect("parse reality string tls mode");
    assert_eq!(reality.tls_mode(), 2);

    let object_reality: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": {
            "type": "reality"
        }
    }))
    .expect("parse reality object tls mode");
    assert_eq!(object_reality.tls_mode(), 2);
}

#[test]
fn parses_bool_like_panel_values() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vmess",
        "server_port": 443,
        "globalPadding": 1,
        "authenticatedLength": "true",
        "ignoreClientBandwidth": "yes",
        "udpOverStream": "0",
        "tls_settings": {
            "allow_insecure": "true",
            "ech": {
                "enabled": 1
            }
        }
    }))
    .expect("parse bool-like values");

    assert!(config.global_padding);
    assert!(config.authenticated_length);
    assert!(config.ignore_client_bandwidth);
    assert!(!config.udp_over_stream);
    assert!(config.tls_settings.allow_insecure);
    assert!(config.tls_settings.ech.enabled);
}

#[test]
fn parses_alpn_from_string_lists() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "alpn": "h2, http/1.1\nh3"
    }))
    .expect("parse alpn list");

    assert_eq!(
        config.alpn,
        vec!["h2".to_string(), "http/1.1".to_string(), "h3".to_string()]
    );
}

#[test]
fn falls_back_to_tls_settings_for_reality_mode() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": 2,
        "tls_settings": {
            "server_name": "reality.example.com",
            "allow_insecure": true,
            "server_port": 8443,
            "public_key": "pub",
            "private_key": "priv",
            "short_id": "abcd"
        }
    }))
    .expect("parse reality config");

    let reality = config.effective_reality_settings();
    assert_eq!(reality.server_name, "reality.example.com");
    assert_eq!(reality.server_port, 8443);
    assert_eq!(reality.public_key, "pub");
    assert_eq!(reality.private_key, "priv");
    assert_eq!(reality.short_id, "abcd");
    assert!(reality.allow_insecure);
    assert!(config.tls_settings.is_configured());
    assert!(!config.reality_settings.is_configured());
}

#[test]
fn prefers_explicit_reality_settings_when_present() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": 2,
        "tls_settings": {
            "server_name": "tls.example.com",
            "public_key": "tls-pub"
        },
        "reality_settings": {
            "server_name": "reality.example.com",
            "server_port": 7443,
            "public_key": "reality-pub",
            "short_id": "beef"
        }
    }))
    .expect("parse explicit reality config");

    let reality = config.effective_reality_settings();
    assert_eq!(reality.server_name, "reality.example.com");
    assert_eq!(reality.server_port, 7443);
    assert_eq!(reality.public_key, "reality-pub");
    assert_eq!(reality.short_id, "beef");
}

#[test]
fn parses_reality_server_names_aliases() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": 2,
        "tlsSettings": {
            "serverNames": "tls-a.example.com,tls-b.example.com",
            "publicKey": "tls-pub"
        },
        "realitySettings": {
            "serverNames": ["reality-a.example.com", "reality-b.example.com"],
            "publicKey": "reality-pub"
        }
    }))
    .expect("parse serverNames aliases");

    let reality = config.effective_reality_settings();
    assert_eq!(
        reality.server_names,
        vec![
            "reality-a.example.com".to_string(),
            "reality-b.example.com".to_string()
        ]
    );
    assert!(config.tls_settings.is_configured());
    assert!(reality.is_configured());
}

#[test]
fn merges_partial_reality_settings_with_tls_reality_fields() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": 2,
        "tls_settings": {
            "server_name": "tls.example.com",
            "allow_insecure": true,
            "server_port": 8443,
            "public_key": "tls-pub",
            "private_key": "tls-priv",
            "short_id": "abcd"
        },
        "reality_settings": {
            "server_name": "reality.example.com",
            "public_key": "reality-pub"
        }
    }))
    .expect("parse partial reality config");

    let reality = config.effective_reality_settings();
    assert_eq!(reality.server_name, "reality.example.com");
    assert_eq!(reality.server_port, 8443);
    assert_eq!(reality.public_key, "reality-pub");
    assert_eq!(reality.private_key, "tls-priv");
    assert_eq!(reality.short_id, "abcd");
    assert!(reality.allow_insecure);
}

#[test]
fn accepts_lowercase_shortid_alias_in_reality_fields() {
    let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "server_port": 443,
        "tls": 2,
        "tls_settings": {
            "server_name": "tls.example.com",
            "public_key": "tls-pub",
            "private_key": "tls-priv",
            "shortid": "abcd"
        },
        "reality_settings": {
            "server_name": "reality.example.com",
            "public_key": "reality-pub",
            "private_key": "reality-priv",
            "shortid": "beef"
        }
    }))
    .expect("parse shortid alias config");

    let reality = config.effective_reality_settings();
    assert_eq!(reality.short_id, "beef");
}

#[test]
fn parses_machine_nodes_response() {
    let response: MachineNodesResponse = serde_json::from_value(serde_json::json!({
        "nodes": [
            {
                "id": 1,
                "type": "anytls",
                "name": "alpha"
            }
        ],
        "base_config": {
            "push_interval": 60,
            "pull_interval": 30
        }
    }))
    .expect("parse machine nodes");

    assert_eq!(response.nodes.len(), 1);
    assert_eq!(response.nodes[0].node_type, "anytls");
    assert_eq!(
        response.base_config.unwrap().pull_interval_seconds(),
        Some(30)
    );
}

#[test]
fn websocket_url_uses_machine_credentials() {
    let panel = MachinePanelClient::new(&PanelConfig {
        api: "https://xboard.example.com".to_string(),
        key: "replace-me".to_string(),
        machine_id: 9,
        nodeexpand_api_prefix: None,
    })
    .expect("panel client");

    let ws_url = panel
        .websocket_url("wss://panel.example.com:8076")
        .expect("websocket url");

    assert!(ws_url.contains("machine_id=9"));
    assert!(ws_url.contains("token=replace-me"));
}

#[test]
fn websocket_url_accepts_http_scheme_from_panel() {
    let panel = MachinePanelClient::new(&PanelConfig {
        api: "https://xboard.example.com".to_string(),
        key: "replace-me".to_string(),
        machine_id: 9,
        nodeexpand_api_prefix: None,
    })
    .expect("panel client");

    let ws_url = panel
        .websocket_url("https://panel.example.com/ws")
        .expect("websocket url");

    assert!(ws_url.starts_with("wss://panel.example.com/ws"));
    assert!(ws_url.contains("machine_id=9"));
    assert!(ws_url.contains("token=replace-me"));
}

#[test]
fn normalizes_nodeexpand_api_prefix() {
    let panel = MachinePanelClient::new(&PanelConfig {
        api: "https://xboard.example.com".to_string(),
        key: "replace-me".to_string(),
        machine_id: 9,
        nodeexpand_api_prefix: Some("api/v1/nodeexpand/server/".to_string()),
    })
    .expect("panel client");

    assert_eq!(panel.machine_nodes_path(), "/api/v1/nodeexpand/server/machine/nodes");
    let node = panel
        .node_client(12, true)
        .expect("nodeexpand panel client");
    assert_eq!(
        node.request_path("/api/v2/server/config", "config")
            .expect("nodeexpand config path"),
        "/api/v1/nodeexpand/server/config"
    );
}

#[test]
fn nodeexpand_node_client_requires_plugin_prefix() {
    let panel = MachinePanelClient::new(&PanelConfig {
        api: "https://xboard.example.com".to_string(),
        key: "replace-me".to_string(),
        machine_id: 9,
        nodeexpand_api_prefix: None,
    })
    .expect("panel client");

    let error = match panel.node_client(12, true) {
        Ok(_) => panic!("nodeexpand prefix is required"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("panel.nodeexpand_api_prefix"));
}

#[test]
fn classifies_traffic_status_by_certainty() {
    assert!(classify_traffic_status(StatusCode::OK).is_ok());
    assert!(matches!(
        classify_traffic_status(StatusCode::BAD_REQUEST),
        Err(TrafficReportError::Definite(_))
    ));
    assert!(matches!(
        classify_traffic_status(StatusCode::INTERNAL_SERVER_ERROR),
        Err(TrafficReportError::Uncertain(_))
    ));
}
