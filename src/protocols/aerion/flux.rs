use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::panel::{NodeConfigResponse, PanelUser};
use crate::protocols::ProtocolKind;
use crate::protocols::shared::{EffectiveTlsConfig, aerion_ech_keys, effective_listen_ip};

use super::users::{credentials_for_server, split_primary};
use super::{AerionTlsIdentity, BuiltServerConfig, aerion_tls_identity};

#[derive(Debug, Clone, Deserialize, Default)]
struct FluxNodeSettings {
    #[serde(default, alias = "ipStrategy")]
    ip_strategy: Option<::aerion::FluxIpStrategy>,
    #[serde(default, alias = "standbyChannels")]
    standby_channels: Option<usize>,
    #[serde(default, alias = "rotationIntervalSec")]
    rotation_interval_sec: Option<u64>,
    #[serde(default, alias = "rotationBytesMb")]
    rotation_bytes_mb: Option<u64>,
    #[serde(default, alias = "defaultSecurity", alias = "default_security")]
    security: Option<::aerion::FluxSecurityMode>,
    #[serde(default, alias = "obfsKey")]
    obfs_key: Option<String>,
    #[serde(default)]
    udp: Option<bool>,
    #[serde(default)]
    reality: Option<FluxRealityInput>,
    #[serde(default)]
    channels: Vec<FluxChannelInput>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FluxRealityInput {
    #[serde(default)]
    dest: Option<String>,
    #[serde(default, alias = "serverName", alias = "sni")]
    server_name: Option<String>,
    #[serde(
        default,
        alias = "serverNames",
        deserialize_with = "deserialize_string_list"
    )]
    server_names: Vec<String>,
    #[serde(default, alias = "serverPort")]
    server_port: Option<u16>,
    #[serde(default, alias = "privateKey")]
    private_key: Option<String>,
    #[serde(default, alias = "shortId")]
    short_id: Option<String>,
    #[serde(
        default,
        alias = "shortIds",
        deserialize_with = "deserialize_string_list"
    )]
    short_ids: Vec<String>,
    #[serde(default)]
    fallback: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct FluxChannelInput {
    #[serde(default)]
    id: String,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool_true")]
    enabled: bool,
    #[serde(default, alias = "connectHost", alias = "server", alias = "host")]
    connect_host: String,
    #[serde(default, alias = "connectPorts", alias = "ports", alias = "port")]
    connect_ports: ::aerion::PortSpecInput,
    #[serde(default, alias = "ipVersion")]
    ip_version: String,
    #[serde(default, alias = "listenIp")]
    listen_ip: String,
    #[serde(default, alias = "listenPorts")]
    listen_ports: ::aerion::PortSpecInput,
    #[serde(default)]
    role: Option<::aerion::FluxChannelRole>,
    #[serde(default = "default_weight")]
    weight: u8,
    #[serde(default, alias = "network")]
    transport: Option<String>,
    #[serde(default, alias = "httpMode")]
    http_mode: Option<::aerion::FluxHttpMode>,
    #[serde(default, alias = "httpHost")]
    http_host: Option<String>,
    #[serde(default, alias = "httpPath", alias = "path")]
    http_path: Option<String>,
    #[serde(default, alias = "httpHeaders", alias = "headers")]
    http_headers: BTreeMap<String, String>,
    #[serde(default)]
    security: Option<::aerion::FluxSecurityMode>,
    #[serde(default, alias = "server_name", alias = "serverName")]
    sni: Option<String>,
    #[serde(default, alias = "certMode")]
    cert_mode: Option<::aerion::FluxCertMode>,
    #[serde(default, alias = "certPath")]
    cert_path: Option<String>,
    #[serde(default, alias = "keyPath")]
    key_path: Option<String>,
    #[serde(default, alias = "obfsKey")]
    obfs_key: Option<String>,
    #[serde(default)]
    dest: Option<String>,
    #[serde(default, alias = "privateKey")]
    private_key: Option<String>,
    #[serde(default, alias = "shortId")]
    short_id: Option<String>,
    #[serde(
        default,
        alias = "shortIds",
        deserialize_with = "deserialize_string_list"
    )]
    short_ids: Vec<String>,
    #[serde(default, alias = "realityFallback")]
    reality_fallback: Option<bool>,
    #[serde(default, alias = "reality_opts", alias = "realityOpts")]
    reality: Option<FluxRealityInput>,
}

impl Default for FluxChannelInput {
    fn default() -> Self {
        Self {
            id: String::new(),
            enabled: true,
            connect_host: String::new(),
            connect_ports: ::aerion::PortSpecInput::default(),
            ip_version: String::new(),
            listen_ip: String::new(),
            listen_ports: ::aerion::PortSpecInput::default(),
            role: None,
            weight: 100,
            transport: None,
            http_mode: None,
            http_host: None,
            http_path: None,
            http_headers: BTreeMap::new(),
            security: None,
            sni: None,
            cert_mode: None,
            cert_path: None,
            key_path: None,
            obfs_key: None,
            dest: None,
            private_key: None,
            short_id: None,
            short_ids: Vec::new(),
            reality_fallback: None,
            reality: None,
        }
    }
}

type TlsFingerprint = (
    Option<PathBuf>,
    Option<PathBuf>,
    Vec<String>,
    Option<String>,
    Vec<Vec<u8>>,
);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenerSignature {
    transport: ::aerion::FluxTransportKind,
    http_mode: ::aerion::FluxHttpMode,
    http_host: Option<String>,
    http_path: String,
    http_headers: BTreeMap<String, String>,
    security: ::aerion::FluxSecurityMode,
    cert_mode: ::aerion::FluxCertMode,
    tls_fingerprint: Option<TlsFingerprint>,
    reality: Option<::aerion::RealityServerConfig>,
    reality_fallback: Option<bool>,
    obfs_key: Option<String>,
}

pub(super) async fn build_config(
    remote: &NodeConfigResponse,
    users: &[PanelUser],
) -> anyhow::Result<BuiltServerConfig> {
    let (key, extra_users) = split_primary(credentials_for_server(ProtocolKind::Flux, users)?)?;
    let settings = match remote.flux.as_ref() {
        Some(value) if !value.is_null() => {
            serde_json::from_value::<FluxNodeSettings>(value.clone())
                .context("parse Flux node settings")?
        }
        _ => FluxNodeSettings::default(),
    };

    let options = ::aerion::FluxOptions {
        ip_strategy: settings.ip_strategy.unwrap_or_default(),
        standby_channels: settings
            .standby_channels
            .unwrap_or(::aerion::flux::DEFAULT_STANDBY_CHANNELS),
        rotation_interval_sec: settings
            .rotation_interval_sec
            .unwrap_or(::aerion::flux::DEFAULT_ROTATION_INTERVAL_SEC),
        rotation_bytes_mb: settings
            .rotation_bytes_mb
            .unwrap_or(::aerion::flux::DEFAULT_ROTATION_BYTES_MB),
    };
    options.validate()?;

    let default_sec = resolve_default_security(remote, &settings);
    let raw_channels = if settings.channels.is_empty() {
        ensure!(
            remote.server_port > 0,
            "Flux node requires server_port when channels list is empty"
        );
        vec![
            FluxChannelInput {
                id: "default-tcp".to_string(),
                transport: Some("tcp".to_string()),
                security: Some(default_sec),
                ..Default::default()
            },
            FluxChannelInput {
                id: "default-udp".to_string(),
                transport: Some("udp".to_string()),
                security: Some(default_sec),
                ..Default::default()
            },
        ]
    } else {
        let enabled = settings
            .channels
            .iter()
            .filter(|ch| ch.enabled)
            .cloned()
            .collect::<Vec<_>>();
        ensure!(!enabled.is_empty(), "Flux node has no enabled channels");
        enabled
    };

    let default_listen_ip = effective_listen_ip(remote)
        .parse::<IpAddr>()
        .with_context(|| {
            format!(
                "parse default Flux listen_ip {}",
                effective_listen_ip(remote)
            )
        })?;

    let mut inherited_tls: Option<(EffectiveTlsConfig, AerionTlsIdentity)> = None;
    let mut seen_bindings: HashMap<(IpAddr, u16, bool), ListenerSignature> = HashMap::new();
    let mut listeners: Vec<(ListenerSignature, ::aerion::FluxChannelServerConfig)> = Vec::new();
    let mut distinct_ports = 0usize;

    for (idx, ch) in raw_channels.iter().enumerate() {
        let id = if ch.id.trim().is_empty() {
            format!("ch-{}", idx + 1)
        } else {
            ch.id.trim().to_string()
        };
        let _ = ch.role;
        ensure!(
            (1..=100).contains(&ch.weight),
            "Flux channel {id} weight must be within 1..=100"
        );
        if !ch.ip_version.trim().is_empty() {
            let _ = ::aerion::flux::normalize_ip_version(&ch.ip_version)?;
        }

        let listen_ip = if ch.listen_ip.trim().is_empty() {
            default_listen_ip
        } else {
            ch.listen_ip
                .trim()
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .with_context(|| format!("parse Flux channel {id} listen_ip {}", ch.listen_ip))?
        };

        let listen_spec = {
            let explicit = ch.listen_ports.to_spec_string();
            if !explicit.is_empty() && explicit != "0" {
                explicit
            } else {
                ch.connect_ports.to_spec_string()
            }
        };
        let ports = if listen_spec.is_empty() || listen_spec == "0" {
            ensure!(
                remote.server_port > 0,
                "Flux channel {id} requires listen_ports, connect_ports, or server_port"
            );
            vec![remote.server_port]
        } else {
            ::aerion::parse_port_spec(&listen_spec, ::aerion::MAX_FLUX_EXPANDED_PORTS)
                .with_context(|| format!("parse Flux channel {id} ports {listen_spec}"))?
        };

        let (transport, inferred_mode) =
            ::aerion::flux::parse_transport_and_mode(ch.transport.as_deref())
                .with_context(|| format!("parse Flux channel {id} transport"))?;
        let http_mode = ch.http_mode.or(inferred_mode).unwrap_or_default();
        let http_host = ch
            .http_host
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);
        let http_path = normalize_http_path(ch.http_path.as_deref());
        let security = ch.security.unwrap_or(default_sec);
        let is_udp = matches!(transport, ::aerion::FluxTransportKind::Udp);

        let mut candidate = ::aerion::FluxChannelServerConfig {
            id: id.clone(),
            listen_ip,
            ports: Vec::new(),
            transport,
            http_mode,
            http_host: http_host.clone(),
            http_path: http_path.clone(),
            http_headers: ch.http_headers.clone(),
            security,
            cert_mode: ch.cert_mode.unwrap_or(::aerion::FluxCertMode::Inherit),
            tls_material: None,
            reality: None,
            reality_fallback: None,
            obfs_key: None,
        };

        let alpn = if is_udp {
            vec![b"h3".to_vec()]
        } else {
            candidate.to_vless_transport().alpn_protocols()
        };

        match security {
            ::aerion::FluxSecurityMode::Reality => {
                candidate.reality = Some(build_channel_reality(
                    &id,
                    ch,
                    &settings,
                    remote,
                    alpn.clone(),
                )?);
                candidate.reality_fallback = ch
                    .reality_fallback
                    .or_else(|| ch.reality.as_ref().and_then(|r| r.fallback))
                    .or_else(|| settings.reality.as_ref().and_then(|r| r.fallback));
            }
            ::aerion::FluxSecurityMode::Tls => match candidate.cert_mode {
                ::aerion::FluxCertMode::OriginPlain => {
                    ensure!(
                        !is_udp,
                        "Flux UDP channel {id} cannot use cert_mode origin_plain"
                    );
                }
                ::aerion::FluxCertMode::File => {
                    let cert_path = ch
                        .cert_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .with_context(|| {
                            format!("Flux channel {id} cert_mode=file requires cert_path")
                        })?;
                    let key_path = ch
                        .key_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .with_context(|| {
                            format!("Flux channel {id} cert_mode=file requires key_path")
                        })?;
                    let material = ::aerion::tls::ServerTlsMaterial {
                        cert_path: Some(PathBuf::from(cert_path)),
                        key_path: Some(PathBuf::from(key_path)),
                        certificates: Vec::new(),
                        key: None,
                        label: format!("Flux/{id}"),
                        alpn_protocols: alpn.clone(),
                        early_data: false,
                        ech: None,
                    };
                    material.ensure_supported()?;
                    candidate.tls_material = Some(material);
                }
                ::aerion::FluxCertMode::Inherit => {
                    if inherited_tls.is_none() {
                        let mut tls_remote = remote.clone();
                        if tls_remote.server_name.trim().is_empty()
                            && let Some(fallback_host) = first_non_empty([
                                ch.sni.as_deref(),
                                Some(ch.connect_host.as_str()),
                                Some(remote.host.as_str()),
                            ])
                        {
                            tls_remote.server_name = fallback_host.to_string();
                        }
                        let eff = EffectiveTlsConfig::from_remote(&tls_remote)?;
                        let ident = aerion_tls_identity(&eff, "Flux").await?;
                        inherited_tls = Some((eff, ident));
                    }
                    let (eff, ident) = inherited_tls.as_ref().expect("inherited TLS initialized");
                    let ech = if is_udp {
                        None
                    } else {
                        aerion_ech_keys(eff, false)?
                    };
                    let material = ::aerion::tls::ServerTlsMaterial {
                        cert_path: (!ident.cert_path.as_os_str().is_empty())
                            .then(|| ident.cert_path.clone()),
                        key_path: (!ident.key_path.as_os_str().is_empty())
                            .then(|| ident.key_path.clone()),
                        certificates: ident.certificates.clone(),
                        key: ident.key.clone(),
                        label: format!("Flux/{id}"),
                        alpn_protocols: alpn.clone(),
                        early_data: false,
                        ech,
                    };
                    material.ensure_supported()?;
                    candidate.tls_material = Some(material);
                }
            },
            ::aerion::FluxSecurityMode::Obfs => {
                let obfs_key = first_non_empty([
                    ch.obfs_key.as_deref(),
                    settings.obfs_key.as_deref(),
                    Some(remote.obfs_password.as_str()),
                    Some(remote.server_key.as_str()),
                ])
                .with_context(|| format!("Flux channel {id} security=obfs requires obfs_key"))?;
                ensure!(
                    obfs_key.len() >= 4,
                    "Flux channel {id} obfs_key must be at least 4 characters"
                );
                candidate.obfs_key = Some(obfs_key.to_string());
            }
        }

        let sig = ListenerSignature {
            transport: candidate.transport,
            http_mode: candidate.http_mode,
            http_host: candidate.http_host.clone(),
            http_path: candidate.http_path.clone(),
            http_headers: candidate.http_headers.clone(),
            security: candidate.security,
            cert_mode: candidate.cert_mode,
            tls_fingerprint: candidate.tls_material.as_ref().map(|m| {
                (
                    m.cert_path.clone(),
                    m.key_path.clone(),
                    m.certificates.clone(),
                    m.key.clone(),
                    m.alpn_protocols.clone(),
                )
            }),
            reality: candidate.reality.clone(),
            reality_fallback: candidate.reality_fallback,
            obfs_key: candidate.obfs_key.clone(),
        };

        let mut new_ports_for_listener = Vec::new();
        for port in ports {
            for ((other_ip, other_port, other_udp), _) in &seen_bindings {
                if *other_port == port
                    && *other_udp == is_udp
                    && *other_ip != listen_ip
                    && (listen_ip.is_unspecified() || other_ip.is_unspecified())
                {
                    bail!(
                        "overlapping Flux listener bind on port {port}/{} between {other_ip} and {listen_ip}",
                        if is_udp { "udp" } else { "tcp" }
                    );
                }
            }
            let key_tuple = (listen_ip, port, is_udp);
            if let Some(existing_sig) = seen_bindings.get(&key_tuple) {
                ensure!(
                    existing_sig == &sig,
                    "conflicting Flux listener configuration on {}:{}/{}",
                    listen_ip,
                    port,
                    if is_udp { "udp" } else { "tcp" }
                );
                continue;
            }
            distinct_ports += 1;
            ensure!(
                distinct_ports <= ::aerion::MAX_FLUX_EXPANDED_PORTS,
                "Flux server expanded ports exceed limit of {}",
                ::aerion::MAX_FLUX_EXPANDED_PORTS
            );
            seen_bindings.insert(key_tuple, sig.clone());
            new_ports_for_listener.push(port);
        }

        if new_ports_for_listener.is_empty() {
            continue;
        }
        if let Some((_, existing_listener)) = listeners
            .iter_mut()
            .find(|(s, l)| l.listen_ip == listen_ip && *s == sig)
        {
            for port in new_ports_for_listener {
                if !existing_listener.ports.contains(&port) {
                    existing_listener.ports.push(port);
                }
            }
        } else {
            candidate.ports = new_ports_for_listener;
            listeners.push((sig, candidate));
        }
    }

    let udp_enabled = settings.udp.unwrap_or_else(|| {
        !matches!(
            remote.udp_relay_mode.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no" | "none" | "disabled"
        )
    });

    let server_config = ::aerion::FluxServerConfig {
        key,
        users: extra_users,
        udp: udp_enabled,
        listeners: listeners.into_iter().map(|(_, l)| l).collect(),
    };
    server_config.validate()?;
    Ok(BuiltServerConfig::Flux(server_config))
}

fn resolve_default_security(
    remote: &NodeConfigResponse,
    settings: &FluxNodeSettings,
) -> ::aerion::FluxSecurityMode {
    if let Some(sec) = settings.security {
        return sec;
    }
    match remote.cipher.trim().to_ascii_lowercase().as_str() {
        "reality" => return ::aerion::FluxSecurityMode::Reality,
        "tls" => return ::aerion::FluxSecurityMode::Tls,
        "obfs" => return ::aerion::FluxSecurityMode::Obfs,
        _ => {}
    }
    match remote.tls_mode() {
        2 => ::aerion::FluxSecurityMode::Reality,
        1 => ::aerion::FluxSecurityMode::Tls,
        _ => {
            if has_reality_private_key(remote, settings) {
                ::aerion::FluxSecurityMode::Reality
            } else if first_non_empty([
                settings.obfs_key.as_deref(),
                Some(remote.obfs_password.as_str()),
                Some(remote.server_key.as_str()),
            ])
            .is_some()
            {
                ::aerion::FluxSecurityMode::Obfs
            } else {
                ::aerion::FluxSecurityMode::Tls
            }
        }
    }
}

fn has_reality_private_key(remote: &NodeConfigResponse, settings: &FluxNodeSettings) -> bool {
    first_non_empty([
        settings
            .reality
            .as_ref()
            .and_then(|r| r.private_key.as_deref()),
        Some(remote.reality_settings.private_key.as_str()),
        Some(remote.tls_settings.private_key.as_str()),
    ])
    .is_some()
}

fn build_channel_reality(
    id: &str,
    ch: &FluxChannelInput,
    settings: &FluxNodeSettings,
    remote: &NodeConfigResponse,
    alpn_protocols: Vec<Vec<u8>>,
) -> anyhow::Result<::aerion::RealityServerConfig> {
    let ch_r = ch.reality.as_ref();
    let node_r = settings.reality.as_ref();

    let priv_key_str = first_non_empty([
        ch_r.and_then(|r| r.private_key.as_deref()),
        ch.private_key.as_deref(),
        node_r.and_then(|r| r.private_key.as_deref()),
        Some(remote.reality_settings.private_key.as_str()),
        Some(remote.tls_settings.private_key.as_str()),
    ])
    .with_context(|| format!("Flux channel {id} security=reality requires private_key"))?;
    let private_key = decode_reality_private_key(priv_key_str)
        .with_context(|| format!("decode Flux channel {id} REALITY private_key"))?;

    let dest_str = first_non_empty([
        ch_r.and_then(|r| r.dest.as_deref()),
        ch.dest.as_deref(),
        node_r.and_then(|r| r.dest.as_deref()),
    ]);

    let mut server_names = Vec::new();
    let push_name = |list: &mut Vec<String>, candidate: &str| {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !list.iter().any(|existing| existing == trimmed) {
            list.push(trimmed.to_string());
        }
    };
    if let Some(sni) = ch.sni.as_deref() {
        push_name(&mut server_names, sni);
    }
    if let Some(r) = ch_r {
        if let Some(sn) = r.server_name.as_deref() {
            push_name(&mut server_names, sn);
        }
        for sn in &r.server_names {
            push_name(&mut server_names, sn);
        }
    }
    if server_names.is_empty() {
        if let Some(r) = node_r {
            if let Some(sn) = r.server_name.as_deref() {
                push_name(&mut server_names, sn);
            }
            for sn in &r.server_names {
                push_name(&mut server_names, sn);
            }
        }
        push_name(&mut server_names, &remote.reality_settings.server_name);
        for sn in &remote.reality_settings.server_names {
            push_name(&mut server_names, sn);
        }
        push_name(&mut server_names, &remote.tls_settings.server_name);
        for sn in &remote.tls_settings.server_names {
            push_name(&mut server_names, sn);
        }
        push_name(&mut server_names, &remote.server_name);
    }

    let fallback_port = ch_r
        .and_then(|r| r.server_port)
        .filter(|p| *p > 0)
        .or_else(|| node_r.and_then(|r| r.server_port).filter(|p| *p > 0))
        .or_else(|| {
            (remote.reality_settings.server_port > 0).then_some(remote.reality_settings.server_port)
        })
        .or_else(|| {
            (remote.tls_settings.server_port > 0).then_some(remote.tls_settings.server_port)
        })
        .unwrap_or(443);

    let (server_name, server_port) = if let Some(dest) = dest_str {
        parse_dest_host_port(dest, fallback_port)
            .with_context(|| format!("parse Flux channel {id} REALITY dest {dest}"))?
    } else {
        let first_sni = server_names
            .first()
            .cloned()
            .with_context(|| format!("Flux channel {id} security=reality requires sni or dest"))?;
        (first_sni, fallback_port)
    };
    if server_names.is_empty() {
        server_names.push(server_name.clone());
    }

    let short_ids = collect_short_ids(ch, settings, remote)
        .with_context(|| format!("decode Flux channel {id} REALITY short_id"))?;

    Ok(::aerion::RealityServerConfig {
        server_name,
        server_port,
        server_names,
        private_key,
        short_ids,
        alpn_protocols,
        max_time_diff_secs: 0,
        max_client_version: None,
        fallback_limit: ::aerion::RealityFallbackLimit::default(),
    })
}

fn collect_short_ids(
    ch: &FluxChannelInput,
    settings: &FluxNodeSettings,
    remote: &NodeConfigResponse,
) -> anyhow::Result<Vec<[u8; 8]>> {
    let mut raw: Vec<&str> = Vec::new();
    if let Some(r) = ch.reality.as_ref() {
        if let Some(sid) = r
            .short_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            raw.push(sid);
        }
        for sid in &r.short_ids {
            if !sid.trim().is_empty() {
                raw.push(sid.trim());
            }
        }
    }
    if let Some(sid) = ch
        .short_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        raw.push(sid);
    }
    for sid in &ch.short_ids {
        if !sid.trim().is_empty() {
            raw.push(sid.trim());
        }
    }
    if raw.is_empty() {
        if let Some(r) = settings.reality.as_ref() {
            if let Some(sid) = r
                .short_id
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                raw.push(sid);
            }
            for sid in &r.short_ids {
                if !sid.trim().is_empty() {
                    raw.push(sid.trim());
                }
            }
        }
        if !remote.reality_settings.short_id.trim().is_empty() {
            raw.push(remote.reality_settings.short_id.trim());
        }
        for sid in &remote.reality_settings.short_ids {
            if !sid.trim().is_empty() {
                raw.push(sid.trim());
            }
        }
        if !remote.tls_settings.short_id.trim().is_empty() {
            raw.push(remote.tls_settings.short_id.trim());
        }
        for sid in &remote.tls_settings.short_ids {
            if !sid.trim().is_empty() {
                raw.push(sid.trim());
            }
        }
    }
    if raw.is_empty() {
        return Ok(vec![[0u8; 8]]);
    }
    let mut out = Vec::with_capacity(raw.len());
    for hex_str in raw {
        let sid = decode_short_id(hex_str)?;
        if !out.contains(&sid) {
            out.push(sid);
        }
    }
    Ok(out)
}

fn decode_reality_private_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = encoded.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| STANDARD.decode(trimmed))
        .with_context(|| format!("invalid base64 REALITY key {trimmed}"))?;
    ensure!(
        decoded.len() == 32,
        "REALITY private_key must decode to 32 bytes"
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn decode_short_id(hex_str: &str) -> anyhow::Result<[u8; 8]> {
    ensure!(
        hex_str.len() <= 16 && hex_str.len() % 2 == 0,
        "REALITY short_id must be even-length hex <= 16 chars"
    );
    let mut out = [0u8; 8];
    let len = hex_str.len() / 2;
    hex::decode_to_slice(hex_str.as_bytes(), &mut out[..len])
        .with_context(|| format!("invalid REALITY short_id {hex_str}"))?;
    Ok(out)
}

fn parse_dest_host_port(raw: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    let trimmed = raw.trim();
    ensure!(!trimmed.is_empty(), "empty REALITY dest");
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("invalid bracketed IPv6 REALITY dest")?;
        let port = if let Some(port_str) = tail.strip_prefix(':') {
            port_str.parse::<u16>().context("parse REALITY dest port")?
        } else if tail.is_empty() {
            default_port
        } else {
            bail!("invalid REALITY dest suffix {tail}");
        };
        ensure!(port > 0, "REALITY dest port must be > 0");
        return Ok((host.to_string(), port));
    }
    if let Some((host, port_str)) = trimmed.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        ensure!(!host.trim().is_empty(), "empty REALITY dest host");
        ensure!(port > 0, "REALITY dest port must be > 0");
        return Ok((host.trim().to_string(), port));
    }
    Ok((trimmed.to_string(), default_port))
}

fn normalize_http_path(path: Option<&str>) -> String {
    match path.map(str::trim).filter(|p| !p.is_empty()) {
        None => "/".to_string(),
        Some(p) if p.starts_with('/') => p.to_string(),
        Some(p) => format!("/{p}"),
    }
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|v| !v.is_empty())
}

fn default_true() -> bool {
    true
}

fn default_weight() -> u8 {
    100
}

fn deserialize_bool_true<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(true),
        Some(val) => crate::panel::value_to_bool(&val)
            .ok_or_else(|| serde::de::Error::custom(format!("expected bool, got {val}"))),
    }
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect()),
        Some(Value::String(text)) => Ok(text
            .split([',', '\n', '\r', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect()),
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected string or array, got {other}"
        ))),
    }
}
