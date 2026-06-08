use anyhow::{bail, ensure};

use crate::panel::PanelUser;
use crate::protocols::ProtocolKind;

pub(super) fn core_users(
    protocol: ProtocolKind,
    users: &[PanelUser],
) -> anyhow::Result<Vec<::aerion::core::CoreUser>> {
    let mut entries = Vec::new();
    for user in users {
        for credential in credentials_for_user(protocol, user)? {
            let mut entry = ::aerion::core::CoreUser::password(user.id.to_string(), credential);
            let rate = speed_limit_bytes_per_second(user.speed_limit);
            entry.upload_limit_bps = rate;
            entry.download_limit_bps = rate;
            entry.max_online_ips = u64::try_from(user.device_limit)
                .ok()
                .filter(|limit| *limit > 0);
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub(super) fn credentials_for_server(
    protocol: ProtocolKind,
    users: &[PanelUser],
) -> anyhow::Result<Vec<String>> {
    let mut credentials = Vec::new();
    for user in users {
        credentials.extend(credentials_for_user(protocol, user)?);
    }
    Ok(credentials)
}

fn credentials_for_user(protocol: ProtocolKind, user: &PanelUser) -> anyhow::Result<Vec<String>> {
    let mut credentials = Vec::new();
    match protocol {
        ProtocolKind::Anytls | ProtocolKind::Vless | ProtocolKind::Vmess => {
            let uuid = user.uuid.trim();
            ensure!(
                !uuid.is_empty(),
                "{} user {} is missing uuid",
                protocol.as_str(),
                user.id
            );
            credentials.push(uuid.to_string());
        }
        ProtocolKind::Hysteria2 => {
            push_unique_credential(&mut credentials, user.password.trim());
            push_unique_credential(&mut credentials, user.uuid.trim());
            ensure!(
                !credentials.is_empty(),
                "HY2 user {} is missing password/uuid",
                user.id
            );
        }
        ProtocolKind::Mieru => {
            let identity = mieru_identity(user).ok_or_else(|| {
                anyhow::anyhow!("Mieru user {} is missing password/uuid", user.id)
            })?;
            credentials.push(identity.to_string());
        }
        ProtocolKind::Naive => {
            credentials.push(naive_credential(user)?);
        }
        ProtocolKind::Trojan => {
            let credential = trojan_password(user).ok_or_else(|| {
                anyhow::anyhow!("Trojan user {} is missing password/uuid", user.id)
            })?;
            credentials.push(credential.to_string());
        }
        ProtocolKind::Tuic => {
            let uuid = user.uuid.trim();
            ensure!(!uuid.is_empty(), "TUIC user {} is missing uuid", user.id);
            credentials.push(uuid.to_string());
        }
        ProtocolKind::Shadowsocks => bail!("Shadowsocks users are not mapped to Aerion"),
    }
    Ok(credentials)
}

fn push_unique_credential(credentials: &mut Vec<String>, value: &str) {
    if !value.is_empty() && !credentials.iter().any(|credential| credential == value) {
        credentials.push(value.to_string());
    }
}

pub(super) fn split_primary(mut credentials: Vec<String>) -> anyhow::Result<(String, Vec<String>)> {
    ensure!(
        !credentials.is_empty(),
        "Aerion server requires at least one user credential"
    );
    let first = credentials.remove(0);
    Ok((first, credentials))
}

fn trojan_password(user: &PanelUser) -> Option<&str> {
    let password = user.password.trim();
    if password.is_empty() {
        let uuid = user.uuid.trim();
        (!uuid.is_empty()).then_some(uuid)
    } else {
        Some(password)
    }
}

pub(super) fn mieru_identity(user: &PanelUser) -> Option<&str> {
    let uuid = user.uuid.trim();
    if uuid.is_empty() {
        let password = user.password.trim();
        (!password.is_empty()).then_some(password)
    } else {
        Some(uuid)
    }
}

fn naive_credential(user: &PanelUser) -> anyhow::Result<String> {
    let username = user.uuid.trim();
    let username = if username.is_empty() {
        user.id.to_string()
    } else {
        username.to_string()
    };
    let password = user.password.trim();
    let password = if password.is_empty() {
        user.uuid.trim()
    } else {
        password
    };
    ensure!(
        !password.is_empty(),
        "Naive user {} is missing password/uuid",
        user.id
    );
    Ok(format!("{username}:{password}"))
}
fn speed_limit_bytes_per_second(speed_limit: i64) -> Option<u64> {
    u64::try_from(speed_limit)
        .ok()
        .filter(|limit| *limit > 0)
        .map(|limit| limit.saturating_mul(125_000))
}
