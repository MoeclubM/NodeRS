pub mod aerion;
pub(crate) mod shared;

use std::collections::HashMap;
use std::sync::Arc;

use crate::accounting::Accounting;
use crate::panel::{NodeConfigResponse, PanelUser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolKind {
    Anytls,
    Hysteria2,
    Mieru,
    Naive,
    Shadowsocks,
    Trojan,
    Tuic,
    Vless,
    Vmess,
}

impl ProtocolKind {
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        let normalized = name
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .map(|ch| ch.to_ascii_lowercase())
            .collect::<String>();

        if normalized == "anytls" {
            Some(Self::Anytls)
        } else if matches!(normalized.as_str(), "hysteria2" | "hy2" | "hysteria") {
            Some(Self::Hysteria2)
        } else if normalized == "mieru" {
            Some(Self::Mieru)
        } else if matches!(normalized.as_str(), "naive" | "naiveproxy" | "naivehttps") {
            Some(Self::Naive)
        } else if matches!(
            normalized.as_str(),
            "shadowsocks" | "ss" | "shadowsocks2022" | "ss2022"
        ) {
            Some(Self::Shadowsocks)
        } else if normalized == "trojan" {
            Some(Self::Trojan)
        } else if normalized == "tuic" {
            Some(Self::Tuic)
        } else if normalized == "vless" {
            Some(Self::Vless)
        } else if normalized == "vmess" {
            Some(Self::Vmess)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anytls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Mieru => "mieru",
            Self::Naive => "naive",
            Self::Shadowsocks => "shadowsocks",
            Self::Trojan => "trojan",
            Self::Tuic => "tuic",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProtocolKind;

    #[test]
    fn parses_common_protocol_aliases() {
        assert_eq!(ProtocolKind::parse("mieru"), Some(ProtocolKind::Mieru));
        assert_eq!(ProtocolKind::parse("naive"), Some(ProtocolKind::Naive));
        assert_eq!(ProtocolKind::parse("hy2"), Some(ProtocolKind::Hysteria2));
        assert_eq!(ProtocolKind::parse("ss"), Some(ProtocolKind::Shadowsocks));
        assert_eq!(ProtocolKind::parse("tuic"), Some(ProtocolKind::Tuic));
        assert_eq!(
            ProtocolKind::parse("shadowsocks-2022"),
            Some(ProtocolKind::Shadowsocks)
        );
        assert_eq!(
            ProtocolKind::parse("ss2022"),
            Some(ProtocolKind::Shadowsocks)
        );
    }
}

pub enum ProtocolController {
    Aerion(Arc<aerion::ServerController>),
}

impl ProtocolController {
    pub fn new(protocol: ProtocolKind, accounting: Arc<Accounting>) -> Self {
        Self::Aerion(Arc::new(aerion::ServerController::new(
            protocol, accounting,
        )))
    }

    pub fn kind(&self) -> ProtocolKind {
        match self {
            Self::Aerion(server) => server.protocol(),
        }
    }

    pub async fn apply_remote_config(&self, remote: &NodeConfigResponse) -> anyhow::Result<()> {
        match self {
            Self::Aerion(server) => server.apply_remote_config(remote).await,
        }
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        match self {
            Self::Aerion(server) => server.refresh_runtime_assets().await,
        }
    }

    pub async fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        match self {
            Self::Aerion(server) => server.replace_users(users).await,
        }
    }

    pub async fn flush_traffic(&self) -> anyhow::Result<()> {
        match self {
            Self::Aerion(server) => server.flush_traffic().await,
        }
    }

    pub async fn snapshot_alive(&self) -> anyhow::Result<HashMap<i64, Vec<String>>> {
        match self {
            Self::Aerion(server) => server.snapshot_alive().await,
        }
    }

    pub async fn shutdown(&self) {
        match self {
            Self::Aerion(server) => server.shutdown().await,
        }
    }
}
