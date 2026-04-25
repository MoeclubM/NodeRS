pub mod anytls;
pub mod mieru;
pub mod shadowsocks;
pub mod trojan;
pub mod vless;
pub mod vmess;

use std::sync::Arc;

use crate::accounting::Accounting;
use crate::panel::{NodeConfigResponse, PanelUser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolKind {
    Anytls,
    Mieru,
    Shadowsocks,
    Trojan,
    Vless,
    Vmess,
}

impl ProtocolKind {
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("anytls") {
            Some(Self::Anytls)
        } else if name.eq_ignore_ascii_case("mieru") {
            Some(Self::Mieru)
        } else if name.eq_ignore_ascii_case("shadowsocks") || name.eq_ignore_ascii_case("ss") {
            Some(Self::Shadowsocks)
        } else if name.eq_ignore_ascii_case("trojan") {
            Some(Self::Trojan)
        } else if name.eq_ignore_ascii_case("vless") {
            Some(Self::Vless)
        } else if name.eq_ignore_ascii_case("vmess") || name.eq_ignore_ascii_case("v2ray") {
            Some(Self::Vmess)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anytls => "anytls",
            Self::Mieru => "mieru",
            Self::Shadowsocks => "shadowsocks",
            Self::Trojan => "trojan",
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
        assert_eq!(ProtocolKind::parse("ss"), Some(ProtocolKind::Shadowsocks));
        assert_eq!(ProtocolKind::parse("v2ray"), Some(ProtocolKind::Vmess));
    }
}

pub enum ProtocolController {
    Anytls(Arc<anytls::ServerController>),
    Mieru(Arc<mieru::ServerController>),
    Shadowsocks(Arc<shadowsocks::ServerController>),
    Trojan(Arc<trojan::ServerController>),
    Vless(Arc<vless::ServerController>),
    Vmess(Arc<vmess::ServerController>),
}

impl ProtocolController {
    pub fn new(protocol: ProtocolKind, accounting: Arc<Accounting>) -> Self {
        match protocol {
            ProtocolKind::Anytls => {
                Self::Anytls(Arc::new(anytls::ServerController::new(accounting)))
            }
            ProtocolKind::Mieru => Self::Mieru(Arc::new(mieru::ServerController::new(accounting))),
            ProtocolKind::Shadowsocks => {
                Self::Shadowsocks(Arc::new(shadowsocks::ServerController::new(accounting)))
            }
            ProtocolKind::Trojan => {
                Self::Trojan(Arc::new(trojan::ServerController::new(accounting)))
            }
            ProtocolKind::Vless => Self::Vless(Arc::new(vless::ServerController::new(accounting))),
            ProtocolKind::Vmess => Self::Vmess(Arc::new(vmess::ServerController::new(accounting))),
        }
    }

    pub fn kind(&self) -> ProtocolKind {
        match self {
            Self::Anytls(_) => ProtocolKind::Anytls,
            Self::Mieru(_) => ProtocolKind::Mieru,
            Self::Shadowsocks(_) => ProtocolKind::Shadowsocks,
            Self::Trojan(_) => ProtocolKind::Trojan,
            Self::Vless(_) => ProtocolKind::Vless,
            Self::Vmess(_) => ProtocolKind::Vmess,
        }
    }

    pub async fn apply_remote_config(&self, remote: &NodeConfigResponse) -> anyhow::Result<()> {
        match self {
            Self::Anytls(server) => {
                let effective = anytls::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
            Self::Mieru(server) => {
                let effective = mieru::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
            Self::Shadowsocks(server) => {
                let effective = shadowsocks::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
            Self::Trojan(server) => {
                let effective = trojan::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
            Self::Vless(server) => {
                let effective = vless::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
            Self::Vmess(server) => {
                let effective = vmess::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
        }
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        match self {
            Self::Anytls(server) => server.refresh_tls().await,
            Self::Mieru(server) => server.refresh_runtime_assets().await,
            Self::Shadowsocks(server) => server.refresh_runtime_assets().await,
            Self::Trojan(server) => server.refresh_tls().await,
            Self::Vless(server) => server.refresh_tls().await,
            Self::Vmess(server) => server.refresh_runtime_assets().await,
        }
    }

    pub fn replace_users(&self, users: &[PanelUser]) -> anyhow::Result<()> {
        match self {
            Self::Anytls(server) => server.replace_users(users),
            Self::Mieru(server) => server.replace_users(users),
            Self::Shadowsocks(server) => server.replace_users(users),
            Self::Trojan(server) => server.replace_users(users),
            Self::Vless(server) => server.replace_users(users),
            Self::Vmess(server) => server.replace_users(users),
        }
    }

    pub async fn shutdown(&self) {
        match self {
            Self::Anytls(server) => server.shutdown().await,
            Self::Mieru(server) => server.shutdown().await,
            Self::Shadowsocks(server) => server.shutdown().await,
            Self::Trojan(server) => server.shutdown().await,
            Self::Vless(server) => server.shutdown().await,
            Self::Vmess(server) => server.shutdown().await,
        }
    }
}
