pub mod anytls;

use std::sync::Arc;

use crate::accounting::Accounting;
use crate::panel::NodeConfigResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolKind {
    Anytls,
}

impl ProtocolKind {
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("anytls") {
            Some(Self::Anytls)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anytls => "anytls",
        }
    }
}

pub enum ProtocolController {
    Anytls(Arc<anytls::ServerController>),
}

impl ProtocolController {
    pub fn new(protocol: ProtocolKind, accounting: Arc<Accounting>) -> Self {
        match protocol {
            ProtocolKind::Anytls => {
                Self::Anytls(Arc::new(anytls::ServerController::new(accounting)))
            }
        }
    }

    pub fn kind(&self) -> ProtocolKind {
        match self {
            Self::Anytls(_) => ProtocolKind::Anytls,
        }
    }

    pub async fn apply_remote_config(&self, remote: &NodeConfigResponse) -> anyhow::Result<()> {
        match self {
            Self::Anytls(server) => {
                let effective = anytls::EffectiveNodeConfig::from_remote(remote)?;
                server.apply_config(effective).await
            }
        }
    }

    pub async fn refresh_runtime_assets(&self) -> anyhow::Result<()> {
        match self {
            Self::Anytls(server) => server.refresh_tls().await,
        }
    }

    pub async fn shutdown(&self) {
        match self {
            Self::Anytls(server) => server.shutdown().await,
        }
    }
}
