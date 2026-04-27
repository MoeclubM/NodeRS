use anyhow::Context;
use serde::{Deserialize, Deserializer};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub panel: PanelConfig,
}

impl AppConfig {
    pub async fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path).await?;
        toml::from_str(&raw).context("parse TOML config")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PanelConfig {
    #[serde(alias = "url")]
    pub api: String,
    #[serde(alias = "token")]
    pub key: String,
    pub machine_id: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OutboundConfig {
    #[serde(default)]
    pub dns_resolver: DnsResolver,
    #[serde(default)]
    pub ip_strategy: IpStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnsResolver {
    #[default]
    System,
    Custom(String),
}

impl DnsResolver {
    pub fn nameserver(&self) -> Option<&str> {
        match self {
            Self::System => None,
            Self::Custom(server) => Some(server.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for DnsResolver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("system") {
            Ok(Self::System)
        } else {
            Ok(Self::Custom(value.to_string()))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IpStrategy {
    #[default]
    System,
    #[serde(alias = "ipv4_prefer", alias = "ipv4_first")]
    PreferIpv4,
    #[serde(alias = "ipv6_prefer", alias = "ipv6_first")]
    PreferIpv6,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_machine_panel_config() {
        #[derive(Deserialize)]
        struct Wrapper {
            panel: PanelConfig,
        }

        let parsed: Wrapper = toml::from_str(
            r#"
                [panel]
                api = "https://xboard.example.com"
                key = "replace-me"
                machine_id = 9
            "#,
        )
        .expect("parse panel config");

        assert_eq!(parsed.panel.machine_id, 9);
        assert_eq!(parsed.panel.api, "https://xboard.example.com");
        assert_eq!(parsed.panel.key, "replace-me");
    }

    #[test]
    fn accepts_panel_field_aliases() {
        #[derive(Deserialize)]
        struct Wrapper {
            panel: PanelConfig,
        }

        let parsed: Wrapper = toml::from_str(
            r#"
                [panel]
                url = "https://xboard.example.com"
                token = "replace-me"
                machine_id = 9
            "#,
        )
        .expect("parse aliased panel config");

        assert_eq!(parsed.panel.api, "https://xboard.example.com");
        assert_eq!(parsed.panel.key, "replace-me");
    }
}
