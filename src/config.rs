use anyhow::Context;
use serde::Deserialize;
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
