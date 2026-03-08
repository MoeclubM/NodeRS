use anyhow::Context;
use regex::Regex;
use std::collections::HashSet;

use crate::panel::RouteConfig;

use super::socksaddr::SocksAddr;

#[derive(Debug, Clone, Default)]
pub struct RouteRules {
    blocked_destinations: Vec<Regex>,
    blocked_protocols: HashSet<String>,
    dns_rules: Vec<DnsRule>,
    default_dns_server: Option<String>,
}

#[derive(Debug, Clone)]
struct DnsRule {
    server: String,
    matchers: Vec<DomainMatcher>,
}

impl DnsRule {
    fn matches(&self, domain: &str) -> bool {
        self.matchers.iter().any(|matcher| matcher.matches(domain))
    }
}

#[derive(Debug, Clone)]
enum DomainMatcher {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(Regex),
}

impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact(expected) => domain == expected,
            Self::Suffix(suffix) => domain == suffix || domain.ends_with(&format!(".{suffix}")),
            Self::Keyword(keyword) => domain.contains(keyword),
            Self::Regex(regex) => regex.is_match(domain),
        }
    }
}

impl RouteRules {
    pub fn from_routes(routes: &[RouteConfig]) -> anyhow::Result<Self> {
        let mut blocked_destinations = Vec::new();
        let mut blocked_protocols = HashSet::new();
        let mut dns_rules = Vec::new();
        let mut default_dns_server = None;

        for route in routes {
            match route.action.trim().to_ascii_lowercase().as_str() {
                "block" => {
                    for item in route.match_items() {
                        if let Some(protocol) = item.strip_prefix("protocol:") {
                            let protocol = protocol.trim().to_ascii_lowercase();
                            if !protocol.is_empty() {
                                blocked_protocols.insert(protocol);
                            }
                            continue;
                        }
                        let pattern = item.strip_prefix("regexp:").unwrap_or(&item);
                        blocked_destinations.push(Regex::new(pattern).with_context(|| {
                            format!("compile Xboard route {} pattern {item}", route.id)
                        })?);
                    }
                }
                "dns" => {
                    let server = route.action_value.trim().to_string();
                    if server.is_empty() {
                        continue;
                    }
                    let mut matchers = Vec::new();
                    let mut is_default = false;
                    for item in route.match_items() {
                        if item.eq_ignore_ascii_case("main") {
                            is_default = true;
                            continue;
                        }
                        if let Some(matcher) = compile_domain_matcher(&item)
                            .with_context(|| format!("compile Xboard DNS route {}", route.id))?
                        {
                            matchers.push(matcher);
                        }
                    }
                    if is_default {
                        default_dns_server = Some(server.clone());
                    }
                    if !matchers.is_empty() {
                        dns_rules.push(DnsRule { server, matchers });
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            blocked_destinations,
            blocked_protocols,
            dns_rules,
            default_dns_server,
        })
    }

    pub fn is_blocked(&self, destination: &SocksAddr, protocol: &str) -> bool {
        if self
            .blocked_protocols
            .contains(&protocol.trim().to_ascii_lowercase())
        {
            return true;
        }
        let candidates = destination_candidates(destination);
        self.blocked_destinations
            .iter()
            .any(|rule| candidates.iter().any(|candidate| rule.is_match(candidate)))
    }

    pub fn dns_server_for(&self, domain: &str) -> Option<&str> {
        let domain = normalize_domain(domain);
        self.dns_rules
            .iter()
            .find(|rule| rule.matches(&domain))
            .map(|rule| rule.server.as_str())
            .or(self.default_dns_server.as_deref())
    }
}

fn compile_domain_matcher(item: &str) -> anyhow::Result<Option<DomainMatcher>> {
    let item = item.trim();
    if item.is_empty() {
        return Ok(None);
    }
    if let Some(pattern) = item.strip_prefix("regexp:") {
        return Ok(Some(DomainMatcher::Regex(Regex::new(pattern)?)));
    }
    if let Some(domain) = item
        .strip_prefix("full:")
        .or_else(|| item.strip_prefix("domain_full:"))
    {
        return Ok(Some(DomainMatcher::Exact(normalize_domain(domain))));
    }
    if let Some(domain) = item
        .strip_prefix("domain:")
        .or_else(|| item.strip_prefix("suffix:"))
    {
        return Ok(Some(DomainMatcher::Suffix(normalize_domain(domain))));
    }
    if let Some(keyword) = item.strip_prefix("keyword:") {
        return Ok(Some(DomainMatcher::Keyword(
            keyword.trim().to_ascii_lowercase(),
        )));
    }
    if let Some(domain) = item.strip_prefix("*.") {
        return Ok(Some(DomainMatcher::Suffix(normalize_domain(domain))));
    }
    Ok(Some(DomainMatcher::Exact(normalize_domain(item))))
}

fn destination_candidates(destination: &SocksAddr) -> [String; 2] {
    match destination {
        SocksAddr::Domain(host, port) => [host.clone(), format!("{host}:{port}")],
        SocksAddr::Ip(addr) => [addr.ip().to_string(), addr.to_string()],
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::panel::{RouteConfig, RouteMatch};

    #[test]
    fn blocks_domain_matches() {
        let rules = RouteRules::from_routes(&[RouteConfig {
            id: 1,
            match_value: Some(RouteMatch::String(r"regexp:^example\.com$".to_string())),
            action: "block".to_string(),
            action_value: String::new(),
        }])
        .expect("compile routes");
        assert!(rules.is_blocked(&SocksAddr::Domain("example.com".to_string(), 443), "tcp"));
        assert!(!rules.is_blocked(&SocksAddr::Domain("openai.com".to_string(), 443), "tcp"));
    }

    #[test]
    fn blocks_protocol_and_ip_matches() {
        let rules = RouteRules::from_routes(&[
            RouteConfig {
                id: 1,
                match_value: Some(RouteMatch::String("protocol:tcp".to_string())),
                action: "block".to_string(),
                action_value: String::new(),
            },
            RouteConfig {
                id: 2,
                match_value: Some(RouteMatch::Strings(vec![
                    r"regexp:^1\.2\.3\.4$".to_string(),
                ])),
                action: "block".to_string(),
                action_value: String::new(),
            },
        ])
        .expect("compile routes");
        assert!(rules.is_blocked(&SocksAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 53))), "tcp"));
        assert!(rules.is_blocked(&SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 443))), "udp"));
    }

    #[test]
    fn matches_dns_rules_before_default() {
        let rules = RouteRules::from_routes(&[
            RouteConfig {
                id: 1,
                match_value: Some(RouteMatch::Strings(vec!["main".to_string()])),
                action: "dns".to_string(),
                action_value: "1.1.1.1".to_string(),
            },
            RouteConfig {
                id: 2,
                match_value: Some(RouteMatch::Strings(vec![
                    "full:api.example.com".to_string(),
                ])),
                action: "dns".to_string(),
                action_value: "8.8.8.8".to_string(),
            },
            RouteConfig {
                id: 3,
                match_value: Some(RouteMatch::Strings(vec!["domain:example.org".to_string()])),
                action: "dns".to_string(),
                action_value: "9.9.9.9".to_string(),
            },
            RouteConfig {
                id: 4,
                match_value: Some(RouteMatch::Strings(vec!["keyword:internal".to_string()])),
                action: "dns".to_string(),
                action_value: "4.4.4.4".to_string(),
            },
        ])
        .expect("compile routes");

        assert_eq!(rules.dns_server_for("api.example.com"), Some("8.8.8.8"));
        assert_eq!(rules.dns_server_for("service.example.org"), Some("9.9.9.9"));
        assert_eq!(
            rules.dns_server_for("internal-gateway.local"),
            Some("4.4.4.4")
        );
        assert_eq!(rules.dns_server_for("unmatched.test"), Some("1.1.1.1"));
    }
}
