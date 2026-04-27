use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::config::{DnsResolver, IpStrategy, OutboundConfig};
use crate::panel::RouteConfig;

use super::rules::{DomainMatcher, RouteRules, compile_domain_matcher, normalize_domain};
use super::socksaddr::SocksAddr;

const OUTBOUND_ALLOWED_FIELDS: &[&str] = &[
    "tag",
    "type",
    "dns_resolver",
    "dnsResolver",
    "domain_resolver",
    "domainResolver",
    "address_resolver",
    "addressResolver",
    "ip_strategy",
    "ipStrategy",
    "domain_strategy",
    "domainStrategy",
    "strategy",
    "server",
    "address",
];

const ROUTE_ALLOWED_FIELDS: &[&str] = &[
    "outbound",
    "action",
    "network",
    "protocol",
    "domain",
    "domain_suffix",
    "domainSuffix",
    "domain_keyword",
    "domainKeyword",
    "domain_regex",
    "domainRegex",
    "ip_cidr",
    "ipCidr",
    "ip_is_private",
    "ipIsPrivate",
    "port",
    "port_range",
    "portRange",
];

#[derive(Debug, Clone)]
pub struct RoutingTable {
    legacy: RouteRules,
    default_outbound: OutboundConfig,
    custom_outbounds: HashMap<String, CustomOutbound>,
    custom_rules: Vec<CustomRouteRule>,
}

#[derive(Debug, Clone)]
enum CustomOutbound {
    Block,
    Direct(OutboundConfig),
}

#[derive(Debug, Clone)]
struct CustomRouteRule {
    action: CustomRouteAction,
    networks: HashSet<String>,
    domain_matchers: Vec<DomainMatcher>,
    ip_nets: Vec<IpNet>,
    ip_is_private: bool,
    ports: Vec<PortRange>,
}

#[derive(Debug, Clone)]
enum CustomRouteAction {
    Block,
    Outbound(String),
}

#[derive(Debug, Clone)]
struct IpNet {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug, Deserialize)]
struct RawCustomOutbound {
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    tag: String,
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_default_on_null"
    )]
    kind: String,
    #[serde(
        default,
        alias = "dnsResolver",
        alias = "domain_resolver",
        alias = "domainResolver",
        alias = "address_resolver",
        alias = "addressResolver",
        deserialize_with = "deserialize_default_on_null"
    )]
    dns_resolver: String,
    #[serde(
        default,
        alias = "ipStrategy",
        alias = "domain_strategy",
        alias = "domainStrategy",
        alias = "strategy"
    )]
    ip_strategy: IpStrategy,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    server: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    address: String,
}

#[derive(Debug, Deserialize, Default)]
struct RawCustomRoute {
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    outbound: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    action: String,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    network: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    protocol: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    domain: Vec<String>,
    #[serde(
        default,
        alias = "domainSuffix",
        deserialize_with = "deserialize_string_list"
    )]
    domain_suffix: Vec<String>,
    #[serde(
        default,
        alias = "domainKeyword",
        deserialize_with = "deserialize_string_list"
    )]
    domain_keyword: Vec<String>,
    #[serde(
        default,
        alias = "domainRegex",
        deserialize_with = "deserialize_string_list"
    )]
    domain_regex: Vec<String>,
    #[serde(
        default,
        alias = "ipCidr",
        deserialize_with = "deserialize_string_list"
    )]
    ip_cidr: Vec<String>,
    #[serde(
        default,
        alias = "ipIsPrivate",
        deserialize_with = "crate::panel::deserialize_bool_from_any_on_null"
    )]
    ip_is_private: bool,
    #[serde(default, deserialize_with = "deserialize_port_ranges")]
    port: Vec<PortRange>,
    #[serde(
        default,
        alias = "portRange",
        deserialize_with = "deserialize_string_list"
    )]
    port_range: Vec<String>,
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self {
            legacy: RouteRules::default(),
            default_outbound: OutboundConfig::default(),
            custom_outbounds: HashMap::new(),
            custom_rules: Vec::new(),
        }
    }
}

impl RoutingTable {
    pub fn from_remote(
        routes: &[RouteConfig],
        custom_outbounds: &[Value],
        custom_routes: &[Value],
    ) -> anyhow::Result<Self> {
        let legacy = RouteRules::from_routes(routes)?;
        let custom_outbounds = compile_custom_outbounds(custom_outbounds)?;
        let custom_rules = compile_custom_routes(custom_routes, &custom_outbounds)?;
        Ok(Self {
            legacy,
            default_outbound: OutboundConfig::default(),
            custom_outbounds,
            custom_rules,
        })
    }

    pub fn outbound_for(
        &self,
        destination: &SocksAddr,
        protocol: &str,
    ) -> anyhow::Result<OutboundConfig> {
        if let Some(rule) = self
            .custom_rules
            .iter()
            .find(|rule| rule.matches(destination, protocol))
        {
            return self.resolve_custom_rule(rule, destination);
        }

        if self.legacy.is_blocked(destination, protocol) {
            bail!("destination blocked by Xboard route rules: {destination}");
        }

        Ok(self.apply_legacy_dns(destination, self.default_outbound.clone()))
    }

    fn resolve_custom_rule(
        &self,
        rule: &CustomRouteRule,
        destination: &SocksAddr,
    ) -> anyhow::Result<OutboundConfig> {
        match &rule.action {
            CustomRouteAction::Block => {
                bail!("destination blocked by Xboard custom routes: {destination}")
            }
            CustomRouteAction::Outbound(tag) => {
                let outbound = match self.custom_outbounds.get(tag) {
                    Some(outbound) => outbound.clone(),
                    None if tag == "direct" || tag == "default" => {
                        CustomOutbound::Direct(self.default_outbound.clone())
                    }
                    None if tag == "block" => CustomOutbound::Block,
                    None => bail!("Xboard custom route references unknown outbound tag {tag}"),
                };
                match outbound {
                    CustomOutbound::Block => {
                        bail!("destination blocked by Xboard custom outbound {tag}: {destination}")
                    }
                    CustomOutbound::Direct(outbound) => {
                        Ok(self.apply_legacy_dns(destination, outbound))
                    }
                }
            }
        }
    }

    fn apply_legacy_dns(
        &self,
        destination: &SocksAddr,
        mut outbound: OutboundConfig,
    ) -> OutboundConfig {
        if !matches!(outbound.dns_resolver, DnsResolver::System) {
            return outbound;
        }
        let SocksAddr::Domain(host, _) = destination else {
            return outbound;
        };
        if let Some(server) = self.legacy.dns_server_for(host) {
            outbound.dns_resolver = DnsResolver::Custom(server.to_string());
        }
        outbound
    }
}

impl CustomRouteRule {
    fn matches(&self, destination: &SocksAddr, protocol: &str) -> bool {
        if !self.networks.is_empty()
            && !self
                .networks
                .iter()
                .any(|network| network_matches(network, destination, protocol))
        {
            return false;
        }

        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|range| range.contains(destination_port(destination)))
        {
            return false;
        }

        if !self.domain_matchers.is_empty() {
            let SocksAddr::Domain(host, _) = destination else {
                return false;
            };
            let host = normalize_domain(host);
            if !self
                .domain_matchers
                .iter()
                .any(|matcher| matcher.matches(&host))
            {
                return false;
            }
        }

        if self.ip_is_private || !self.ip_nets.is_empty() {
            let SocksAddr::Ip(addr) = destination else {
                return false;
            };
            let ip = addr.ip();
            if self.ip_is_private && !is_private_ip(ip) {
                return false;
            }
            if !self.ip_nets.is_empty() && !self.ip_nets.iter().any(|net| net.contains(ip)) {
                return false;
            }
        }

        true
    }
}

impl IpNet {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let (network, prefix) = raw
            .trim()
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid CIDR {raw}"))?;
        let network = network.parse::<IpAddr>()?;
        let prefix = prefix.parse::<u8>()?;
        match network {
            IpAddr::V4(_) => ensure!(prefix <= 32, "invalid IPv4 prefix length {prefix}"),
            IpAddr::V6(_) => ensure!(prefix <= 128, "invalid IPv6 prefix length {prefix}"),
        }
        Ok(Self { network, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_to_mask_v4(self.prefix);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_to_mask_v6(self.prefix);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl PortRange {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let raw = raw.trim();
        ensure!(!raw.is_empty(), "empty port range");
        if let Ok(port) = raw.parse::<u16>() {
            return Ok(Self {
                start: port,
                end: port,
            });
        }
        let (start, end) = raw
            .split_once(':')
            .or_else(|| raw.split_once('-'))
            .ok_or_else(|| anyhow::anyhow!("invalid port range {raw}"))?;
        let start = start.parse::<u16>()?;
        let end = end.parse::<u16>()?;
        ensure!(start <= end, "invalid port range {raw}");
        Ok(Self { start, end })
    }

    fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

fn compile_custom_outbounds(values: &[Value]) -> anyhow::Result<HashMap<String, CustomOutbound>> {
    let mut outbounds = HashMap::new();
    for (index, value) in values.iter().enumerate() {
        let mut object = value
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Xboard custom_outbounds[{index}] must be an object"))?;
        ensure_known_fields(
            "Xboard custom_outbounds",
            index,
            &object,
            OUTBOUND_ALLOWED_FIELDS,
        )?;
        let raw: RawCustomOutbound = serde_json::from_value(Value::Object(object.clone()))
            .with_context(|| format!("decode Xboard custom_outbounds[{index}]"))?;
        let tag = raw.tag.trim().to_string();
        ensure!(
            !tag.is_empty(),
            "Xboard custom_outbounds[{index}] is missing tag"
        );
        let kind = raw.kind.trim().to_ascii_lowercase();
        let dns_resolver = raw.dns_resolver.trim();
        let server = pick_first_non_empty(&[raw.server.trim(), raw.address.trim()]);
        let outbound = match kind.as_str() {
            "direct" => {
                ensure!(
                    server.is_none(),
                    "Xboard custom_outbounds[{index}] type direct does not accept server/address"
                );
                CustomOutbound::Direct(OutboundConfig {
                    dns_resolver: if dns_resolver.is_empty() {
                        DnsResolver::System
                    } else {
                        DnsResolver::Custom(dns_resolver.to_string())
                    },
                    ip_strategy: raw.ip_strategy,
                })
            }
            "dns" => {
                let resolver = pick_first_non_empty(&[dns_resolver, server.unwrap_or_default()]);
                let resolver =
                    resolver.ok_or_else(|| anyhow::anyhow!(
                        "Xboard custom_outbounds[{index}] type dns requires dns_resolver, server, or address"
                    ))?;
                CustomOutbound::Direct(OutboundConfig {
                    dns_resolver: DnsResolver::Custom(resolver.to_string()),
                    ip_strategy: raw.ip_strategy,
                })
            }
            "block" => {
                ensure!(
                    dns_resolver.is_empty() && server.is_none(),
                    "Xboard custom_outbounds[{index}] type block does not accept resolver fields"
                );
                CustomOutbound::Block
            }
            _ => bail!(
                "unsupported Xboard custom_outbounds[{index}] type {}",
                raw.kind.trim()
            ),
        };
        if tag == "default" || tag == "direct" {
            ensure!(
                matches!(outbound, CustomOutbound::Direct(_)),
                "reserved Xboard custom outbound tag {tag} must use type direct"
            );
        }
        if tag == "block" {
            ensure!(
                matches!(outbound, CustomOutbound::Block),
                "reserved Xboard custom outbound tag block must use type block"
            );
        }
        ensure!(
            outbounds.insert(tag.clone(), outbound).is_none(),
            "duplicate Xboard custom outbound tag {tag}"
        );
        object.clear();
    }
    Ok(outbounds)
}

fn compile_custom_routes(
    values: &[Value],
    outbounds: &HashMap<String, CustomOutbound>,
) -> anyhow::Result<Vec<CustomRouteRule>> {
    let mut routes = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let object = value
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Xboard custom_routes[{index}] must be an object"))?;
        ensure_known_fields("Xboard custom_routes", index, &object, ROUTE_ALLOWED_FIELDS)?;
        let raw: RawCustomRoute = serde_json::from_value(Value::Object(object))
            .with_context(|| format!("decode Xboard custom_routes[{index}]"))?;

        let mut networks = HashSet::new();
        for value in raw.network.iter().chain(raw.protocol.iter()) {
            let value = value.trim().to_ascii_lowercase();
            ensure!(
                matches!(value.as_str(), "tcp" | "udp" | "dns"),
                "unsupported Xboard custom_routes[{index}] network/protocol {value}"
            );
            networks.insert(value);
        }

        let mut domain_matchers = Vec::new();
        for domain in raw.domain {
            let domain = normalize_domain(&domain);
            if !domain.is_empty() {
                domain_matchers.push(DomainMatcher::Exact(domain));
            }
        }
        for domain in raw.domain_suffix {
            let domain = normalize_domain(&domain);
            if !domain.is_empty() {
                domain_matchers.push(DomainMatcher::Suffix(domain));
            }
        }
        for keyword in raw.domain_keyword {
            let keyword = keyword.trim().to_ascii_lowercase();
            if !keyword.is_empty() {
                domain_matchers.push(DomainMatcher::Keyword(keyword));
            }
        }
        for pattern in raw.domain_regex {
            let pattern = pattern.trim();
            if !pattern.is_empty() {
                let matcher =
                    compile_domain_matcher(&format!("regexp:{pattern}")).with_context(|| {
                        format!("compile Xboard custom_routes[{index}] domain_regex {pattern}")
                    })?;
                if let Some(matcher) = matcher {
                    domain_matchers.push(matcher);
                }
            }
        }

        let mut ip_nets = Vec::new();
        for cidr in raw.ip_cidr {
            let cidr = cidr.trim();
            if cidr.is_empty() {
                continue;
            }
            ip_nets.push(
                IpNet::parse(cidr)
                    .with_context(|| format!("parse Xboard custom_routes[{index}] ip_cidr"))?,
            );
        }

        let mut ports = raw.port;
        for value in raw.port_range {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            ports.push(
                PortRange::parse(value)
                    .with_context(|| format!("parse Xboard custom_routes[{index}] port_range"))?,
            );
        }

        let action = if !raw.outbound.trim().is_empty() {
            let outbound = raw.outbound.trim().to_string();
            ensure!(
                raw.action.trim().is_empty() || raw.action.trim().eq_ignore_ascii_case("route"),
                "Xboard custom_routes[{index}] cannot combine outbound with action {}",
                raw.action.trim()
            );
            ensure!(
                outbounds.contains_key(&outbound)
                    || matches!(outbound.as_str(), "direct" | "default" | "block"),
                "Xboard custom_routes[{index}] references unknown outbound tag {outbound}"
            );
            CustomRouteAction::Outbound(outbound)
        } else {
            match raw.action.trim().to_ascii_lowercase().as_str() {
                "reject" | "block" => CustomRouteAction::Block,
                "" => bail!(
                    "Xboard custom_routes[{index}] must specify outbound or a supported action"
                ),
                other => bail!("unsupported Xboard custom_routes[{index}] action {other}"),
            }
        };

        routes.push(CustomRouteRule {
            action,
            networks,
            domain_matchers,
            ip_nets,
            ip_is_private: raw.ip_is_private,
            ports,
        });
    }
    Ok(routes)
}

fn network_matches(network: &str, destination: &SocksAddr, protocol: &str) -> bool {
    match network {
        "tcp" | "udp" => network == protocol,
        "dns" => destination_port(destination) == 53,
        _ => false,
    }
}

fn destination_port(destination: &SocksAddr) -> u16 {
    match destination {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local(),
    }
}

fn prefix_to_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_to_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn pick_first_non_empty<'a>(values: &[&'a str]) -> Option<&'a str> {
    values
        .iter()
        .copied()
        .find(|value| !value.trim().is_empty())
}

fn ensure_known_fields(
    label: &str,
    index: usize,
    object: &Map<String, Value>,
    allowed: &[&str],
) -> anyhow::Result<()> {
    for key in object.keys() {
        ensure!(
            allowed.iter().any(|allowed| allowed == key),
            "{label}[{index}] contains unsupported field {key}"
        );
    }
    Ok(())
}

fn deserialize_default_on_null<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?.unwrap_or(Value::Null);
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(text) => Ok(vec![text]),
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(text) => Ok(text),
                Value::Number(number) => Ok(number.to_string()),
                _ => Err(serde::de::Error::custom("expected string list item")),
            })
            .collect(),
        Value::Number(number) => Ok(vec![number.to_string()]),
        _ => Err(serde::de::Error::custom("expected string or array")),
    }
}

fn deserialize_port_ranges<'de, D>(deserializer: D) -> Result<Vec<PortRange>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = deserialize_string_list(deserializer)?;
    values
        .into_iter()
        .map(|value| PortRange::parse(&value).map_err(serde::de::Error::custom))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_direct_outbound_overrides_ip_strategy() {
        let routing = RoutingTable::from_remote(
            &[],
            &[serde_json::json!({
                "tag": "ipv6-first",
                "type": "direct",
                "domain_strategy": "prefer_ipv6"
            })],
            &[serde_json::json!({
                "domain_suffix": ["example.com"],
                "outbound": "ipv6-first"
            })],
        )
        .expect("routing");

        let outbound = routing
            .outbound_for(
                &SocksAddr::Domain("api.example.com".to_string(), 443),
                "tcp",
            )
            .expect("outbound");

        assert_eq!(outbound.ip_strategy, IpStrategy::PreferIpv6);
    }

    #[test]
    fn custom_routes_accept_camel_case_aliases() {
        let routing = RoutingTable::from_remote(
            &[],
            &[serde_json::json!({
                "tag": "ipv4-first",
                "type": "direct",
                "ipStrategy": "prefer_ipv4"
            })],
            &[serde_json::json!({
                "domainSuffix": ["example.com"],
                "ipIsPrivate": "false",
                "portRange": "443-443",
                "outbound": "ipv4-first"
            })],
        )
        .expect("routing");

        let outbound = routing
            .outbound_for(
                &SocksAddr::Domain("api.example.com".to_string(), 443),
                "tcp",
            )
            .expect("outbound");

        assert_eq!(outbound.ip_strategy, IpStrategy::PreferIpv4);
    }

    #[test]
    fn custom_dns_outbound_sets_resolver() {
        let routing = RoutingTable::from_remote(
            &[],
            &[serde_json::json!({
                "tag": "dns-cn",
                "type": "dns",
                "server": "223.5.5.5"
            })],
            &[serde_json::json!({
                "domain_keyword": ["internal"],
                "outbound": "dns-cn"
            })],
        )
        .expect("routing");

        let outbound = routing
            .outbound_for(
                &SocksAddr::Domain("internal.example.com".to_string(), 443),
                "tcp",
            )
            .expect("outbound");

        assert_eq!(outbound.dns_resolver.nameserver(), Some("223.5.5.5"));
    }

    #[test]
    fn custom_block_route_rejects_destination() {
        let routing = RoutingTable::from_remote(
            &[],
            &[],
            &[serde_json::json!({
                "ip_cidr": ["10.0.0.0/8"],
                "action": "reject"
            })],
        )
        .expect("routing");

        let error = routing
            .outbound_for(&SocksAddr::Ip(([10, 1, 2, 3], 443).into()), "tcp")
            .expect_err("blocked");

        assert!(error.to_string().contains("custom routes"));
    }

    #[test]
    fn rejects_unknown_custom_route_fields() {
        let error = RoutingTable::from_remote(
            &[],
            &[],
            &[serde_json::json!({
                "rule_set": ["geoip-cn"],
                "outbound": "direct"
            })],
        )
        .expect_err("unknown field");

        assert!(error.to_string().contains("rule_set"));
    }
}
