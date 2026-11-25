use crate::error::ConversionError;
use crate::protocol::{ConfigType, Protocol};
use semver::Version;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct SingBoxConfig {
    version: Version,
    log: Value,
    dns: Value,
    http_clients: Vec<Value>,
    endpoints: Vec<Value>,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    route: Value,
    experimental: Value,
}

impl SingBoxConfig {
    pub fn new(version: String) -> Result<Self, ConversionError> {
        let version = Version::parse(version.trim())
            .map_err(|e| ConversionError::InvalidVersion(e.to_string()))?;

        Ok(Self {
            version,
            log: json!({}),
            dns: json!({
                "servers": [],
                "rules": [],
            }),
            http_clients: Vec::new(),
            endpoints: Vec::new(),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: json!({}),
            experimental: json!({}),
        })
    }

    fn at_least(&self, minor: u64) -> bool {
        self.version >= Version::new(1, minor, 0)
    }

    /// sing-box 1.12 introduced the typed DNS server format; the legacy
    /// format was removed in 1.14.
    fn is_1_12_or_newer(&self) -> bool {
        self.at_least(12)
    }

    /// Endpoints (used for WireGuard) were added in sing-box 1.11.0.
    fn supports_endpoints(&self) -> bool {
        self.version >= Version::new(1, 11, 0)
    }

    pub fn set_log_level(&mut self, level: &str) {
        self.log = json!({
            "level": level,
            "timestamp": true
        });
    }

    pub fn add_mixed_inbound(&mut self) {
        self.inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            // Loopback only: the inbound has no authentication.
            "listen": "127.0.0.1",
            "listen_port": 2080,
        }));
    }

    pub fn add_tun_inbound(&mut self) {
        self.inbounds.push(json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "tun0",
            "address": [
                "172.18.0.1/30",
                "fdfe:dcba:9876::1/126"
            ],
            "route_exclude_address": [
                "192.168.0.0/16",
                "10.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "fe80::/10",
                "fc00::/7"
            ],
            "auto_route": true,
            "mtu": 1358,
            "strict_route": true,
            "udp_timeout": "5s",
        }));
    }

    /// Adds the proxy (tagged `proxy`) plus the `direct` outbound that the
    /// route and DNS rules rely on.
    pub fn add_outbound(&mut self, protocol: Protocol) -> Result<(), ConversionError> {
        match protocol.to_singbox_outbound(&self.version)? {
            ConfigType::Endpoint(endpoint) => self.endpoints.push(endpoint),
            ConfigType::Outbound(outbound) => self.outbounds.push(outbound),
        }

        let has_direct = self
            .outbounds
            .iter()
            .any(|o| o.get("tag").and_then(Value::as_str) == Some("direct"));
        if !has_direct {
            self.outbounds.push(json!({
                "type": "direct",
                "tag": "direct",
            }));
        }
        Ok(())
    }

    fn dns_servers_mut(&mut self) -> Option<&mut Vec<Value>> {
        self.dns
            .as_object_mut()?
            .entry("servers")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
    }

    pub fn add_dns_server(&mut self) {
        let servers = if self.is_1_12_or_newer() {
            vec![
                json!({
                    "tag": "remote",
                    "type": "tls",
                    "server": "dns.adguard-dns.com",
                    "domain_resolver": "local",
                    // Typed DNS servers dial directly by default; send
                    // remote queries through the proxy to avoid DNS leaks.
                    "detour": "proxy"
                }),
                // System resolver: only used for the proxy server's hostname
                // and directly routed domains. Encrypted DNS to public
                // resolvers (e.g. DoT to 1.1.1.1:853) is often blocked on
                // filtered networks, which made startup fail.
                json!({
                    "tag": "local",
                    "type": "local"
                }),
            ]
        } else {
            vec![
                json!({
                    "tag": "remote",
                    "address": "tls://dns.adguard-dns.com",
                    "address_resolver": "dns-local",
                    "detour": "proxy"
                }),
                json!({
                    "tag": "dns-local",
                    "address": "local",
                    "detour": "direct"
                }),
                json!({
                    "tag": "fake",
                    "address": "fakeip"
                }),
            ]
        };

        if let Some(existing) = self.dns_servers_mut() {
            existing.extend(servers);
        }
    }

    pub fn add_dns_rule(&mut self) {
        if self.is_1_12_or_newer() {
            self.add_typed_dns_rules();
            return;
        }
        let Some(dns) = self.dns.as_object_mut() else {
            return;
        };

        if let Some(rules) = dns
            .entry("rules")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
        {
            rules.extend([
                json!({
                    "outbound": "any",
                    "server": "dns-local"
                }),
                json!({
                    "domain": [
                        "raw.githubusercontent.com",
                        "time.apple.com",
                    ],
                    "server": "dns-local"
                }),
                json!({
                    "rule_set": "geosite-category-ir",
                    "server": "dns-local"
                }),
                json!({
                    "disable_cache": true,
                    "inbound": "tun-in",
                    "query_type": [
                        "A",
                        "AAAA"
                    ],
                    "server": "fake"
                }),
            ]);
        }
        dns.insert("independent_cache".to_string(), json!(true));
        dns.insert(
            "fakeip".to_string(),
            json!({
                "enabled": true,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            }),
        );
        dns.insert("strategy".to_string(), json!("prefer_ipv4"));
    }

    /// DNS rules for the typed (1.12+) DNS format. Domains that are routed
    /// directly are resolved by the local server so they get local answers.
    fn add_typed_dns_rules(&mut self) {
        let Some(dns) = self.dns.as_object_mut() else {
            return;
        };
        if let Some(rules) = dns
            .entry("rules")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
        {
            rules.extend([
                json!({
                    "domain": [
                        "raw.githubusercontent.com",
                        "time.apple.com",
                    ],
                    "server": "local"
                }),
                json!({
                    "rule_set": "geosite-category-ir",
                    "server": "local"
                }),
            ]);
        }
        dns.insert("final".to_string(), json!("remote"));
        dns.insert("strategy".to_string(), json!("prefer_ipv4"));
    }

    pub fn set_route(&mut self) {
        let mut route = json!({
            "auto_detect_interface": true,
            "override_android_vpn": true,
            "rules": [
                {
                    // Sniff every inbound so domain and QUIC rules also match
                    // traffic from the mixed inbound.
                    "action": "sniff"
                },
                {
                    "protocol": "dns",
                    "action": "hijack-dns"
                },
                {
                    "ip_is_private": true,
                    "outbound": "direct"
                },
                {
                    // Force QUIC/HTTP3 to fall back to TCP. This has to come
                    // before the catch-all proxy rule or it never matches.
                    "network": "udp",
                    "port": 443,
                    "protocol": "quic",
                    "action": "reject"
                },
                {
                    "rule_set": [
                        "geosite-category-public-tracker",
                        "geosite-category-ads",
                        "geosite-category-ads-all",
                        "geosite-google-ads"
                    ],
                    "action": "reject",
                    "method": "default"
                },
                {
                    "rule_set": [
                        "geosite-category-ir",
                        "geoip-ir"
                    ],
                    "outbound": "direct"
                },
                {
                    "inbound": [
                        "mixed-in",
                        "tun-in"
                    ],
                    "outbound": "proxy"
                }
            ],
            "final": "proxy"
        });

        // Since 1.14, rule-sets are downloaded through an HTTP client;
        // download_detour and the implicit default client are deprecated.
        let http_client = self.at_least(14);
        route["rule_set"] = json!([
            remote_rule_set(
                "geosite-category-ads-all",
                "sing-geosite",
                "1d",
                http_client
            ),
            remote_rule_set("geosite-google-ads", "sing-geosite", "1d", http_client),
            remote_rule_set("geosite-category-ads", "sing-geosite", "1d", http_client),
            remote_rule_set(
                "geosite-category-public-tracker",
                "sing-geosite",
                "1d",
                http_client
            ),
            remote_rule_set(
                "geosite-category-ir",
                "sing-geosite",
                "168h0m0s",
                http_client
            ),
            remote_rule_set("geoip-ir", "sing-geoip", "168h0m0s", http_client),
        ]);

        if http_client {
            self.http_clients = vec![json!({
                "tag": RULE_SET_HTTP_CLIENT,
                "detour": RULE_SET_DETOUR
            })];
            route["default_http_client"] = json!(RULE_SET_HTTP_CLIENT);
        }

        if self.is_1_12_or_newer() {
            route["default_domain_resolver"] = json!({ "server": "local" });
        }

        self.route = route;
    }

    pub fn add_default_experimental(&mut self) {
        self.experimental = json!({
            "cache_file": {
                "enabled": true
            },
        });
    }

    /// Builds the complete sing-box configuration document.
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();

        map.insert("log".to_string(), self.log.clone());
        map.insert("dns".to_string(), self.dns.clone());
        if !self.http_clients.is_empty() {
            map.insert(
                "http_clients".to_string(),
                Value::Array(self.http_clients.clone()),
            );
        }
        if self.supports_endpoints() && !self.endpoints.is_empty() {
            map.insert(
                "endpoints".to_string(),
                Value::Array(self.endpoints.clone()),
            );
        }
        map.insert("inbounds".to_string(), Value::Array(self.inbounds.clone()));
        map.insert(
            "outbounds".to_string(),
            Value::Array(self.outbounds.clone()),
        );
        map.insert("route".to_string(), self.route.clone());
        map.insert("experimental".to_string(), self.experimental.clone());

        Value::Object(map)
    }

    pub fn to_json_string(&self) -> Result<String, ConversionError> {
        serde_json::to_string_pretty(&self.to_json())
            .map_err(|e| ConversionError::SerializationError(e.to_string()))
    }

    pub fn save_to_file(&self, filename: &str) -> Result<(), ConversionError> {
        let path = Path::new(filename);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| ConversionError::IoError(e.to_string()))?;
        }
        fs::write(path, self.to_json_string()?).map_err(|e| ConversionError::IoError(e.to_string()))
    }
}

const RULE_SET_HTTP_CLIENT: &str = "rule-set-http";

/// Rule-sets are fetched from raw.githubusercontent.com, which is often
/// unreachable directly on filtered networks, so download them through the
/// proxy. A failed initial download stops sing-box from starting.
const RULE_SET_DETOUR: &str = "proxy";

fn remote_rule_set(tag: &str, repo: &str, update_interval: &str, http_client: bool) -> Value {
    let mut rule_set = json!({
        "type": "remote",
        "tag": tag,
        "format": "binary",
        "url": format!("https://raw.githubusercontent.com/SagerNet/{}/rule-set/{}.srs", repo, tag),
        "update_interval": update_interval
    });
    if !http_client {
        rule_set["download_detour"] = json!(RULE_SET_DETOUR);
    }
    rule_set
}

/// Oldest sing-box version the generated config works with (rule actions
/// and endpoints were introduced in 1.11.0).
pub const MIN_VERSION: Version = Version::new(1, 11, 0);

/// Converts a share link into a complete sing-box configuration using the
/// default inbounds, DNS and routing.
pub fn generate(version: &str, uri: &str) -> Result<String, ConversionError> {
    let mut config = SingBoxConfig::new(version.to_string())?;
    if config.version < MIN_VERSION {
        return Err(ConversionError::InvalidVersion(format!(
            "{} is too old, the generated config needs sing-box {} or newer",
            config.version, MIN_VERSION
        )));
    }
    let protocol = Protocol::parse_uri(uri)?;
    config.set_log_level("warn");
    config.add_dns_server();
    config.add_dns_rule();
    config.add_mixed_inbound();
    config.add_tun_inbound();
    config.add_outbound(protocol)?;
    config.set_route();
    config.add_default_experimental();
    config.to_json_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(version: &str, uri: &str) -> Value {
        serde_json::from_str(&generate(version, uri).unwrap()).unwrap()
    }

    fn tags(values: &Value) -> Vec<String> {
        values
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v["tag"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn every_route_outbound_exists() {
        for version in ALL_VERSIONS {
            let cfg = build(version, "vless://uuid@example.com:443?security=tls&type=ws");
            let outbounds = tags(&cfg["outbounds"]);
            for rule in cfg["route"]["rules"].as_array().unwrap() {
                if let Some(out) = rule["outbound"].as_str() {
                    assert!(outbounds.contains(&out.to_string()), "{version}: {out}");
                }
            }
        }
    }

    #[test]
    fn wireguard_uses_endpoint_and_keeps_direct() {
        for version in ALL_VERSIONS {
            let cfg = build(
                version,
                "wireguard://key@1.2.3.4:51820?publickey=pub&address=10.0.0.2/32",
            );
            assert_eq!(tags(&cfg["endpoints"]), vec!["proxy"], "{version}");
            assert_eq!(tags(&cfg["outbounds"]), vec!["direct"], "{version}");
        }
    }

    #[test]
    fn legacy_dns_only_before_1_12() {
        let old = build("1.11.0", "trojan://pw@example.com:443");
        assert!(old["dns"]["servers"][0].get("address").is_some());
        assert!(old["route"].get("default_domain_resolver").is_none());

        let new = build("1.12.0", "trojan://pw@example.com:443");
        assert_eq!(new["dns"]["servers"][0]["type"], "tls");
        assert_eq!(new["route"]["default_domain_resolver"]["server"], "local");
        assert!(new.get("endpoints").is_none());
    }

    const ALL_VERSIONS: [&str; 4] = ["1.11.0", "1.12.0", "1.13.0", "1.14.4"];

    #[test]
    fn rule_set_download_options_follow_version() {
        let old = build("1.13.0", "trojan://pw@example.com:443");
        assert!(old.get("http_clients").is_none());
        assert!(old["route"].get("default_http_client").is_none());
        assert_eq!(old["route"]["rule_set"][0]["download_detour"], "proxy");

        let new = build("1.14.4", "trojan://pw@example.com:443");
        assert_eq!(tags(&new["http_clients"]), vec!["rule-set-http"]);
        assert_eq!(new["http_clients"][0]["detour"], "proxy");
        assert_eq!(new["route"]["default_http_client"], "rule-set-http");
        for rule_set in new["route"]["rule_set"].as_array().unwrap() {
            assert!(rule_set.get("download_detour").is_none());
            let tag = rule_set["tag"].as_str().unwrap();
            assert!(rule_set["url"]
                .as_str()
                .unwrap()
                .ends_with(&format!("/{tag}.srs")));
        }
    }

    #[test]
    fn no_removed_or_unsafe_fields() {
        for version in ALL_VERSIONS {
            let cfg = build(version, "trojan://pw@example.com:443");
            let tun = &cfg["inbounds"][1];
            assert_eq!(tun["type"], "tun");
            assert!(tun.get("gso").is_none(), "gso was removed in 1.13");
            assert!(tun.get("stack").is_none());
            assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
            let sniff = &cfg["route"]["rules"][0];
            assert_eq!(sniff["action"], "sniff");
            assert!(sniff.get("inbound").is_none());
        }
    }

    #[test]
    fn typed_dns_goes_through_proxy() {
        for version in ["1.12.0", "1.13.0", "1.14.4"] {
            let cfg = build(version, "trojan://pw@example.com:443");
            let servers = cfg["dns"]["servers"].as_array().unwrap();
            assert!(
                servers.iter().all(|s| s.get("address").is_none()),
                "{version}"
            );
            assert_eq!(servers[0]["tag"], "remote");
            assert_eq!(servers[0]["detour"], "proxy");
            assert_eq!(cfg["dns"]["final"], "remote");
            assert!(cfg["dns"].get("independent_cache").is_none());
            for rule in cfg["dns"]["rules"].as_array().unwrap() {
                assert!(rule.get("outbound").is_none(), "{version}");
            }
        }
    }

    #[test]
    fn local_dns_uses_system_resolver() {
        let old = build("1.11.0", "trojan://pw@example.com:443");
        let local = old["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["tag"] == "dns-local")
            .unwrap();
        assert_eq!(local["address"], "local");

        for version in ["1.12.0", "1.13.0", "1.14.4"] {
            let cfg = build(version, "trojan://pw@example.com:443");
            let local = cfg["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["tag"] == "local")
                .unwrap();
            assert_eq!(
                local,
                &json!({ "tag": "local", "type": "local" }),
                "{version}"
            );
        }
    }

    #[test]
    fn too_old_version_is_rejected() {
        assert!(matches!(
            generate("1.10.0", "trojan://pw@example.com:443"),
            Err(ConversionError::InvalidVersion(_))
        ));
    }

    #[test]
    fn invalid_version() {
        assert!(matches!(
            SingBoxConfig::new("latest".to_string()),
            Err(ConversionError::InvalidVersion(_))
        ));
    }
}
