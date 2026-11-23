mod tls;
mod transport;

use crate::error::ConversionError;
use base64::engine::general_purpose;
use base64::Engine;
use semver::Version;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use url::Url;

#[derive(Debug)]
pub enum ConfigType {
    Endpoint(Value),
    Outbound(Value),
}

#[derive(Debug)]
pub enum Protocol {
    Shadowsocks {
        method: String,
        password: String,
        host: String,
        port: u16,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    },
    Vmess {
        uuid: String,
        host: String,
        port: u16,
        alter_id: u32,
        security: String,
        transport: transport::TransportConfig,
        tls: tls::TlsConfig,
    },
    Vless {
        uuid: String,
        host: String,
        port: u16,
        flow: Option<String>,
        transport: transport::TransportConfig,
        tls: tls::TlsConfig,
    },
    Trojan {
        password: String,
        host: String,
        port: u16,
        transport: transport::TransportConfig,
        tls: tls::TlsConfig,
    },
    Wireguard {
        private_key: String,
        public_key: String,
        pre_shared_key: Option<String>,
        host: String,
        port: u16,
        address: Vec<String>,
        reserved: Option<Vec<u8>>,
        mtu: Option<u16>,
    },
}

impl Protocol {
    pub fn parse_uri(uri: &str) -> Result<Self, ConversionError> {
        let uri = uri.trim();
        let (scheme, content) = uri.split_once("://").ok_or(ConversionError::InvalidUri)?;

        match scheme.to_ascii_lowercase().as_str() {
            "ss" => Self::parse_shadowsocks(content),
            "vmess" => Self::parse_vmess(content),
            "vless" => Self::parse_vless(content),
            "trojan" => Self::parse_trojan(content),
            "wg" | "wireguard" => Self::parse_wireguard(content),
            _ => Err(ConversionError::UnsupportedProtocol(scheme.to_string())),
        }
    }
}

impl Protocol {
    /// Supports both SIP002 (`ss://base64(method:pass)@host:port?plugin=...#tag`,
    /// or with a percent-encoded plain `method:pass` user info) and the legacy
    /// format (`ss://base64(method:pass@host:port)#tag`).
    fn parse_shadowsocks(data: &str) -> Result<Self, ConversionError> {
        let without_tag = strip_fragment(data);

        let normalized = if without_tag.contains('@') {
            without_tag.to_string()
        } else {
            let (encoded, rest) = match without_tag.find(['?', '/']) {
                Some(idx) => without_tag.split_at(idx),
                None => (without_tag, ""),
            };
            let decoded = String::from_utf8(decode_base64(encoded)?)
                .map_err(|_| ConversionError::FailedDecode)?;
            format!("{}{}", decoded, rest)
        };

        let (user_info, server) = normalized
            .rsplit_once('@')
            .ok_or(ConversionError::InvalidUri)?;

        let user_info = percent_decode(user_info)?;
        let credentials = if user_info.contains(':') {
            user_info
        } else {
            String::from_utf8(decode_base64(&user_info)?)
                .map_err(|_| ConversionError::FailedDecode)?
        };
        let (method, password) = credentials
            .split_once(':')
            .ok_or(ConversionError::UnsupportedShadowsocks)?;
        if method.is_empty() {
            return Err(ConversionError::UnsupportedShadowsocks);
        }
        if password.is_empty() {
            return Err(ConversionError::MissingPassword);
        }

        let url = Url::parse(&format!("ss://placeholder@{}", server))
            .map_err(|_| ConversionError::InvalidUri)?;
        let query = query_map(&url);

        let (plugin, plugin_opts) = match query.get("plugin").filter(|p| !p.is_empty()) {
            Some(raw) => {
                let (name, opts) = match raw.split_once(';') {
                    Some((name, opts)) => (name, Some(opts.to_string())),
                    None => (raw.as_str(), None),
                };
                let name = match name {
                    "simple-obfs" | "obfs-local" => "obfs-local",
                    "v2ray-plugin" => "v2ray-plugin",
                    other => return Err(ConversionError::UnsupportedFeature(format!(
                        "shadowsocks plugin '{}' (sing-box supports obfs-local and v2ray-plugin)",
                        other
                    ))),
                };
                (Some(name.to_string()), opts.filter(|o| !o.is_empty()))
            }
            None => (None, None),
        };

        Ok(Self::Shadowsocks {
            method: method.to_string(),
            password: password.to_string(),
            host: host_of(&url)?,
            port: url.port().ok_or(ConversionError::MissingPort)?,
            plugin,
            plugin_opts,
        })
    }

    fn parse_vmess(data: &str) -> Result<Self, ConversionError> {
        let decoded = decode_base64(strip_fragment(data))?;
        let vmess: Value =
            serde_json::from_slice(&decoded).map_err(|_| ConversionError::InvalidJson)?;
        let obj = vmess
            .as_object()
            .ok_or(ConversionError::InvalidVmessFormat)?;

        let get = |key: &str| json_field_as_string(obj, key);

        // Translate the VMess JSON keys to the share-link query keys so the
        // common transport/TLS parsers can be reused.
        let network = get("net").unwrap_or_else(|| "tcp".to_string());
        let mut query = HashMap::new();
        if let Some(header_type) = get("type") {
            query.insert("headerType".to_string(), header_type);
        }
        if let Some(host) = get("host") {
            query.insert("host".to_string(), host);
        }
        if let Some(path) = get("path") {
            if network == "grpc" {
                query.insert("serviceName".to_string(), path);
            } else {
                query.insert("path".to_string(), path);
            }
        }
        query.insert("type".to_string(), network);
        if let Some(tls) = get("tls") {
            query.insert("security".to_string(), tls);
        }
        for (from, to) in [
            ("sni", "sni"),
            ("alpn", "alpn"),
            ("fp", "fp"),
            ("pbk", "pbk"),
            ("sid", "sid"),
            ("allowInsecure", "insecure"),
            ("skip-cert-verify", "insecure"),
        ] {
            if let Some(value) = get(from) {
                query.insert(to.to_string(), value);
            }
        }

        let port = get("port")
            .ok_or(ConversionError::MissingPort)?
            .parse::<u16>()
            .map_err(|_| ConversionError::MissingPort)?;

        let tls = parse_tls(&mut query, "")?;
        let transport = parse_transport(&mut query)?;

        Ok(Self::Vmess {
            uuid: get("id").ok_or(ConversionError::MissingUUID)?,
            host: get("add").ok_or(ConversionError::MissingHost)?,
            port,
            alter_id: get("aid").and_then(|a| a.parse().ok()).unwrap_or(0),
            security: get("scy")
                .or_else(|| get("security"))
                .unwrap_or_else(|| "auto".to_string()),
            transport,
            tls,
        })
    }

    fn parse_vless(data: &str) -> Result<Self, ConversionError> {
        let url =
            Url::parse(&format!("vless://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let mut query = query_map(&url);

        let uuid = percent_decode(url.username())?;
        if uuid.is_empty() {
            return Err(ConversionError::MissingUUID);
        }

        let tls = parse_tls(&mut query, "")?;
        let transport = parse_transport(&mut query)?;

        Ok(Self::Vless {
            uuid,
            host: host_of(&url)?,
            port: url.port().ok_or(ConversionError::MissingPort)?,
            flow: query.remove("flow").filter(|f| !f.is_empty()),
            transport,
            tls,
        })
    }

    fn parse_trojan(data: &str) -> Result<Self, ConversionError> {
        let url =
            Url::parse(&format!("trojan://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let mut query = query_map(&url);

        let password = percent_decode(url.username())?;
        if password.is_empty() {
            return Err(ConversionError::MissingPassword);
        }

        // Trojan runs over TLS unless explicitly told otherwise.
        let tls = parse_tls(&mut query, "tls")?;
        let transport = parse_transport(&mut query)?;

        Ok(Self::Trojan {
            password,
            host: host_of(&url)?,
            port: url.port().ok_or(ConversionError::MissingPort)?,
            transport,
            tls,
        })
    }

    fn parse_wireguard(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("wireguard://{}", data))
            .map_err(|_| ConversionError::InvalidUri)?;
        let mut query = query_map(&url);

        let private_key = Some(percent_decode(url.username())?)
            .filter(|k| !k.is_empty())
            .or_else(|| take_first(&mut query, &["privatekey", "private_key"]))
            .ok_or(ConversionError::MissingField("private_key"))?;

        let public_key = take_first(&mut query, &["publickey", "public_key", "peer_public_key"])
            .ok_or(ConversionError::MissingPublicKey)?;

        let pre_shared_key = take_first(
            &mut query,
            &["presharedkey", "preshared_key", "pre_shared_key"],
        );

        let address: Vec<String> = take_first(&mut query, &["address", "ip"])
            .ok_or(ConversionError::MissingIP)?
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(with_prefix_len)
            .collect();
        if address.is_empty() {
            return Err(ConversionError::MissingIP);
        }

        let reserved = match query.remove("reserved").filter(|r| !r.is_empty()) {
            Some(raw) => Some(
                raw.split(',')
                    .map(|b| b.trim().parse::<u8>())
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| {
                        ConversionError::ParseError(format!("invalid reserved value '{}'", raw))
                    })?,
            ),
            None => None,
        };

        let mtu = match query.remove("mtu").filter(|m| !m.is_empty()) {
            Some(raw) => Some(
                raw.parse::<u16>()
                    .map_err(|_| ConversionError::ParseError(format!("invalid mtu '{}'", raw)))?,
            ),
            None => None,
        };

        Ok(Self::Wireguard {
            private_key,
            public_key,
            pre_shared_key,
            host: host_of(&url)?,
            port: url.port().ok_or(ConversionError::MissingPort)?,
            address,
            reserved,
            mtu,
        })
    }

    pub fn to_singbox_outbound(&self, version: &Version) -> Result<ConfigType, ConversionError> {
        match self {
            // WireGuard endpoints were introduced in sing-box 1.11.0; the
            // WireGuard outbound is deprecated from that version on.
            Self::Wireguard {
                private_key,
                public_key,
                pre_shared_key,
                host,
                port,
                address,
                reserved,
                mtu,
            } if version >= &Version::new(1, 11, 0) => {
                let mut peer = json!({
                    "address": host,
                    "port": port,
                    "public_key": public_key,
                    "allowed_ips": ["0.0.0.0/0", "::/0"],
                });
                if let Some(psk) = pre_shared_key {
                    peer["pre_shared_key"] = json!(psk);
                }
                if let Some(reserved) = reserved {
                    peer["reserved"] = json!(reserved);
                }

                let mut endpoint = json!({
                    "type": "wireguard",
                    "tag": "proxy",
                    "address": address,
                    "private_key": private_key,
                    "peers": [peer],
                });
                if let Some(mtu) = mtu {
                    endpoint["mtu"] = json!(mtu);
                }
                Ok(ConfigType::Endpoint(endpoint))
            }
            _ => Ok(ConfigType::Outbound(self.to_legacy_singbox_outbound())),
        }
    }

    pub fn to_legacy_singbox_outbound(&self) -> Value {
        match self {
            Self::Shadowsocks {
                method,
                password,
                host,
                port,
                plugin,
                plugin_opts,
            } => {
                let mut config = json!({
                    "type": "shadowsocks",
                    "tag": "proxy",
                    "server": host,
                    "server_port": port,
                    "method": method,
                    "password": password,
                });
                if let Some(plugin) = plugin {
                    config["plugin"] = json!(plugin);
                    if let Some(opts) = plugin_opts {
                        config["plugin_opts"] = json!(opts);
                    }
                }
                config
            }
            Self::Vmess {
                uuid,
                host,
                port,
                alter_id,
                security,
                transport,
                tls,
            } => {
                let mut config = json!({
                    "type": "vmess",
                    "tag": "proxy",
                    "server": host,
                    "server_port": port,
                    "uuid": uuid,
                    "alter_id": alter_id,
                    "security": security,
                });
                apply_transport_and_tls(&mut config, transport, tls);
                config
            }
            Self::Vless {
                uuid,
                host,
                port,
                flow,
                transport,
                tls,
            } => {
                let mut config = json!({
                    "type": "vless",
                    "tag": "proxy",
                    "server": host,
                    "server_port": port,
                    "uuid": uuid,
                    "packet_encoding": "xudp",
                });
                if let Some(flow) = flow {
                    config["flow"] = json!(flow);
                }
                apply_transport_and_tls(&mut config, transport, tls);
                config
            }
            Self::Trojan {
                password,
                host,
                port,
                transport,
                tls,
            } => {
                let mut config = json!({
                    "type": "trojan",
                    "tag": "proxy",
                    "server": host,
                    "server_port": port,
                    "password": password,
                });
                apply_transport_and_tls(&mut config, transport, tls);
                config
            }
            Self::Wireguard {
                private_key,
                public_key,
                pre_shared_key,
                host,
                port,
                address,
                reserved,
                mtu,
            } => {
                let mut config = json!({
                    "type": "wireguard",
                    "tag": "proxy",
                    "server": host,
                    "server_port": port,
                    "local_address": address,
                    "private_key": private_key,
                    "peer_public_key": public_key,
                });
                if let Some(psk) = pre_shared_key {
                    config["pre_shared_key"] = json!(psk);
                }
                if let Some(reserved) = reserved {
                    config["reserved"] = json!(reserved);
                }
                if let Some(mtu) = mtu {
                    config["mtu"] = json!(mtu);
                }
                config
            }
        }
    }
}

fn apply_transport_and_tls(
    config: &mut Value,
    transport: &transport::TransportConfig,
    tls: &tls::TlsConfig,
) {
    if let Some(transport) = transport.to_config() {
        config["transport"] = transport;
    }
    if tls.enabled {
        config["tls"] = tls.to_config();
    }
}

fn parse_transport(
    query: &mut HashMap<String, String>,
) -> Result<transport::TransportConfig, ConversionError> {
    let transport_type = query
        .remove("type")
        .unwrap_or_default()
        .trim()
        .to_lowercase();

    let take_timeout = |query: &mut HashMap<String, String>, key: &str| {
        query
            .remove(key)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "15s".to_string())
    };

    let http = |query: &mut HashMap<String, String>| transport::TransportConfig::Http {
        host: query
            .remove("host")
            .map(|h| {
                h.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        path: query
            .remove("path")
            .filter(|p| !p.is_empty())
            .map(ensure_leading_slash)
            .unwrap_or_default(),
        method: query
            .remove("method")
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "GET".to_string()),
        headers: parse_headers(query.remove("headers")),
        idle_timeout: take_timeout(query, "idle_timeout"),
        ping_timeout: take_timeout(query, "ping_timeout"),
    };

    match transport_type.as_str() {
        "tcp" | "raw" | "" => {
            let header_type = query.remove("headerType").unwrap_or_default();
            if header_type.eq_ignore_ascii_case("http") {
                Ok(http(query))
            } else {
                Ok(transport::TransportConfig::Tcp)
            }
        }
        "http" | "h2" => Ok(http(query)),
        "ws" | "websocket" => {
            let mut headers = parse_headers(query.remove("headers"));
            if let Some(host) = query.remove("host").filter(|h| !h.is_empty()) {
                headers.insert("Host".to_string(), host);
            }

            let raw_path = query.remove("path").unwrap_or_default();
            let (path, path_early_data) = split_early_data(&raw_path);

            let max_early_data = query
                .remove("max_early_data")
                .or_else(|| query.remove("ed"))
                .and_then(|s| s.parse().ok())
                .or(path_early_data)
                .unwrap_or(0);

            let early_data_header_name = query
                .remove("early_data_header_name")
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| {
                    if max_early_data > 0 {
                        // Xray-compatible servers read early data from this header.
                        "Sec-WebSocket-Protocol".to_string()
                    } else {
                        String::new()
                    }
                });

            Ok(transport::TransportConfig::Websocket {
                path: if path.is_empty() {
                    path
                } else {
                    ensure_leading_slash(path)
                },
                headers,
                max_early_data,
                early_data_header_name,
            })
        }
        "quic" => Ok(transport::TransportConfig::Quic),
        "grpc" => Ok(transport::TransportConfig::Grpc {
            service_name: query.remove("serviceName").unwrap_or_default(),
            idle_timeout: take_timeout(query, "idle_timeout"),
            ping_timeout: take_timeout(query, "ping_timeout"),
            permit_without_stream: query
                .remove("permit_without_stream")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
        }),
        "httpupgrade" => Ok(transport::TransportConfig::Httpupgrade {
            host: query.remove("host").unwrap_or_default(),
            path: query
                .remove("path")
                .filter(|p| !p.is_empty())
                .map(ensure_leading_slash)
                .unwrap_or_default(),
            headers: parse_headers(query.remove("headers")),
        }),
        _ => Err(ConversionError::InvalidTransportType(transport_type)),
    }
}

/// `default_security` is used when the link has no (or an empty) `security`
/// parameter.
fn parse_tls(
    query: &mut HashMap<String, String>,
    default_security: &str,
) -> Result<tls::TlsConfig, ConversionError> {
    let security = query
        .remove("security")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_security.to_string())
        .to_lowercase();
    let mut tls = tls::TlsConfig::default();

    if security != "tls" && security != "reality" {
        return Ok(tls);
    }

    tls.enabled = true;
    tls.sni = take_first(query, &["sni", "peer"]).or_else(|| {
        // Fall back to the HTTP/WS host header, like most clients do.
        query
            .get("host")
            .and_then(|h| h.split(',').next())
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
    });

    let mut insecure = false;
    for key in ["insecure", "allowInsecure", "allow_insecure"] {
        if let Some(value) = query.remove(key) {
            insecure |= value == "1" || value.eq_ignore_ascii_case("true");
        }
    }
    tls.insecure = insecure;

    tls.alpn = query
        .remove("alpn")
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let fingerprint = query
        .remove("fp")
        .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("none"))
        .unwrap_or_else(|| "chrome".to_string());
    tls.utls = Some(tls::UTlsConfig {
        enabled: true,
        fingerprint,
    });

    if security == "reality" {
        tls.reality = Some(tls::RealityConfig {
            public_key: query
                .remove("pbk")
                .filter(|p| !p.is_empty())
                .ok_or(ConversionError::MissingRealityParam("pbk".to_string()))?,
            // An empty short ID is valid for REALITY.
            short_id: query.remove("sid").unwrap_or_default(),
        });
    }
    Ok(tls)
}

fn parse_headers(header_str: Option<String>) -> HashMap<String, String> {
    header_str
        .map(|s| {
            s.split('&')
                .filter_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Splits Xray-style early data (`/path?ed=2048`) out of a WebSocket path.
fn split_early_data(path: &str) -> (String, Option<u32>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };

    let mut early_data = None;
    let mut rest = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("ed", value)) => early_data = value.parse().ok(),
            _ => rest.push(pair),
        }
    }

    if rest.is_empty() {
        (base.to_string(), early_data)
    } else {
        (format!("{}?{}", base, rest.join("&")), early_data)
    }
}

fn ensure_leading_slash(mut path: String) -> String {
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    path
}

fn strip_fragment(data: &str) -> &str {
    data.split('#').next().unwrap_or_default()
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs().into_owned().collect()
}

fn take_first(query: &mut HashMap<String, String>, keys: &[&str]) -> Option<String> {
    let mut found = None;
    for key in keys {
        if let Some(value) = query.remove(*key).filter(|v| !v.is_empty()) {
            found.get_or_insert(value);
        }
    }
    found
}

/// Returns the host without IPv6 brackets, as sing-box expects.
fn host_of(url: &Url) -> Result<String, ConversionError> {
    let host = url.host_str().ok_or(ConversionError::MissingHost)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(ConversionError::MissingHost);
    }
    Ok(host.to_string())
}

fn percent_decode(value: &str) -> Result<String, ConversionError> {
    urlencoding::decode(value)
        .map(|v| v.into_owned())
        .map_err(|_| ConversionError::FailedDecode)
}

/// Decodes standard or URL-safe base64, with or without padding.
fn decode_base64(value: &str) -> Result<Vec<u8>, ConversionError> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.trim_end_matches('=');
    general_purpose::STANDARD_NO_PAD
        .decode(cleaned)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(cleaned))
        .map_err(|_| ConversionError::FailedDecode)
}

/// Reads a VMess JSON field that may be a string, number or boolean.
fn json_field_as_string(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// sing-box requires WireGuard addresses in prefix form.
fn with_prefix_len(address: &str) -> String {
    if address.contains('/') {
        address.to_string()
    } else if address.contains(':') {
        format!("{}/128", address)
    } else {
        format!("{}/32", address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(uri: &str) -> Value {
        Protocol::parse_uri(uri)
            .expect("parse")
            .to_legacy_singbox_outbound()
    }

    #[test]
    fn vless_reality() {
        let out = outbound(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=reality&sni=www.google.com&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp&headerType=none&flow=xtls-rprx-vision#name",
        );
        assert_eq!(out["type"], "vless");
        assert_eq!(out["server"], "example.com");
        assert_eq!(out["server_port"], 443);
        assert_eq!(out["flow"], "xtls-rprx-vision");
        assert!(
            out.get("transport").is_none(),
            "tcp must not emit transport"
        );
        assert_eq!(out["tls"]["server_name"], "www.google.com");
        assert_eq!(out["tls"]["reality"]["public_key"], "PUBKEY");
        assert_eq!(out["tls"]["reality"]["short_id"], "abcd");
    }

    #[test]
    fn vless_without_type_defaults_to_tcp() {
        let out = outbound("vless://uuid@1.2.3.4:443?security=none");
        assert!(out.get("transport").is_none());
        assert!(out.get("tls").is_none());
    }

    #[test]
    fn vless_ws_early_data_in_path() {
        let out = outbound(
            "vless://uuid@example.com:443?type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&security=tls",
        );
        assert_eq!(out["transport"]["type"], "ws");
        assert_eq!(out["transport"]["path"], "/ws");
        assert_eq!(out["transport"]["max_early_data"], 2048);
        assert_eq!(
            out["transport"]["early_data_header_name"],
            "Sec-WebSocket-Protocol"
        );
        assert_eq!(out["transport"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(out["tls"]["server_name"], "cdn.example.com");
    }

    #[test]
    fn vmess_ws_tls_with_numeric_fields() {
        let json = r#"{"add":"example.com","aid":0,"host":"cdn.example.com","id":"uuid","net":"ws","path":"/path","port":443,"ps":"name","tls":"tls","type":"auto","scy":"auto","skip-cert-verify":true,"sni":""}"#;
        let uri = format!("vmess://{}", general_purpose::STANDARD.encode(json));
        let out = outbound(&uri);
        assert_eq!(out["type"], "vmess");
        assert_eq!(out["server_port"], 443);
        assert_eq!(out["alter_id"], 0);
        assert_eq!(out["transport"]["type"], "ws");
        assert_eq!(out["tls"]["enabled"], true);
        assert_eq!(out["tls"]["insecure"], true);
        assert_eq!(out["tls"]["server_name"], "cdn.example.com");
    }

    #[test]
    fn vmess_string_port_unpadded_base64() {
        let json = r#"{"add":"1.2.3.4","aid":"0","id":"uuid","net":"tcp","port":"8080"}"#;
        let encoded = general_purpose::STANDARD_NO_PAD.encode(json);
        let out = outbound(&format!("vmess://{}", encoded));
        assert_eq!(out["server_port"], 8080);
        assert!(out.get("tls").is_none());
    }

    #[test]
    fn trojan_defaults_to_tls_and_decodes_password() {
        let out = outbound("trojan://p%40ss@example.com:443#name");
        assert_eq!(out["password"], "p@ss");
        assert_eq!(out["tls"]["enabled"], true);
        assert!(out.get("transport").is_none());
    }

    #[test]
    fn shadowsocks_sip002_urlsafe_base64() {
        let user = general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let out = outbound(&format!("ss://{}@1.2.3.4:8388#name", user));
        assert_eq!(out["method"], "aes-256-gcm");
        assert_eq!(out["password"], "secret");
        assert_eq!(out["server_port"], 8388);
    }

    #[test]
    fn shadowsocks_plain_userinfo_and_plugin() {
        let out = outbound(
            "ss://2022-blake3-aes-128-gcm:a%2Bb%3D@example.com:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.org#n",
        );
        assert_eq!(out["method"], "2022-blake3-aes-128-gcm");
        assert_eq!(out["password"], "a+b=");
        assert_eq!(out["plugin"], "obfs-local");
        assert_eq!(out["plugin_opts"], "obfs=http;obfs-host=example.org");
    }

    #[test]
    fn shadowsocks_legacy_format() {
        let encoded = general_purpose::STANDARD.encode("chacha20-ietf-poly1305:pw@5.6.7.8:1234");
        let out = outbound(&format!("ss://{}#tag", encoded));
        assert_eq!(out["server"], "5.6.7.8");
        assert_eq!(out["server_port"], 1234);
        assert_eq!(out["password"], "pw");
    }

    #[test]
    fn wireguard_endpoint() {
        let protocol = Protocol::parse_uri(
            "wg://cHJpdmF0ZQ%3D%3D@1.2.3.4:51820?publickey=cHVibGlj&address=10.0.0.2,fd00::2&reserved=1,2,3&mtu=1280#wg",
        )
        .unwrap();
        let ConfigType::Endpoint(ep) = protocol
            .to_singbox_outbound(&Version::new(1, 11, 0))
            .unwrap()
        else {
            panic!("expected endpoint");
        };
        assert_eq!(ep["tag"], "proxy");
        assert_eq!(ep["private_key"], "cHJpdmF0ZQ==");
        assert_eq!(ep["address"], json!(["10.0.0.2/32", "fd00::2/128"]));
        assert_eq!(ep["mtu"], 1280);
        assert_eq!(ep["peers"][0]["address"], "1.2.3.4");
        assert_eq!(ep["peers"][0]["port"], 51820);
        assert_eq!(ep["peers"][0]["public_key"], "cHVibGlj");
        assert_eq!(ep["peers"][0]["reserved"], json!([1, 2, 3]));
    }

    #[test]
    fn wireguard_bad_mtu_is_an_error_not_a_panic() {
        assert!(Protocol::parse_uri(
            "wireguard://key@1.2.3.4:51820?publickey=x&ip=10.0.0.2&mtu=abc"
        )
        .is_err());
    }

    #[test]
    fn unsupported_scheme() {
        assert!(matches!(
            Protocol::parse_uri("hysteria2://x@y:1"),
            Err(ConversionError::UnsupportedProtocol(_))
        ));
    }
}
