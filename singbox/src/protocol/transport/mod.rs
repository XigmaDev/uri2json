use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum TransportConfig {
    Tcp,
    Http {
        host: Vec<String>,
        path: String,
        method: String,
        headers: HashMap<String, String>,
        idle_timeout: String,
        ping_timeout: String,
    },
    Websocket {
        path: String,
        headers: HashMap<String, String>,
        max_early_data: u32,
        early_data_header_name: String,
    },
    Quic,
    Grpc {
        service_name: String,
        idle_timeout: String,
        ping_timeout: String,
        permit_without_stream: bool,
    },
    Httpupgrade {
        host: String,
        path: String,
        headers: HashMap<String, String>,
    },
}

impl TransportConfig {
    /// Returns the sing-box `transport` object, or `None` for plain TCP
    /// (sing-box rejects a transport object without a type).
    pub fn to_config(&self) -> Option<Value> {
        let config = match self {
            TransportConfig::Tcp => return None,
            TransportConfig::Http {
                host,
                path,
                method,
                headers,
                idle_timeout,
                ping_timeout,
            } => json!({
                "type": "http",
                "host": host,
                "path": path,
                "method": method,
                "headers": headers,
                "idle_timeout": idle_timeout,
                "ping_timeout": ping_timeout
            }),

            TransportConfig::Websocket {
                path,
                headers,
                max_early_data,
                early_data_header_name,
            } => {
                let mut config = json!({
                    "type": "ws",
                    "path": path,
                    "headers": headers,
                });
                if *max_early_data > 0 {
                    config["max_early_data"] = json!(max_early_data);
                    config["early_data_header_name"] = json!(early_data_header_name);
                }
                config
            }

            TransportConfig::Quic => json!({ "type": "quic" }),

            TransportConfig::Grpc {
                service_name,
                idle_timeout,
                ping_timeout,
                permit_without_stream,
            } => json!({
                "type": "grpc",
                "service_name": service_name,
                "idle_timeout": idle_timeout,
                "ping_timeout": ping_timeout,
                "permit_without_stream": permit_without_stream
            }),

            TransportConfig::Httpupgrade {
                host,
                path,
                headers,
            } => json!({
                "type": "httpupgrade",
                "host": host,
                "path": path,
                "headers": headers
            }),
        };
        Some(config)
    }
}
