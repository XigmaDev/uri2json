use serde_json::{json,Map, Value};
use std::fs;
use std::path::Path;
use crate::error::ConversionError;
use crate::protocols::{Protocol, ConfigType};
use semver::Version;


#[derive(Debug)]
pub struct SingBoxConfig {
    version: Version,
    log: Value,
    dns: Value,
    //ntp: Value,
    endpoints: Vec<Value>,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    route: Value,
    experimental: Value,
}

impl SingBoxConfig {
    pub fn new(version: String) -> Result<Self, ConversionError> {
        let version = Version::parse(&version).map_err(|e| ConversionError::InvalidVersion(e.to_string()))?;
        
        Ok(Self {
            version,
            log: json!({}),
            dns: json!({
                "servers": [],
                "rules": [],
            }),
            //ntp: json!({}),
            endpoints: Vec::new(),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: json!({}),
            experimental: json!({}),
        })
    }

    // {
    //     "log": {
    //       "disabled": false,
    //       "level": "info",
    //       "output": "box.log",
    //       "timestamp": true
    //     }
    // }
    pub fn set_log_level(&mut self, level: &str) {
        self.log = json!({
            "level": level,
            "timestamp": true
        });
    }

    pub fn add_default_inbound(&mut self) {
        self.inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": 1080,
            "sniff": true,
            "sniff_override_destination": true,
        }));
    }

    pub fn add_outbound(&mut self, protocol: Protocol) -> Result<(), ConversionError> {
        match protocol.to_singbox_outbound(&self.version)? {
            ConfigType::Endpoint(endpoint) => {
                self.endpoints.push(endpoint);
            }
            ConfigType::Outbound(outbound) => {
                self.outbounds.push(outbound);
                self.outbounds.push(json!({
                    "type": "direct",
                    "tag": "direct",
                }));
                self.outbounds.push(json!({
                    "type": "block",
                    "tag": "block",
                }));
                self.outbounds.push(json!({
                    "type": "dns",
                    "tag": "dns-out",
                }));
            }
        }
        Ok(())
    }
    // {
    //     "dns": {
    //       "servers": [],
    //       "rules": [],
    //       "final": "",
    //       "strategy": "",
    //       "disable_cache": false,
    //       "disable_expire": false,
    //       "independent_cache": false,
    //       "cache_capacity": 0,
    //       "reverse_mapping": false,
    //       "client_subnet": "",
    //       "fakeip": {}
    //     }
    //   }


    pub fn add_dns_server(&mut self, type_: &str, server: &str) {
        if let Value::Object(ref mut dns) = self.dns {
            if let Some(Value::Array(ref mut servers)) = dns.get_mut("servers") {
                servers.push(json!({
                    "type": type_,
                    "server": server
                }));
            }
        }
    }

      // {
    //     "route": {
    //       "rules": [],
    //       "rule_set": [],
    //       "final": "",
    //       "auto_detect_interface": false,
    //       "override_android_vpn": false,
    //       "default_interface": "",
    //       "default_mark": 0,
    //       "default_domain_resolver": "", // or {}
    //       "default_network_strategy": "",
    //       "default_network_type": [],
    //       "default_fallback_network_type": [],
    //       "default_fallback_delay": "",
      
    //       // Removed
      
    //       "geoip": {},
    //       "geosite": {}
    //     }
    //   }

    pub fn set_route(&mut self, rules: Value, rule_set: Value) {
        self.route = json!({
            "rules": rules,
            "rule_set":rule_set,

        });
    }

    pub fn add_default_experimental(&mut self) {
        self.experimental = json!({
            "cache_file": {
            "enabled": true
            },
        });
    }


    

    pub fn save_to_file(&self, filename: &str) -> Result<(), ConversionError> {
        let mut map = Map::new();

        map.insert("log".to_string(), self.log.clone());
        map.insert("dns".to_string(), self.dns.clone());
        //map.insert("ntp".to_string(), self.ntp.clone());
        map.insert("endpoints".to_string(), Value::Array(self.endpoints.clone()));
        map.insert("inbounds".to_string(), Value::Array(self.inbounds.clone()));
        map.insert("outbounds".to_string(), Value::Array(self.outbounds.clone()));
        map.insert("route".to_string(), self.route.clone());
        map.insert("experimental".to_string(), self.experimental.clone());

        let content = serde_json::to_string_pretty(&Value::Object(map))
            .map_err(|e| ConversionError::SerializationError(e.to_string()))?;

        fs::write(Path::new(filename), content)
            .map_err(|e| ConversionError::IoError(e.to_string()))?;

        Ok(())
    }  
}


