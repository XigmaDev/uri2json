/// sing-box release lines the generated config is built for. Any patch
/// release of a listed line is accepted (e.g. `1.14.4`).
pub const SUPPORTED_VERSIONS: [&str; 4] = ["1.11.0", "1.12.0", "1.13.0", "1.14.0"];

/// Accepts `1.14`, `1.14.0` or any `1.14.x` when the `1.14` line is supported.
pub fn normalize_version(input: &str) -> Option<String> {
    let input = input.trim().trim_start_matches(['v', 'V']);
    let mut parts = input.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = match parts.next() {
        Some(p) => p.parse().ok()?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    let line = format!("{}.{}.0", major, minor);
    SUPPORTED_VERSIONS
        .contains(&line.as_str())
        .then(|| format!("{}.{}.{}", major, minor, patch))
}

/// Human-readable list, e.g. `1.11.x, 1.12.x`.
pub fn supported_versions_text() -> String {
    SUPPORTED_VERSIONS
        .iter()
        .map(|v| format!("{}.x", v.trim_end_matches(".0")))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn welcome_message() -> String {
    format!(
        "🎉 Welcome to the URI to JSON Bot!

I'm here to help you convert URIs into JSON configurations compatible with SingBox and Xray.

📋 Available Commands:
- /start — Show this welcome message
- /help — Display all available commands
- /singbox <version> <URI> — Process a URI for a specific version

🔍 Supported sing-box versions: {}

🚀 Coming Soon:
- /xray command

Beta Notice:
We're currently in beta! If you encounter any issues or have feedback, please let us know.
@ip_routes_admin
We appreciate your support!",
        SUPPORTED_VERSIONS
            .iter()
            .map(|v| format!("- {}", v))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

pub fn help_message() -> String {
    format!(
        "📋 Available commands:
/start - Show the welcome message
/help - Show available commands
/singbox <version> <URI> - Process URI for specific version

🔍 Supported versions: {}

Supported Protocols:
- ss:// Shadowsocks
- vmess:// VMess
- vless:// VLESS
- trojan:// Trojan
- wg:// or wireguard:// WireGuard",
        supported_versions_text()
    )
}

#[cfg(test)]
mod tests {
    use super::normalize_version;

    #[test]
    fn version_lines() {
        assert_eq!(normalize_version("1.14.4").as_deref(), Some("1.14.4"));
        assert_eq!(normalize_version("v1.13").as_deref(), Some("1.13.0"));
        assert_eq!(normalize_version("1.11.0").as_deref(), Some("1.11.0"));
        assert_eq!(normalize_version("1.10.0"), None);
        assert_eq!(normalize_version("1.15.0"), None);
        assert_eq!(normalize_version("latest"), None);
        assert_eq!(normalize_version("1.14.0.1"), None);
    }
}
