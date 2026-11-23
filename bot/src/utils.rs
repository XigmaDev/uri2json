pub const SUPPORTED_VERSIONS: [&str; 2] = ["1.11.0", "1.12.0"];

pub fn welcome_message() -> String {
    format!(
        "🎉 Welcome to the URI to JSON Bot!

I'm here to help you convert URIs into JSON configurations compatible with SingBox and Xray.

📋 Available Commands:
- /start — Show this welcome message
- /help — Display all available commands
- /singbox <version> <URI> — Process a URI for a specific version

🔍 Supported Versions:
{}

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
        SUPPORTED_VERSIONS.join(", ")
    )
}
