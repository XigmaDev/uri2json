# uri2json
**Telegram Bot to Converts URIs into JSON configurations compatible with SingBox and Xray.**

> **Disclaimer:** This project is only for personal learning.

## Supported

- **Protocols:** `ss://`, `vmess://`, `vless://` (incl. REALITY), `trojan://`, `wg://` / `wireguard://`
- **Transports:** tcp, http/h2, ws (incl. early data), grpc, httpupgrade, quic
- **sing-box versions:** 1.11.x, 1.12.x, 1.13.x, 1.14.x

The generated config follows the format of the requested version:

| Version | Differences |
|---------|-------------|
| 1.11.x  | Legacy DNS servers with FakeIP |
| 1.12.x – 1.13.x | Typed DNS servers, `default_domain_resolver` |
| 1.14.x  | Rule-sets downloaded through `http_clients` / `default_http_client` |

WireGuard is always emitted as an endpoint (the WireGuard outbound was removed in sing-box 1.13).

## Usage

Bot: `/singbox <version> <URI>`, e.g. `/singbox 1.14.4 vless://...`

CLI (local testing):

```sh
cargo run -p singbox -- 1.14.4 'vless://uuid@host:443?security=tls&type=ws' config.json
```

## Running the bot

Copy `.env.template` to `.env`, set `TELOXIDE_TOKEN`, then `cargo run -p bot`.
