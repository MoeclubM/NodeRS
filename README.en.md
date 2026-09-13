# NodeRS

English | [简体中文](README.md)

NodeRS is a Linux node agent for [Xboard](https://github.com/cedar2025/Xboard). One command on your server hooks it up to the panel; nodes, users, listen ports, and certificates are then provisioned from the panel, and the machine itself only keeps an API address, a machine key, and a `machine_id`. Protocols are served by [Aerion](https://github.com/MoeclubM/Aerion), the same implementation behind [XBClient](https://github.com/MoeclubM/XBClient).

[![Release](https://img.shields.io/github/v/release/MoeclubM/NodeRS?style=flat-square)](https://github.com/MoeclubM/NodeRS/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/MoeclubM/NodeRS/ci.yml?style=flat-square&label=CI)](https://github.com/MoeclubM/NodeRS/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/MoeclubM/NodeRS?style=flat-square)](LICENSE)

## Features

- Works with Xboard machine mode (`/api/v2/server/*`, `/api/v2/server/machine/*`); node membership, user sync, traffic, and online status are reported automatically
- One process runs every node attached to the same machine — install once and you're done
- Three lines of local config; the panel decides how nodes run and how certificates are issued
- Certificates come from the panel's `cert_config`: file paths, inline PEM, Let's Encrypt HTTP-01 / DNS-01 (Cloudflare, AliDNS), or local self-signed
- Multi-user, device limits, and `speed_limit` are enforced at protocol runtime
- Prebuilt packages for amd64 / arm64, GNU (glibc 2.36+) and musl, with architecture and libc detected by the installer
- Panel fields a protocol doesn't use are logged and skipped; only real problems (a missing password, a bad cipher) block startup

## Protocols

| Protocol | TCP | UDP | Notes |
| --- | :---: | :---: | --- |
| AnyTLS | ✓ | UoT | Multiplexing, padding |
| Hysteria2 | ✓ | Native | Salamander, BBR |
| Mieru | ✓ | Native / in-stream | TCP and UDP underlay |
| Naive | ✓ | UoT | HTTP/1.1, H2, H3 |
| Shadowsocks | ✓ | ✓ | AEAD / 2022 |
| Trojan | ✓ | In-stream | WS / H2 / gRPC / XHTTP |
| TUIC v5 | ✓ | Native / stream | QUIC |
| VLESS | ✓ | ✓ | TLS, REALITY, Vision |
| VMess | ✓ | ✓ | AEAD |

Wire-level limits are documented in the [Aerion docs](https://github.com/MoeclubM/Aerion).

## Quick Start

Create a machine in Xboard and note the machine ID and machine key. Attach your nodes to it and configure ports, protocols, and certificates, then run this on the server:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key MACHINE_KEY \
  --machine-id 1
```

On Alpine or other non-systemd distros, use [install-openrc.sh](scripts/install-openrc.sh) instead. For multiple panels on one server, pinning a version, and custom paths, see the [install docs](docs/en/install.md).

After the install, watch the logs — once your nodes are listening, you're done:

```bash
noders log -f
```

Running `noders` with no arguments opens an interactive menu. From here on, nodes, ports, and certificates are managed in the panel; NodeRS picks up the changes on its own.

## Handy Commands

```bash
noders restart 1            # restart only machine_id = 1; no argument means every instance
noders update               # upgrade to the latest release
noders uninstall --all      # uninstall
```

The full command list and selector syntax live in the [management CLI docs](docs/en/management.md).

## Documentation

| Document | Description |
| --- | --- |
| [Getting-started tutorial](docs/en/tutorial.md) | The full path from panel to a working node |
| [Install & upgrade](docs/en/install.md) | Installer options, building from source |
| [Management CLI](docs/en/management.md) | `noders` subcommands and selectors |
| [Certificates](docs/en/certificates.md) | `cert_config` modes and DNS-01 |
| [FAQ](docs/en/faq.md) | Nodes offline, startup failures, and other troubleshooting |

## Related Projects

- [Aerion](https://github.com/MoeclubM/Aerion) — protocol and TUN core
- [XBClient](https://github.com/MoeclubM/XBClient) — Xboard client (Android / Windows / Linux)
- [Xboard](https://github.com/cedar2025/Xboard) — the panel

## License

MIT. See [LICENSE](LICENSE).
