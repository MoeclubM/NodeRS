# NodeRS

NodeRS is a pure Rust Xboard machine-node runtime. The repository currently includes AnyTLS, VLESS, Trojan, VMess, and Shadowsocks protocol handlers.

## Overview

- Linux only
- Prebuilt release bundles are published for `linux-amd64`, `linux-amd64-musl`, `linux-arm64`, and `linux-arm64-musl`; install and upgrade scripts auto-detect `x86_64`/`aarch64` plus `glibc`/`musl`
- Compatible with Xboard `/api/v2/server/*` and `/api/v2/server/machine/*`
- One local process manages every AnyTLS node assigned to the same Xboard machine
- Node membership, users, routes, listen address, port, and TLS are supplied by the panel
- Device-limit control is supported
- `speed_limit` is intentionally not implemented

## Runtime Model

NodeRS currently runs in Xboard machine mode only.

- Local config contains only `panel.api`, `panel.key`, and `panel.machine_id`
- `panel.key` must be the machine key for the target Xboard machine
- Node membership comes from `/api/v2/server/machine/nodes`
- Per-node config and users come from `/api/v2/server/config` and `/api/v2/server/user`
- Traffic, alive state, and node status are reported through `/api/v2/server/report`
- Host status is reported through `/api/v2/server/machine/status`
- WebSocket sync uses the machine connection returned by `/api/v2/server/handshake`

## TLS Delivery

TLS is no longer read from the local config file.

- AnyTLS, VLESS, Trojan, and VMess nodes receive TLS from Xboard `cert_config`
- `listen_ip`, `server_port`, `server_name`, `tls_settings`, and `routes` are taken from the panel response; `padding_scheme` is currently AnyTLS-specific
- Supported `cert_config.cert_mode` values are `file`, `path`, `inline`, `pem`, `content`, `acme`, `letsencrypt`, `http`, and `dns`
- File or path mode requires `cert_path` and `key_path`
- Inline or PEM mode requires certificate PEM content and private key PEM content; the pushed certificate may be CA-issued or self-signed because NodeRS only validates that the PEM/key pair is usable
- Xboard passes `cert_config` through as a JSON object; NodeRS accepts both `mode` and `cert_mode`, along with common aliases for certificate paths, inline PEM content, domains, and provider credentials
- ACME mode supports multiple domains and uses `cert_config.domain`, `cert_config.domains`, or the panel `server_name` / `tls_settings.server_name`
- `cert_mode = http` uses ACME HTTP-01; `cert_mode = dns` uses ACME DNS-01; `cert_mode = acme` / `letsencrypt` defaults to HTTP-01 unless a DNS challenge or DNS provider is supplied
- DNS-01 currently supports Cloudflare and AliDNS provider APIs
- If ACME mode does not deliver `cert_path` or `key_path`, NodeRS stores them under `acme/<domain>/fullchain.pem` and `acme/<domain>/privkey.pem` relative to the working directory; in the installed service this resolves under `/var/lib/noders/anytls`
- Optional ACME fields are `email`, `directory_url` or `directory`, `challenge_listen` or `http01_listen`, `renew_before_days`, `account_key_path`, DNS propagation settings, and provider-specific credentials such as Cloudflare API tokens or AliDNS access keys
- `cert_mode = none`, `self_signed`, or `self-signed` generates a local self-signed certificate automatically when the panel does not push a PEM or ACME configuration
- Any other `cert_mode` fails explicitly during config sync

## Support Matrix

- Supported panel fields: `listen_ip`, `server_port`, `server_name`, `padding_scheme`, `routes`, and `cert_config`
- Supported certificate modes: `cert_config.cert_mode = file`, `path`, `inline`, `pem`, `content`, `acme`, `letsencrypt`, `http`, or `dns`
- Supported `custom_outbounds` types: `direct`, `dns`, and `block`
- Supported `custom_routes` actions: `outbound`, `reject`, and `block`
- Supported `custom_routes` match fields: `network`, `protocol`, `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `ip_cidr`, `ip_is_private`, `port`, and `port_range`
- Supported ECH delivery: Xboard `tls_settings.ech.key` or `key_path`, with optional `config` or `config_path`, for AnyTLS/VLESS/Trojan/VMess TLS listeners
- `padding_scheme` is consumed by AnyTLS only; VLESS and Trojan ignore it because their wire formats do not use AnyTLS padding frames
- Unsupported `custom_outbounds` types, unsupported `custom_routes` fields or actions, and malformed ECH settings fail explicitly during config sync; they are not ignored silently

## Install

### systemd

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key machine_key \
  --machine-id 1
```

### OpenRC

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install-openrc.sh | bash -s -- \
  --api https://api.example.com \
  --key machine_key \
  --machine-id 1
```

### Multiple machine configs on one host

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --machine https://secapi.example.com machine_key_a 10 \
  --machine https://api.example.com machine_key_b 10
```

Multiple APIs may reuse the same `machine_id` on one host. NodeRS derives a stable local instance suffix from `api + machine_id`, so config files and service names do not conflict.

## Runtime Paths

- Project name in documentation: `NodeRS`
- Binary: `/usr/local/lib/noders/noders`
- Manager command: `/usr/local/bin/noders`
- Config root: `/etc/noders/anytls`
- Machine config: `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml`
- State: `/var/lib/noders/anytls`
- systemd service: `noders-<machine_id>-<api_hash>`
- OpenRC service: `noders-<machine_id>-<api_hash>`

## Manager Script

After installation, the `noders` command provides a small management entrypoint similar to V2bX-style helper scripts.

- `noders` without arguments opens an interactive menu
- `noders update` upgrades the installed binary
- `noders uninstall --all` removes the whole installation
- `noders start`, `noders stop`, and `noders restart` operate on all discovered NodeRS services by default
- `noders log` shows logs for all discovered services by default
- When multiple instances exist, you may pass a full service name, a `machine_id`, or an instance suffix to target one or more services

Examples:

```bash
noders
noders update
noders restart
noders restart 1
noders log -f
noders uninstall --machine-id 1
noders uninstall --all
```

## Common Operations

### systemd

```bash
systemctl status noders-1-123456789 --no-pager -l
journalctl -u noders-1-123456789 -n 100 --no-pager
journalctl -u noders-1-123456789 -f
systemctl restart noders-1-123456789
systemctl stop noders-1-123456789
systemctl enable noders-1-123456789
```

### OpenRC

```bash
rc-service noders-1-123456789 status
rc-service noders-1-123456789 restart
tail -n 100 /var/log/noders/noders-1-123456789.log
tail -f /var/log/noders/noders-1-123456789.log
```

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/upgrade.sh | bash -s --
```

`upgrade.sh` only supports hosts that already run the current `noders` runtime layout.

### Migrate Legacy `noders-anytls` Installs

If the host still uses the old `noders-anytls` binary or service layout, run the dedicated migration helper instead of `upgrade.sh`:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/migrate-legacy-install.sh | bash -s --
```

The migration helper reads the existing machine configs under `/etc/noders/anytls/machines`, reinstalls the current `noders` runtime, and cleans up legacy artifacts such as:

- `/usr/local/bin/noders-anytls`
- `noders-anytls-<...>` service names
- plain `noders-<machine_id>` units left from pre-hash installs
- OpenRC `noders-anytls` user/group and `/run/noders-anytls` / `/var/log/noders-anytls` paths

It also creates a backup under `/etc/noders/anytls/migration-backups/` before removing legacy config or service files.

If an existing host already uses `noders` but still has old plain `noders-<machine_id>` units, reinstall or migrate once so the host switches to the hashed `noders-<machine_id>-<api_hash>` instance names.

## Uninstall

### Remove one machine instance

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --machine-id 1
```

This removes every local instance whose `machine_id` is `1`. To remove one exact instance when multiple APIs share the same `machine_id`, pass the original `--machine <url> <key> <id>` triplet together with `--uninstall`.

### Remove everything

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --all
```

## Local Run

```bash
cp config.example.toml config.toml
cargo run --offline -- config.toml
```

Required fields:

- `panel.api`
- `panel.key`
- `panel.machine_id`
