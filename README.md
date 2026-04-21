# NodeRS

NodeRS is a pure Rust Xboard machine-node runtime. This repository currently ships the AnyTLS implementation, and the installed binary remains `noders-anytls`.

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

- AnyTLS nodes must receive `cert_config` from Xboard
- `listen_ip`, `server_port`, `server_name`, `tls_settings`, `padding_scheme`, and `routes` are all taken from the panel response
- Supported `cert_config.cert_mode` values are `file`, `path`, `inline`, `pem`, `content`, `acme`, `letsencrypt`, and `http`
- File or path mode requires `cert_path` and `key_path`
- Inline or PEM mode requires certificate PEM content and private key PEM content
- ACME mode uses `cert_config.domain` or the panel `server_name` as the certificate domain
- If ACME mode does not deliver `cert_path` or `key_path`, NodeRS stores them under `acme/<domain>/fullchain.pem` and `acme/<domain>/privkey.pem` relative to the working directory; in the installed service this resolves under `/var/lib/noders/anytls`
- Optional ACME fields are `email`, `directory_url` or `directory`, `challenge_listen` or `http01_listen`, `renew_before_days`, and `account_key_path`
- Any other `cert_mode` fails explicitly during config sync

## Support Matrix

- Supported panel fields: `listen_ip`, `server_port`, `server_name`, `padding_scheme`, `routes`, and `cert_config`
- Supported certificate modes: `cert_config.cert_mode = file`, `path`, `inline`, `pem`, `content`, `acme`, `letsencrypt`, or `http`
- Supported `custom_outbounds` types: `direct`, `dns`, and `block`
- Supported `custom_routes` actions: `outbound`, `reject`, and `block`
- Supported `custom_routes` match fields: `network`, `protocol`, `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `ip_cidr`, `ip_is_private`, `port`, and `port_range`
- Supported ECH delivery: Xboard `tls_settings.ech.key` or `key_path`, with optional `config` or `config_path`
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
- Binary: `/usr/local/bin/noders-anytls`
- Config root: `/etc/noders/anytls`
- Machine config: `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml`
- State: `/var/lib/noders/anytls`
- systemd service: `noders-<machine_id>-<api_hash>`
- OpenRC service: `noders-<machine_id>-<api_hash>`

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
tail -n 100 /var/log/noders-anytls/noders-1-123456789.log
tail -f /var/log/noders-anytls/noders-1-123456789.log
```

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/upgrade.sh | bash -s --
```

If an existing host still uses old `noders-anytls-<machine_id>` or `noders-<machine_id>` units, uninstall and reinstall to switch to the new `noders-<machine_id>-<api_hash>` instance names.

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
