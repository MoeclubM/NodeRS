# NodeRS

NodeRS is a pure Rust Xboard machine-node runtime. This repository currently ships the AnyTLS implementation, so the installed binary, service, and state names remain `noders-anytls`.

## Overview

- Linux only
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
- Supported `cert_config.cert_mode` values are `file`, `path`, `inline`, `pem`, `content`, `acme`, and `letsencrypt`
- File or path mode requires `cert_path` and `key_path`
- Inline or PEM mode requires certificate PEM content and private key PEM content
- ACME mode requires `cert_path` and `key_path`, and uses `cert_config.domain` or the panel `server_name` as the certificate domain
- Optional ACME fields are `email`, `directory_url` or `directory`, `challenge_listen` or `http01_listen`, `renew_before_days`, and `account_key_path`
- Any other `cert_mode` fails explicitly during config sync

## Support Matrix

- Supported panel fields: `listen_ip`, `server_port`, `server_name`, `padding_scheme`, `routes`, and `cert_config`
- Supported certificate modes: `cert_config.cert_mode = file`, `path`, `inline`, `pem`, `content`, `acme`, or `letsencrypt`
- Supported `custom_outbounds` types: `direct`, `dns`, and `block`
- Supported `custom_routes` actions: `outbound`, `reject`, and `block`
- Supported `custom_routes` match fields: `network`, `protocol`, `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `ip_cidr`, `ip_is_private`, `port`, and `port_range`
- Supported ECH delivery: Xboard `tls_settings.ech.key` or `key_path`, with optional `config` or `config_path`
- Unsupported `custom_outbounds` types, unsupported `custom_routes` fields or actions, and malformed ECH settings fail explicitly during config sync; they are not ignored silently

## Migrate Legacy Config

The installer and release bundle no longer migrate legacy `UniProxy` or node-based configs automatically.

Use `scripts/migrate_config.py` before switching an old deployment to the machine-based version:

```bash
python3 scripts/migrate_config.py /etc/noders/anytls/nodes/1.toml
```

The script prompts for the new `machine_id`, writes a backup next to the source file, and by default writes the migrated config to `/etc/noders/anytls/machines/<machine_id>.toml`.

You can also run it non-interactively:

```bash
python3 scripts/migrate_config.py /etc/noders/anytls/nodes/1.toml --machine-id 9
```

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
  --machine https://api.example.com machine_key_a 1 \
  --machine https://api.example.com machine_key_b 2
```

## Runtime Paths

- Project name in documentation: `NodeRS`
- Binary: `/usr/local/bin/noders-anytls`
- Config root: `/etc/noders/anytls`
- Machine config: `/etc/noders/anytls/machines/<machine_id>.toml`
- State: `/var/lib/noders/anytls`
- systemd service: `noders-anytls-<machine_id>`
- OpenRC service: `noders-anytls-<machine_id>`

## Common Operations

### systemd

```bash
systemctl status noders-anytls-1 --no-pager -l
journalctl -u noders-anytls-1 -n 100 --no-pager
journalctl -u noders-anytls-1 -f
systemctl restart noders-anytls-1
systemctl stop noders-anytls-1
systemctl enable noders-anytls-1
```

### OpenRC

```bash
rc-service noders-anytls-1 status
rc-service noders-anytls-1 restart
tail -n 100 /var/log/noders-anytls/noders-anytls-1.log
tail -f /var/log/noders-anytls/noders-anytls-1.log
```

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/upgrade.sh | bash -s --
```

If you are upgrading from a legacy node-based deployment, migrate the config first with `scripts/migrate_config.py`, then reinstall with the new machine-based installer.

Example migration path:

```bash
python3 scripts/migrate_config.py /etc/noders/anytls/nodes/1.toml --machine-id 9
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key machine_key \
  --machine-id 9
```

## Uninstall

### Remove one machine instance

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --machine-id 1
```

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
