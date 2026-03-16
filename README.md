# NodeRS-AnyTLS

Pure Rust AnyTLS node for Xboard `UniProxy`.

- Linux only
- Native Rust AnyTLS + UOT implementation
- Xboard `config / user / push / alive / alivelist / status` compatible
- Built-in ACME HTTP-01, TLS hot reload, dual-stack listen
- Multi-user hot reload and device-limit control

## Quick Start

### Before you install

- `--panel-token` must be the Xboard global `server_token` used by `/api/v1/server/UniProxy/*`
- `install.sh` is the default entry point on Linux
- If the host does not provide `systemd` but does provide `OpenRC`, `install.sh` automatically switches to the OpenRC installer
- `install-openrc.sh` is still available if you want to call the OpenRC installer directly
- On `glibc` hosts the installer prefers the GNU build; on Alpine, other `musl` hosts, or `glibc < 2.17`, it falls back to the `musl` bundle automatically

### Install one node

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1
```

What this does:

- downloads the matching release package
- writes config under `/etc/noders/anytls`
- installs `/usr/local/bin/noders-anytls`
- creates and starts `noders-anytls-<node_id>`

### Install multiple nodes

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --xboard https://api.example.com server_token 1 \
  --xboard https://api.example.com server_token 2
```

### Install on Alpine / OpenRC / non-systemd hosts

`install.sh` now auto-detects `OpenRC`, so this direct installer is optional.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install-openrc.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1
```

## TLS Options

### Default: automatic ACME

By default the installer fetches the node `server_name` from Xboard and uses it as the ACME domain.

### Override the certificate domain

If you want to force the certificate domain instead of using the one from Xboard, pass `--server-name`.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --server-name node.example.com
```

### Generate a self-signed certificate

If you do not want ACME, pass `--self-signed`. This mode requires `openssl` on the target Linux host.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --server-name node.example.com \
  --self-signed
```

### Use existing certificate files

If you already have a certificate and key, pass both paths. In this mode ACME is disabled.

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --cert-file /etc/ssl/private/fullchain.pem \
  --key-file /etc/ssl/private/privkey.pem
```

### Set outbound DNS and IP preference

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- \
  --panel-url https://api.example.com \
  --panel-token server_token \
  --node-id 1 \
  --dns-resolver 1.1.1.1 \
  --ip-strategy prefer_ipv6
```

## Paths

- Binary: `/usr/local/bin/noders-anytls`
- Config root: `/etc/noders/anytls`
- Node config: `/etc/noders/anytls/nodes/<node_id>.toml`
- State: `/var/lib/noders/anytls`
- Service: `noders-anytls-<node_id>`

## Common Operations

### Check systemd service status

```bash
systemctl status noders-anytls-1 --no-pager -l
```

### View systemd logs

```bash
journalctl -u noders-anytls-1 -n 100 --no-pager
journalctl -u noders-anytls-1 -f
```

### Restart or stop a systemd service

```bash
systemctl restart noders-anytls-1
systemctl start noders-anytls-1
systemctl stop noders-anytls-1
```

### Enable or disable systemd auto start

```bash
systemctl enable noders-anytls-1
systemctl disable noders-anytls-1
```

### Check generated config

```bash
cat /etc/noders/anytls/nodes/1.toml
```

### Check OpenRC status and logs

```bash
rc-service noders-anytls-1 status
tail -n 100 /var/log/noders-anytls/noders-anytls-1.log
tail -f /var/log/noders-anytls/noders-anytls-1.log
```

## Upgrade

### Upgrade to latest release

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s --
```

### Upgrade to a specific release

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s -- --version v0.0.27
```

### Upgrade without restart

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/upgrade.sh | bash -s -- --version v0.0.27 --no-restart
```

## Uninstall

### Remove one node

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --uninstall --node-id 1
```

### Remove everything

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS-AnyTLS/main/scripts/install.sh | bash -s -- --uninstall --all
```

## Local Run

```bash
cp config.example.toml config.toml
cargo run --offline -- config.toml
```

Minimum required fields:

- `panel.url`
- `panel.token`
- `panel.node_id`
- `tls.cert_path`
- `tls.key_path`

Common optional fields:

- `[outbound].dns_resolver`
- `[outbound].ip_strategy`
- `[tls.acme]`
