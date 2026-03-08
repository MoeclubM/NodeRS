# NodeRS-AnyTLS

Rust implementation of an Xboard `UniProxy` AnyTLS node.

## Features

- Native Rust AnyTLS inbound with TLS handshake and stream multiplexing
- Xboard `UniProxy` compatibility for `config`, `user`, `push`, `alive`, `alivelist`, `status`
- Multi-user hot reload, kicked sessions on removal, and shared per-user speed limiting
- Device limit enforcement with local + panel alive-state accounting
- Xboard `routes` support for `block` and `dns` actions
- TLS file hot reload for external certificate renewal workflows
- Embedded ACME HTTP-01 issuance and renewal for native TLS certificate management
- GitHub Actions release packaging for Linux, Windows, and macOS archives

## Implementation

- The AnyTLS protocol stack is implemented directly in this repository under `src/server/`
- No `sing-box_mod`, `sing-box`, subprocess core, FFI bridge, or external protocol engine is used at runtime
- CI enforces this constraint with `scripts/verify-pure-rust.sh` and `scripts/verify-pure-rust.ps1`

## TLS Notes

- `uTLS` is an outbound TLS fingerprinting feature in `sing-box_mod`; it does not apply to this inbound node process
- Server-side AnyTLS padding negotiation is implemented by accepting client preface padding and sending `UPDATE_PADDING_SCHEME` when `padding-md5` mismatches
- Active record padding generation is a client-side behavior in the upstream AnyTLS reference implementation, so it is intentionally not emitted by this server
- Certificate files are hot-reloaded from disk according to `tls.reload_interval_seconds`
- Embedded ACME HTTP-01 is implemented in pure Rust under `src/acme.rs`; issued certificates are renewed before expiry and reloaded automatically
- ACME renewal timing is computed from the current certificate `notAfter` field rather than a fixed timer guess
- ACME `http-01` requires `tls.acme.challenge_listen` to be reachable by the CA, typically `0.0.0.0:80`
- Install scripts can bootstrap self-signed certificates with `--self-signed-domain` or `-SelfSignedDomain`
- External ACME tools such as `acme.sh` or `certbot` can renew `cert.pem` / `key.pem`, and the node will reload them automatically
- Embedded ACME `dns-01` provider integration is not implemented yet

## Route Support

Current `routes` handling:

- `action=block`
  - `protocol:tcp`
  - `regexp:...`
  - raw regex matches against `host`, `host:port`, `ip`, `ip:port`
- `action=dns`
  - `main` sets the default upstream DNS server for domain resolution
  - `full:example.com` exact match
  - `domain:example.com` / `suffix:example.com` suffix match
  - `keyword:internal` substring match
  - `regexp:...` regex match

DNS routes are applied only to domain targets. IP targets bypass DNS rules.

## Local Run

1. Copy `config.example.toml` to `config.toml`
2. Fill `panel.url`, `panel.token`, `panel.node_id`, `tls.cert_path`, `tls.key_path`
3. Optional: enable `[tls.acme]` for built-in HTTP-01 certificate issuance
4. Run `cargo run --offline -- config.toml`

## Release Packaging

A release workflow is provided at `.github/workflows/release.yml`.

- Trigger: GitHub Release `published`
- Outputs:
  - `noders-anytls-<tag>-linux-amd64.tar.gz`
  - `noders-anytls-<tag>-windows-amd64.zip`
  - `noders-anytls-<tag>-macos-amd64.tar.gz`
  - `noders-anytls-<tag>-macos-arm64.tar.gz`
  - matching `.sha256` checksum files

Each archive contains:

- `noders-anytls` or `noders-anytls.exe`
- `config.example.toml`
- `install.sh`
- `install.ps1`
- `packaging/systemd/noders-anytls.service`
- `README.md`
- `LICENSE`

## Install Scripts

### Linux / macOS

Use `scripts/install.sh` or the packaged `install.sh`:

```bash
./install.sh
./install.sh --archive ./noders-anytls-v1.0.0-linux-amd64.tar.gz
./install.sh --repo yourname/NodeRS-AnyTLS --version v1.0.0
./install.sh --panel-url https://api.example.com --panel-token token --node-id 1
./install.sh --xboard https://api.example.com tokenA 1 --xboard https://api.example.com tokenB 2
./install.sh --self-signed-domain node.example.com
./install.sh --acme-domain node.example.com --acme-email admin@example.com
```

Default install paths:

- Binary: `/usr/local/bin/noders-anytls`
- Config: `/etc/noders-anytls/config.toml`
- State: `/var/lib/noders-anytls`
- Cert: `/etc/noders-anytls/cert.pem`
- Key: `/etc/noders-anytls/key.pem`

When `--xboard` is repeated, the installer creates one config per node under `/etc/noders-anytls/nodes/<node_id>.toml` and one service per node named `noders-anytls-<node_id>`.

When running as root on a systemd host, the script also installs and starts the corresponding `systemd` service or services.

If `--acme-domain` is used, the installer enables `[tls.acme]` in `config.toml` and skips self-signed generation.
If neither `--self-signed-domain` nor `--acme-domain` is passed, the installer tries to fetch `server_name` from Xboard and auto-generates a per-node self-signed certificate when no certificate already exists.

### Windows

Use `scripts/install.ps1` or the packaged `install.ps1`:

```powershell
.\install.ps1
.\install.ps1 -ArchivePath .\noders-anytls-v1.0.0-windows-amd64.zip
.\install.ps1 -Repository yourname/NodeRS-AnyTLS -Version v1.0.0
.\install.ps1 -SelfSignedDomain node.example.com
.\install.ps1 -AcmeDomain node.example.com -AcmeEmail admin@example.com
```

Default install paths:

- Binary: `%ProgramFiles%\NodeRS-AnyTLS\noders-anytls.exe`
- Config: `%ProgramData%\NodeRS-AnyTLS\config.toml`
- State: `%ProgramData%\NodeRS-AnyTLS\data`
- Cert: `%ProgramData%\NodeRS-AnyTLS\cert.pem`
- Key: `%ProgramData%\NodeRS-AnyTLS\key.pem`

When running as Administrator, the script also creates or updates a Windows service named `NodeRS-AnyTLS`.

If `-AcmeDomain` is used, the installer enables `[tls.acme]` in `config.toml` and skips self-signed generation.
