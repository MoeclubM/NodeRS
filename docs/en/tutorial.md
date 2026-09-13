# Getting-started Tutorial

[简体中文](../zh/tutorial.md) | [English](../en/tutorial.md)

This tutorial walks the full path from zero: Xboard panel → NodeRS node → client connectivity. If you are already installed and only need commands or options, jump straight to [Install & upgrade](install.md) or [Management CLI](management.md).

## 0. Prerequisites

- An [Xboard](https://github.com/cedar2025/Xboard) panel that supports machine mode (the `/api/v2/server/machine/*` endpoints).
- A Linux server for the node: `x86_64` or `aarch64`, glibc 2.36+ or musl (Alpine works too). NodeRS is Linux-only.
- The node machine must reach the panel API, and the panel must be able to reach the node's configured listen ports.
- For Let's Encrypt certificates: HTTP-01 requires port 80 on the node to be reachable from the internet; DNS-01 requires Cloudflare or AliDNS API credentials.

## 1. Panel side: create a machine and attach nodes

1. Log in to the Xboard admin area, open the **machine (node server)** management page, and create a new machine.
2. Note two values after creation:
   - The **machine ID** (`machine_id`, an integer)
   - The **machine key** (needed during installation)
3. Create or edit a node in the node management page and **attach it to this machine**, then configure:
   - The listen port
   - The protocol (AnyTLS / Hysteria2 / Mieru / Naive / Shadowsocks / Trojan / TUIC / VLESS / VMess) and its parameters
   - The certificate (`cert_config`) — see [Certificates](certificates.md) for the available modes
4. Repeat step 3 for more nodes — they are all managed by the single NodeRS process on the node machine; there is no per-node install.

## 2. Server side: one-command install

Run this on the node machine (replace `https://api.example.com` with your panel API address and `MACHINE_KEY` with the key from step 1):

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key MACHINE_KEY \
  --machine-id 1
```

On OpenRC distributions (Alpine etc.) use:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install-openrc.sh | bash -s -- \
  --api https://api.example.com \
  --key MACHINE_KEY \
  --machine-id 1
```

The script detects architecture and libc, downloads the matching release bundle, writes the machine config, registers a systemd / OpenRC service, and starts it.

All installer options (pinning a version, custom paths, skipping the service, …) are listed in [Install & upgrade](install.md).

### Connecting one server to multiple panels

Repeat `--machine <url> <key> <id>`; each pair becomes an independent instance:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --machine https://secapi.example.com KEY_A 10 \
  --machine https://api.example.com KEY_B 10
```

Different APIs may share the same `machine_id`; local instance names are distinguished by an `api + machine_id` hash, so they never collide.

## 3. Verify

```bash
noders log -f
```

You should see the node config being fetched and each protocol starting to listen on its port. Back in the panel's node list, the nodes should show as online.

Then test with a real client: [XBClient](https://github.com/MoeclubM/XBClient) (Android / Windows / Linux) or any client supporting the protocols above — import your subscription and connect.

Not listening, or the panel still shows offline? Head to the [FAQ](faq.md).

## 4. Day-to-day maintenance

- **Upgrade**: `noders update`, or re-run `upgrade.sh`; machine configs, certificates, and ACME accounts are preserved.
- **Change settings**: nodes, ports, and certificates are all edited in the panel; NodeRS picks up changes automatically — usually no need to log into the server.
- **Restart / logs / uninstall**: see [Management CLI](management.md).

## 5. Uninstall

```bash
# Remove every instance of one machine by machine_id
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall --machine-id 1

# Wipe NodeRS from this host
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall --all
```
