# FAQ

[简体中文](../zh/faq.md) | [English](../en/faq.md)

## Node always shows offline in the panel

Check in this order:

1. **Is the service running?** `noders log -f` or `systemctl status noders-1-123456789`. If it is not running, see "Service fails to start" below.
2. **Is the API address right?** `panel.api` in the local config must be the panel API address (usually the panel site's own domain), not a frontend-only address or a database host.
3. **Is the machine key right?** `/api/v2/server/*` authenticates with the machine key, not a user token. A wrong key shows 401/403-style errors in the logs.
4. **Is the network reachable?** On the node machine try `curl -v https://api.example.com/api/v2/server/config`; allow outbound access in firewalls or security groups.
5. **Is the node attached to the machine?** Only nodes attached to the machine matching your `machine_id` are delivered.

## Service fails to start

```bash
noders log -n 200        # or: journalctl -u noders-1-123456789 -n 200
```

Common causes:

- **Missing or invalid config**: the config at `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml` fails when `api`, `key`, or `machine_id` is missing. After editing by hand, restart with `noders restart`.
- **Port already in use**: another process (including a stale NodeRS instance) holds the listen port. Check with `ss -tlnp | grep <port>`, stop the conflicting process, and restart.
- **Missing protocol fields**: unknown panel fields are ignored, but fields the protocol actually needs (a missing password, a wrong cipher) fail loudly. Complete the node config in the panel.
- **Permissions**: services run as the `noders` user with only `CAP_NET_BIND_SERVICE`. For custom deployment paths, make sure the `noders` user can read and write the config and working directories.

## Certificate issuance fails

- **HTTP-01**: confirm the domain resolves to the node machine and port 80 is open to the internet (`curl -I http://your.domain/` should answer). Domains proxied through a CDN must forward to the node machine, or switch to DNS-01.
- **DNS-01**: verify the credentials are valid and allowed to edit DNS for the zone; for Cloudflare use an API Token (not the Global Key). Increase `propagation_timeout` / `propagation_interval` in the panel if DNS propagation is slow.
- **Certificate not refreshed**: restarting the instance re-runs issuance: `noders restart <selector>`.
- **ACME account issues**: the account key lives under `/var/lib/noders/anytls/acme/`; make sure the disk is not full and the directory is writable. Deleting the domain's directory and restarting re-registers the account.

## Where are the logs?

```bash
noders log -f                 # all instances, follow mode
noders log -n 200 1           # machine_id = 1, last 200 lines
journalctl -u noders-1-123456789 -f          # systemd
tail -f /var/log/noders/noders-1-123456789.log   # OpenRC
```

## How do I change node settings?

Nodes, ports, protocols, and certificates are edited in the **panel**; NodeRS fetches changes automatically, so you usually never log into the server. Only the local panel connection info (`panel.api` / `panel.key` / `panel.machine_id`) lives in the TOML files under `/etc/noders/anytls/machines/`; restart with `noders restart` after editing.

## An old service name is still around

Legacy service names `noders-anytls` and `noders-<machine_id>` are migrated to `noders-<machine_id>-<api_hash>` during upgrade. If anything remains, run `noders uninstall --all` and reinstall.

## Which systems are supported?

Linux only: `x86_64` / `aarch64` with glibc 2.36+ or musl. Both systemd and OpenRC have install scripts. Windows and macOS are not supported.

Still stuck? Check the [Aerion docs](https://github.com/MoeclubM/Aerion) for protocol-level limits, or ask in the [GitHub Issues](https://github.com/MoeclubM/NodeRS/issues).
