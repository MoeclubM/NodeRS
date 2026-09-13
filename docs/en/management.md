# Management CLI

[简体中文](../zh/management.md) | [English](../en/management.md)

The installer places a management command at `/usr/local/bin/noders` for administering every NodeRS instance on the host. Running it with no arguments opens an interactive menu.

```bash
noders
```

## Subcommands

```
Usage: noders <command> [options] [selector...]
```

| Command | Description |
| --- | --- |
| `noders update [--version <tag>] [--no-restart]` | Upgrade the installed binary |
| `noders start [all\|selector...]` | Start services |
| `noders stop [all\|selector...]` | Stop services |
| `noders restart [all\|selector...]` | Restart services |
| `noders log [-f\|--follow] [-n\|--lines <count>] [all\|selector...]` | Show logs |
| `noders uninstall [--all \| --machine-id <id> \| --machine <url> <key> <id>]` | Remove one instance or the whole installation |
| `noders help` | Show help |

Without a selector, commands apply to **every** instance discovered on the host.

## Selectors

Selectors narrow an operation to a subset of instances. Four forms are supported:

| Form | Example |
| --- | --- |
| Full service name | `noders-1-123456789` |
| machine ID | `1` |
| Instance suffix | `1-123456789` |
| `all` | Every instance |

```bash
noders restart 1              # restart only instances with machine_id = 1
noders log -f 1-123456789     # follow one instance's logs
noders stop all               # stop everything
```

## Interactive Menu

Running `noders` in a terminal opens an interactive menu with: update, uninstall, start, stop, restart, and view logs. Uninstalling everything requires typing `YES` to confirm.

## Paths

| Item | Path |
| --- | --- |
| Binary | `/usr/local/lib/noders/noders` |
| Management command | `/usr/local/bin/noders` |
| Machine configs | `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml` |
| Runtime data | `/var/lib/noders/anytls` |
| ACME certificates | `/var/lib/noders/anytls/acme/<domain>/` |
| Service name | `noders-<machine_id>-<api_hash>` |

Services run as a dedicated `noders` user and keep only `CAP_NET_BIND_SERVICE` (so low ports can be bound).

## systemd / OpenRC

You can also bypass `noders` and drive the system service manager directly (replace `noders-1-123456789` with your actual service name):

systemd:

```bash
systemctl status noders-1-123456789 --no-pager -l
journalctl -u noders-1-123456789 -f
systemctl restart noders-1-123456789
```

OpenRC:

```bash
rc-service noders-1-123456789 status
rc-service noders-1-123456789 restart
tail -f /var/log/noders/noders-1-123456789.log
```
