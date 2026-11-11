# PxBoard Integration

[简体中文](../zh/pxboard.md) | [English](../en/pxboard.md)

NodeRS connects to PxBoard through its nodes plugin. The local `type` setting selects the panel API and authentication method.

Starting with `v0.1.50`, NodeRS connects to PxBoard over the unified `/rpc/v1` contract shared with Web and native clients. Official packages support both Xboard and PxBoard, with Xboard as the default panel type.

## Panel Setup

Use the current `0.0.1` PxBoard core and matching access-account and node-management plugins. Plugin manifests define the required version epoch. Client configuration export also requires the subscriptions plugin.

Create a machine in the administration panel and obtain its machine number and key. Create nodes with the `NodeRS` engine, assign the machine, and configure their protocol, address, ports, and certificates. Users need active access accounts, available quota, and permission to use the node's groups.

One machine can host multiple nodes. Machine and node numbers are separate identifiers. Set `--api` to the panel root, such as `https://panel.example.com`, without an `/api/v1` suffix.

## Installation

Both the executable and installer must support PxBoard. From an extracted release bundle:

```bash
bash install.sh --version v0.1.50 --panel-type pxboard \
  --api https://panel.example.com \
  --key MACHINE_KEY \
  --machine-id 1
```

Use `install-openrc.sh` on OpenRC systems. From a source checkout, run `bash scripts/install.sh`; it downloads a release bundle. If that bundle lacks PxBoard support, installation stops before replacing the installed executable. Use a release containing this feature or a local PxBoard-capable build.

To download the installer and pin the release:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --version v0.1.50 --panel-type pxboard \
  --api https://panel.example.com --key MACHINE_KEY --machine-id 1
```

The default release repository is `MoeclubM/NodeRS`. To use another repository, set `NODERS_REPOSITORY=owner/repo` on the `bash` command and provide the same override on later upgrade commands.

Check executable capabilities with:

```bash
./noders --supported-panels
# xboard pxboard
```

The default `--panel-type` is `xboard`. Every `--machine` in one invocation uses that type. To connect the host to both panel types, run the installer separately for each type. The shared NodeRS executable supports both, while services and configuration files remain separate.

## Local Configuration

```toml
[panel]
type = "pxboard"
api = "https://panel.example.com"
key = "replace-with-machine-key"
machine_id = 1
```

`type` accepts `xboard` or `pxboard`; omission selects Xboard. PxBoard configuration names use `pxboard-<machineId>-<addressId>.toml` and services use `noders-pxboard-<machineId>-<addressId>`. Existing Xboard names stay unchanged.

When starting NodeRS manually, pass the configuration path and use a writable persistent working directory:

```bash
cd /var/lib/noders/anytls
/usr/local/lib/noders/noders /etc/noders/anytls/machines/ACTUAL_CONFIG.toml
```

Installed systemd and OpenRC services already set their working directory. After rotating a machine key, update the local `key` and restart the corresponding service.

## API Contract

Procedures are invoked via `POST /rpc/v1/nodes/{method}` with `Authorization: Bearer pxm_<machineId>.<key>` (or a pre-formatted `pxm_` token). Successful responses return `{"data": ...}` and errors return `{"error": {"code": "...", "message": "..."}}`. Keys are never placed in URLs, and machine tokens are scoped strictly to `nodes` `server.*` procedures.

| Procedure (`POST /rpc/v1/nodes/{method}`) | Purpose |
| --- | --- |
| `server.bootstrap` | Verify machine API and RPC version `1.0` |
| `server.pull` | Fetch whole-machine snapshot (`nodes`, per-node `config` and `users`, polling intervals, and pending `managedConfiguration`) with `knownRevision` delta support |
| `server.traffic` | Submit upload and download byte counts with `nodeId` and a unique `batchId` |
| `server.telemetry` | Report machine host `status` metrics and per-node online accounts/IPs |
| `server.ackConfig` | Report `applied` or `failed` outcome for a `managedConfiguration` revision |

Node configuration contains `protocol`, `host`, `listen`, `transport`, `security`, and `protocolOptions`. NodeRS adapts this structure to its existing protocol runtime; PxBoard does not need Xboard compatibility endpoints. Separate UUID and password fields support the credential requirements of Shadowsocks, Trojan, TUIC, and other protocols.

The current integration uses HTTP polling. Aerion determines protocol capabilities. Unsupported transports, routing, or fallback settings prevent that node configuration from being applied instead of silently changing its meaning. The panel must supply valid certificate and key settings where required.

## Managed Configuration and Panel Migration

NodeRS checks its currently authenticated panel every 30 seconds for a new local panel configuration. PxBoard administrators can change the panel type, address, machine number, and key from the machine page. NodeRS updates only the TOML file supplied at startup; it accepts no remote file paths or system commands.

| Procedure | Payload |
| --- | --- |
| `server.pull` (`managedConfiguration` field) | `null`, or `{revision, config: {panel: {type, api, key, machine_id}}}` |
| `server.ackConfig` | `{machineId, revision, status: "applied" or "failed", message}` |

Both procedures authenticate with the machine's `Authorization: Bearer pxm_<machineId>.<key>` header. Target configuration contains a machine key and should be managed only by trusted panel administrators.

Before applying a change, NodeRS authenticates the target machine, fetches every target node configuration and user list, and backs up its existing TOML file. It then stops old synchronization tasks, closes existing connections, drains final traffic to the source panel, starts the target nodes, and saves the new configuration. Configuration, listener, or save failures restore the source runtime. If restoring the source also fails, NodeRS saves the source configuration and exits so the service manager can restart it. Clients must reconnect during a migration.

Backups are saved beside the original file as `<config>.backup-<time>`. Results are sent to the source panel only after target startup and persistence. An undelivered result is saved as `<config>.configuration-status.json` and retried during later polling or after restart. This receipt contains source authentication credentials. The service user needs write access to the configuration directory; protect backups and receipts as credentials.

### Taking Over from Xboard

The source Xboard must add the following extension to its authenticated `POST /api/v2/server/machine/nodes` response, alongside its normal fields:

```json
{
  "agent_config": {
    "managed_configuration": {
      "revision": 1,
      "config": {
        "panel": {
          "type": "pxboard",
          "api": "https://panel.example.com",
          "key": "target-machine-key",
          "machine_id": 1
        }
      }
    }
  }
}
```

NodeRS retrieves this command using the existing Xboard `token` and `machine_id` authentication. It reports `{revision,status,message}` to `POST /api/v2/server/machine/configuration/status` with the same authentication. The source should stop delivering a revision after its result; retries require a new revision. Xboard installations without the extension continue working normally. The official plugins repository includes the source bridge and its installation and removal instructions.

If the source cannot deliver configuration, prepare a target TOML file on the node and run the updated executable:

```bash
/usr/local/lib/noders/noders --migrate-panel \
  /etc/noders/anytls/machines/original-config.toml \
  /root/target-pxboard.toml
```

The command authenticates the target, backs up the existing file, and updates it in place. A running NodeRS with managed configuration support detects it within 30 seconds. Upgrade older executables first and restart the existing service. Restrict access to the target file because it contains a key.

Service names, file names, and working directories remain unchanged after migration; use the original full service name for maintenance. Avoid installing another instance on the same ports. To return to the source panel, restore its backup to the original path; a running updated NodeRS validates and reloads it. Alternatively, stop the service, restore the file, and start it again.

### Final Usage and Service Shutdown

Xboard usage reports have no batch deduplication. Final usage is saved to `xboard-final-node-*.json` before delivery. Records proven undelivered remain `pending` and are retried against the source panel during later reporting. An ambiguous result becomes `unconfirmed`, or is stored as `xboard-unconfirmed-node-*.json`. NodeRS preserves these records, continues reporting new usage, and blocks migration until they are reconciled.

Check ambiguous records against the source panel's usage ledger. Once resolved, change their `status` to `resolved`, retain the original records, and retry with a new configuration revision. Replaying without checking can charge usage twice. PxBoard retries its original batch IDs; migration scans every queue for the source machine, including removed nodes, and stops if any cannot be drained.

On `SIGTERM` or Ctrl+C, NodeRS stops synchronization, waits for in-flight usage reports, closes nodes, and saves and sends final usage. The systemd template sets `TimeoutStopSec=300`; update existing units accordingly. Saved records survive source outages. An in-progress machine reconciliation or certificate request can delay shutdown; avoid forcing termination and retain the complete working directory.

## Traffic Retries and Maintenance

Before sending usage, NodeRS writes a batch to `pxboard-<encodedPanelAddress>-<machineId>-node-<nodeId>-traffic.json` in its working directory. A network failure or process restart retries the same batch ID; the nodes plugin deduplicates it. A batch is removed only after the panel acknowledges it. Files are separated by panel, machine, and node.

Keep the directory writable and provide sufficient disk space. Do not delete pending traffic files. When relocating the service, stop it and copy these files along with the rest of the state. Restore connectivity and drain pending batches before disabling a node or machine. The queue can recover usage that was collected and saved during normal operation.

```bash
noders log -f pxboard-1
noders restart pxboard-1
noders uninstall --panel-type pxboard --machine-id 1
```

A numeric service selector such as `noders restart 1` matches machine 1 across panel types. `pxboard-1` selects only PxBoard. Targeted uninstall defaults to Xboard unless `--panel-type pxboard` is supplied; `--all` removes the entire installation and its data.

Upgrade preserves configuration, certificates, and state. If PxBoard instances exist, the upgrade script rejects bundles without PxBoard support before replacing the executable.
