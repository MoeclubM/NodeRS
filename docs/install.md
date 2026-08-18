# 安装与运维 / Install

NodeRS 只在 Linux 上运行。安装脚本会识别 `x86_64` / `aarch64` 以及 `glibc` / `musl`。  
NodeRS is Linux-only. The install scripts detect `x86_64` / `aarch64` and `glibc` / `musl`.

## 安装 / Install

systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key machine_key \
  --machine-id 1
```

OpenRC:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install-openrc.sh | bash -s -- \
  --api https://api.example.com \
  --key machine_key \
  --machine-id 1
```

同一台机器上多个面板：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --machine https://secapi.example.com machine_key_a 10 \
  --machine https://api.example.com machine_key_b 10
```

不同 API 可以复用同一个 `machine_id`。实例名由 `api + machine_id` 生成，避免冲突。  
The same `machine_id` may be reused across APIs. Instance names are derived from `api + machine_id`.

本地最小配置 / local config (`config.example.toml`):

```toml
[panel]
api = "https://xboard.example.com"
key = "replace-me"
machine_id = 1
```

`key` 必须是该机器的机器密钥。节点、用户、监听地址、端口和证书都从面板拉取。  
`key` is the machine key. Nodes, users, listen address, port, and TLS come from the panel.

## 路径 / Paths

| 项目 / Item | 路径 / Path |
| --- | --- |
| 二进制 / binary | `/usr/local/lib/noders/noders` |
| 管理命令 / manager | `/usr/local/bin/noders` |
| 配置 / config | `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml` |
| 状态 / state | `/var/lib/noders/anytls` |
| 服务名 / service | `noders-<machine_id>-<api_hash>` |

## 管理 / Manager

不带参数打开交互菜单。默认对发现的全部实例生效；也可传入服务名、`machine_id` 或实例后缀。  
No arguments opens an interactive menu. Commands apply to every discovered instance unless you pass a service name, `machine_id`, or instance suffix.

```bash
noders
noders update
noders restart
noders restart 1
noders log -f
noders uninstall --machine-id 1
noders uninstall --all
```

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

## 升级 / Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/upgrade.sh | bash -s --
```

会保留机器配置、证书、ACME 账号和状态。旧的 `noders-anytls` 或 `noders-<machine_id>` 会先迁到当前实例名再换二进制。  
Keeps machine configs, certificates, ACME accounts, and state. Old `noders-anytls` binaries and `noders-<machine_id>` names are migrated in place.

## 卸载 / Uninstall

按 `machine_id` 删除该机器在本机的全部实例：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --machine-id 1
```

多个 API 共用同一 `machine_id` 时，带上原来的 `--machine <url> <key> <id>` 只删那一个。  
To remove one instance when several APIs share a `machine_id`, pass the original `--machine <url> <key> <id>` with `--uninstall`.

全部删除 / remove everything:

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --all
```

## 面板同步 / Panel

| API | 用途 / Use |
| --- | --- |
| `/api/v2/server/machine/nodes` | 节点列表 / membership |
| `/api/v2/server/config` | 节点配置 / node settings |
| `/api/v2/server/user` | 用户 / users |
| `/api/v2/server/report` | 流量与在线 / traffic and alive IPs |
| `/api/v2/server/machine/status` | 主机状态 / host status |
| `/api/v2/server/handshake` | WebSocket；空则 HTTP 轮询 / WebSocket, or HTTP polling if empty |

证书来自面板 `cert_config`（文件、内联 PEM、ACME HTTP-01 / DNS-01，或本地自签）。协议不使用的面板字段会被忽略。  
Certificates come from panel `cert_config` (file, inline PEM, ACME HTTP-01 / DNS-01, or local self-signed). Panel fields a protocol does not consume are ignored.

协议由 Aerion 提供：AnyTLS、Hysteria2、Mieru、Naive、Shadowsocks、Trojan、TUIC、VLESS、VMess。限制见 [Aerion docs](https://github.com/MoeclubM/Aerion/blob/main/docs/limitations.md)。  
Protocols are served by Aerion. See [Aerion docs](https://github.com/MoeclubM/Aerion/blob/main/docs/limitations.md) for wire-level limits.
