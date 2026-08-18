# NodeRS

面向 [Xboard](https://github.com/cedar2025/Xboard) 的 Linux 机器节点。

一条命令把服务器接到面板：节点、用户、监听端口和证书都从面板下发，本机只保留 API 地址、机器密钥和 `machine_id`。协议由 [Aerion](https://github.com/MoeclubM/Aerion) 提供，和 [XBClient](https://github.com/MoeclubM/XBClient) 共用同一套实现。

[![Release](https://img.shields.io/github/v/release/MoeclubM/NodeRS?style=flat-square)](https://github.com/MoeclubM/NodeRS/releases)
[![License](https://img.shields.io/github/license/MoeclubM/NodeRS?style=flat-square)](LICENSE)

## 特性

- **对接 Xboard 机器模式**：兼容 `/api/v2/server/*` 与 `/api/v2/server/machine/*`，节点增减、用户同步、流量与在线状态自动回报。
- **一机一进程**：挂到同一台 Xboard 机器上的节点，都由同一个 NodeRS 进程管理。
- **配置极简**：服务器上只需 `panel.api`、`panel.key`、`panel.machine_id`。
- **证书跟面板走**：文件路径、内联 PEM、Let's Encrypt（HTTP-01 / DNS-01）或本机自签，都由 `cert_config` 决定。
- **多用户与限速**：设备数限制、`speed_limit` 在协议运行时生效。
- **现成 Linux 包**：`amd64` / `arm64`，GNU（glibc 2.36+）与 musl；安装脚本自动识别架构和 libc。

## 协议

| 协议 | TCP | UDP | 说明 |
| --- | :---: | :---: | --- |
| AnyTLS | ✓ | UoT | 多路复用、padding |
| Hysteria2 | ✓ | 原生 | Salamander、BBR |
| Mieru | ✓ | 原生 / 流内 | TCP 与 UDP underlay |
| Naive | ✓ | UoT | HTTP/1.1、H2、H3 |
| Shadowsocks | ✓ | ✓ | AEAD / 2022 |
| Trojan | ✓ | 流内 | WS / H2 / gRPC / XHTTP |
| TUIC v5 | ✓ | 原生 / 流 | QUIC |
| VLESS | ✓ | ✓ | TLS、REALITY、Vision |
| VMess | ✓ | ✓ | AEAD |

能力边界见 [Aerion 文档](https://github.com/MoeclubM/Aerion)。

## 快速开始

在 Xboard 里创建机器，记下 **机器 ID** 和 **机器密钥**，把要跑的节点挂到这台机器上，并在面板里配好端口、协议和证书。然后在服务器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key 机器密钥 \
  --machine-id 1
```

没有 systemd、使用 OpenRC 的发行版：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install-openrc.sh | bash -s -- \
  --api https://api.example.com \
  --key 机器密钥 \
  --machine-id 1
```

一台机器对接多个面板时，重复 `--machine` 即可（不同 API 可以共用同一个 `machine_id`，本地实例名按 `api + machine_id` 区分）：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --machine https://secapi.example.com 密钥A 10 \
  --machine https://api.example.com 密钥B 10
```

安装完成后：

```bash
noders          # 交互菜单
noders log -f   # 看日志，确认节点已监听
```

## 日常运维

`noders` 默认作用于本机发现的全部实例；也可以传服务名、`machine_id` 或实例后缀，只操作其中一部分。

```bash
noders update              # 升级到最新 Release
noders restart             # 重启全部
noders restart 1           # 只重启 machine_id = 1
noders log -f
noders uninstall --machine-id 1
noders uninstall --all
```

也可以直接升到指定版本（会保留机器配置、证书和 ACME 账号）：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/upgrade.sh | bash -s --
```

### 路径

| 项目 | 路径 |
| --- | --- |
| 程序 | `/usr/local/lib/noders/noders` |
| 管理命令 | `/usr/local/bin/noders` |
| 机器配置 | `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml` |
| 运行数据 | `/var/lib/noders/anytls` |
| 服务名 | `noders-<machine_id>-<api_hash>` |

### systemd / OpenRC

```bash
systemctl status noders-1-123456789 --no-pager -l
journalctl -u noders-1-123456789 -f
systemctl restart noders-1-123456789
```

```bash
rc-service noders-1-123456789 status
rc-service noders-1-123456789 restart
tail -f /var/log/noders/noders-1-123456789.log
```

## 证书

证书不再写在本地 toml 里，全部来自面板 `cert_config`：

| `cert_mode` | 行为 |
| --- | --- |
| `file` / `path` | 使用面板给出的证书和私钥路径 |
| `inline` / `pem` / `content` | 使用面板下发的 PEM |
| `http` / `acme` / `letsencrypt` | Let's Encrypt HTTP-01 |
| `dns` | Let's Encrypt DNS-01（Cloudflare、AliDNS） |
| `none` / `self_signed` | 本机生成自签证书 |

ACME 证书默认落在工作目录的 `acme/<域名>/` 下；安装后的服务工作目录是 `/var/lib/noders/anytls`。

## 卸载

```bash
# 按 machine_id 删除该机器在本机的全部实例
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --machine-id 1

# 清空本机 NodeRS
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --all
```

多个 API 共用同一个 `machine_id` 时，带上原来的 `--machine <url> <key> <id>` 只删那一个实例。

## 相关项目

- [Aerion](https://github.com/MoeclubM/Aerion) — 协议与 TUN 核心
- [XBClient](https://github.com/MoeclubM/XBClient) — Xboard 用户端（Android / Windows / Linux）
- [Xboard](https://github.com/cedar2025/Xboard) — 面板

## 许可

MIT。详见 [LICENSE](LICENSE)。
