# 安装与升级

[简体中文](../zh/install.md) | [English](../en/install.md)

NodeRS 只在 Linux 上运行。安装脚本会识别 `x86_64` / `aarch64` 以及 `glibc`（2.36+）/ `musl`，并自动选择对应的 Release 包。有 systemd 用 `install.sh`，只有 OpenRC（如 Alpine）用 `install-openrc.sh`。

默认对接 Xboard。对接 PxBoard 时增加 `--panel-type pxboard`，并使用支持 PxBoard 的安装包，详见 [PxBoard 接入](pxboard.md)。

## 系统要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Linux（systemd 或 OpenRC） |
| 架构 | `x86_64` / `aarch64` |
| libc | glibc 2.36+ 或 musl |
| 网络 | 能访问面板 API；面板能访问节点监听端口 |

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key 机器密钥 \
  --machine-id 1
```

OpenRC：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install-openrc.sh | bash -s -- \
  --api https://api.example.com \
  --key 机器密钥 \
  --machine-id 1
```

同一台服务器对接多个面板时，重复 `--machine <url> <key> <id>`；不同 API 可以共用同一个 `machine_id`，实例名由 `api + machine_id` 哈希生成，不会冲突：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --machine https://secapi.example.com 密钥A 10 \
  --machine https://api.example.com 密钥B 10
```

## 安装脚本参数

| 参数 | 说明 |
| --- | --- |
| `--version <tag>` | 安装指定的 Release 标签，默认 `latest` |
| `--prefix <path>` | 二进制安装前缀，默认 `/usr/local` |
| `--config-dir <path>` | 配置目录，默认 `/etc/noders/anytls` |
| `--state-dir <path>` | 工作目录，默认 `/var/lib/noders/anytls` |
| `--panel-type <type>` | 对接类型：`xboard`（默认）或 `pxboard` |
| `--api <url>` | 所选面板的根地址 |
| `--key <token>` | 所选面板的机器密钥 |
| `--machine-id <id>` | 机器 ID；配合 `--uninstall` 时删除所选面板类型中该 ID 的全部本地实例 |
| `--machine <url> <key> <id>` | 添加一组机器三元组，可重复；配合 `--uninstall` 时只删除该实例 |
| `--uninstall` | 卸载已安装的服务、二进制和相关文件 |
| `--all` | 配合 `--uninstall`，删除全部节点和全部数据 |
| `--no-service` | 只装文件，不注册服务 |
| `-h, --help` | 显示帮助 |

脚本直接从仓库或 raw URL 运行时会自动下载 Release 包；如果已经在解压好的 Release 包内运行，则直接使用本地文件，不再下载。

安装和升级默认从 `MoeclubM/NodeRS` 获取发布包，可用环境变量 `NODERS_REPOSITORY` 为本次命令指定其他 `owner/repo`。例如：

```bash
NODERS_REPOSITORY=owner/NodeRS bash scripts/install.sh --version v0.1.50 \
  --panel-type pxboard --api https://panel.example.com --key 机器密钥 --machine-id 1
NODERS_REPOSITORY=owner/NodeRS noders update --version v0.1.50
```

覆盖发布源只影响本次命令，不修改对接类型。安装或升级后，管理脚本使用新包中的默认发布源；PxBoard 实例仍要求下载的程序支持 PxBoard。

### 从组织适配版升级

此前从 `MoeClub-Open/NodeRS` 安装的 `v0.1.49-pxboard.1` 或 `.2`，使用原仓库完成一次升级：

```bash
NODERS_REPOSITORY=MoeclubM/NodeRS noders update --version v0.1.50
```

升级保留面板连接配置、证书和流量队列，并将后续更新切回原仓库。之后直接执行 `noders update` 即可。

## 本地配置文件

每个实例有一份本地 TOML 配置，路径为 `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml`，由安装脚本生成，内容只有面板连接信息（`config.example.toml`）：

```toml
[panel]
type = "xboard"
api = "https://xboard.example.com"
key = "replace-me"
machine_id = 1
```

`key` 必须是该机器的机器密钥。节点、用户、监听地址、端口和证书全部由面板下发（`api`/`key` 也接受别名 `url`/`token`）。手动改这个文件后需要 `noders restart` 生效。

`type` 省略时为 `xboard`。PxBoard 实例配置与服务名增加 `pxboard-` 前缀，接口和运行数据说明见 [PxBoard 接入](pxboard.md)。

守护进程的启动方式是 `noders <配置文件路径>`（省略时使用工作目录下的 `config.toml`）；安装好的服务已带好该参数，一般不需要手动运行。

## 从源码编译

需要 Rust（edition 2024，建议最新 stable）：

```bash
git clone https://github.com/MoeclubM/NodeRS.git
cd NodeRS
cargo build --release
```

构建产物在 `target/release/noders`。仓库中的 `scripts/verify-pure-rust.sh` 用于校验依赖的纯 Rust 情况，打包脚本 `scripts/package-release-bundle.sh` 用于组装 Release 包结构。

## 升级

管理命令升级到最新 Release：

```bash
noders update
# 指定版本 / 升级后不重启
noders update --version v0.1.50
noders update --no-restart
```

或使用脚本（会保留机器配置、证书、ACME 账号和状态；旧的 `noders-anytls`、`noders-<machine_id>` 命名会先迁移到当前实例名再换二进制）：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/upgrade.sh | bash -s --
```

## 卸载

按 `machine_id` 删除该机器在本机的全部 Xboard 实例；PxBoard 增加 `--panel-type pxboard`：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --machine-id 1
```

多个 API 共用同一个 `machine_id` 时，带上原来的 `--machine <url> <key> <id>` 只删那一个实例：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --machine https://api.example.com 机器密钥 1
```

清空本机 NodeRS：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall \
  --all
```

## Xboard 同步接口

| API | 用途 |
| --- | --- |
| `/api/v2/server/machine/nodes` | 节点列表 |
| `/api/v2/server/config` | 节点配置 |
| `/api/v2/server/user` | 用户 |
| `/api/v2/server/report` | 流量与在线 IP |
| `/api/v2/server/machine/status` | 主机状态 |
| `/api/v2/server/handshake` | WebSocket；面板未启用时回退 HTTP 轮询 |

PxBoard 使用统一的 `POST /rpc/v1/nodes/server.*` 接口与 `Authorization: Bearer pxm_<machineId>.<key>` 认证，完整约定见 [PxBoard 接入](pxboard.md)。

协议由 Aerion 提供：AnyTLS、Flux、Hysteria2、Mieru、Naive、Shadowsocks、Sudoku、Trojan、TUIC、VLESS、VMess。协议在线上的限制见 [Aerion 文档](https://github.com/MoeclubM/Aerion/blob/main/docs/limitations.md)。
