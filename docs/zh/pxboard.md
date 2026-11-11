# PxBoard 接入

[简体中文](../zh/pxboard.md) | [English](../en/pxboard.md)

NodeRS 通过 PxBoard 的节点插件对接机器。PxBoard 使用自己的 API 和认证方式；本地配置中的 `type` 决定使用哪一组接口。

从 `v0.1.50` 起，NodeRS 通过与 Web、原生客户端一致的 `/rpc/v1` 接口对接 PxBoard，正式发布包同时支持 Xboard 与 PxBoard，默认对接类型仍为 Xboard。

## 面板准备

使用当前 `0.0.1` PxBoard 核心，以及同版本的访问账户、节点管理插件；版本序列要求以插件声明为准。用于导出客户端配置时还需要订阅插件。

在管理后台的“机器”中创建机器，取得机器编号与接入密钥。添加节点时选择 `NodeRS`，指定所属机器，填写协议、服务器地址、端口与证书。用户需要有正常的访问账户、剩余流量和对应节点分组权限。

一台机器可以挂载多个节点；节点编号和机器编号由面板分配，不能互换。`--api` 填面板根地址，例如 `https://panel.example.com`，不要附加 `/api/v1`。

## 安装

安装包中的程序和安装脚本都必须包含 PxBoard 支持。在已解压的安装包目录运行：

```bash
bash install.sh --version v0.1.50 --panel-type pxboard \
  --api https://panel.example.com \
  --key 机器接入密钥 \
  --machine-id 1
```

OpenRC 系统将脚本名换成 `install-openrc.sh`。从源码目录运行时使用 `bash scripts/install.sh`，脚本会下载 Release 包；若该包尚不支持 PxBoard，安装会在替换程序前停止。需要发布包含此功能的安装包，或者使用本机已有的 PxBoard 构建产物。

直接下载安装脚本时可固定此发布标签：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --version v0.1.50 --panel-type pxboard \
  --api https://panel.example.com --key 机器接入密钥 --machine-id 1
```

默认发布源为 `MoeclubM/NodeRS`。使用其他发布仓库时，在 `bash` 命令前设置 `NODERS_REPOSITORY=owner/repo`，后续升级命令也需显式提供相同覆盖值。

程序本身可以检查支持的面板类型：

```bash
./noders --supported-panels
# xboard pxboard
```

`--panel-type` 默认是 `xboard`，同一次安装命令中所有 `--machine` 使用这一类型。需要同时接入两种面板时分别执行安装命令；共享的 NodeRS 程序同时支持两种类型，配置与服务独立保存。

## 本地配置

```toml
[panel]
type = "pxboard"
api = "https://panel.example.com"
key = "replace-with-machine-key"
machine_id = 1
```

`type` 取 `xboard` 或 `pxboard`；省略时按 Xboard 处理。PxBoard 配置文件名为 `pxboard-<机器编号>-<地址标识>.toml`，服务名为 `noders-pxboard-<机器编号>-<地址标识>`。Xboard 原有实例命名不变，两类配置不会相互覆盖。

手动启动时传入配置路径，并将工作目录设为可写的持久目录：

```bash
cd /var/lib/noders/anytls
/usr/local/lib/noders/noders /etc/noders/anytls/machines/实际配置文件.toml
```

安装器创建的 systemd / OpenRC 服务已经配置工作目录。轮换机器密钥后，更新本地 `key` 并重启对应服务。

## 接口约定

所有过程统一通过 `POST /rpc/v1/nodes/{method}` 调用。请求头携带 `Authorization: Bearer pxm_<machineId>.<key>`（兼容已带 `pxm_` 前缀的机器令牌），成功响应放在 JSON 的 `data` 字段中，错误响应为 `{"error":{"code":"...","message":"..."}}`。密钥不出现在 URL 中，机器令牌在面板核心层仅允许调用 `nodes` 服务的 `server.*` 过程。

| 过程（`POST /rpc/v1/nodes/{method}`） | 内容 |
| --- | --- |
| `server.bootstrap` | 握手并确认 `apiVersion` 与 `rpcVersion` 均为 `1.0` |
| `server.pull` | 按 `knownRevision` 合并拉取整机节点列表、各节点配置、授权用户、轮询间隔及待处理的面板迁移配置；未变化时直接返回 `unchanged: true` |
| `server.traffic` | 按 `nodeId` 与唯一 `batchId` 上报增量上传与下载字节数 |
| `server.telemetry` | 上报主机运行指标 `status` 及各节点在线账户与 IP（`nodeId/accounts`） |
| `server.ackConfig` | 回报待处理面板迁移任务的应用状态（`applied` 或 `failed`） |

节点配置由 `protocol`、`host`、`listen`、`transport`、`security`、`protocolOptions` 组成。NodeRS 将该结构转换为已有协议运行配置，不需要 PxBoard 提供 Xboard 兼容接口。用户的连接密码与 UUID 分开接收，适用于 Shadowsocks、Trojan、TUIC 等不同凭据需求。

当前使用 HTTP 轮询。协议能力由 Aerion 决定；不支持的传输、路由和回落设置会阻止该节点配置应用，避免静默改变配置含义。面板应下发该协议需要的有效证书与密钥。

## 面板配置管理与迁移

包含配置管理功能的 NodeRS 每 30 秒向当前已认证面板检查一次本地面板配置。PxBoard 管理员可在机器页下发新的面板类型、地址、机器编号与密钥；NodeRS 只更新启动时指定的 TOML 文件，不接受远程文件路径或系统命令。

| 过程 | 内容 |
| --- | --- |
| `server.pull`（`managedConfiguration` 字段） | 为 `null`，或 `{revision, config: {panel: {type, api, key, machine_id}}}` |
| `server.ackConfig` | `{machineId, revision, status: "applied" 或 "failed", message}` |

以上过程沿用当前机器的 `Authorization: Bearer pxm_<machineId>.<key>` 认证。配置包含机器密钥，仅允许信任的面板管理员设置迁移目标。

应用前会认证目标机器，读取其全部节点配置和用户，再备份现有 TOML 文件。随后停止旧面板的同步任务、结束现有连接并向旧面板回报最后流量，启动目标节点并保存新配置。目标配置、监听或保存失败时恢复旧配置及运行；若旧节点也无法恢复，则保留旧配置并退出，由服务管理器重新启动。迁移会断开已有连接，客户端需要重新连接。

备份以 `<原配置文件>.backup-<时间编号>` 保存在同一目录。配置结果在目标启动并保存后发回原面板；回报失败会将含原面板认证信息的待回报文件保存在 `<原配置文件>.configuration-status.json`，下次轮询或重启后继续发送。配置目录需要允许 NodeRS 服务用户写入，备份与待回报文件应按密钥保存。

### 从 Xboard 接管

源 Xboard 需要在已经认证的 `POST /api/v2/server/machine/nodes` 响应中附加以下字段，普通节点列表及其他字段保持原样：

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

NodeRS 通过原 Xboard 的 `token` 与 `machine_id` 鉴权请求取得指令，并以相同鉴权向 `POST /api/v2/server/machine/configuration/status` 回报 `{revision,status,message}`。Xboard 收到结果后应停止下发同一版本；重试使用新的 `revision`。未添加这些扩展的 Xboard 继续按原方式工作。官方迁移插件仓库提供源站桥接文件，安装与卸载方式见该仓库的迁移文档。

源面板无法下发配置时，可以在节点服务器准备目标 TOML 文件，使用新 NodeRS 执行：

```bash
/usr/local/lib/noders/noders --migrate-panel \
  /etc/noders/anytls/machines/原配置.toml \
  /root/target-pxboard.toml
```

命令认证目标后备份并原位更新现有文件。正在运行且支持配置管理的 NodeRS 会在 30 秒内读取并切换；较旧程序需要先升级，再重启原服务。目标文件含密钥，应仅允许管理员读取。

原服务名、配置文件名和工作目录在迁移后保持原值，维护时使用原服务全名。不要同时为相同监听端口安装另一个 PxBoard 实例。迁移回旧面板时，将对应备份恢复到原配置路径；运行中的新版 NodeRS 会重新验证并切回，也可以停止服务后恢复文件并重新启动。

### 最后流量与停止服务

Xboard 的流量接口没有批次去重。最后流量先写入工作目录中的 `xboard-final-node-*.json` 再发送，明确未投递的 `pending` 记录会在原面板下次回报时重试。无法判断服务器是否接收的记录会标为 `unconfirmed`，也可能以 `xboard-unconfirmed-node-*.json` 保存；NodeRS 保留这些记录，继续回报新的流量，但拒绝迁移。

管理员需结合旧面板的入账记录核对不确定批次。确认已处理后，将对应记录的 `status` 改为 `resolved`，保留原档，然后使用新的配置版本号重试。不要未经核对直接重发，避免重复扣量。PxBoard 的待报批次使用原编号重试；切换前会扫描同来源、同机器的全部队列，包含已移除节点，无法排空则停止迁移。

程序收到 `SIGTERM` 或 Ctrl+C 后停止同步，等待正在进行的流量回报完成，停止节点并保存和发送最后流量。systemd 模板使用 `TimeoutStopSec=300`；现有服务需要更新此配置。源站断网时仍会保留已落盘记录。正在进行的机器节点重建或证书申请可能延长停止时间；避免强制结束进程，并保留整个工作目录。

## 流量重试与维护

每次回报先将批次写入工作目录中的 `pxboard-<面板地址编码>-<机器编号>-node-<节点编号>-traffic.json`，再发送给面板。网络失败或程序重启后使用原批次编号重试；节点插件按批次去重。收到面板确认后才从队列删除批次。不同面板、机器与节点的队列分开保存。

工作目录需要可写且有足够空间。不要手动删除待发送的流量文件。移动运行目录或迁移服务器时，停止服务后一起复制这些文件；在停用节点或机器前先恢复网络并让待发送批次完成回报。只有正常运行时采集并写入队列的流量才能由队列恢复。

常用管理命令：

```bash
noders log -f pxboard-1
noders restart pxboard-1
noders uninstall --panel-type pxboard --machine-id 1
```

数字选择器 `noders restart 1` 会选择所有面板类型中编号为 1 的机器；使用 `pxboard-1` 只选择 PxBoard。卸载命令不传 `--panel-type` 时只按 Xboard 查找指定机器，`--all` 则删除整个 NodeRS 安装及数据。

升级时保留配置、证书和工作目录。若已有 PxBoard 实例，升级器会拒绝缺少 PxBoard 支持的安装包，避免将正在使用的实例升级到不支持其面板的程序。
