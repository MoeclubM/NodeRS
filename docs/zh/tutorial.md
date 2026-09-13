# 从零搭建教程

[简体中文](../zh/tutorial.md) | [English](../en/tutorial.md)

本教程从零开始，完整走一遍「Xboard 面板 → NodeRS 节点 → 客户端连通」的流程。已经装好、只想查命令或参数的读者可以直接看[安装与升级](install.md)和[管理命令](management.md)。

## 0. 前置条件

- 一台装好 [Xboard](https://github.com/cedar2025/Xboard) 的面板，且版本支持机器模式（`/api/v2/server/machine/*` 接口）。
- 一台 Linux 服务器（节点机），`x86_64` 或 `aarch64`，glibc 2.36+ 或 musl（Alpine 也可以）。NodeRS 只支持 Linux。
- 节点机可以访问面板 API，面板可以访问节点机上配置的监听端口。
- 如果打算用 Let's Encrypt 签证书：HTTP-01 需要节点的 80 端口可从公网访问；DNS-01 需要准备 Cloudflare 或阿里云 DNS 的 API 凭据。

## 1. 面板端：创建机器并挂载节点

1. 登录 Xboard 管理后台，进入**机器（节点服务器）**管理页，创建一台新机器。
2. 创建完成后记下两个值：
   - **机器 ID**（`machine_id`，一个整数）
   - **机器密钥**（machine key，安装时要用）
3. 在节点管理里创建或编辑节点，把节点**挂到这台机器**上，并配置好：
   - 监听端口
   - 协议类型（AnyTLS / Hysteria2 / Mieru / Naive / Shadowsocks / Trojan / TUIC / VLESS / VMess）及对应参数
   - 证书（`cert_config`），可选模式见[证书配置](certificates.md)
4. 需要多个节点时重复第 3 步即可——它们都会由节点机上的同一个 NodeRS 进程管理，不需要每个节点单独装一遍。

## 2. 服务器端：一键安装

在节点机上执行（把 `https://api.example.com` 换成面板 API 地址，`机器密钥` 换成第 1 步拿到的密钥）：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --api https://api.example.com \
  --key 机器密钥 \
  --machine-id 1
```

使用 OpenRC 的发行版（Alpine 等）改用：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install-openrc.sh | bash -s -- \
  --api https://api.example.com \
  --key 机器密钥 \
  --machine-id 1
```

脚本会自动识别架构和 libc，下载对应的 Release 包，写入机器配置并注册 systemd / OpenRC 服务，然后启动。

安装脚本的全部参数（指定版本、自定义路径、跳过服务等）见[安装与升级](install.md)。

### 一台服务器对接多个面板

重复 `--machine <url> <key> <id>` 即可，每对组合生成一个独立实例：

```bash
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --machine https://secapi.example.com 密钥A 10 \
  --machine https://api.example.com 密钥B 10
```

不同 API 可以共用同一个 `machine_id`，本地实例名按 `api + machine_id` 哈希区分，不会冲突。

## 3. 验证

```bash
noders log -f
```

正常情况下可以看到节点配置拉取成功、各协议开始监听端口。回到面板的节点列表，节点应显示为在线。

再用客户端实测一次连通性：[XBClient](https://github.com/MoeclubM/XBClient)（Android / Windows / Linux）或任何支持上述协议的客户端，导入订阅后连接节点即可。

看不到监听或面板一直离线？跳到[常见问题](faq.md)。

## 4. 日常维护

- **升级**：`noders update`，或重新跑一遍 `upgrade.sh`；机器配置、证书和 ACME 账号都会保留。
- **改配置**：节点、端口、证书都在面板改，改完 NodeRS 会自动拉取生效，通常不需要登录服务器。
- **重启 / 日志 / 卸载**：见[管理命令](management.md)。

## 5. 卸载

```bash
# 按 machine_id 删除该机器的全部实例
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall --machine-id 1

# 清空本机 NodeRS
curl -fsSL https://raw.githubusercontent.com/MoeclubM/NodeRS/main/scripts/install.sh | bash -s -- \
  --uninstall --all
```
