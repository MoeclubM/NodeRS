# 常见问题（FAQ）

[简体中文](../zh/faq.md) | [English](../en/faq.md)

## 节点在面板上一直离线

按顺序检查：

1. **服务在跑吗**：`noders log -f` 或 `systemctl status noders-1-123456789`。服务没起来先看下面的「启动失败」。
2. **API 地址对吗**：本机配置里的 `panel.api` 必须是面板 API 地址（通常是面板站点域名本身），而不是网站前端地址或数据库地址。
3. **机器密钥对吗**：`/api/v2/server/*` 鉴权用的是机器密钥，不是用户 token。密钥错了会在日志里看到 401/403 类报错。
4. **网络通吗**：在节点机上 `curl -v https://api.example.com/api/v2/server/config` 试试能否直连面板；有防火墙或安全组时放行出站。
5. **节点挂到机器了吗**：面板里节点必须挂在这台机器（`machine_id` 对应的机器）上才会下发。

## 服务启动失败

```bash
noders log -n 200        # 或 journalctl -u noders-1-123456789 -n 200
```

常见原因：

- **配置文件缺失或非法**：`/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml` 缺字段（`api`、`key`、`machine_id`）会直接失败；手动改过配置后用 `noders restart` 重启。
- **端口被占用**：其他进程（包括旧的 NodeRS 实例）占了监听端口。`ss -tlnp | grep <端口>` 查占用，停掉冲突进程后重启。
- **协议必需字段缺失**：面板多余字段会被忽略，但缺密码、错误 cipher 这类协议真正需要的项会报错。回面板补全节点配置。
- **权限不足**：服务以 `noders` 用户运行，只保留 `CAP_NET_BIND_SERVICE`。如果你在自定义路径部署，确认 `noders` 用户对配置和工作目录有读写权限。

## 证书签发失败

- **HTTP-01**：确认域名解析指向节点机、80 端口对公网开放（`curl -I http://你的域名/` 应该有响应）。被 CDN 代理的域名需要回源到节点机，或改用 DNS-01。
- **DNS-01**：检查凭据是否有效、是否有对应域名的 DNS 编辑权限；Cloudflare 用的是 API Token（不是 Global Key）。可以调大面板里的 `propagation_timeout` / `propagation_interval`。
- **证书没刷新**：重启实例会重新走签发流程：`noders restart <选择器>`。
- **ACME 账号异常**：账号密钥在 `/var/lib/noders/anytls/acme/` 下；确认磁盘没满、目录可写。删除对应域名目录后重启会重新注册账号。

## 日志在哪看

```bash
noders log -f                 # 全部实例，跟踪模式
noders log -n 200 1           # machine_id = 1，最近 200 行
journalctl -u noders-1-123456789 -f          # systemd
tail -f /var/log/noders/noders-1-123456789.log   # OpenRC
```

## 怎么改节点配置

节点、端口、协议、证书都在**面板**上改，NodeRS 会自动拉取，一般不需要登录服务器。只有本机的面板连接信息（`panel.api` / `panel.key` / `panel.machine_id`）在 `/etc/noders/anytls/machines/` 下的 toml 里改，改完 `noders restart`。

## 升级后旧服务名还在

早期版本的服务名 `noders-anytls`、`noders-<machine_id>` 会在升级时自动迁移为 `noders-<machine_id>-<api_hash>`。若仍残留，`noders uninstall --all` 后重装即可。

## 支持哪些系统

Linux only：`x86_64` / `aarch64`，glibc 2.36+ 或 musl。systemd 与 OpenRC 都有对应安装脚本。不支持 Windows / macOS。

还有其他问题：先翻 [Aerion 文档](https://github.com/MoeclubM/Aerion)（协议层限制），或在 [GitHub Issues](https://github.com/MoeclubM/NodeRS/issues) 提问。
