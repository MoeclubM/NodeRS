# 管理命令

[简体中文](../zh/management.md) | [English](../en/management.md)

安装脚本会在 `/usr/local/bin/noders` 放一个管理命令，用于在本机管理全部 NodeRS 实例。直接不带参数运行打开交互菜单。

```bash
noders
```

## 子命令

```
用法: noders <command> [options] [selector...]
```

| 命令 | 说明 |
| --- | --- |
| `noders update [--version <tag>] [--no-restart]` | 升级已安装的二进制 |
| `noders start [all\|selector...]` | 启动服务 |
| `noders stop [all\|selector...]` | 停止服务 |
| `noders restart [all\|selector...]` | 重启服务 |
| `noders log [-f\|--follow] [-n\|--lines <count>] [all\|selector...]` | 查看日志 |
| `noders uninstall [--all \| --machine-id <id> \| --machine <url> <key> <id>]` | 卸载一个实例或整个安装 |
| `noders help` | 显示帮助 |

不传选择器时，命令作用于本机发现的**全部**实例。

## 选择器

选择器用于把操作范围缩小到部分实例，支持四种写法：

| 写法 | 示例 |
| --- | --- |
| 完整服务名 | `noders-1-123456789` |
| machine_id | `1` |
| 实例后缀 | `1-123456789` |
| `all` | 作用于全部实例 |

```bash
noders restart 1              # 只重启 machine_id = 1 的实例
noders log -f 1-123456789     # 跟踪一个实例的日志
noders stop all               # 停止全部
```

## 交互菜单

在终端直接运行 `noders` 会进入交互菜单，包含：更新、卸载、启动、停止、重启、查看日志。卸载全部前会要求输入 `YES` 确认。

## 路径

| 项目 | 路径 |
| --- | --- |
| 程序 | `/usr/local/lib/noders/noders` |
| 管理命令 | `/usr/local/bin/noders` |
| 机器配置 | `/etc/noders/anytls/machines/<machine_id>-<api_hash>.toml` |
| 运行数据 | `/var/lib/noders/anytls` |
| ACME 证书 | `/var/lib/noders/anytls/acme/<域名>/` |
| 服务名 | `noders-<machine_id>-<api_hash>` |

服务以专用用户 `noders` 运行，只保留 `CAP_NET_BIND_SERVICE`（允许绑定低位端口）。

## systemd / OpenRC

也可以绕过 `noders`，直接用系统服务管理器操作（把 `noders-1-123456789` 换成实际服务名）：

systemd：

```bash
systemctl status noders-1-123456789 --no-pager -l
journalctl -u noders-1-123456789 -f
systemctl restart noders-1-123456789
```

OpenRC：

```bash
rc-service noders-1-123456789 status
rc-service noders-1-123456789 restart
tail -f /var/log/noders/noders-1-123456789.log
```
