# 证书配置

[简体中文](../zh/certificates.md) | [English](../en/certificates.md)

NodeRS 不在本地 toml 里写证书，全部证书行为由面板节点配置中的 `cert_config` 决定：节点增减、换域名、换证书，都只需要在面板改配置，NodeRS 会自动拉取。

## cert_mode 一览

| `cert_mode` | 行为 |
| --- | --- |
| `file` / `path` | 使用面板给出的证书和私钥文件路径（节点机本机路径） |
| `inline` / `pem` / `content` | 使用面板直接下发的 PEM 证书与私钥 |
| `http` / `acme` / `letsencrypt` | Let's Encrypt HTTP-01 自动签发 |
| `dns` | Let's Encrypt DNS-01 自动签发（Cloudflare、AliDNS） |
| `none` / `self_signed` | 本机生成自签证书（留空时同样按 `none` 处理） |

## HTTP-01

面板把 `cert_mode` 配为 `http` / `acme` / `letsencrypt` 即可。要求：

- 节点域名的 A/AAAA 记录指向节点机；
- 节点机的 **80 端口**可从公网访问（ACME 验证走 HTTP）。

签发的证书和 ACME 账号密钥保存在服务工作目录的 `acme/<域名>/` 下。安装后的服务工作目录是 `/var/lib/noders/anytls`，即 `/var/lib/noders/anytls/acme/<域名>/`。升级、重启都会复用已有账号，不会重复注册。

ACME 目录地址默认为 Let's Encrypt 生产环境（`https://acme-v02.api.letsencrypt.org/directory`），面板也可以通过 `directory_url`（别名 `directory`、`acme_directory_url`）指定其他 ACME 服务，注册账号使用的邮箱由面板的 `email` 字段下发。

## DNS-01

面板把 `cert_mode` 配为 `dns`，并给出 DNS 提供商与凭据。适合 80 端口不可用、或需要泛域名证书（`*.example.com`）的场景。目前支持两个提供商：

### Cloudflare

凭据字段按以下顺序识别（任选其一即可）：`cloudflare_api_token`、`cloudflare.token` / `cloudflare.api_token`、`dns.token` / `dns.api_token`、或环境变量 `CF_DNS_API_TOKEN` / `CF_API_TOKEN` / `CLOUDFLARE_API_TOKEN`。建议使用只有「Zone · DNS · Edit」权限的 API Token。

可选参数：`zone_id`（或 `cloudflare_zone_id`）、`ttl`、`propagation_timeout`、`propagation_interval`。

### AliDNS（阿里云）

凭据字段按以下顺序识别：`access_key_id` + `access_key_secret`（或 `alidns_access_key_id` / `aliyun_access_key_id` 等别名），或环境变量 `ALIDNS_ACCESS_KEY_ID` / `ALICLOUD_ACCESS_KEY_SECRET` 等。建议使用仅授权 AliDNS 操作的 RAM 子账号。

可选参数与 Cloudflare 相同：`zone`、`zone_id`、`ttl`、`propagation_timeout`、`propagation_interval`。

> `provider` 字段可用 `provider`、`dns_provider`、`acme_dns_provider` 或 `dns.provider` 传入，用于显式指定提供商；challenge 类型也可由 `acme.challenge` 指定。

## 自签证书

`cert_mode` 配为 `none` / `self_signed`（或留空）时，NodeRS 在本机生成自签证书。适合内网测试或客户端允许跳过证书校验的场景；生产环境建议使用 ACME 或面板下发证书。

## 文件 / 内联证书

- `file` / `path`：面板下发证书与私钥在**节点机上的路径**，NodeRS 直接读取。
- `inline` / `pem` / `content`：面板直接下发 PEM 内容，节点机上不落盘明文私钥文件。

## 常见问题

签发失败、续期异常等排查思路见[常见问题](faq.md)。
