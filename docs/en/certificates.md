# Certificates

[简体中文](../zh/certificates.md) | [English](../en/certificates.md)

NodeRS does not keep certificates in the local TOML file — all certificate behavior is decided by the node's `cert_config` in the panel. Adding nodes, switching domains, or rotating certificates only requires panel-side changes; NodeRS picks them up automatically.

## cert_mode Overview

| `cert_mode` | Behavior |
| --- | --- |
| `file` / `path` | Use the certificate and private key file paths given by the panel (paths on the node machine) |
| `inline` / `pem` / `content` | Use the PEM certificate and private key issued directly by the panel |
| `http` / `acme` / `letsencrypt` | Let's Encrypt HTTP-01 automatic issuance |
| `dns` | Let's Encrypt DNS-01 automatic issuance (Cloudflare, AliDNS) |
| `none` / `self_signed` | Generate a self-signed certificate locally (an empty value is treated as `none`) |

## HTTP-01

Set `cert_mode` to `http` / `acme` / `letsencrypt` in the panel. Requirements:

- The node domain's A/AAAA records point to the node machine;
- **Port 80** on the node machine is reachable from the internet (ACME validates over HTTP).

Issued certificates and the ACME account key are stored under `acme/<domain>/` in the service working directory. After installation that directory is `/var/lib/noders/anytls`, i.e. `/var/lib/noders/anytls/acme/<domain>/`. Upgrades and restarts reuse the existing account instead of registering a new one.

The ACME directory URL defaults to Let's Encrypt production (`https://acme-v02.api.letsencrypt.org/directory`); the panel can point to another ACME service via `directory_url` (aliases: `directory`, `acme_directory_url`), and the account email comes from the panel's `email` field.

## DNS-01

Set `cert_mode` to `dns` in the panel and provide the DNS provider and credentials. This is the right choice when port 80 is unavailable or you need a wildcard certificate (`*.example.com`). Two providers are supported:

### Cloudflare

Credential fields are recognized in this order (any one is enough): `cloudflare_api_token`, `cloudflare.token` / `cloudflare.api_token`, `dns.token` / `dns.api_token`, or the environment variables `CF_DNS_API_TOKEN` / `CF_API_TOKEN` / `CLOUDFLARE_API_TOKEN`. Use an API Token scoped to "Zone · DNS · Edit".

Optional parameters: `zone_id` (or `cloudflare_zone_id`), `ttl`, `propagation_timeout`, `propagation_interval`.

### AliDNS (Alibaba Cloud)

Credential fields are recognized in this order: `access_key_id` + `access_key_secret` (or the `alidns_access_key_id` / `aliyun_access_key_id` aliases), or the environment variables `ALIDNS_ACCESS_KEY_ID` / `ALICLOUD_ACCESS_KEY_SECRET` and friends. Use a RAM sub-account authorized only for AliDNS.

Optional parameters are the same as Cloudflare's: `zone`, `zone_id`, `ttl`, `propagation_timeout`, `propagation_interval`.

> The provider can be passed explicitly via `provider`, `dns_provider`, `acme_dns_provider`, or `dns.provider`; the challenge type can be set through `acme.challenge`.

## Self-signed Certificates

When `cert_mode` is `none` / `self_signed` (or empty), NodeRS generates a self-signed certificate locally. Fine for internal testing or clients that skip certificate verification; production deployments should prefer ACME or panel-issued certificates.

## File / Inline Certificates

- `file` / `path`: the panel issues the **paths on the node machine** where the certificate and private key live, and NodeRS reads them directly.
- `inline` / `pem` / `content`: the panel issues the PEM contents themselves, so no plaintext private key file is written on the node machine.

## Troubleshooting

For issuance failures and renewal problems, see the [FAQ](faq.md).
