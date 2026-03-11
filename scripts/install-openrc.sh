#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="MoeclubM/NodeRS-AnyTLS"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PREFIX="/usr/local"
CONFIG_DIR="/etc/noders/anytls"
STATE_DIR="/var/lib/noders/anytls"
SERVICE_NAME="noders-anytls"
SERVICE_USER="noders-anytls"
SERVICE_GROUP="noders-anytls"
OPENRC_DIR="/etc/init.d"
RUN_DIR="/run/noders-anytls"
LOG_DIR="/var/log/noders-anytls"
VERSION="latest"
ACME_EMAIL=""
ACME_CHALLENGE_LISTEN="[::]:80"
TLS_SERVER_NAME=""
DNS_RESOLVER="system"
IP_STRATEGY="system"
SELF_SIGNED=0
SELF_SIGNED_DAYS=3650
NO_SERVICE=0
UNINSTALL=0
REMOVE_ALL=0
CERT_PATH=""
KEY_PATH=""
PANEL_URL=""
PANEL_TOKEN=""
PANEL_NODE_ID=""
TMP_ROOT=""
declare -a XBOARD_SPECS=()
declare -a GENERATED_CONFIGS=()
declare -a INSTALLED_SERVICES=()
declare -a TARGET_NODE_IDS=()

cleanup() {
  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: install-openrc.sh [options]

Install mode:
  This installer is for Alpine/OpenRC or other non-systemd Linux hosts.
  It downloads the Linux release bundle automatically, writes configs under
  /etc/noders/anytls, creates OpenRC service scripts, enables them, and starts them.

Uninstall mode:
  Pass `--uninstall` to remove one node or the whole installation.

Options:
  --version <tag>             Release tag to install, default: latest
  --prefix <path>             Binary installation prefix, default: /usr/local
  --config-dir <path>         Config directory, default: /etc/noders/anytls
  --state-dir <path>          Working directory, default: /var/lib/noders/anytls
  --panel-url <url>           Single-node Xboard API address
  --panel-token <token>       Single-node Xboard server_token
  --node-id <id>              Single-node Xboard node id
  --xboard <url> <token> <id> Add one Xboard node triplet; may be repeated
  --server-name <fqdn>        Override local tls.server_name and auto-issue ACME for it
  --self-signed               Generate a self-signed certificate per node and disable ACME
  --self-signed-days <days>   Validity for generated self-signed certs, default: 3650
  --cert-file <path>          Use an existing certificate file and disable ACME
  --key-file <path>           Use an existing private key file and disable ACME
  --acme-email <mailbox>      Contact email for ACME account registration
  --dns-resolver <value>      Outbound DNS: system or a custom nameserver like 1.1.1.1
  --ip-strategy <value>       Outbound IP order: system, prefer_ipv4, prefer_ipv6
  --acme-challenge-listen <addr>
                              HTTP-01 listener address, default: [::]:80
  --uninstall                 Remove installed service(s), binary, and related files
  --all                       Used with --uninstall to remove all nodes and all data
  --no-service                Skip OpenRC service installation
  -h, --help                  Show this help message

Examples:
  bash install-openrc.sh --panel-url https://api.example.com --panel-token token --node-id 1
  bash install-openrc.sh --panel-url https://api.example.com --panel-token token --node-id 1 --server-name node.example.com
  bash install-openrc.sh --panel-url https://api.example.com --panel-token token --node-id 1 --self-signed --server-name node.example.com
  bash install-openrc.sh --panel-url https://api.example.com --panel-token token --node-id 1 --cert-file /path/fullchain.pem --key-file /path/privkey.pem
  bash install-openrc.sh --xboard https://api.example.com tokenA 1 --xboard https://api.example.com tokenB 2
  bash install-openrc.sh --panel-url https://api.example.com --panel-token token --node-id 171 --uninstall
  bash install-openrc.sh --uninstall --all
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This installer only supports Linux." >&2
    exit 1
  fi
}

normalize_paths() {
  :
}

detect_asset_suffix() {
  local arch_suffix libc_variant
  case "$(uname -m)" in
    x86_64|amd64)
      arch_suffix="amd64"
      ;;
    *)
      echo "Unsupported architecture for prebuilt releases: $(uname -m)" >&2
      exit 1
      ;;
  esac

  libc_variant="gnu"
  if [[ -f /etc/alpine-release ]] || compgen -G '/lib/ld-musl-*.so.1' >/dev/null; then
    libc_variant="musl"
  elif command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | head -n1 | grep -qi 'musl'; then
    libc_variant="musl"
  fi

  if [[ "$libc_variant" == "musl" ]]; then
    printf 'linux-%s-musl\n' "$arch_suffix"
  else
    printf 'linux-%s\n' "$arch_suffix"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        VERSION="$2"
        shift 2
        ;;
      --prefix)
        PREFIX="$2"
        shift 2
        ;;
      --config-dir)
        CONFIG_DIR="$2"
        shift 2
        ;;
      --state-dir)
        STATE_DIR="$2"
        shift 2
        ;;
      --panel-url)
        PANEL_URL="$2"
        shift 2
        ;;
      --panel-token)
        PANEL_TOKEN="$2"
        shift 2
        ;;
      --node-id)
        PANEL_NODE_ID="$2"
        TARGET_NODE_IDS+=("$2")
        shift 2
        ;;
      --xboard)
        XBOARD_SPECS+=("$2|$3|$4")
        TARGET_NODE_IDS+=("$4")
        shift 4
        ;;
      --cert-file)
        CERT_PATH="$2"
        shift 2
        ;;
      --key-file)
        KEY_PATH="$2"
        shift 2
        ;;
      --acme-email)
        ACME_EMAIL="$2"
        shift 2
        ;;
      --server-name)
        TLS_SERVER_NAME="$2"
        shift 2
        ;;
      --self-signed)
        SELF_SIGNED=1
        shift
        ;;
      --self-signed-days)
        SELF_SIGNED_DAYS="$2"
        shift 2
        ;;
      --dns-resolver)
        DNS_RESOLVER="$2"
        shift 2
        ;;
      --ip-strategy)
        IP_STRATEGY="$2"
        shift 2
        ;;
      --acme-challenge-listen)
        ACME_CHALLENGE_LISTEN="$2"
        shift 2
        ;;
      --uninstall)
        UNINSTALL=1
        shift
        ;;
      --all)
        REMOVE_ALL=1
        shift
        ;;
      --no-service)
        NO_SERVICE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

validate_args() {
  if [[ -n "$PANEL_URL" || -n "$PANEL_TOKEN" || -n "$PANEL_NODE_ID" ]]; then
    if [[ -z "$PANEL_URL" || -z "$PANEL_TOKEN" || -z "$PANEL_NODE_ID" ]]; then
      echo "--panel-url, --panel-token and --node-id must be provided together." >&2
      exit 1
    fi
    XBOARD_SPECS+=("$PANEL_URL|$PANEL_TOKEN|$PANEL_NODE_ID")
  fi

  if [[ -n "$CERT_PATH" || -n "$KEY_PATH" ]]; then
    if [[ -z "$CERT_PATH" || -z "$KEY_PATH" ]]; then
      echo "--cert-file and --key-file must be provided together." >&2
      exit 1
    fi
    if [[ ! -f "$CERT_PATH" ]]; then
      echo "Certificate file not found: $CERT_PATH" >&2
      exit 1
    fi
    if [[ ! -f "$KEY_PATH" ]]; then
      echo "Private key file not found: $KEY_PATH" >&2
      exit 1
    fi
  fi

  if [[ "$SELF_SIGNED" -eq 1 && ( -n "$CERT_PATH" || -n "$KEY_PATH" ) ]]; then
    echo "--self-signed cannot be used together with --cert-file/--key-file." >&2
    exit 1
  fi

  [[ "$SELF_SIGNED_DAYS" =~ ^[0-9]+$ ]] || {
    echo "--self-signed-days must be a positive integer." >&2
    exit 1
  }
  if [[ "$SELF_SIGNED_DAYS" -lt 1 ]]; then
    echo "--self-signed-days must be at least 1." >&2
    exit 1
  fi

  if [[ "$UNINSTALL" -eq 1 ]]; then
    return
  fi

  if [[ ${#XBOARD_SPECS[@]} -eq 0 ]]; then
    echo "At least one node is required; pass --panel-url/--panel-token/--node-id or --xboard." >&2
    exit 1
  fi

  if [[ ${#XBOARD_SPECS[@]} -gt 1 && -n "$TLS_SERVER_NAME" ]]; then
    echo "--server-name applies to every node in this install invocation." >&2
  fi

  if [[ ${#XBOARD_SPECS[@]} -gt 1 && ( -n "$CERT_PATH" || -n "$KEY_PATH" ) ]]; then
    echo "--cert-file/--key-file apply to every node in this install invocation." >&2
  fi

  if [[ -n "$TLS_SERVER_NAME" && ( -n "$CERT_PATH" || -n "$KEY_PATH" ) ]]; then
    echo "--server-name only affects local SNI when using --cert-file/--key-file; ACME stays disabled." >&2
  fi
}

release_layout_present() {
  [[ -f "$SCRIPT_DIR/noders-anytls" ]] &&
  [[ -f "$SCRIPT_DIR/config.example.toml" ]]
}

resolve_release_tag() {
  if [[ "$VERSION" != "latest" ]]; then
    printf '%s\n' "$VERSION"
    return
  fi
  need_cmd curl
  local tag
  tag="$(curl -fsSL "https://api.github.com/repos/$REPOSITORY/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$tag" ]] || {
    echo "Unable to detect the latest release tag for $REPOSITORY" >&2
    exit 1
  }
  printf '%s\n' "$tag"
}

bootstrap_release() {
  need_cmd curl
  need_cmd tar

  local tag asset_suffix package_name archive_path package_root
  tag="$(resolve_release_tag)"
  asset_suffix="$(detect_asset_suffix)"
  package_name="noders-anytls-${tag}-${asset_suffix}"
  TMP_ROOT="$(mktemp -d)"
  archive_path="$TMP_ROOT/${package_name}.tar.gz"

  echo "Downloading ${package_name}.tar.gz from GitHub Release ${tag}"
  curl -fL -o "$archive_path" "https://github.com/${REPOSITORY}/releases/download/${tag}/${package_name}.tar.gz"
  tar -xzf "$archive_path" -C "$TMP_ROOT"
  package_root="$TMP_ROOT/$package_name"
  [[ -d "$package_root" ]] || {
    echo "Release package layout is invalid: $package_root not found" >&2
    exit 1
  }
  [[ -f "$package_root/noders-anytls" ]] &&
  [[ -f "$package_root/config.example.toml" ]] || {
    echo "Release package layout is invalid: required install assets are missing under $package_root" >&2
    exit 1
  }

  install_from_bundle "$package_root"
}

ensure_directories() {
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$STATE_DIR" "$CONFIG_DIR/nodes" "$LOG_DIR" "$RUN_DIR"
}

sed_escape() {
  printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

render_config_file() {
  local template_path target_path panel_url panel_token node_id cert_path key_path tls_server_name acme_enabled acme_domain account_key_path escaped_url escaped_token escaped_node_id escaped_cert escaped_key escaped_tls_server_name escaped_dns_resolver escaped_ip_strategy escaped_acme_domain escaped_acme_email escaped_acme_challenge escaped_account_key
  template_path="$1"
  target_path="$2"
  panel_url="$3"
  panel_token="$4"
  node_id="$5"
  cert_path="$6"
  key_path="$7"
  tls_server_name="$8"
  acme_enabled="$9"
  acme_domain="${10}"
  account_key_path="${11}"

  escaped_url="$(sed_escape "$panel_url")"
  escaped_token="$(sed_escape "$panel_token")"
  escaped_node_id="$(sed_escape "$node_id")"
  escaped_cert="$(sed_escape "$cert_path")"
  escaped_key="$(sed_escape "$key_path")"
  escaped_tls_server_name="$(sed_escape "$tls_server_name")"
  escaped_dns_resolver="$(sed_escape "$DNS_RESOLVER")"
  escaped_ip_strategy="$(sed_escape "$IP_STRATEGY")"
  escaped_acme_domain="$(sed_escape "$acme_domain")"
  escaped_acme_email="$(sed_escape "$ACME_EMAIL")"
  escaped_acme_challenge="$(sed_escape "$ACME_CHALLENGE_LISTEN")"
  escaped_account_key="$(sed_escape "$account_key_path")"

  sed \
    -e "s#url = \"https://xboard.example.com\"#url = \"$escaped_url\"#g" \
    -e "s#token = \"replace-me\"#token = \"$escaped_token\"#g" \
    -e "s#node_id = 1#node_id = $escaped_node_id#g" \
    -e "s#cert_path = \"cert.pem\"#cert_path = \"$escaped_cert\"#g" \
    -e "s#key_path = \"key.pem\"#key_path = \"$escaped_key\"#g" \
    -e "s#server_name = \"\"#server_name = \"$escaped_tls_server_name\"#g" \
    -e "s#dns_resolver = \"system\"#dns_resolver = \"$escaped_dns_resolver\"#g" \
    -e "s#ip_strategy = \"system\"#ip_strategy = \"$escaped_ip_strategy\"#g" \
    -e "s#enabled = false#enabled = $acme_enabled#g" \
    -e "s#email = \"admin@example.com\"#email = \"$escaped_acme_email\"#g" \
    -e "s#domain = \"node.example.com\"#domain = \"$escaped_acme_domain\"#g" \
    -e "s#challenge_listen = \"\[::\]:80\"#challenge_listen = \"$escaped_acme_challenge\"#g" \
    -e "s#account_key_path = \"acme-account.pem\"#account_key_path = \"$escaped_account_key\"#g" \
    "$template_path" > "$target_path"
}

fetch_remote_server_name() {
  local panel_url panel_token node_id endpoint response http_code response_body server_name
  panel_url="${1%/}"
  panel_token="$2"
  node_id="$3"
  endpoint="$panel_url/api/v1/server/UniProxy/config"

  need_cmd curl
  if ! response="$(curl -sSL --get \
    --write-out $'\n%{http_code}' \
    --data-urlencode "token=$panel_token" \
    --data-urlencode "node_id=$node_id" \
    --data-urlencode "node_type=anytls" \
    "$endpoint")"; then
    echo "Unable to query $endpoint while discovering server_name." >&2
    return 1
  fi
  http_code="${response##*$'\n'}"
  response_body="${response%$'\n'*}"
  if [[ "$http_code" != "200" ]]; then
    echo "Xboard rejected automatic server_name discovery with HTTP $http_code from $endpoint." >&2
    if [[ "$http_code" == "403" ]]; then
      echo "This endpoint requires Xboard's global server_token; make sure --panel-token is admin_setting('server_token'), not a node key or user token." >&2
    fi
    if [[ -n "$response_body" ]]; then
      echo "Response body: $response_body" >&2
    fi
    echo "You can bypass auto-discovery by passing --server-name explicitly." >&2
    return 1
  fi
  response="$response_body"
  server_name="$(printf '%s' "$response" | tr -d '\n' | sed -n 's/.*"server_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  printf '%s\n' "$server_name"
}

node_cert_path() {
  printf '%s\n' "${CONFIG_DIR%/}/acme-cert-${1}.pem"
}

node_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/acme-key-${1}.pem"
}

node_account_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/acme-account-${1}.pem"
}

node_self_signed_cert_path() {
  printf '%s\n' "${CONFIG_DIR%/}/selfsigned-cert-${1}.pem"
}

node_self_signed_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/selfsigned-key-${1}.pem"
}

node_config_path() {
  printf '%s\n' "${CONFIG_DIR%/}/nodes/${1}.toml"
}

node_service_path() {
  printf '%s\n' "${OPENRC_DIR%/}/${SERVICE_NAME}-${1}"
}

node_service_pid_path() {
  printf '%s\n' "${RUN_DIR%/}/${SERVICE_NAME}-${1}.pid"
}

node_service_log_path() {
  printf '%s\n' "${LOG_DIR%/}/${SERVICE_NAME}-${1}.log"
}

generate_self_signed_certificate() {
  local server_name cert_path key_path tmp_config cert_dir
  server_name="$1"
  cert_path="$2"
  key_path="$3"
  cert_dir="$(dirname "$cert_path")"

  need_cmd openssl
  install -d "$cert_dir"
  tmp_config="$(mktemp)"
  trap 'rm -f "$tmp_config"' RETURN
  cat > "$tmp_config" <<EOF
[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no

[req_dn]
CN = $server_name

[v3_req]
subjectAltName = DNS:$server_name
EOF
  openssl req -x509 -newkey rsa:2048 -nodes \
    -days "$SELF_SIGNED_DAYS" \
    -config "$tmp_config" \
    -extensions v3_req \
    -keyout "$key_path" \
    -out "$cert_path" >/dev/null 2>&1
  trap - RETURN
  rm -f "$tmp_config"
  chmod 600 "$key_path"
  chmod 644 "$cert_path"
}

determine_tls_settings() {
  local panel_url panel_token node_id discovered_domain selected_server_name cert_path key_path acme_enabled acme_domain account_key_path
  panel_url="$1"
  panel_token="$2"
  node_id="$3"
  selected_server_name="$TLS_SERVER_NAME"
  account_key_path="$(node_account_key_path "$node_id")"

  if [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
    printf '%s|%s|%s|false|node.example.com|%s\n' "$CERT_PATH" "$KEY_PATH" "$selected_server_name" "$account_key_path"
    return
  fi

  if [[ -z "$selected_server_name" ]]; then
    if ! discovered_domain="$(fetch_remote_server_name "$panel_url" "$panel_token" "$node_id")"; then
      exit 1
    fi
    selected_server_name="$discovered_domain"
  fi

  [[ -n "$selected_server_name" ]] || {
    echo "Unable to discover server_name for node $node_id; pass --server-name explicitly or configure Xboard server_name." >&2
    exit 1
  }

  if [[ "$SELF_SIGNED" -eq 1 ]]; then
    cert_path="$(node_self_signed_cert_path "$node_id")"
    key_path="$(node_self_signed_key_path "$node_id")"
    generate_self_signed_certificate "$selected_server_name" "$cert_path" "$key_path"
    printf '%s|%s|%s|false|node.example.com|%s\n' "$cert_path" "$key_path" "$selected_server_name" "$account_key_path"
    return
  fi

  cert_path="$(node_cert_path "$node_id")"
  key_path="$(node_key_path "$node_id")"
  acme_enabled=true
  acme_domain="$selected_server_name"
  printf '%s|%s|%s|%s|%s|%s\n' "$cert_path" "$key_path" "$selected_server_name" "$acme_enabled" "$acme_domain" "$account_key_path"
}

write_xboard_configs() {
  local staging_dir template_path spec panel_url panel_token node_id tls_settings cert_path key_path tls_server_name config_path acme_enabled acme_domain account_key_path rest
  staging_dir="$1"
  template_path="$staging_dir/config.example.toml"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r panel_url panel_token node_id <<<"$spec"
    tls_settings="$(determine_tls_settings "$panel_url" "$panel_token" "$node_id")"
    cert_path="${tls_settings%%|*}"
    rest="${tls_settings#*|}"
    key_path="${rest%%|*}"
    rest="${rest#*|}"
    tls_server_name="${rest%%|*}"
    rest="${rest#*|}"
    acme_enabled="${rest%%|*}"
    rest="${rest#*|}"
    acme_domain="${rest%%|*}"
    account_key_path="${rest#*|}"
    config_path="$(node_config_path "$node_id")"
    render_config_file \
      "$template_path" \
      "$config_path" \
      "$panel_url" \
      "$panel_token" \
      "$node_id" \
      "$cert_path" \
      "$key_path" \
      "$tls_server_name" \
      "$acme_enabled" \
      "$acme_domain" \
      "$account_key_path"
    GENERATED_CONFIGS+=("$config_path")
  done
}

service_account_spec() {
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    printf '%s|%s\n' "$SERVICE_USER" "$SERVICE_GROUP"
    return
  fi

  if command -v addgroup >/dev/null 2>&1 && command -v adduser >/dev/null 2>&1; then
    addgroup -S "$SERVICE_GROUP" >/dev/null 2>&1 || true
    adduser -S -D -H -h "$STATE_DIR" -s /sbin/nologin -G "$SERVICE_GROUP" "$SERVICE_USER" >/dev/null 2>&1 || \
      adduser -S -D -H -h "$STATE_DIR" -s /bin/false -G "$SERVICE_GROUP" "$SERVICE_USER" >/dev/null 2>&1 || true
  elif command -v useradd >/dev/null 2>&1; then
    if command -v getent >/dev/null 2>&1; then
      getent group "$SERVICE_GROUP" >/dev/null 2>&1 || groupadd --system "$SERVICE_GROUP" >/dev/null 2>&1 || true
    else
      groupadd --system "$SERVICE_GROUP" >/dev/null 2>&1 || true
    fi
    useradd --system --home "$STATE_DIR" --gid "$SERVICE_GROUP" --shell /usr/sbin/nologin "$SERVICE_USER" >/dev/null 2>&1 || \
      useradd --system --home "$STATE_DIR" --gid "$SERVICE_GROUP" --shell /sbin/nologin "$SERVICE_USER" >/dev/null 2>&1 || \
      useradd --system --home "$STATE_DIR" --gid "$SERVICE_GROUP" --shell /bin/false "$SERVICE_USER" >/dev/null 2>&1 || true
  fi

  if id "$SERVICE_USER" >/dev/null 2>&1; then
    printf '%s|%s\n' "$SERVICE_USER" "$SERVICE_GROUP"
  else
    echo "Unable to create dedicated service user; falling back to root." >&2
    printf '%s|%s\n' "root" "root"
  fi
}

render_service_file() {
  local target node_id config_path service_user service_group pid_path log_path
  target="$1"
  node_id="$2"
  config_path="$3"
  service_user="$4"
  service_group="$5"
  pid_path="$(node_service_pid_path "$node_id")"
  log_path="$(node_service_log_path "$node_id")"

  cat > "$target" <<EOF
#!/sbin/openrc-run

name="${SERVICE_NAME}-${node_id}"
description="NodeRS-AnyTLS service for node ${node_id}"
command="${PREFIX}/bin/noders-anytls"
command_args="${config_path}"
command_user="${service_user}:${service_group}"
directory="${STATE_DIR}"
pidfile="${pid_path}"
command_background="yes"
start_stop_daemon_args="--stdout ${log_path} --stderr ${log_path}"

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath --directory --owner ${service_user}:${service_group} --mode 0755 "${STATE_DIR}" "${RUN_DIR}" "${LOG_DIR}"
  checkpath --file --owner ${service_user}:${service_group} --mode 0644 "${log_path}"
}
EOF
  chmod 0755 "$target"
}

install_service() {
  local service_user service_group spec node_id config_path service_path service_unit

  [[ "$NO_SERVICE" -eq 0 ]] || return 0
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Skipping OpenRC service installation because the script is not running as root."
    return 0
  fi
  if ! command -v rc-service >/dev/null 2>&1 || ! command -v rc-update >/dev/null 2>&1 || ! command -v start-stop-daemon >/dev/null 2>&1; then
    echo "OpenRC not detected; service installation skipped."
    return 0
  fi

  IFS='|' read -r service_user service_group <<<"$(service_account_spec)"
  chown -R "$service_user":"$service_group" "$STATE_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r _ _ node_id <<<"$spec"
    config_path="$(node_config_path "$node_id")"
    service_path="$(node_service_path "$node_id")"
    service_unit="${SERVICE_NAME}-${node_id}"
    render_service_file "$service_path" "$node_id" "$config_path" "$service_user" "$service_group"
    INSTALLED_SERVICES+=("$service_unit")
  done

  for service_unit in "${INSTALLED_SERVICES[@]}"; do
    rc-update add "$service_unit" default >/dev/null 2>&1 || true
    rc-service "$service_unit" restart >/dev/null 2>&1 || rc-service "$service_unit" start
  done
}

stop_disable_unit() {
  local unit_name service_path
  unit_name="$1"
  service_path="${OPENRC_DIR%/}/${unit_name}"
  if command -v rc-service >/dev/null 2>&1; then
    rc-service "$unit_name" stop >/dev/null 2>&1 || true
  fi
  if command -v rc-update >/dev/null 2>&1; then
    rc-update del "$unit_name" default >/dev/null 2>&1 || true
  fi
  rm -f "$service_path"
}

remove_service_account() {
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    if command -v deluser >/dev/null 2>&1; then
      deluser "$SERVICE_USER" >/dev/null 2>&1 || true
    elif command -v userdel >/dev/null 2>&1; then
      userdel "$SERVICE_USER" >/dev/null 2>&1 || true
    fi
  fi

  if command -v delgroup >/dev/null 2>&1; then
    delgroup "$SERVICE_GROUP" >/dev/null 2>&1 || true
  elif command -v groupdel >/dev/null 2>&1; then
    groupdel "$SERVICE_GROUP" >/dev/null 2>&1 || true
  fi
}

remove_single_node() {
  local node_id config_path cert_path key_path legacy_cert_path legacy_key_path account_key_path self_signed_cert_path self_signed_key_path unit_name log_path pid_path
  node_id="$1"
  config_path="$(node_config_path "$node_id")"
  cert_path="$(node_cert_path "$node_id")"
  key_path="$(node_key_path "$node_id")"
  legacy_cert_path="${CONFIG_DIR%/}/cert-${node_id}.pem"
  legacy_key_path="${CONFIG_DIR%/}/key-${node_id}.pem"
  account_key_path="$(node_account_key_path "$node_id")"
  self_signed_cert_path="$(node_self_signed_cert_path "$node_id")"
  self_signed_key_path="$(node_self_signed_key_path "$node_id")"
  unit_name="${SERVICE_NAME}-${node_id}"
  log_path="$(node_service_log_path "$node_id")"
  pid_path="$(node_service_pid_path "$node_id")"

  stop_disable_unit "$unit_name"
  rm -f "$config_path" "$cert_path" "$key_path" "$legacy_cert_path" "$legacy_key_path" "$account_key_path" "$self_signed_cert_path" "$self_signed_key_path" "$log_path" "$pid_path"
}

remove_all_nodes() {
  local unit_path unit_name
  for unit_path in "${OPENRC_DIR%/}/${SERVICE_NAME}-"*; do
    [[ -e "$unit_path" ]] || continue
    unit_name="$(basename "$unit_path")"
    stop_disable_unit "$unit_name"
  done

  rm -f "$PREFIX/bin/noders-anytls"
  rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$RUN_DIR"
  remove_service_account
}

uninstall() {
  require_linux
  normalize_paths

  if [[ "$REMOVE_ALL" -eq 1 || ${#TARGET_NODE_IDS[@]} -eq 0 ]]; then
    remove_all_nodes
    echo "Removed all NodeRS-AnyTLS nodes, configs, OpenRC services, logs, and binary."
    return
  fi

  for node_id in "${TARGET_NODE_IDS[@]}"; do
    remove_single_node "$node_id"
    echo "Removed node ${node_id}."
  done
}

print_summary() {
  local service_unit log_path tls_summary
  if [[ "$SELF_SIGNED" -eq 1 ]]; then
    tls_summary="Self-signed certificates generated locally from --server-name or Xboard server_name"
  elif [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
    tls_summary="Using existing certificate files from --cert-file/--key-file"
  else
    tls_summary="Auto ACME from local --server-name or Xboard server_name"
  fi
  cat <<EOF
Installed NodeRS-AnyTLS (OpenRC)
  Binary: $PREFIX/bin/noders-anytls
  State:  $STATE_DIR
  Logs:   $LOG_DIR
  TLS:    $tls_summary
EOF

  for config_path in "${GENERATED_CONFIGS[@]}"; do
    echo "  Config: $config_path"
  done
  for service_unit in "${INSTALLED_SERVICES[@]}"; do
    log_path="${LOG_DIR%/}/${service_unit}.log"
    echo "  Service: $service_unit"
    echo "  Log:     $log_path"
  done
}

install_from_bundle() {
  local staging_dir
  staging_dir="$1"

  ensure_directories
  install -m 0755 "$staging_dir/noders-anytls" "$PREFIX/bin/noders-anytls"
  write_xboard_configs "$staging_dir"
  install_service
  print_summary
}

main() {
  parse_args "$@"
  validate_args

  if [[ "$UNINSTALL" -eq 1 ]]; then
    uninstall
    return
  fi

  require_linux
  normalize_paths

  if ! release_layout_present; then
    bootstrap_release
    return
  fi

  install_from_bundle "$SCRIPT_DIR"
}

main "$@"
