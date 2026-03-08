#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PREFIX="/usr/local"
CONFIG_DIR="/etc/noders/anytls"
STATE_DIR="/var/lib/noders/anytls"
SERVICE_NAME="noders-anytls"
SERVICE_USER="noders-anytls"
SELF_SIGNED_DOMAIN=""
ACME_DOMAIN=""
ACME_EMAIL=""
ACME_CHALLENGE_LISTEN="0.0.0.0:80"
NO_SERVICE=0
CERT_PATH=""
KEY_PATH=""
PANEL_URL=""
PANEL_TOKEN=""
PANEL_NODE_ID=""
declare -a XBOARD_SPECS=()
declare -a GENERATED_CONFIGS=()
declare -a INSTALLED_SERVICES=()

usage() {
  cat <<'EOF'
Usage: install.sh [options]

This installer is for Linux release packages only. Run it from the unpacked
release directory that already contains `noders-anytls`, `config.example.toml`
and `packaging/systemd/noders-anytls.service`.

Options:
  --prefix <path>             Binary installation prefix, default: /usr/local
  --config-dir <path>         Config directory, default: /etc/noders/anytls
  --state-dir <path>          Working directory, default: /var/lib/noders/anytls
  --panel-url <url>           Single-node Xboard API address
  --panel-token <token>       Single-node Xboard key/token
  --node-id <id>              Single-node Xboard node id
  --xboard <url> <token> <id> Add one Xboard node triplet; may be repeated
  --self-signed-domain <fqdn> Generate a self-signed certificate into the config directory
  --acme-domain <fqdn>        Enable embedded ACME HTTP-01 for this domain
  --acme-email <mailbox>      Contact email for ACME account registration
  --acme-challenge-listen <addr>
                              HTTP-01 listener address, default: 0.0.0.0:80
  --no-service                Skip systemd service installation
  -h, --help                  Show this help message

Examples:
  ./install.sh --panel-url https://api.example.com --panel-token token --node-id 1
  ./install.sh --xboard https://api.example.com tokenA 1 --xboard https://api.example.com tokenB 2
  ./install.sh --xboard https://api.example.com token 1 --self-signed-domain node.example.com
  ./install.sh --xboard https://api.example.com token 1 --acme-domain node.example.com --acme-email admin@example.com
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
    echo "This installer only supports Linux release packages." >&2
    exit 1
  fi
}

normalize_paths() {
  CERT_PATH="${CONFIG_DIR%/}/cert.pem"
  KEY_PATH="${CONFIG_DIR%/}/key.pem"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
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
        shift 2
        ;;
      --xboard)
        XBOARD_SPECS+=("$2|$3|$4")
        shift 4
        ;;
      --self-signed-domain)
        SELF_SIGNED_DOMAIN="$2"
        shift 2
        ;;
      --acme-domain)
        ACME_DOMAIN="$2"
        shift 2
        ;;
      --acme-email)
        ACME_EMAIL="$2"
        shift 2
        ;;
      --acme-challenge-listen)
        ACME_CHALLENGE_LISTEN="$2"
        shift 2
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

  if [[ -n "$SELF_SIGNED_DOMAIN" && -n "$ACME_DOMAIN" ]]; then
    echo "--self-signed-domain and --acme-domain are mutually exclusive." >&2
    exit 1
  fi
}

find_local_staging() {
  [[ -f "$SCRIPT_DIR/noders-anytls" ]] || return 1
  [[ -f "$SCRIPT_DIR/config.example.toml" ]] || return 1
  [[ -f "$SCRIPT_DIR/packaging/systemd/noders-anytls.service" ]] || return 1
  printf '%s\n' "$SCRIPT_DIR"
}

ensure_directories() {
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$STATE_DIR" "$CONFIG_DIR/nodes"
}

sed_escape() {
  printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

render_config_file() {
  local template_path target_path panel_url panel_token node_id cert_path key_path acme_enabled acme_domain account_key_path escaped_url escaped_token escaped_node_id escaped_cert escaped_key escaped_acme_domain escaped_acme_email escaped_acme_challenge escaped_account_key
  template_path="$1"
  target_path="$2"
  panel_url="$3"
  panel_token="$4"
  node_id="$5"
  cert_path="$6"
  key_path="$7"
  acme_enabled="$8"
  acme_domain="$9"
  account_key_path="${10}"

  escaped_url="$(sed_escape "$panel_url")"
  escaped_token="$(sed_escape "$panel_token")"
  escaped_node_id="$(sed_escape "$node_id")"
  escaped_cert="$(sed_escape "$cert_path")"
  escaped_key="$(sed_escape "$key_path")"
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
    -e "s#enabled = false#enabled = $acme_enabled#g" \
    -e "s#email = \"admin@example.com\"#email = \"$escaped_acme_email\"#g" \
    -e "s#domain = \"node.example.com\"#domain = \"$escaped_acme_domain\"#g" \
    -e "s#challenge_listen = \"0.0.0.0:80\"#challenge_listen = \"$escaped_acme_challenge\"#g" \
    -e "s#account_key_path = \"acme-account.pem\"#account_key_path = \"$escaped_account_key\"#g" \
    "$template_path" > "$target_path"
}

generate_self_signed_certificate() {
  local domain cert_path key_path
  domain="$1"
  cert_path="$2"
  key_path="$3"

  [[ -n "$domain" ]] || {
    echo "Cannot generate self-signed certificate without a domain." >&2
    exit 1
  }
  if [[ -f "$cert_path" && -f "$key_path" ]]; then
    echo "TLS files already exist for $domain, skipping self-signed generation."
    return 0
  fi
  need_cmd openssl
  install -d "$(dirname "$cert_path")" "$(dirname "$key_path")"
  echo "Generating self-signed certificate for $domain"
  if ! openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -subj "/CN=$domain" \
      -addext "subjectAltName=DNS:$domain" \
      -keyout "$key_path" \
      -out "$cert_path"; then
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -subj "/CN=$domain" \
      -keyout "$key_path" \
      -out "$cert_path"
  fi
  chmod 600 "$key_path"
}

fetch_remote_server_name() {
  local panel_url panel_token node_id response server_name
  panel_url="${1%/}"
  panel_token="$2"
  node_id="$3"

  need_cmd curl
  response="$(curl -fsSL --get \
    --data-urlencode "token=$panel_token" \
    --data-urlencode "node_id=$node_id" \
    --data-urlencode "node_type=anytls" \
    "$panel_url/api/v1/server/UniProxy/config")"
  server_name="$(printf '%s' "$response" | tr -d '\n' | sed -n 's/.*"server_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  printf '%s\n' "$server_name"
}

node_cert_path() {
  printf '%s\n' "${CONFIG_DIR%/}/cert-${1}.pem"
}

node_key_path() {
  printf '%s\n' "${CONFIG_DIR%/}/key-${1}.pem"
}

node_config_path() {
  printf '%s\n' "${CONFIG_DIR%/}/nodes/${1}.toml"
}

determine_tls_paths() {
  local panel_url panel_token node_id discovered_domain
  panel_url="$1"
  panel_token="$2"
  node_id="$3"

  if [[ -n "$ACME_DOMAIN" ]]; then
    printf '%s|%s\n' "$CERT_PATH" "$KEY_PATH"
    return
  fi

  if [[ -n "$SELF_SIGNED_DOMAIN" ]]; then
    generate_self_signed_certificate "$SELF_SIGNED_DOMAIN" "$CERT_PATH" "$KEY_PATH"
    printf '%s|%s\n' "$CERT_PATH" "$KEY_PATH"
    return
  fi

  if [[ -f "$CERT_PATH" && -f "$KEY_PATH" ]]; then
    printf '%s|%s\n' "$CERT_PATH" "$KEY_PATH"
    return
  fi

  discovered_domain="$(fetch_remote_server_name "$panel_url" "$panel_token" "$node_id")"
  [[ -n "$discovered_domain" ]] || {
    echo "Unable to discover server_name for node $node_id; pass --self-signed-domain or --acme-domain." >&2
    exit 1
  }
  generate_self_signed_certificate "$discovered_domain" "$(node_cert_path "$node_id")" "$(node_key_path "$node_id")"
  printf '%s|%s\n' "$(node_cert_path "$node_id")" "$(node_key_path "$node_id")"
}

write_default_config() {
  local staging_dir template_path acme_enabled acme_domain account_key_path cert_path key_path
  staging_dir="$1"
  template_path="$staging_dir/config.example.toml"
  cert_path="$CERT_PATH"
  key_path="$KEY_PATH"
  if [[ -n "$SELF_SIGNED_DOMAIN" ]]; then
    generate_self_signed_certificate "$SELF_SIGNED_DOMAIN" "$cert_path" "$key_path"
  fi
  if [[ -n "$ACME_DOMAIN" ]]; then
    acme_enabled=true
    acme_domain="$ACME_DOMAIN"
  else
    acme_enabled=false
    acme_domain="node.example.com"
  fi
  account_key_path="${CONFIG_DIR%/}/acme-account.pem"
  render_config_file \
    "$template_path" \
    "$CONFIG_DIR/config.toml" \
    "https://xboard.example.com" \
    "replace-me" \
    "1" \
    "$cert_path" \
    "$key_path" \
    "$acme_enabled" \
    "$acme_domain" \
    "$account_key_path"
}

write_xboard_configs() {
  local staging_dir template_path spec panel_url panel_token node_id tls_paths cert_path key_path config_path acme_enabled acme_domain account_key_path
  staging_dir="$1"
  template_path="$staging_dir/config.example.toml"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r panel_url panel_token node_id <<<"$spec"
    tls_paths="$(determine_tls_paths "$panel_url" "$panel_token" "$node_id")"
    cert_path="${tls_paths%%|*}"
    key_path="${tls_paths##*|}"
    config_path="$(node_config_path "$node_id")"
    if [[ -n "$ACME_DOMAIN" ]]; then
      acme_enabled=true
      acme_domain="$ACME_DOMAIN"
    else
      acme_enabled=false
      acme_domain="node.example.com"
    fi
    account_key_path="${CONFIG_DIR%/}/acme-account.pem"
    render_config_file \
      "$template_path" \
      "$config_path" \
      "$panel_url" \
      "$panel_token" \
      "$node_id" \
      "$cert_path" \
      "$key_path" \
      "$acme_enabled" \
      "$acme_domain" \
      "$account_key_path"
    GENERATED_CONFIGS+=("$config_path")
  done
}

render_service_file() {
  local staging_dir target config_path template shell_path
  staging_dir="$1"
  target="$2"
  config_path="$3"
  template="$staging_dir/packaging/systemd/noders-anytls.service"
  [[ -f "$template" ]] || {
    echo "Missing service template at $template" >&2
    exit 1
  }
  shell_path="/usr/sbin/nologin"
  if [[ ! -x "$shell_path" ]]; then
    shell_path="/sbin/nologin"
  fi
  sed \
    -e "s#__BINARY__#$PREFIX/bin/noders-anytls#g" \
    -e "s#__CONFIG__#$config_path#g" \
    -e "s#__STATE_DIR__#$STATE_DIR#g" \
    -e "s#__USER__#$SERVICE_USER#g" \
    -e "s#__SHELL__#$shell_path#g" \
    "$template" > "$target"
}

install_service() {
  local staging_dir spec node_id config_path unit_path service_unit
  staging_dir="$1"
  [[ "$NO_SERVICE" -eq 0 ]] || return 0
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Skipping service installation because the script is not running as root."
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd not detected; service installation skipped."
    return 0
  fi
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || \
      useradd --system --home "$STATE_DIR" --shell /sbin/nologin "$SERVICE_USER"
  fi
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$STATE_DIR" "$CONFIG_DIR"

  if [[ ${#XBOARD_SPECS[@]} -eq 0 ]]; then
    unit_path="/etc/systemd/system/${SERVICE_NAME}.service"
    render_service_file "$staging_dir" "$unit_path" "$CONFIG_DIR/config.toml"
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"
    INSTALLED_SERVICES+=("$SERVICE_NAME")
    return
  fi

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r _ _ node_id <<<"$spec"
    config_path="$(node_config_path "$node_id")"
    service_unit="${SERVICE_NAME}-${node_id}"
    unit_path="/etc/systemd/system/${service_unit}.service"
    render_service_file "$staging_dir" "$unit_path" "$config_path"
    INSTALLED_SERVICES+=("$service_unit")
  done

  systemctl daemon-reload
  for service_unit in "${INSTALLED_SERVICES[@]}"; do
    systemctl enable --now "$service_unit"
  done
}

print_summary() {
  local service_unit
  cat <<EOF
Installed NodeRS-AnyTLS
  Binary: $PREFIX/bin/noders-anytls
  State:  $STATE_DIR
EOF

  if [[ ${#XBOARD_SPECS[@]} -eq 0 ]]; then
    echo "  Config: $CONFIG_DIR/config.toml"
    echo "  Cert:   $CERT_PATH"
    echo "  Key:    $KEY_PATH"
  else
    for config_path in "${GENERATED_CONFIGS[@]}"; do
      echo "  Config: $config_path"
    done
  fi

  for service_unit in "${INSTALLED_SERVICES[@]}"; do
    echo "  Service: $service_unit"
  done
  if [[ -n "$ACME_DOMAIN" ]]; then
    echo "  ACME:   enabled for $ACME_DOMAIN via HTTP-01 on $ACME_CHALLENGE_LISTEN"
  fi
}

main() {
  parse_args "$@"
  validate_args
  require_linux
  normalize_paths

  local staging_dir
  staging_dir="$(find_local_staging)" || {
    echo "Release package files not found next to install.sh. Use the unpacked Linux release bundle." >&2
    exit 1
  }

  ensure_directories
  install -m 0755 "$staging_dir/noders-anytls" "$PREFIX/bin/noders-anytls"

  if [[ ${#XBOARD_SPECS[@]} -eq 0 ]]; then
    if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
      write_default_config "$staging_dir"
    fi
  else
    write_xboard_configs "$staging_dir"
  fi

  install_service "$staging_dir"
  print_summary
}

main "$@"
