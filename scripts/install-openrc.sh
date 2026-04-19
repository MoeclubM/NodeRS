#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="MoeclubM/NodeRS"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
COMMON_LIB_PATH="$SCRIPT_DIR/lib/install-common.sh"
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
NO_SERVICE=0
UNINSTALL=0
REMOVE_ALL=0
PANEL_API=""
PANEL_KEY=""
PANEL_MACHINE_ID=""
TMP_ROOT=""
declare -a XBOARD_SPECS=()
declare -a GENERATED_CONFIGS=()
declare -a INSTALLED_SERVICES=()
declare -a TARGET_MACHINE_IDS=()

if [[ -f "$COMMON_LIB_PATH" ]]; then
  # shellcheck source=/dev/null
  source "$COMMON_LIB_PATH"
fi

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
  Pass `--uninstall` to remove one machine instance or the whole installation.

Options:
  --version <tag>             Release tag to install, default: latest
  --prefix <path>             Binary installation prefix, default: /usr/local
  --config-dir <path>         Config directory, default: /etc/noders/anytls
  --state-dir <path>          Working directory, default: /var/lib/noders/anytls
  --api <url>                 Xboard API address
  --key <token>               Xboard machine key
  --machine-id <id>           Xboard machine id
  --machine <url> <key> <id>  Add one Xboard machine triplet; may be repeated
  --uninstall                 Remove installed service(s), binary, and related files
  --all                       Used with --uninstall to remove all nodes and all data
  --no-service                Skip OpenRC service installation
  -h, --help                  Show this help message

Examples:
  bash install-openrc.sh --api https://api.example.com --key token --machine-id 1
  bash install-openrc.sh --machine https://api.example.com tokenA 1 --machine https://api.example.com tokenB 2
  bash install-openrc.sh --api https://api.example.com --key token --machine-id 171 --uninstall
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

detect_asset_suffix() {
  if declare -F detect_release_asset_suffix >/dev/null 2>&1; then
    detect_release_asset_suffix
    return
  fi

  local detected_glibc_version libc_family
  version_at_least() {
    local lhs rhs
    lhs="$1"
    rhs="$2"
    awk -v lhs="$lhs" -v rhs="$rhs" '
      BEGIN {
        split(lhs, left, ".");
        split(rhs, right, ".");
        max_len = length(left) > length(right) ? length(left) : length(right);
        for (i = 1; i <= max_len; i++) {
          left_part = (i in left) ? left[i] + 0 : 0;
          right_part = (i in right) ? right[i] + 0 : 0;
          if (left_part > right_part) exit 0;
          if (left_part < right_part) exit 1;
        }
        exit 0;
      }
    '
  }
  glibc_version() {
    if command -v getconf >/dev/null 2>&1; then
      getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}'
    fi
  }
  detect_local_libc() {
    local output version
    version="$(glibc_version)"
    if [[ -n "$version" ]]; then
      printf 'glibc\n'
      return
    fi
    if command -v ldd >/dev/null 2>&1; then
      output="$(ldd --version 2>&1 || true)"
      if printf '%s' "$output" | grep -qi 'musl'; then
        printf 'musl\n'
        return
      fi
    fi
    if compgen -G '/lib/ld-musl-*.so.1' >/dev/null || compgen -G '/usr/lib/ld-musl-*.so.1' >/dev/null; then
      printf 'musl\n'
      return
    fi
    printf 'unknown\n'
  }

  case "$(uname -m)" in
    x86_64|amd64)
      libc_family="$(detect_local_libc)"
      if [[ "$libc_family" == "glibc" ]]; then
        detected_glibc_version="$(glibc_version)"
        if [[ -n "$detected_glibc_version" ]] && version_at_least "$detected_glibc_version" "2.17"; then
          printf 'linux-amd64\n'
          return
        fi
        echo "Detected glibc ${detected_glibc_version:-unknown}; falling back to linux-amd64-musl because GNU builds target glibc >= 2.17." >&2
        printf 'linux-amd64-musl\n'
        return
      fi
      if [[ "$libc_family" == "musl" ]]; then
        echo "Detected musl userspace; using linux-amd64-musl release bundle." >&2
      else
        echo "Unable to detect the host libc; using linux-amd64-musl release bundle for compatibility." >&2
      fi
      printf 'linux-amd64-musl\n'
      ;;
    *)
      echo "Unsupported architecture for prebuilt releases: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

release_layout_present() {
  [[ -f "$SCRIPT_DIR/noders-anytls" ]] &&
  [[ -f "$SCRIPT_DIR/config.example.toml" ]] &&
  [[ -f "$COMMON_LIB_PATH" ]]
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

  local tag asset_suffix package_name archive_path package_root bundle_script
  tag="$(resolve_release_tag)"
  asset_suffix="$(detect_asset_suffix)"
  package_name="noders-anytls-${tag}-${asset_suffix}"
  TMP_ROOT="$(mktemp -d)"
  archive_path="$TMP_ROOT/${package_name}.tar.gz"

  echo "Downloading ${package_name}.tar.gz from GitHub Release ${tag}"
  curl -fL -o "$archive_path" "https://github.com/${REPOSITORY}/releases/download/${tag}/${package_name}.tar.gz"
  tar -xzf "$archive_path" -C "$TMP_ROOT"
  package_root="$TMP_ROOT/$package_name"
  bundle_script="$package_root/install-openrc.sh"
  [[ -d "$package_root" && -f "$bundle_script" && -f "$package_root/lib/install-common.sh" ]] || {
    echo "Release package layout is invalid under $package_root" >&2
    exit 1
  }

  exec bash "$bundle_script" "$@"
}

bootstrap_args_only() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        VERSION="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        shift
        ;;
    esac
  done
}

load_common_or_bootstrap() {
  if declare -F parse_args >/dev/null 2>&1; then
    return
  fi

  bootstrap_args_only "$@"
  bootstrap_release "$@"
}

ensure_directories() {
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$STATE_DIR" "$CONFIG_DIR/machines" "$LOG_DIR" "$RUN_DIR"
}

node_service_path() {
  openrc_node_service_path "$1"
}

node_service_pid_path() {
  openrc_node_service_pid_path "$1"
}

node_service_log_path() {
  openrc_node_service_log_path "$1"
}

service_account_spec() {
  local user group
  user="$SERVICE_USER"
  group="$SERVICE_GROUP"

  if [[ "$(id -u)" -ne 0 ]]; then
    printf '%s|%s\n' "$user" "$group"
    return
  fi

  if ! getent group "$group" >/dev/null 2>&1; then
    if command -v addgroup >/dev/null 2>&1; then
      addgroup -S "$group" >/dev/null 2>&1 || true
    elif command -v groupadd >/dev/null 2>&1; then
      groupadd --system "$group" >/dev/null 2>&1 || true
    fi
  fi

  if ! id "$user" >/dev/null 2>&1; then
    if command -v adduser >/dev/null 2>&1; then
      adduser -S -D -H -h "$STATE_DIR" -s /sbin/nologin -G "$group" "$user" >/dev/null 2>&1 || true
    elif command -v useradd >/dev/null 2>&1; then
      useradd --system --home "$STATE_DIR" --shell /sbin/nologin --gid "$group" "$user" >/dev/null 2>&1 || true
    fi
  fi

  printf '%s|%s\n' "$user" "$group"
}

render_service_file() {
  render_openrc_service_file "$@"
}

install_service() {
  local service_user service_group spec machine_id config_path service_path service_unit

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
    IFS='|' read -r _ _ machine_id <<<"$spec"
    config_path="$(node_config_path "$machine_id")"
    service_path="$(node_service_path "$machine_id")"
    service_unit="${SERVICE_NAME}-${machine_id}"
    render_service_file "$service_path" "$machine_id" "$config_path" "$service_user" "$service_group"
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
  local machine_id config_path unit_name log_path pid_path
  machine_id="$1"
  config_path="$(node_config_path "$machine_id")"
  unit_name="${SERVICE_NAME}-${machine_id}"
  log_path="$(node_service_log_path "$machine_id")"
  pid_path="$(node_service_pid_path "$machine_id")"

  stop_disable_unit "$unit_name"
  rm -f "$config_path" "$log_path" "$pid_path"
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

  if [[ "$REMOVE_ALL" -eq 1 || ${#TARGET_MACHINE_IDS[@]} -eq 0 ]]; then
    remove_all_nodes
    echo "Removed all NodeRS machine instances, configs, OpenRC services, logs, and binary."
    return
  fi

  for machine_id in "${TARGET_MACHINE_IDS[@]}"; do
    remove_single_node "$machine_id"
    echo "Removed machine ${machine_id}."
  done
}

print_summary() {
  local service_unit log_path
  cat <<EOF
Installed NodeRS (OpenRC)
  Binary: $PREFIX/bin/noders-anytls
  State:  $STATE_DIR
  Logs:   $LOG_DIR
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
  load_common_or_bootstrap "$@"
  parse_args "$@"
  validate_args

  if [[ "$UNINSTALL" -eq 1 ]]; then
    uninstall
    return
  fi

  require_linux

  if ! release_layout_present; then
    bootstrap_release "$@"
    return
  fi

  install_from_bundle "$SCRIPT_DIR"
}

main "$@"
