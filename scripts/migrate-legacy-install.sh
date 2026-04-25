#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="MoeclubM/NodeRS"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
COMMON_LIB_PATH="$SCRIPT_DIR/lib/install-common.sh"
PREFIX="/usr/local"
CONFIG_DIR="/etc/noders/anytls"
STATE_DIR="/var/lib/noders/anytls"
SERVICE_NAME="noders"
LEGACY_SERVICE_NAME="${SERVICE_NAME}-anytls"
SERVICE_USER="noders"
SERVICE_GROUP="noders"
SYSTEMD_UNIT_DIR="/etc/systemd/system"
OPENRC_DIR="/etc/init.d"
RUN_DIR="/run/noders"
LOG_DIR="/var/log/noders"
LEGACY_OPENRC_USER="noders-anytls"
LEGACY_OPENRC_GROUP="noders-anytls"
LEGACY_OPENRC_RUN_DIR="/run/noders-anytls"
LEGACY_OPENRC_LOG_DIR="/var/log/noders-anytls"
VERSION="latest"
TMP_ROOT=""
BACKUP_DIR=""
SERVICE_MANAGER="none"
declare -a DISCOVERED_CONFIGS=()
declare -a MACHINE_SPECS=()
declare -a TARGET_MACHINE_IDS=()
declare -a MIGRATED_ITEMS=()
declare -a WARNING_MESSAGES=()
declare -A SEEN_INSTANCE_IDS=()

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
Usage: migrate-legacy-install.sh [options]

Migrate a legacy noders-anytls Linux install to the current noders runtime
layout. The script reads existing machine configs, reinstalls the current
runtime, and cleans up known legacy binary/service artifacts.

Options:
  --version <tag>       Release tag to install, default: latest
  --prefix <path>       Binary prefix, default: /usr/local
  --config-dir <path>   Config directory, default: /etc/noders/anytls
  --state-dir <path>    Working directory, default: /var/lib/noders/anytls
  -h, --help            Show this help message

Examples:
  bash migrate-legacy-install.sh
  bash migrate-legacy-install.sh --version v0.1.0
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
    echo "This migrator only supports Linux." >&2
    exit 1
  fi
}

detect_asset_suffix() {
  if declare -F detect_release_asset_suffix >/dev/null 2>&1; then
    detect_release_asset_suffix
    return
  fi

  local arch detected_glibc_version libc_family asset_prefix
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

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      asset_prefix='linux-amd64'
      ;;
    aarch64|arm64)
      asset_prefix='linux-arm64'
      ;;
    *)
      echo "Unsupported architecture for prebuilt releases: $arch" >&2
      exit 1
      ;;
  esac

  libc_family="$(detect_local_libc)"
  if [[ "$libc_family" == "glibc" ]]; then
    detected_glibc_version="$(glibc_version)"
    if [[ -n "$detected_glibc_version" ]] && version_at_least "$detected_glibc_version" "2.17"; then
      printf '%s\n' "$asset_prefix"
      return
    fi
    echo "Detected glibc ${detected_glibc_version:-unknown}; falling back to ${asset_prefix}-musl because GNU builds target glibc >= 2.17." >&2
    printf '%s-musl\n' "$asset_prefix"
    return
  fi
  if [[ "$libc_family" == "musl" ]]; then
    echo "Detected musl userspace; using ${asset_prefix}-musl release bundle." >&2
  else
    echo "Unable to detect the host libc; using ${asset_prefix}-musl release bundle for compatibility." >&2
  fi
  printf '%s-musl\n' "$asset_prefix"
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

release_layout_present() {
  [[ -f "$SCRIPT_DIR/noders" ]] &&
  [[ -f "$SCRIPT_DIR/config.example.toml" ]] &&
  [[ -f "$SCRIPT_DIR/install.sh" ]] &&
  [[ -f "$SCRIPT_DIR/install-openrc.sh" ]] &&
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
  need_cmd mktemp

  local tag asset_suffix package_name archive_path package_root
  tag="$(resolve_release_tag)"
  asset_suffix="$(detect_asset_suffix)"
  package_name="noders-${tag}-${asset_suffix}"
  TMP_ROOT="$(mktemp -d)"
  archive_path="$TMP_ROOT/${package_name}.tar.gz"

  echo "Downloading ${package_name}.tar.gz from GitHub Release ${tag}"
  curl -fL -o "$archive_path" "https://github.com/${REPOSITORY}/releases/download/${tag}/${package_name}.tar.gz"
  tar -xzf "$archive_path" -C "$TMP_ROOT"
  package_root="$TMP_ROOT/$package_name"
  [[ -d "$package_root" && -f "$package_root/migrate-legacy-install.sh" && -f "$package_root/lib/install-common.sh" ]] || {
    echo "Release package layout is invalid under $package_root" >&2
    exit 1
  }

  exec bash "$package_root/migrate-legacy-install.sh" "$@"
}

record_migration() {
  MIGRATED_ITEMS+=("$1")
}

record_warning() {
  WARNING_MESSAGES+=("$1")
}

ensure_backup_dir() {
  if [[ -n "$BACKUP_DIR" ]]; then
    return
  fi
  BACKUP_DIR="${CONFIG_DIR%/}/migration-backups/legacy-install-$(date +%Y%m%d-%H%M%S)"
  install -d "$BACKUP_DIR"
}

backup_path() {
  local src target
  src="$1"
  [[ -e "$src" ]] || return 0

  ensure_backup_dir
  target="${BACKUP_DIR%/}/${src#/}"
  if [[ -e "$target" ]]; then
    return 0
  fi

  install -d "$(dirname "$target")"
  if [[ -d "$src" ]]; then
    cp -pR "$src" "$target"
  else
    cp -p "$src" "$target"
  fi
}

parse_machine_config() {
  local config_path
  config_path="$1"

  awk '
    function trim_quotes(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value ~ /^".*"$/) {
        sub(/^"/, "", value)
        sub(/"$/, "", value)
      }
      return value
    }

    BEGIN {
      in_panel = 0
    }

    /^[[:space:]]*\[/ {
      in_panel = ($0 ~ /^[[:space:]]*\[panel\][[:space:]]*$/)
      next
    }

    !in_panel {
      next
    }

    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
    }

    /^[[:space:]]*api[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", line)
      api = trim_quotes(line)
      next
    }

    /^[[:space:]]*key[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", line)
      key = trim_quotes(line)
      next
    }

    /^[[:space:]]*machine_id[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", line)
      machine_id = trim_quotes(line)
      next
    }

    END {
      if (api != "" && key != "" && machine_id != "") {
        printf "%s|%s|%s\n", api, key, machine_id
      }
    }
  ' "$config_path"
}

append_machine_spec() {
  local panel_api panel_key machine_id instance_id
  panel_api="$1"
  panel_key="$2"
  machine_id="$3"
  instance_id="$(machine_instance_id "$panel_api" "$machine_id")"

  if [[ -n "${SEEN_INSTANCE_IDS[$instance_id]:-}" ]]; then
    return 0
  fi

  SEEN_INSTANCE_IDS["$instance_id"]=1
  MACHINE_SPECS+=("$panel_api|$panel_key|$machine_id")
  TARGET_MACHINE_IDS+=("$machine_id")
}

discover_machine_configs() {
  local config_path
  DISCOVERED_CONFIGS=()

  if [[ -d "${CONFIG_DIR%/}/machines" ]]; then
    shopt -s nullglob
    for config_path in "${CONFIG_DIR%/}/machines/"*.toml; do
      [[ -f "$config_path" ]] || continue
      DISCOVERED_CONFIGS+=("$config_path")
    done
    shopt -u nullglob
  fi

  if [[ ${#DISCOVERED_CONFIGS[@]} -eq 0 ]]; then
    echo "No machine configs were found under ${CONFIG_DIR%/}/machines." >&2
    echo "This migrator currently supports legacy noders-anytls machine installs only." >&2
    exit 1
  fi
}

collect_machine_specs() {
  local config_path spec panel_api panel_key machine_id

  MACHINE_SPECS=()
  TARGET_MACHINE_IDS=()
  SEEN_INSTANCE_IDS=()

  for config_path in "${DISCOVERED_CONFIGS[@]}"; do
    spec="$(parse_machine_config "$config_path")"
    if [[ -z "$spec" ]]; then
      record_warning "Skipping config with unreadable panel settings: $config_path"
      continue
    fi
    IFS='|' read -r panel_api panel_key machine_id <<<"$spec"
    if [[ ! "$machine_id" =~ ^[0-9]+$ ]]; then
      record_warning "Skipping config with invalid machine_id: $config_path"
      continue
    fi
    append_machine_spec "$panel_api" "$panel_key" "$machine_id"
  done

  if [[ ${#MACHINE_SPECS[@]} -eq 0 ]]; then
    echo "No valid machine configs could be parsed from ${CONFIG_DIR%/}/machines." >&2
    exit 1
  fi
}

has_systemd_units() {
  local unit_path
  shopt -s nullglob
  for unit_path in \
    "$SYSTEMD_UNIT_DIR/${SERVICE_NAME}.service" \
    "$SYSTEMD_UNIT_DIR/${SERVICE_NAME}-"*.service \
    "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}.service" \
    "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}-"*.service; do
    [[ -f "$unit_path" ]] || continue
    shopt -u nullglob
    return 0
  done
  shopt -u nullglob
  return 1
}

has_openrc_units() {
  local service_path
  shopt -s nullglob
  for service_path in \
    "$OPENRC_DIR/${SERVICE_NAME}" \
    "$OPENRC_DIR/${SERVICE_NAME}-"* \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}" \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}-"*; do
    [[ -f "$service_path" ]] || continue
    shopt -u nullglob
    return 0
  done
  shopt -u nullglob
  return 1
}

detect_service_manager() {
  if has_systemd_units; then
    SERVICE_MANAGER="systemd"
    return
  fi

  if has_openrc_units; then
    SERVICE_MANAGER="openrc"
    return
  fi

  if command -v systemctl >/dev/null 2>&1; then
    SERVICE_MANAGER="systemd"
    return
  fi

  if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    SERVICE_MANAGER="openrc"
    return
  fi

  echo "No supported service manager was detected on this host." >&2
  exit 1
}

legacy_openrc_artifacts_present() {
  local service_path

  shopt -s nullglob
  for service_path in \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}" \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}-"*; do
    [[ -f "$service_path" ]] || continue
    shopt -u nullglob
    return 0
  done
  shopt -u nullglob

  [[ -d "$LEGACY_OPENRC_LOG_DIR" || -d "$LEGACY_OPENRC_RUN_DIR" ]]
}

legacy_group_exists() {
  if command -v getent >/dev/null 2>&1; then
    getent group "$LEGACY_OPENRC_GROUP" >/dev/null 2>&1
    return
  fi

  [[ -r /etc/group ]] && grep -Fq "${LEGACY_OPENRC_GROUP}:" /etc/group
}

legacy_service_account_present() {
  if [[ "$LEGACY_OPENRC_USER" != "$SERVICE_USER" ]] && id "$LEGACY_OPENRC_USER" >/dev/null 2>&1; then
    return 0
  fi

  [[ "$LEGACY_OPENRC_GROUP" != "$SERVICE_GROUP" ]] && legacy_group_exists
}

backup_legacy_artifacts() {
  local config_path unit_path service_path machine_id instance_id

  for config_path in "${DISCOVERED_CONFIGS[@]}"; do
    backup_path "$config_path"
  done

  if [[ -x "$PREFIX/bin/${LEGACY_SERVICE_NAME}" ]]; then
    backup_path "$PREFIX/bin/${LEGACY_SERVICE_NAME}"
  fi

  for machine_id in "${TARGET_MACHINE_IDS[@]}"; do
    backup_path "$SYSTEMD_UNIT_DIR/${SERVICE_NAME}-${machine_id}.service"
    backup_path "$OPENRC_DIR/${SERVICE_NAME}-${machine_id}"
  done

  for instance_id in "${!SEEN_INSTANCE_IDS[@]}"; do
    backup_path "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}-${instance_id}.service"
    backup_path "$OPENRC_DIR/${LEGACY_SERVICE_NAME}-${instance_id}"
  done

  shopt -s nullglob
  for unit_path in \
    "$SYSTEMD_UNIT_DIR/${SERVICE_NAME}.service" \
    "$SYSTEMD_UNIT_DIR/${SERVICE_NAME}-"*.service \
    "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}.service" \
    "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}-"*.service; do
    [[ -f "$unit_path" ]] || continue
    if [[ "$(basename "$unit_path")" == ${LEGACY_SERVICE_NAME}* ]] || grep -Fq "noders-anytls" "$unit_path" 2>/dev/null; then
      backup_path "$unit_path"
    fi
  done

  for service_path in \
    "$OPENRC_DIR/${SERVICE_NAME}" \
    "$OPENRC_DIR/${SERVICE_NAME}-"* \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}" \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}-"*; do
    [[ -f "$service_path" ]] || continue
    if [[ "$(basename "$service_path")" == ${LEGACY_SERVICE_NAME}* ]] || grep -Fq "noders-anytls" "$service_path" 2>/dev/null; then
      backup_path "$service_path"
    fi
  done
  shopt -u nullglob
}

preferred_install_helper() {
  case "$SERVICE_MANAGER" in
    openrc)
      printf '%s\n' "$SCRIPT_DIR/install-openrc.sh"
      ;;
    *)
      printf '%s\n' "$SCRIPT_DIR/install.sh"
      ;;
  esac
}

install_current_runtime() {
  local helper spec panel_api panel_key machine_id
  local -a args

  helper="$(preferred_install_helper)"
  [[ -f "$helper" ]] || {
    echo "Required helper script not found: $helper" >&2
    exit 1
  }

  args=(--prefix "$PREFIX" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR")
  for spec in "${MACHINE_SPECS[@]}"; do
    IFS='|' read -r panel_api panel_key machine_id <<<"$spec"
    args+=(--machine "$panel_api" "$panel_key" "$machine_id")
  done

  bash "$helper" "${args[@]}"
  record_migration "Installed current NodeRS runtime via $(basename "$helper")"
}

remove_systemd_unit_path() {
  local unit_path unit_name
  unit_path="$1"
  [[ -f "$unit_path" ]] || return 0

  unit_name="$(basename "$unit_path" .service)"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
  fi
  rm -f "$unit_path"
  record_migration "Removed legacy systemd unit: $unit_name"
}

cleanup_legacy_systemd_units() {
  local machine_id unit_path

  shopt -s nullglob
  for unit_path in \
    "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}.service" \
    "$SYSTEMD_UNIT_DIR/${LEGACY_SERVICE_NAME}-"*.service; do
    remove_systemd_unit_path "$unit_path"
  done
  shopt -u nullglob

  for machine_id in "${TARGET_MACHINE_IDS[@]}"; do
    remove_systemd_unit_path "$SYSTEMD_UNIT_DIR/${SERVICE_NAME}-${machine_id}.service"
  done

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

remove_openrc_service_path() {
  local service_path unit_name
  service_path="$1"
  [[ -f "$service_path" ]] || return 0

  unit_name="$(basename "$service_path")"
  if command -v rc-service >/dev/null 2>&1; then
    rc-service "$unit_name" stop >/dev/null 2>&1 || true
  fi
  if command -v rc-update >/dev/null 2>&1; then
    rc-update del "$unit_name" default >/dev/null 2>&1 || true
  fi
  rm -f "$service_path"
  record_migration "Removed legacy OpenRC service: $unit_name"
}

cleanup_legacy_openrc_units() {
  local machine_id service_path

  shopt -s nullglob
  for service_path in \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}" \
    "$OPENRC_DIR/${LEGACY_SERVICE_NAME}-"*; do
    remove_openrc_service_path "$service_path"
  done
  shopt -u nullglob

  for machine_id in "${TARGET_MACHINE_IDS[@]}"; do
    remove_openrc_service_path "$OPENRC_DIR/${SERVICE_NAME}-${machine_id}"
  done
}

remove_legacy_dir() {
  local path label
  path="$1"
  label="$2"

  [[ -e "$path" ]] || return 0
  case "$path" in
    ''|/|/run|/var|/var/log)
      record_warning "Refusing to remove suspicious legacy ${label} path: ${path:-<empty>}"
      return 1
      ;;
  esac
  rm -rf "$path"
  record_migration "Removed legacy ${label}: $path"
}

cleanup_legacy_binary_alias() {
  local binary_path
  binary_path="$PREFIX/bin/${LEGACY_SERVICE_NAME}"
  if [[ -e "$binary_path" ]]; then
    rm -f "$binary_path"
    record_migration "Removed legacy binary alias: $binary_path"
  fi
}

migrate_legacy_openrc_logs() {
  local log_path target_path

  [[ -d "$LEGACY_OPENRC_LOG_DIR" ]] || return 0
  install -d "$LOG_DIR"

  shopt -s nullglob
  for log_path in "$LEGACY_OPENRC_LOG_DIR/"*; do
    [[ -e "$log_path" ]] || continue
    target_path="$LOG_DIR/$(basename "$log_path")"
    if [[ -e "$target_path" ]]; then
      record_warning "Leaving legacy OpenRC log in place because the target already exists: $log_path"
      continue
    fi
    mv "$log_path" "$target_path"
    record_migration "Moved legacy OpenRC log: $log_path -> $target_path"
  done
  shopt -u nullglob

  if [[ -d "$LEGACY_OPENRC_LOG_DIR" ]]; then
    rmdir "$LEGACY_OPENRC_LOG_DIR" >/dev/null 2>&1 || true
  fi
}

cleanup_legacy_service_account() {
  if [[ "$(id -u)" -ne 0 ]]; then
    return 0
  fi

  if [[ "$LEGACY_OPENRC_USER" != "$SERVICE_USER" ]] && id "$LEGACY_OPENRC_USER" >/dev/null 2>&1; then
    if command -v deluser >/dev/null 2>&1 && deluser "$LEGACY_OPENRC_USER" >/dev/null 2>&1; then
      record_migration "Removed legacy service user: $LEGACY_OPENRC_USER"
    elif command -v userdel >/dev/null 2>&1 && userdel "$LEGACY_OPENRC_USER" >/dev/null 2>&1; then
      record_migration "Removed legacy service user: $LEGACY_OPENRC_USER"
    else
      record_warning "Failed to remove legacy service user: $LEGACY_OPENRC_USER"
    fi
  fi

  if [[ "$LEGACY_OPENRC_GROUP" != "$SERVICE_GROUP" ]] && legacy_group_exists; then
    if command -v delgroup >/dev/null 2>&1 && delgroup "$LEGACY_OPENRC_GROUP" >/dev/null 2>&1; then
      record_migration "Removed legacy service group: $LEGACY_OPENRC_GROUP"
    elif command -v groupdel >/dev/null 2>&1 && groupdel "$LEGACY_OPENRC_GROUP" >/dev/null 2>&1; then
      record_migration "Removed legacy service group: $LEGACY_OPENRC_GROUP"
    else
      record_warning "Failed to remove legacy service group: $LEGACY_OPENRC_GROUP"
    fi
  fi
}

print_summary() {
  local item

  cat <<EOF
Migrated legacy noders-anytls install
  Runtime: $(runtime_binary_path)
  Manager: $PREFIX/bin/noders
  Config:  $CONFIG_DIR
  State:   $STATE_DIR
  Service manager: $SERVICE_MANAGER
EOF

  if [[ -n "$BACKUP_DIR" ]]; then
    echo "  Backup:  $BACKUP_DIR"
  fi

  if [[ ${#MIGRATED_ITEMS[@]} -gt 0 ]]; then
    echo "  Changes:"
    for item in "${MIGRATED_ITEMS[@]}"; do
      echo "    - $item"
    done
  fi

  if [[ ${#WARNING_MESSAGES[@]} -gt 0 ]]; then
    echo "  Warnings:"
    for item in "${WARNING_MESSAGES[@]}"; do
      echo "    - $item"
    done
  fi
}

main() {
  parse_args "$@"
  require_linux

  if ! release_layout_present; then
    bootstrap_release "$@"
    return
  fi

  discover_machine_configs
  collect_machine_specs
  detect_service_manager
  backup_legacy_artifacts
  install_current_runtime
  cleanup_legacy_binary_alias
  cleanup_legacy_systemd_units
  if legacy_openrc_artifacts_present; then
    cleanup_legacy_openrc_units
    migrate_legacy_openrc_logs
    remove_legacy_dir "$LEGACY_OPENRC_RUN_DIR" "OpenRC run directory" || true
  fi
  if legacy_service_account_present; then
    cleanup_legacy_service_account
  fi
  print_summary
}

main "$@"
