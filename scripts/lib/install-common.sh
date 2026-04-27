#!/usr/bin/env bash

: "${PREFIX:=/usr/local}"
: "${CONFIG_DIR:=/etc/noders/anytls}"
: "${STATE_DIR:=/var/lib/noders/anytls}"
: "${SERVICE_NAME:=noders}"
: "${LEGACY_SERVICE_NAME:=${SERVICE_NAME}-anytls}"

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

GNU_GLIBC_FLOOR="2.17"

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
        if (left_part > right_part) {
          exit 0;
        }
        if (left_part < right_part) {
          exit 1;
        }
      }
      exit 0;
    }
  '
}

detect_glibc_version() {
  if command -v getconf >/dev/null 2>&1; then
    getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}'
  fi
}

detect_linux_libc() {
  local glibc_version ldd_output
  glibc_version="$(detect_glibc_version)"
  if [[ -n "$glibc_version" ]]; then
    printf 'glibc\n'
    return
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd_output="$(ldd --version 2>&1 || true)"
    if printf '%s' "$ldd_output" | grep -qi 'musl'; then
      printf 'musl\n'
      return
    fi
    if printf '%s' "$ldd_output" | grep -qiE 'glibc|gnu libc'; then
      printf 'glibc\n'
      return
    fi
  fi

  if compgen -G '/lib/ld-musl-*.so.1' >/dev/null || compgen -G '/usr/lib/ld-musl-*.so.1' >/dev/null; then
    printf 'musl\n'
    return
  fi

  printf 'unknown\n'
}

detect_release_asset_suffix() {
  local arch libc_family glibc_version asset_prefix
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

  libc_family="$(detect_linux_libc)"
  if [[ "$libc_family" == "glibc" ]]; then
    glibc_version="$(detect_glibc_version)"
    if [[ -n "$glibc_version" ]] && version_at_least "$glibc_version" "$GNU_GLIBC_FLOOR"; then
      printf '%s\n' "$asset_prefix"
      return
    fi
    if [[ -n "$glibc_version" ]]; then
      echo "Detected glibc ${glibc_version}; falling back to ${asset_prefix}-musl because GNU builds target glibc >= ${GNU_GLIBC_FLOOR}." >&2
    else
      echo "Detected glibc but could not determine the exact version; falling back to ${asset_prefix}-musl for compatibility." >&2
    fi
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
      --api)
        PANEL_API="$2"
        shift 2
        ;;
      --key)
        PANEL_KEY="$2"
        shift 2
        ;;
      --machine-id)
        PANEL_MACHINE_ID="$2"
        TARGET_MACHINE_IDS+=("$2")
        shift 2
        ;;
      --machine)
        XBOARD_SPECS+=("$2|$3|$4")
        shift 4
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
  if [[ -n "$PANEL_API" || -n "$PANEL_KEY" ]]; then
    if [[ -z "$PANEL_API" || -z "$PANEL_KEY" || -z "$PANEL_MACHINE_ID" ]]; then
      echo "--api, --key and --machine-id must be provided together." >&2
      exit 1
    fi
    XBOARD_SPECS+=("$PANEL_API|$PANEL_KEY|$PANEL_MACHINE_ID")
  elif [[ "$UNINSTALL" -eq 0 && -n "$PANEL_MACHINE_ID" ]]; then
    echo "--api, --key and --machine-id must be provided together." >&2
    exit 1
  fi

  local spec spec_machine_id target_machine_id
  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r _ _ spec_machine_id <<<"$spec"
    if [[ ! "$spec_machine_id" =~ ^[0-9]+$ ]]; then
      printf 'machine_id must be a decimal integer: %q\n' "$spec_machine_id" >&2
      exit 1
    fi
  done
  for target_machine_id in "${TARGET_MACHINE_IDS[@]}"; do
    if [[ ! "$target_machine_id" =~ ^[0-9]+$ ]]; then
      printf 'machine_id must be a decimal integer: %q\n' "$target_machine_id" >&2
      exit 1
    fi
  done

  if [[ "$UNINSTALL" -eq 1 ]]; then
    return
  fi

  if [[ ${#XBOARD_SPECS[@]} -eq 0 ]]; then
    echo "At least one machine is required; pass --api/--key/--machine-id or --machine." >&2
    exit 1
  fi
}

sed_escape() {
  printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

normalized_panel_api() {
  printf '%s\n' "${1%/}"
}

machine_instance_id() {
  local panel_api machine_id panel_hash
  panel_api="$(normalized_panel_api "$1")"
  machine_id="$2"
  panel_hash="$(printf '%s' "$panel_api" | cksum | awk '{print $1}')"
  printf '%s-%s\n' "$machine_id" "$panel_hash"
}

valid_managed_service_unit_name() {
  local candidate
  candidate="$1"
  case "$candidate" in
    "$SERVICE_NAME"|"$SERVICE_NAME"-*|"$LEGACY_SERVICE_NAME"|"$LEGACY_SERVICE_NAME"-*)
      ;;
    *)
      return 1
      ;;
  esac
  [[ "$candidate" =~ ^[A-Za-z0-9_.:@-]+$ ]]
}

append_unique_service_unit() {
  local candidate existing
  candidate="$1"
  if ! valid_managed_service_unit_name "$candidate"; then
    printf 'Skipping invalid NodeRS service unit name: %q\n' "$candidate" >&2
    return 0
  fi
  for existing in "${DISCOVERED_UNITS[@]}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return 0
    fi
  done
  DISCOVERED_UNITS+=("$candidate")
}

render_config_file() {
  local template_path target_path panel_api panel_key machine_id escaped_api escaped_key escaped_machine_id
  template_path="$1"
  target_path="$2"
  panel_api="$3"
  panel_key="$4"
  machine_id="$5"

  escaped_api="$(sed_escape "$panel_api")"
  escaped_key="$(sed_escape "$panel_key")"
  escaped_machine_id="$(sed_escape "$machine_id")"

  sed \
    -e "s#api = \"https://xboard.example.com\"#api = \"$escaped_api\"#g" \
    -e "s#key = \"replace-me\"#key = \"$escaped_key\"#g" \
    -e "s#machine_id = 1#machine_id = $escaped_machine_id#g" \
    "$template_path" > "$target_path"
}

node_config_path() {
  printf '%s\n' "${CONFIG_DIR%/}/machines/${1}.toml"
}

legacy_node_config_path() {
  printf '%s\n' "${CONFIG_DIR%/}/machines/${1}.toml"
}

openrc_node_service_path() {
  printf '%s\n' "${OPENRC_DIR%/}/${SERVICE_NAME}-${1}"
}

openrc_node_service_pid_path() {
  printf '%s\n' "${RUN_DIR%/}/${SERVICE_NAME}-${1}.pid"
}

openrc_node_service_log_path() {
  printf '%s\n' "${LOG_DIR%/}/${SERVICE_NAME}-${1}.log"
}

support_root_dir() {
  printf '%s\n' "${PREFIX%/}/lib/noders"
}

runtime_binary_path() {
  printf '%s\n' "$(support_root_dir)/noders"
}

write_manager_install_env() {
  local target
  target="$1"

  : > "$target"
  printf 'PREFIX=%q\n' "$PREFIX" >> "$target"
  printf 'CONFIG_DIR=%q\n' "$CONFIG_DIR" >> "$target"
  printf 'STATE_DIR=%q\n' "$STATE_DIR" >> "$target"
  printf 'SERVICE_NAME=%q\n' "$SERVICE_NAME" >> "$target"
  printf 'LEGACY_SERVICE_NAME=%q\n' "$LEGACY_SERVICE_NAME" >> "$target"
  if [[ -n "${LOG_DIR:-}" ]]; then
    printf 'LOG_DIR=%q\n' "$LOG_DIR" >> "$target"
  fi
  if [[ -n "${RUN_DIR:-}" ]]; then
    printf 'RUN_DIR=%q\n' "$RUN_DIR" >> "$target"
  fi
}

write_management_script() {
  local target
  target="$1"

  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEFAULT_PREFIX="/usr/local"
DEFAULT_CONFIG_DIR="/etc/noders/anytls"
DEFAULT_STATE_DIR="/var/lib/noders/anytls"
DEFAULT_LOG_DIR="/var/log/noders"
DEFAULT_RUN_DIR="/run/noders"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SUPPORT_DIR=""
PREFIX=""
CONFIG_DIR=""
STATE_DIR=""
LOG_DIR=""
RUN_DIR=""
SERVICE_NAME="noders"
LEGACY_SERVICE_NAME="${SERVICE_NAME}-anytls"
SERVICE_MANAGER="none"

declare -a DISCOVERED_UNITS=()
declare -a RESOLVED_UNITS=()

action_usage() {
  cat <<'USAGE'
Usage: noders <command> [options] [selector...]

Commands:
  update [--version <tag>] [--no-restart]
      Upgrade the installed NodeRS binary.

  uninstall [--all | --machine-id <id> | --machine <url> <key> <id>]
      Remove one machine instance or the whole installation.

  start [all|selector...]
  stop [all|selector...]
  restart [all|selector...]
      Control discovered NodeRS services. With no selector, all services are targeted.

  log [-f|--follow] [-n|--lines <count>] [all|selector...]
      Show NodeRS logs. With no selector, all services are targeted.

  help
      Show this help message.

Selectors:
  - Full service name, for example: noders-1-123456789
  - Machine ID, for example: 1
  - Instance suffix, for example: 1-123456789
  - all

Examples:
  noders
  noders update
  noders restart
  noders restart 1
  noders log -f
  noders uninstall --machine-id 1
  noders uninstall --all
USAGE
}

append_unique_unit() {
  local candidate existing
  candidate="$1"
  case "$candidate" in
    "$SERVICE_NAME"|"$SERVICE_NAME"-*|"$LEGACY_SERVICE_NAME"|"$LEGACY_SERVICE_NAME"-*)
      ;;
    *)
      return 0
      ;;
  esac
  if [[ ! "$candidate" =~ ^[A-Za-z0-9_.:@-]+$ ]]; then
    printf 'Skipping invalid NodeRS service unit name: %q\n' "$candidate" >&2
    return 0
  fi
  for existing in "${DISCOVERED_UNITS[@]}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return 0
    fi
  done
  DISCOVERED_UNITS+=("$candidate")
}

append_resolved_unit() {
  local candidate existing
  candidate="$1"
  for existing in "${RESOLVED_UNITS[@]:-}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return 0
    fi
  done
  RESOLVED_UNITS+=("$candidate")
}

discover_support_dir() {
  if [[ -f "$SCRIPT_DIR/install.sh" && -f "$SCRIPT_DIR/lib/install-common.sh" ]]; then
    SUPPORT_DIR="$SCRIPT_DIR"
    return
  fi

  local prefix_candidate
  prefix_candidate="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
  if [[ -f "$prefix_candidate/lib/noders/install.sh" && -f "$prefix_candidate/lib/noders/lib/install-common.sh" ]]; then
    SUPPORT_DIR="$prefix_candidate/lib/noders"
    return
  fi

  if [[ -f "$DEFAULT_PREFIX/lib/noders/install.sh" && -f "$DEFAULT_PREFIX/lib/noders/lib/install-common.sh" ]]; then
    SUPPORT_DIR="$DEFAULT_PREFIX/lib/noders"
    return
  fi

  SUPPORT_DIR="$SCRIPT_DIR"
}

load_install_env() {
  local env_path
  env_path="$SUPPORT_DIR/install.env"
  if [[ -f "$env_path" ]]; then
    # shellcheck source=/dev/null
    source "$env_path"
  fi

  if [[ -z "$PREFIX" ]]; then
    if [[ "$SUPPORT_DIR" == */lib/noders ]]; then
      PREFIX="$(CDPATH= cd -- "$SUPPORT_DIR/../.." && pwd)"
    else
      PREFIX="$DEFAULT_PREFIX"
    fi
  fi
  CONFIG_DIR="${CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
  STATE_DIR="${STATE_DIR:-$DEFAULT_STATE_DIR}"
  LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
  RUN_DIR="${RUN_DIR:-$DEFAULT_RUN_DIR}"
  SERVICE_NAME="${SERVICE_NAME:-noders}"
  LEGACY_SERVICE_NAME="${LEGACY_SERVICE_NAME:-${SERVICE_NAME}-anytls}"
}

print_discovered_units() {
  if [[ ${#DISCOVERED_UNITS[@]} -eq 0 ]]; then
    echo "No NodeRS services were discovered."
    return
  fi

  echo "Discovered NodeRS services (${SERVICE_MANAGER}):"
  local unit
  for unit in "${DISCOVERED_UNITS[@]}"; do
    echo "  - $unit"
  done
}

discover_systemd_units() {
  local unit_path unit_name found=1
  if ! command -v systemctl >/dev/null 2>&1; then
    return 1
  fi

  shopt -s nullglob
  for unit_path in \
    /etc/systemd/system/${SERVICE_NAME}.service \
    /etc/systemd/system/${SERVICE_NAME}-*.service \
    /etc/systemd/system/${LEGACY_SERVICE_NAME}.service \
    /etc/systemd/system/${LEGACY_SERVICE_NAME}-*.service; do
    [[ -f "$unit_path" ]] || continue
    unit_name="$(basename "$unit_path" .service)"
    append_unique_unit "$unit_name"
    found=0
  done
  shopt -u nullglob
  return "$found"
}

discover_openrc_units() {
  local service_path unit_name found=1
  if ! command -v rc-service >/dev/null 2>&1; then
    return 1
  fi

  shopt -s nullglob
  for service_path in \
    /etc/init.d/${SERVICE_NAME} \
    /etc/init.d/${SERVICE_NAME}-* \
    /etc/init.d/${LEGACY_SERVICE_NAME} \
    /etc/init.d/${LEGACY_SERVICE_NAME}-*; do
    [[ -f "$service_path" ]] || continue
    unit_name="$(basename "$service_path")"
    append_unique_unit "$unit_name"
    found=0
  done
  shopt -u nullglob
  return "$found"
}

discover_units() {
  DISCOVERED_UNITS=()
  if discover_systemd_units; then
    SERVICE_MANAGER="systemd"
    return
  fi
  if discover_openrc_units; then
    SERVICE_MANAGER="openrc"
    return
  fi

  if command -v systemctl >/dev/null 2>&1; then
    SERVICE_MANAGER="systemd"
  elif command -v rc-service >/dev/null 2>&1; then
    SERVICE_MANAGER="openrc"
  else
    SERVICE_MANAGER="none"
  fi
}

selector_matches_unit() {
  local selector unit
  selector="$1"
  unit="$2"

  [[ "$selector" == "$unit" ]] \
    || [[ "$unit" == "${SERVICE_NAME}-${selector}" ]] \
    || [[ "$unit" == "${LEGACY_SERVICE_NAME}-${selector}" ]] \
    || [[ "$unit" == "${SERVICE_NAME}-${selector}-"* ]] \
    || [[ "$unit" == "${LEGACY_SERVICE_NAME}-${selector}-"* ]]
}

resolve_targets() {
  local selector unit matched
  discover_units
  RESOLVED_UNITS=()

  if [[ "$SERVICE_MANAGER" == "none" ]]; then
    echo "No supported service manager was detected on this host." >&2
    exit 1
  fi
  if [[ ${#DISCOVERED_UNITS[@]} -eq 0 ]]; then
    echo "No NodeRS services were discovered." >&2
    exit 1
  fi

  if [[ $# -eq 0 || ( $# -eq 1 && "$1" == "all" ) ]]; then
    RESOLVED_UNITS=("${DISCOVERED_UNITS[@]}")
    return
  fi

  for selector in "$@"; do
    matched=1
    for unit in "${DISCOVERED_UNITS[@]}"; do
      if selector_matches_unit "$selector" "$unit"; then
        append_resolved_unit "$unit"
        matched=0
      fi
    done
    if [[ "$matched" -ne 0 ]]; then
      echo "No NodeRS service matched selector: $selector" >&2
      print_discovered_units >&2
      exit 1
    fi
  done
}

run_allow_interrupt() {
  local status
  set +e
  "$@"
  status=$?
  set -e
  if [[ "$status" -ne 0 && "$status" -ne 130 ]]; then
    return "$status"
  fi
  return 0
}

require_helper_script() {
  local helper
  helper="$1"
  if [[ ! -f "$helper" ]]; then
    echo "Required helper script not found: $helper" >&2
    echo "Please reinstall NodeRS so the support files are refreshed." >&2
    exit 1
  fi
}

preferred_install_helper() {
  discover_units
  if [[ "$SERVICE_MANAGER" == "openrc" ]]; then
    printf '%s\n' "$SUPPORT_DIR/install-openrc.sh"
  else
    printf '%s\n' "$SUPPORT_DIR/install.sh"
  fi
}

run_update() {
  local helper
  helper="$SUPPORT_DIR/upgrade.sh"
  require_helper_script "$helper"
  bash "$helper" --prefix "$PREFIX" --config-dir "$CONFIG_DIR" "$@"
}

run_uninstall() {
  local helper
  helper="$(preferred_install_helper)"
  require_helper_script "$helper"
  bash "$helper" --prefix "$PREFIX" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" --uninstall "$@"
}

perform_service_action() {
  local action unit
  action="$1"
  shift
  resolve_targets "$@"

  case "$SERVICE_MANAGER" in
    systemd)
      systemctl "$action" "${RESOLVED_UNITS[@]}"
      ;;
    openrc)
      for unit in "${RESOLVED_UNITS[@]}"; do
        rc-service "$unit" "$action"
      done
      ;;
    *)
      echo "No supported service manager was detected on this host." >&2
      exit 1
      ;;
  esac
}

show_logs() {
  local follow lines unit log_path
  follow=0
  lines=100
  local -a selectors=()
  local -a log_files=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f|--follow)
        follow=1
        shift
        ;;
      -n|--lines)
        if [[ $# -lt 2 ]]; then
          echo "Missing value for $1" >&2
          exit 1
        fi
        lines="$2"
        shift 2
        ;;
      *)
        selectors+=("$1")
        shift
        ;;
    esac
  done

  if [[ ! "$lines" =~ ^[0-9]+$ ]]; then
    echo "Log line count must be a non-negative integer: $lines" >&2
    exit 1
  fi

  resolve_targets "${selectors[@]}"

  case "$SERVICE_MANAGER" in
    systemd)
      if ! command -v journalctl >/dev/null 2>&1; then
        echo "journalctl is required to view systemd logs." >&2
        exit 1
      fi
      local -a journal_cmd=(journalctl --no-pager -n "$lines")
      if [[ "$follow" -eq 1 ]]; then
        journal_cmd+=(-f)
      fi
      for unit in "${RESOLVED_UNITS[@]}"; do
        journal_cmd+=(-u "$unit")
      done
      run_allow_interrupt "${journal_cmd[@]}"
      ;;
    openrc)
      for unit in "${RESOLVED_UNITS[@]}"; do
        log_path="${LOG_DIR%/}/${unit}.log"
        if [[ -f "$log_path" ]]; then
          log_files+=("$log_path")
        fi
      done
      if [[ ${#log_files[@]} -eq 0 ]]; then
        echo "No OpenRC log files were found under $LOG_DIR." >&2
        exit 1
      fi
      local -a tail_cmd=(tail -n "$lines")
      if [[ "$follow" -eq 1 ]]; then
        tail_cmd+=(-f)
      fi
      tail_cmd+=("${log_files[@]}")
      run_allow_interrupt "${tail_cmd[@]}"
      ;;
    *)
      echo "No supported service manager was detected on this host." >&2
      exit 1
      ;;
  esac
}

pause_if_interactive() {
  if [[ -t 0 && -t 1 ]]; then
    read -r -p "按回车继续..." _ || true
  fi
}

prompt_selectors() {
  local response
  local -n output_ref=$1
  output_ref=()

  read -r -p "目标服务（留空=全部，可填服务名 / machine_id / 实例后缀）: " response
  if [[ -z "$response" ]]; then
    return
  fi
  read -r -a output_ref <<<"$response"
}

interactive_update() {
  local version no_restart
  local -a args=()

  read -r -p "升级到哪个版本标签（留空=latest）: " version
  if [[ -n "$version" ]]; then
    args+=(--version "$version")
  fi
  read -r -p "升级后不重启服务？[y/N]: " no_restart
  if [[ "$no_restart" =~ ^[Yy]$ ]]; then
    args+=(--no-restart)
  fi
  run_update "${args[@]}"
}

interactive_uninstall() {
  local choice machine_id confirm
  echo "1) 卸载全部"
  echo "2) 按 machine_id 卸载"
  echo "0) 返回"
  read -r -p "请选择 [0-2]: " choice

  case "$choice" in
    1)
      read -r -p "确认卸载全部 NodeRS 实例？输入 YES 继续: " confirm
      if [[ "$confirm" != "YES" ]]; then
        echo "已取消。"
        return 0
      fi
      run_uninstall --all
      ;;
    2)
      read -r -p "请输入 machine_id: " machine_id
      if [[ -z "$machine_id" ]]; then
        echo "machine_id 不能为空。" >&2
        return 1
      fi
      run_uninstall --machine-id "$machine_id"
      ;;
    0)
      return 0
      ;;
    *)
      echo "无效选择。" >&2
      return 1
      ;;
  esac
}

interactive_service_action() {
  local action
  local -a selectors=()
  action="$1"
  prompt_selectors selectors
  perform_service_action "$action" "${selectors[@]}"
}

interactive_logs() {
  local lines follow
  local -a selectors=()
  local -a args=()

  prompt_selectors selectors
  read -r -p "显示最近多少行日志（默认 100）: " lines
  if [[ -n "$lines" ]]; then
    args+=(--lines "$lines")
  fi
  read -r -p "持续追踪日志？[y/N]: " follow
  if [[ "$follow" =~ ^[Yy]$ ]]; then
    args+=(--follow)
  fi
  show_logs "${args[@]}" "${selectors[@]}"
}

interactive_menu() {
  local choice

  if [[ ! -t 0 || ! -t 1 ]]; then
    action_usage >&2
    exit 1
  fi

  while true; do
    echo
    echo "NodeRS 管理菜单"
    echo "================"
    discover_units
    print_discovered_units
    echo
    echo "1) 更新"
    echo "2) 卸载"
    echo "3) 启动"
    echo "4) 停止"
    echo "5) 重启"
    echo "6) 查看日志"
    echo "0) 退出"
    read -r -p "请选择 [0-6]: " choice

    case "$choice" in
      1)
        interactive_update
        return
        ;;
      2)
        interactive_uninstall
        return
        ;;
      3)
        interactive_service_action start
        pause_if_interactive
        ;;
      4)
        interactive_service_action stop
        pause_if_interactive
        ;;
      5)
        interactive_service_action restart
        pause_if_interactive
        ;;
      6)
        interactive_logs
        pause_if_interactive
        ;;
      0)
        return
        ;;
      *)
        echo "无效选择。" >&2
        ;;
    esac
  done
}

main() {
  discover_support_dir
  load_install_env

  if [[ $# -eq 0 ]]; then
    interactive_menu
    return
  fi

  case "$1" in
    help|-h|--help)
      action_usage
      ;;
    update)
      shift
      run_update "$@"
      ;;
    uninstall)
      shift
      run_uninstall "$@"
      ;;
    start)
      shift
      perform_service_action start "$@"
      ;;
    stop)
      shift
      perform_service_action stop "$@"
      ;;
    restart)
      shift
      perform_service_action restart "$@"
      ;;
    log|logs)
      shift
      show_logs "$@"
      ;;
    *)
      echo "Unknown noders command: $1" >&2
      action_usage >&2
      exit 1
      ;;
  esac
}

main "$@"
EOF
  chmod 0755 "$target"
}

install_support_file() {
  local src dst mode
  src="$1"
  dst="$2"
  mode="$3"

  if [[ -e "$dst" && "$src" -ef "$dst" ]]; then
    return 0
  fi

  install -m "$mode" "$src" "$dst"
}

install_management_support() {
  local staging_dir support_dir
  staging_dir="$1"
  support_dir="$(support_root_dir)"

  install -d "$PREFIX/bin" "$support_dir" "$support_dir/lib"
  write_management_script "$PREFIX/bin/noders"
  install_support_file "$staging_dir/install.sh" "$support_dir/install.sh" 0755
  install_support_file "$staging_dir/install-openrc.sh" "$support_dir/install-openrc.sh" 0755
  install_support_file "$staging_dir/upgrade.sh" "$support_dir/upgrade.sh" 0755
  install_support_file "$staging_dir/lib/install-common.sh" "$support_dir/lib/install-common.sh" 0644
  write_manager_install_env "$support_dir/install.env"
}

remove_management_support() {
  rm -f "$PREFIX/bin/noders"
  rm -rf "$(support_root_dir)"
}

render_openrc_service_file() {
  local target instance_id config_path service_user service_group pid_path log_path
  target="$1"
  instance_id="$2"
  config_path="$3"
  service_user="$4"
  service_group="$5"
  pid_path="$(openrc_node_service_pid_path "$instance_id")"
  log_path="$(openrc_node_service_log_path "$instance_id")"

  cat > "$target" <<EOF
#!/sbin/openrc-run

name="${SERVICE_NAME}-${instance_id}"
description="NodeRS service for instance ${instance_id}"
command="$(runtime_binary_path)"
command_args="${config_path}"
command_user="${service_user}:${service_group}"
directory="${STATE_DIR}"
pidfile="${pid_path}"
supervisor="supervise-daemon"
respawn_delay="2"
respawn_max="0"
output_log="${log_path}"
error_log="${log_path}"

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

write_xboard_configs() {
  local staging_dir template_path spec panel_api panel_key machine_id instance_id config_path
  staging_dir="$1"
  template_path="$staging_dir/config.example.toml"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r panel_api panel_key machine_id <<<"$spec"
    instance_id="$(machine_instance_id "$panel_api" "$machine_id")"
    rm -f "$(legacy_node_config_path "$machine_id")"
    config_path="$(node_config_path "$instance_id")"
    render_config_file \
      "$template_path" \
      "$config_path" \
      "$panel_api" \
      "$panel_key" \
      "$machine_id"
    GENERATED_CONFIGS+=("$config_path")
  done
}
