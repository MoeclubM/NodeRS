#!/usr/bin/env bash

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
  local arch libc_family glibc_version
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      libc_family="$(detect_linux_libc)"
      if [[ "$libc_family" == "glibc" ]]; then
        glibc_version="$(detect_glibc_version)"
        if [[ -n "$glibc_version" ]] && version_at_least "$glibc_version" "$GNU_GLIBC_FLOOR"; then
          printf 'linux-amd64\n'
          return
        fi
        if [[ -n "$glibc_version" ]]; then
          echo "Detected glibc ${glibc_version}; falling back to linux-amd64-musl because GNU builds target glibc >= ${GNU_GLIBC_FLOOR}." >&2
        else
          echo "Detected glibc but could not determine the exact version; falling back to linux-amd64-musl for compatibility." >&2
        fi
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
      echo "Unsupported architecture for prebuilt releases: $arch" >&2
      exit 1
      ;;
  esac
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
        TARGET_MACHINE_IDS+=("$4")
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
  if [[ -n "$PANEL_API" || -n "$PANEL_KEY" || -n "$PANEL_MACHINE_ID" ]]; then
    if [[ -z "$PANEL_API" || -z "$PANEL_KEY" || -z "$PANEL_MACHINE_ID" ]]; then
      echo "--api, --key and --machine-id must be provided together." >&2
      exit 1
    fi
    XBOARD_SPECS+=("$PANEL_API|$PANEL_KEY|$PANEL_MACHINE_ID")
  fi

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

openrc_node_service_path() {
  printf '%s\n' "${OPENRC_DIR%/}/${SERVICE_NAME}-${1}"
}

openrc_node_service_pid_path() {
  printf '%s\n' "${RUN_DIR%/}/${SERVICE_NAME}-${1}.pid"
}

openrc_node_service_log_path() {
  printf '%s\n' "${LOG_DIR%/}/${SERVICE_NAME}-${1}.log"
}

render_openrc_service_file() {
  local target machine_id config_path service_user service_group pid_path log_path
  target="$1"
  machine_id="$2"
  config_path="$3"
  service_user="$4"
  service_group="$5"
  pid_path="$(openrc_node_service_pid_path "$machine_id")"
  log_path="$(openrc_node_service_log_path "$machine_id")"

  cat > "$target" <<EOF
#!/sbin/openrc-run

name="${SERVICE_NAME}-${machine_id}"
description="NodeRS-AnyTLS service for machine ${machine_id}"
command="${PREFIX}/bin/noders-anytls"
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
  local staging_dir template_path spec panel_api panel_key machine_id config_path
  staging_dir="$1"
  template_path="$staging_dir/config.example.toml"

  for spec in "${XBOARD_SPECS[@]}"; do
    IFS='|' read -r panel_api panel_key machine_id <<<"$spec"
    config_path="$(node_config_path "$machine_id")"
    render_config_file \
      "$template_path" \
      "$config_path" \
      "$panel_api" \
      "$panel_key" \
      "$machine_id"
    GENERATED_CONFIGS+=("$config_path")
  done
}
