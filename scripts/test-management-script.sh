#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_LIB_PATH="$ROOT_DIR/scripts/lib/install-common.sh"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "scripts/test-management-script.sh must run as root because it creates temporary service files under /etc/systemd/system and /etc/init.d." >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$COMMON_LIB_PATH"

assert_file_exists() {
  local path message
  path="$1"
  message="$2"
  if [[ ! -e "$path" ]]; then
    echo "$message" >&2
    exit 1
  fi
}

assert_file_missing() {
  local path message
  path="$1"
  message="$2"
  if [[ -e "$path" ]]; then
    echo "$message" >&2
    exit 1
  fi
}

assert_contains() {
  local needle path message
  needle="$1"
  path="$2"
  message="$3"
  if ! grep -Fq "$needle" "$path"; then
    echo "$message" >&2
    cat "$path" >&2
    exit 1
  fi
}

assert_not_contains() {
  local needle path message
  needle="$1"
  path="$2"
  message="$3"
  if grep -Fq "$needle" "$path"; then
    echo "$message" >&2
    cat "$path" >&2
    exit 1
  fi
}

assert_equals() {
  local expected actual message
  expected="$1"
  actual="$2"
  message="$3"
  if [[ "$expected" != "$actual" ]]; then
    echo "$message" >&2
    echo "expected:" >&2
    printf '%s\n' "$expected" >&2
    echo "actual:" >&2
    printf '%s\n' "$actual" >&2
    exit 1
  fi
}

make_fake_command() {
  local path body
  path="$1"
  body="$2"
  printf '%s\n' "$body" > "$path"
  chmod 0755 "$path"
}

prepare_fake_release_bundle() {
  local bundle_dir
  bundle_dir="$1"

  install -d "$bundle_dir/lib" "$bundle_dir/packaging/systemd"
  install -m 0755 /bin/sh "$bundle_dir/noders"
  cp "$ROOT_DIR/config.example.toml" "$bundle_dir/config.example.toml"
  cp "$ROOT_DIR/scripts/install.sh" "$bundle_dir/install.sh"
  cp "$ROOT_DIR/scripts/install-openrc.sh" "$bundle_dir/install-openrc.sh"
  cp "$ROOT_DIR/scripts/migrate-legacy-install.sh" "$bundle_dir/migrate-legacy-install.sh"
  cp "$ROOT_DIR/scripts/upgrade.sh" "$bundle_dir/upgrade.sh"
  cp "$ROOT_DIR/scripts/lib/install-common.sh" "$bundle_dir/lib/install-common.sh"
  cp "$ROOT_DIR/packaging/systemd/noders.service" "$bundle_dir/packaging/systemd/noders.service"
}

test_validate_args() {
  (
    PANEL_API=""
    PANEL_KEY=""
    PANEL_MACHINE_ID="3"
    UNINSTALL=1
    REMOVE_ALL=0
    XBOARD_SPECS=()
    TARGET_MACHINE_IDS=("3")
    validate_args
  )

  if (
    PANEL_API=""
    PANEL_KEY=""
    PANEL_MACHINE_ID=$'3\003'
    UNINSTALL=1
    REMOVE_ALL=0
    XBOARD_SPECS=()
    TARGET_MACHINE_IDS=($'3\003')
    validate_args
  ) 2>/dev/null; then
    echo "validate_args accepted an invalid machine_id" >&2
    exit 1
  fi
}

test_management_script_filters_invalid_units() (
  local tmp_root unit_dir fake_bin systemctl_log stdout_path stderr_path valid_unit invalid_unit expected actual

  tmp_root="$(mktemp -d)"
  unit_dir="/etc/systemd/system"
  SERVICE_NAME="noders-ci-test"
  LEGACY_SERVICE_NAME="noders-anytls-ci-test"
  valid_unit="${LEGACY_SERVICE_NAME}-3-820183675"
  invalid_unit="${LEGACY_SERVICE_NAME}-3"$'\003'"-820183675"

  cleanup_management_test() {
    rm -f \
      "${unit_dir}/${valid_unit}.service" \
      "${unit_dir}/${invalid_unit}.service"
    rm -rf "$tmp_root"
  }

  trap cleanup_management_test EXIT

  PREFIX="$tmp_root/prefix"
  CONFIG_DIR="$tmp_root/config"
  STATE_DIR="$tmp_root/state"
  LOG_DIR="$tmp_root/log"
  RUN_DIR="$tmp_root/run"

  install_management_support "$ROOT_DIR/scripts"
  install -d "$unit_dir"

  fake_bin="$tmp_root/fake-bin"
  systemctl_log="$tmp_root/systemctl.log"
  mkdir -p "$fake_bin"
  : > "$systemctl_log"
  make_fake_command "$fake_bin/systemctl" '#!/usr/bin/env bash
{
  for arg in "$@"; do
    printf "[%s]\n" "$arg"
  done
} >> "$NODERS_FAKE_SYSTEMCTL_LOG"'

  : > "${unit_dir}/${valid_unit}.service"
  : > "${unit_dir}/${invalid_unit}.service"

  stdout_path="$tmp_root/stdout"
  stderr_path="$tmp_root/stderr"
  PATH="$fake_bin:$PATH" \
    NODERS_FAKE_SYSTEMCTL_LOG="$systemctl_log" \
    "$PREFIX/bin/noders" restart >"$stdout_path" 2>"$stderr_path"

  assert_contains "Skipping invalid NodeRS service unit name" "$stderr_path" "management script did not report the invalid systemd unit name"

  expected="$(printf '[restart]\n[%s]' "$valid_unit")"
  actual="$(<"$systemctl_log")"
  assert_equals "$expected" "$actual" "management script passed unexpected unit arguments to systemctl"
)

test_upgrade_rejects_legacy_layout() (
  local tmp_root bundle_root stderr_path stdout_path upgrade_path expected_hint

  tmp_root="$(mktemp -d)"
  cleanup_upgrade_test() {
    rm -rf "$tmp_root"
  }
  trap cleanup_upgrade_test EXIT

  PREFIX="$tmp_root/prefix"
  CONFIG_DIR="$tmp_root/config"
  STATE_DIR="$tmp_root/state"
  OPENRC_DIR="$tmp_root/openrc"
  install -d "$PREFIX/bin" "$CONFIG_DIR/machines" "$STATE_DIR" "$OPENRC_DIR"
  : > "$PREFIX/bin/noders-anytls"
  chmod 0755 "$PREFIX/bin/noders-anytls"
  : > "$CONFIG_DIR/machines/3.toml"

  bundle_root="$tmp_root/bundle"
  prepare_fake_release_bundle "$bundle_root"

  stdout_path="$tmp_root/stdout"
  stderr_path="$tmp_root/stderr"
  upgrade_path="$bundle_root/upgrade.sh"
  if bash "$upgrade_path" --prefix "$PREFIX" --config-dir "$CONFIG_DIR" >"$stdout_path" 2>"$stderr_path"; then
    echo "upgrade.sh unexpectedly accepted a legacy noders-anytls layout" >&2
    exit 1
  fi

  expected_hint="Run ${PREFIX%/}/lib/noders/migrate-legacy-install.sh instead of upgrade.sh."
  assert_contains "Legacy noders-anytls install layout detected." "$stderr_path" "upgrade.sh did not report the legacy layout"
  assert_contains "$expected_hint" "$stderr_path" "upgrade.sh did not point to the bundled migration helper"
)

test_migrate_legacy_install_systemd() (
  local tmp_root bundle_root fake_bin prefix_root config_root state_root unit_dir support_dir fake_systemctl_log fake_userdb panel_api panel_key machine_id instance_id old_config new_config old_unit new_unit legacy_hashed_unit legacy_binary stdout_path stderr_path backup_glob expected_support_path backup_root

  tmp_root="$(mktemp -d)"
  bundle_root="$tmp_root/bundle"
  prepare_fake_release_bundle "$bundle_root"
  cleanup_migration_test() {
    rm -f "$old_unit" "$legacy_hashed_unit" "$new_unit"
    rm -rf "$tmp_root"
  }
  trap cleanup_migration_test EXIT

  prefix_root="$tmp_root/prefix"
  config_root="$tmp_root/config"
  state_root="$tmp_root/state"
  unit_dir="/etc/systemd/system"
  support_dir="$prefix_root/lib/noders"
  legacy_binary="$prefix_root/bin/noders-anytls"
  panel_api="https://legacy.example.com"
  panel_key="legacy-token"
  machine_id="398765"
  instance_id="$(machine_instance_id "$panel_api" "$machine_id")"
  old_config="$config_root/machines/${machine_id}.toml"
  new_config="$config_root/machines/${instance_id}.toml"
  old_unit="$unit_dir/noders-${machine_id}.service"
  new_unit="$unit_dir/noders-${instance_id}.service"
  legacy_hashed_unit="$unit_dir/noders-anytls-${instance_id}.service"
  fake_systemctl_log="$tmp_root/systemctl.log"

  install -d "$prefix_root/bin" "$config_root/machines" "$state_root" "$unit_dir"
  install -m 0755 /bin/sh "$legacy_binary"
  cat > "$old_config" <<EOF
[panel]
api = "$panel_api"
key = "$panel_key"
machine_id = $machine_id
EOF

  cat > "$old_unit" <<EOF
[Unit]
Description=Legacy plain machine service

[Service]
ExecStart=${prefix_root}/bin/noders-anytls ${old_config}
EOF

  cat > "$legacy_hashed_unit" <<EOF
[Unit]
Description=Legacy hashed machine service

[Service]
ExecStart=${prefix_root}/bin/noders-anytls ${old_config}
EOF

  fake_bin="$tmp_root/fake-bin"
  fake_userdb="$tmp_root/userdb"
  mkdir -p "$fake_bin" "$fake_userdb"
  : > "$fake_systemctl_log"

  make_fake_command "$fake_bin/systemctl" '#!/usr/bin/env bash
unit_dir="/etc/systemd/system"
log_path="$NODERS_FAKE_SYSTEMCTL_LOG"
cmd="$1"
shift || true
case "$cmd" in
  is-active)
    exit 1
    ;;
  show)
    printf "inactive\n"
    exit 0
    ;;
  daemon-reload)
    printf "[daemon-reload]\n" >> "$log_path"
    exit 0
    ;;
  enable|restart|start|disable)
    for arg in "$@"; do
      printf "[%s][%s]\n" "$cmd" "$arg" >> "$log_path"
    done
    exit 0
    ;;
  *)
    printf "[%s]" "$cmd" >> "$log_path"
    for arg in "$@"; do
      printf "[%s]" "$arg" >> "$log_path"
    done
    printf "\n" >> "$log_path"
    exit 0
    ;;
esac'

  make_fake_command "$fake_bin/useradd" '#!/usr/bin/env bash
user="${@: -1}"
mkdir -p "$NODERS_FAKE_USERDB"
touch "$NODERS_FAKE_USERDB/$user"
exit 0'

  make_fake_command "$fake_bin/id" '#!/usr/bin/env bash
if [[ "$#" -eq 0 || "$1" == -* ]]; then
  /usr/bin/id "$@"
  exit 0
fi
if [[ -e "$NODERS_FAKE_USERDB/$1" ]]; then
  printf "uid=999(%s) gid=999(%s) groups=999(%s)\n" "$1" "$1" "$1"
  exit 0
fi
exit 1'

  make_fake_command "$fake_bin/chown" '#!/usr/bin/env bash
exit 0'

  make_fake_command "$fake_bin/userdel" '#!/usr/bin/env bash
exit 0'

  make_fake_command "$fake_bin/groupdel" '#!/usr/bin/env bash
exit 0'

  make_fake_command "$fake_bin/getent" '#!/usr/bin/env bash
exit 2'

  stdout_path="$tmp_root/stdout"
  stderr_path="$tmp_root/stderr"
  PATH="$fake_bin:$PATH" \
    NODERS_FAKE_SYSTEMCTL_LOG="$fake_systemctl_log" \
    NODERS_FAKE_USERDB="$fake_userdb" \
    bash "$bundle_root/migrate-legacy-install.sh" \
      --prefix "$prefix_root" \
      --config-dir "$config_root" \
      --state-dir "$state_root" >"$stdout_path" 2>"$stderr_path"

  assert_file_exists "$prefix_root/bin/noders" "migration did not install the noders manager command"
  assert_file_exists "$support_dir/migrate-legacy-install.sh" "migration did not install the bundled migration helper"
  assert_file_exists "$support_dir/install.sh" "migration did not refresh bundled install support"
  assert_file_exists "$support_dir/install-openrc.sh" "migration did not refresh bundled OpenRC support"
  assert_file_exists "$support_dir/upgrade.sh" "migration did not refresh bundled upgrade support"
  assert_file_exists "$prefix_root/lib/noders/noders" "migration did not install the noders runtime binary"
  assert_file_missing "$legacy_binary" "migration did not remove the legacy binary alias"
  assert_file_exists "$new_config" "migration did not generate the hashed machine config"
  assert_file_missing "$old_config" "migration did not replace the legacy machine config path"
  assert_file_missing "$old_unit" "migration did not remove the plain legacy systemd unit"
  assert_file_missing "$legacy_hashed_unit" "migration did not remove the noders-anytls hashed systemd unit"
  assert_file_exists "$new_unit" "migration did not create the new systemd unit"

  assert_contains 'api = "https://legacy.example.com"' "$new_config" "migration did not preserve panel.api"
  assert_contains 'key = "legacy-token"' "$new_config" "migration did not preserve panel.key"
  assert_contains "machine_id = $machine_id" "$new_config" "migration did not preserve machine_id"
  assert_not_contains 'legacy plain machine service' "$new_unit" "migration reused the old plain systemd unit instead of rewriting it"
  assert_contains 'ExecStart='"$prefix_root"'/lib/noders/noders '"$new_config" "$new_unit" "migration wrote an unexpected ExecStart into the new systemd unit"

  expected_support_path="$(printf 'PREFIX=%q\n' "$prefix_root")"
  assert_contains "$expected_support_path" "$support_dir/install.env" "migration did not write install.env for the new prefix"
  assert_contains 'SERVICE_NAME=noders' "$support_dir/install.env" "migration wrote the wrong service name into install.env"
  assert_contains 'LEGACY_SERVICE_NAME=noders-anytls' "$support_dir/install.env" "migration wrote the wrong legacy service name into install.env"
  assert_contains 'Installed current NodeRS runtime via install.sh' "$stdout_path" "migration summary did not report the current installer path"
  assert_contains 'Migrated legacy noders-anytls install' "$stdout_path" "migration did not print the migrator summary"

  backup_glob="$config_root/migration-backups"/*
  if ! compgen -G "$backup_glob" >/dev/null; then
    echo "migration did not create a backup directory" >&2
    exit 1
  fi

  backup_root="$(compgen -G "$backup_glob" | head -n1)"
  assert_file_exists "$backup_root/${old_config#/}" "migration did not back up the legacy machine config"
  assert_file_exists "$backup_root/${old_unit#/}" "migration did not back up the plain legacy systemd unit"
  assert_file_exists "$backup_root/${legacy_hashed_unit#/}" "migration did not back up the hashed legacy systemd unit"

  assert_contains "[enable][noders-${instance_id}]" "$fake_systemctl_log" "migration did not enable the new hashed systemd unit"
  assert_contains "[restart][noders-${instance_id}]" "$fake_systemctl_log" "migration did not restart the new hashed systemd unit"
  assert_contains "[disable][--now][noders-${machine_id}]" "$fake_systemctl_log" "migration did not disable the plain legacy systemd unit"
  assert_contains "[disable][--now][noders-anytls-${machine_id}]" "$fake_systemctl_log" "migration did not attempt to disable the legacy plain anytls unit"
  assert_contains "[disable][--now][noders-anytls-${instance_id}]" "$fake_systemctl_log" "migration did not disable the legacy hashed anytls unit"
  if [[ ! -s "$fake_systemctl_log" ]]; then
    echo "migration did not exercise the fake systemctl path" >&2
    exit 1
  fi
)

main() {
  test_validate_args
  test_management_script_filters_invalid_units
  test_upgrade_rejects_legacy_layout
  test_migrate_legacy_install_systemd
}

main "$@"
