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

test_install_common_defaults_service_names() (
  local tmp_root script_path stdout_path stderr_path

  tmp_root="$(mktemp -d)"
  cleanup_install_common_defaults_test() {
    rm -rf "$tmp_root"
  }
  trap cleanup_install_common_defaults_test EXIT

  script_path="$tmp_root/check.sh"
  cat > "$script_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
unset SERVICE_NAME LEGACY_SERVICE_NAME PREFIX CONFIG_DIR STATE_DIR
source "$COMMON_LIB_PATH"
printf '%s\n' "$SERVICE_NAME"
printf '%s\n' "$LEGACY_SERVICE_NAME"
printf '%s\n' "$PREFIX"
printf '%s\n' "$CONFIG_DIR"
printf '%s\n' "$STATE_DIR"
EOF
  chmod 0755 "$script_path"

  stdout_path="$tmp_root/stdout"
  stderr_path="$tmp_root/stderr"
  bash "$script_path" >"$stdout_path" 2>"$stderr_path"

  assert_equals $'noders\nnoders-anytls\n/usr/local\n/etc/noders/anytls\n/var/lib/noders/anytls' "$(<"$stdout_path")" "install-common defaults did not initialize expected values"
  if [[ -s "$stderr_path" ]]; then
    echo "install-common defaults test emitted unexpected stderr" >&2
    cat "$stderr_path" >&2
    exit 1
  fi
)

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

  expected_hint="Back up $CONFIG_DIR and your existing state directory, then reinstall with scripts/install.sh or scripts/install-openrc.sh."
  assert_contains "Legacy noders-anytls install layout detected." "$stderr_path" "upgrade.sh did not report the legacy layout"
  assert_contains "$expected_hint" "$stderr_path" "upgrade.sh did not report the manual reinstall guidance"
)

test_install_management_support_skips_self_copy() (
  local tmp_root stdout_path stderr_path support_dir

  tmp_root="$(mktemp -d)"
  cleanup_self_copy_test() {
    rm -rf "$tmp_root"
  }
  trap cleanup_self_copy_test EXIT

  PREFIX="$tmp_root/prefix"
  CONFIG_DIR="$tmp_root/config"
  STATE_DIR="$tmp_root/state"
  LOG_DIR="$tmp_root/log"
  RUN_DIR="$tmp_root/run"

  install_management_support "$ROOT_DIR/scripts"
  support_dir="$PREFIX/lib/noders"

  stdout_path="$tmp_root/stdout"
  stderr_path="$tmp_root/stderr"
  if ! install_management_support "$support_dir" >"$stdout_path" 2>"$stderr_path"; then
    echo "install_management_support failed when source and destination support directories matched" >&2
    cat "$stderr_path" >&2
    exit 1
  fi

  if [[ -s "$stderr_path" ]]; then
    echo "install_management_support emitted unexpected stderr when source and destination matched" >&2
    cat "$stderr_path" >&2
    exit 1
  fi
)

test_upgrade_skips_binary_self_copy() (
  local tmp_root prefix_dir support_dir config_dir stdout_path stderr_path

  tmp_root="$(mktemp -d)"
  cleanup_upgrade_self_copy_test() {
    rm -rf "$tmp_root"
  }
  trap cleanup_upgrade_self_copy_test EXIT

  prefix_dir="$tmp_root/prefix"
  support_dir="$prefix_dir/lib/noders"
  config_dir="$tmp_root/config"
  install -d "$support_dir/lib" "$support_dir/packaging/systemd" "$prefix_dir/bin" "$config_dir"

  cp "$ROOT_DIR/scripts/install.sh" "$support_dir/install.sh"
  cp "$ROOT_DIR/scripts/install-openrc.sh" "$support_dir/install-openrc.sh"
  cp "$ROOT_DIR/scripts/upgrade.sh" "$support_dir/upgrade.sh"
  cp "$ROOT_DIR/scripts/lib/install-common.sh" "$support_dir/lib/install-common.sh"
  cp "$ROOT_DIR/packaging/systemd/noders.service" "$support_dir/packaging/systemd/noders.service"
  install -m 0755 /bin/sh "$support_dir/noders"

  stdout_path="$tmp_root/stdout"
  stderr_path="$tmp_root/stderr"
  if ! bash "$support_dir/upgrade.sh" --prefix "$prefix_dir" --config-dir "$config_dir" --no-restart >"$stdout_path" 2>"$stderr_path"; then
    echo "upgrade.sh failed when running from installed support directory" >&2
    cat "$stderr_path" >&2
    exit 1
  fi

  if grep -Fq "are the same file" "$stderr_path"; then
    echo "upgrade.sh still hit same-file install error for binary self-copy" >&2
    cat "$stderr_path" >&2
    exit 1
  fi

  assert_contains "Upgraded NodeRS" "$stdout_path" "upgrade.sh did not finish successfully in binary self-copy scenario"
)

main() {
  test_validate_args
  test_install_common_defaults_service_names
  test_management_script_filters_invalid_units
  test_upgrade_rejects_legacy_layout
  test_install_management_support_skips_self_copy
  test_upgrade_skips_binary_self_copy
}

main "$@"
