#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_LIB_PATH="$ROOT_DIR/scripts/lib/install-common.sh"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "scripts/test-management-script.sh must run as root because it creates temporary systemd unit files under /etc/systemd/system." >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$COMMON_LIB_PATH"

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

TMP_ROOT="$(mktemp -d)"
UNIT_DIR="/etc/systemd/system"
SERVICE_NAME="noders-ci-test"
LEGACY_SERVICE_NAME="noders-anytls-ci-test"
VALID_UNIT="${SERVICE_NAME}-3-820183675"
INVALID_UNIT="${SERVICE_NAME}-3"$'\003'"-820183675"

cleanup() {
  rm -f \
    "${UNIT_DIR}/${VALID_UNIT}.service" \
    "${UNIT_DIR}/${INVALID_UNIT}.service"
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

PREFIX="$TMP_ROOT/prefix"
CONFIG_DIR="$TMP_ROOT/config"
STATE_DIR="$TMP_ROOT/state"
LOG_DIR="$TMP_ROOT/log"
RUN_DIR="$TMP_ROOT/run"

install_management_support "$ROOT_DIR/scripts"

install -d "$UNIT_DIR"

FAKE_BIN="$TMP_ROOT/fake-bin"
SYSTEMCTL_LOG="$TMP_ROOT/systemctl.log"
mkdir -p "$FAKE_BIN"
: > "$SYSTEMCTL_LOG"
cat > "$FAKE_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
{
  for arg in "$@"; do
    printf '[%s]\n' "$arg"
  done
} >> "$NODERS_FAKE_SYSTEMCTL_LOG"
EOF
chmod 0755 "$FAKE_BIN/systemctl"

: > "${UNIT_DIR}/${VALID_UNIT}.service"
: > "${UNIT_DIR}/${INVALID_UNIT}.service"

STDOUT_PATH="$TMP_ROOT/stdout"
STDERR_PATH="$TMP_ROOT/stderr"
PATH="$FAKE_BIN:$PATH" \
  NODERS_FAKE_SYSTEMCTL_LOG="$SYSTEMCTL_LOG" \
  "$PREFIX/bin/noders" restart >"$STDOUT_PATH" 2>"$STDERR_PATH"

if ! grep -Fq "Skipping invalid NodeRS service unit name" "$STDERR_PATH"; then
  echo "management script did not report the invalid systemd unit name" >&2
  cat "$STDERR_PATH" >&2
  exit 1
fi

EXPECTED_SYSTEMCTL_LOG="$(printf '[restart]\n[%s]' "$VALID_UNIT")"
ACTUAL_SYSTEMCTL_LOG="$(cat "$SYSTEMCTL_LOG")"
if [[ "$ACTUAL_SYSTEMCTL_LOG" != "$EXPECTED_SYSTEMCTL_LOG" ]]; then
  echo "management script passed unexpected unit arguments to systemctl" >&2
  echo "expected:" >&2
  printf '%s\n' "$EXPECTED_SYSTEMCTL_LOG" >&2
  echo "actual:" >&2
  printf '%s\n' "$ACTUAL_SYSTEMCTL_LOG" >&2
  exit 1
fi
