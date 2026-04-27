#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

command -v rg >/dev/null 2>&1 || {
  echo "verify-pure-rust.sh requires 'rg' in PATH" >&2
  exit 1
}

banned_patterns=(
  'sing-box_mod'
  'sing-box'
  'sing_box'
  'singbox'
  'std::process'
  'tokio::process'
  'Command::new'
)

for pattern in "${banned_patterns[@]}"; do
  if rg -n --glob '!README.md' --glob '!scripts/*' --glob '!.github/*' --glob '!target/*' "$pattern" Cargo.toml Cargo.lock src >/dev/null; then
    echo "Forbidden external-core pattern found: $pattern" >&2
    rg -n --glob '!README.md' --glob '!scripts/*' --glob '!.github/*' --glob '!target/*' "$pattern" Cargo.toml Cargo.lock src >&2
    exit 1
  fi
done

echo 'Pure-Rust protocol check passed.'
