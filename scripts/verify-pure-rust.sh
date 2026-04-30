#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

banned_patterns=(
  'sing-box_mod'
  'sing_box'
  'singbox'
)

for pattern in "${banned_patterns[@]}"; do
  if git grep -F -n -- "$pattern" -- Cargo.toml Cargo.lock src >/dev/null; then
    echo "Forbidden external-core pattern found: $pattern" >&2
    git grep -F -n -- "$pattern" -- Cargo.toml Cargo.lock src >&2
    exit 1
  fi
done

echo 'Pure-Rust protocol check passed.'
