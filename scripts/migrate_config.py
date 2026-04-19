#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("scripts/migrate_config.py requires Python 3.11 or newer") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate a legacy NodeRS config to the machine-based config format."
    )
    parser.add_argument("source", help="Path to the legacy TOML config file")
    parser.add_argument(
        "--machine-id",
        type=int,
        help="New machine_id for the migrated config; if omitted, the script prompts for it",
    )
    parser.add_argument(
        "--output",
        help="Output path for the migrated config; default: <config-root>/machines/<machine_id>.toml",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create <source>.bak before writing the migrated config",
    )
    return parser.parse_args()


def prompt_machine_id() -> int:
    raw = input("Enter the new machine_id: ").strip()
    if not raw:
        raise SystemExit("machine_id is required")
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"invalid machine_id: {raw!r}") from exc


def read_panel_config(source: pathlib.Path) -> tuple[str, str, int | None]:
    data = tomllib.loads(source.read_text(encoding="utf-8"))
    panel = data.get("panel")
    if not isinstance(panel, dict):
        raise SystemExit(f"{source} does not contain a [panel] table")

    api = str(panel.get("api") or panel.get("url") or "").strip()
    key = str(panel.get("key") or panel.get("token") or "").strip()
    current_machine_id = panel.get("machine_id")
    current_node_id = panel.get("node_id")

    if not api:
        raise SystemExit(f"{source} is missing panel.api or panel.url")
    if not key:
        raise SystemExit(f"{source} is missing panel.key or panel.token")

    previous_id = current_machine_id if current_machine_id is not None else current_node_id
    if previous_id is not None:
        previous_id = int(previous_id)

    return api, key, previous_id


def default_output_path(source: pathlib.Path, machine_id: int) -> pathlib.Path:
    if source.parent.name in {"nodes", "machines"}:
        root = source.parent.parent
    else:
        root = source.parent
    return root / "machines" / f"{machine_id}.toml"


def render_config(api: str, key: str, machine_id: int) -> str:
    return (
        "[panel]\n"
        f"api = {json.dumps(api, ensure_ascii=False)}\n"
        f"key = {json.dumps(key, ensure_ascii=False)}\n"
        f"machine_id = {machine_id}\n"
    )


def main() -> int:
    args = parse_args()
    source = pathlib.Path(args.source).expanduser().resolve()
    if not source.is_file():
        raise SystemExit(f"source config not found: {source}")

    api, key, previous_id = read_panel_config(source)
    machine_id = args.machine_id if args.machine_id is not None else prompt_machine_id()
    target = (
        pathlib.Path(args.output).expanduser().resolve()
        if args.output
        else default_output_path(source, machine_id)
    )

    if not args.no_backup:
        backup = source.with_suffix(source.suffix + ".bak")
        shutil.copy2(source, backup)
        print(f"Backup written to {backup}")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_config(api, key, machine_id), encoding="utf-8", newline="\n")

    if previous_id is None:
        print(f"Migrated {source} to {target}")
    else:
        print(f"Migrated {source} ({previous_id}) to {target} ({machine_id})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
