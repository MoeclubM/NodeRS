import argparse
import contextlib
import json
import os
import pathlib
import re
import shlex
import socket
import tarfile
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

import paramiko


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "real-host-bench"
ASSETS = WORK / "assets"
RESULTS_ROOT = WORK / "runs"
ASSETS.mkdir(parents=True, exist_ok=True)
RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

USERS = [f"bench-user-uuid-{index:02d}" for index in range(1, 5)]
UPLOAD_CHUNK = 32768
SAMPLE_INTERVAL = 1.0

PORTS = {
    "panel_current": 21080,
    "panel_v031": 21081,
    "source": 29080,
    "sink": 29081,
    "current": 24443,
    "v031": 24444,
    "sing": 24445,
    "socks_base": 20880,
}

NETEM_PROFILES = {
    "high-latency-lossy": "delay 200ms loss 0.5%",
    "high-loss-low-latency-lossy": "delay 55ms loss 20%",
    "jittery-lossy": "delay 40ms 150ms distribution paretonormal loss 6%",
}


@dataclass(frozen=True)
class Scenario:
    name: str
    mode: str
    profile: str | None = None
    attempts: int = 2
    parallel: int = 1
    seconds: int = 20
    warmup_seconds: float | None = None
    capture_curve: bool = True


SCENARIOS = [
    Scenario("upload-long-connection", "upload"),
    Scenario("download-long-connection", "download"),
    Scenario("idle-keepalive-65s", "idle", attempts=1, parallel=4, seconds=65, capture_curve=False),
]
for profile_name in NETEM_PROFILES:
    SCENARIOS.extend(
        [
            Scenario(
                f"upload-long-connection-{profile_name}",
                "upload",
                profile=profile_name,
                warmup_seconds=8.0 if profile_name == "high-latency-lossy" else None,
            ),
            Scenario(f"download-long-connection-{profile_name}", "download", profile=profile_name),
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real-host AnyTLS benchmarks on one host or across two hosts.")
    parser.add_argument("--mode", choices=["single-host", "interconnect"], required=True)
    parser.add_argument("--nyc-host", required=True)
    parser.add_argument("--brn-host")
    parser.add_argument("--username", default="root")
    parser.add_argument("--password")
    parser.add_argument("--password-env")
    parser.add_argument("--remote-root", default="/root/test")
    parser.add_argument("--output-dir")
    parser.add_argument("--scenarios", help="comma separated scenario names; defaults to the full suite")
    parser.add_argument("--long-seconds", type=int, default=20)
    parser.add_argument("--idle-seconds", type=int, default=65)
    parser.add_argument("--attempts", type=int, default=2, help="override throughput attempts when > 0")
    parser.add_argument("--sing-version", default="latest")
    args = parser.parse_args()
    if args.mode == "interconnect" and not args.brn_host:
        parser.error("--brn-host is required for interconnect mode")
    if not args.password and not args.password_env:
        parser.error("provide --password or --password-env")
    return args


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    assert args.password_env
    value = os.environ.get(args.password_env)
    if not value:
        raise SystemExit(f"environment variable {args.password_env!r} is empty or unset")
    return value


def build_scenarios(args: argparse.Namespace) -> list[Scenario]:
    scenarios: list[Scenario] = []
    allowed = None
    if args.scenarios:
        allowed = {item.strip() for item in args.scenarios.split(",") if item.strip()}
        unknown = allowed - {scenario.name for scenario in SCENARIOS}
        if unknown:
            raise SystemExit(f"unknown scenarios: {', '.join(sorted(unknown))}")

    for base in SCENARIOS:
        if allowed and base.name not in allowed:
            continue
        attempts = base.attempts
        if base.mode != "idle" and args.attempts > 0:
            attempts = args.attempts
        seconds = args.idle_seconds if base.mode == "idle" else args.long_seconds
        scenarios.append(
            Scenario(
                name=base.name if base.mode != "idle" else f"idle-keepalive-{args.idle_seconds}s",
                mode=base.mode,
                profile=base.profile,
                attempts=attempts,
                parallel=base.parallel,
                seconds=seconds,
                warmup_seconds=base.warmup_seconds,
                capture_curve=base.capture_curve,
            )
        )
    return scenarios


def github_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NodeRS-AnyTLS-real-host-bench",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def download_file(url: str, dest: pathlib.Path) -> pathlib.Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return dest
    request = urllib.request.Request(url, headers={"User-Agent": "NodeRS-AnyTLS-real-host-bench"})
    with urllib.request.urlopen(request, timeout=60) as response:
        dest.write_bytes(response.read())
    return dest


def extract_single_binary(archive_path: pathlib.Path, binary_name: str, out_path: pathlib.Path) -> pathlib.Path:
    if out_path.exists():
        out_path.chmod(0o755)
        return out_path
    with tarfile.open(archive_path, "r:gz") as archive:
        member = next((item for item in archive.getmembers() if pathlib.PurePosixPath(item.name).name == binary_name), None)
        if member is None:
            raise RuntimeError(f"{binary_name} not found in {archive_path}")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"unable to extract {binary_name} from {archive_path}")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(extracted.read())
    out_path.chmod(0o755)
    return out_path


def ensure_local_assets(*, sing_version: str) -> dict:
    current_dir = ROOT / "target" / "x86_64-unknown-linux-musl" / "release"
    current_server = current_dir / "noders-anytls"
    current_bench = current_dir / "bench_anytls"
    if not current_server.exists() or not current_bench.exists():
        raise RuntimeError("missing local musl build outputs under target/x86_64-unknown-linux-musl/release")

    v031_archive = download_file(
        "https://github.com/MoeclubM/NodeRS-AnyTLS/releases/download/v0.0.31/noders-anytls-v0.0.31-linux-amd64-musl.tar.gz",
        ASSETS / "noders-anytls-v0.0.31-linux-amd64-musl.tar.gz",
    )
    v031_server = extract_single_binary(v031_archive, "noders-anytls", ASSETS / "noders-anytls-v0.0.31")

    requested = sing_version
    if requested == "latest":
        cached = sorted((path for path in ASSETS.glob("sing-box-v*") if path.is_file()), key=lambda path: path.stat().st_mtime, reverse=True)
        if cached:
            sing_binary = cached[0]
            sing_tag = sing_binary.name.removeprefix("sing-box-")
        else:
            release = github_json("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
            sing_tag = release["tag_name"]
            asset = next(
                (
                    item
                    for item in release.get("assets", [])
                    if item["name"].endswith("linux-amd64.tar.gz") and "with-pgo" not in item["name"]
                ),
                None,
            )
            if asset is None:
                raise RuntimeError(f"linux-amd64 sing-box asset not found in {sing_tag}")
            archive = download_file(asset["browser_download_url"], ASSETS / asset["name"])
            sing_binary = extract_single_binary(archive, "sing-box", ASSETS / f"sing-box-{sing_tag}")
    else:
        tag = requested if requested.startswith("v") else f"v{requested}"
        archive_name = f"sing-box-{tag}-linux-amd64.tar.gz"
        archive = download_file(
            f"https://github.com/SagerNet/sing-box/releases/download/{tag}/{archive_name}",
            ASSETS / archive_name,
        )
        sing_tag = tag
        sing_binary = extract_single_binary(archive, "sing-box", ASSETS / f"sing-box-{sing_tag}")

    return {
        "current_server": current_server,
        "bench": current_bench,
        "v031_server": v031_server,
        "sing": sing_binary,
        "sing_tag": sing_tag,
        "compare_script": ROOT / "scripts" / "benchmark_compare_socks.py",
    }


def ssh_connect(host: str, *, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, timeout=20, banner_timeout=20, auth_timeout=20)
    return client


def run(ssh: paramiko.SSHClient, cmd: str, *, timeout: int = 120, check: bool = True) -> tuple[int, str, str]:
    wrapped = f"bash -lc {shlex.quote(cmd)}"
    stdin, stdout, stderr = ssh.exec_command(wrapped, timeout=timeout)
    del stdin
    channel = stdout.channel
    deadline = time.time() + timeout
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    while True:
        drained = False
        while channel.recv_ready():
            out_chunks.append(channel.recv(65536))
            drained = True
        while channel.recv_stderr_ready():
            err_chunks.append(channel.recv_stderr(65536))
            drained = True
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.time() >= deadline:
            channel.close()
            raise TimeoutError(f"remote command timed out after {timeout}s: {cmd}")
        if not drained:
            time.sleep(0.1)
    code = channel.recv_exit_status()
    out = b"".join(out_chunks).decode("utf-8", "replace")
    err = b"".join(err_chunks).decode("utf-8", "replace")
    if check and code != 0:
        raise RuntimeError(f"remote command failed ({code}): {cmd}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    return code, out, err


def put_text(sftp: paramiko.SFTPClient, remote_path: str, text: str, mode: int = 0o644) -> None:
    with sftp.file(remote_path, "w") as handle:
        handle.write(text)
    sftp.chmod(remote_path, mode)


def put_file(sftp: paramiko.SFTPClient, local_path: pathlib.Path, remote_path: str, mode: int = 0o755) -> None:
    sftp.put(str(local_path), remote_path)
    sftp.chmod(remote_path, mode)


def wait_port(ssh: paramiko.SSHClient, host: str, port: int, *, timeout_s: float = 30.0, label: str) -> None:
    deadline = time.time() + timeout_s
    probe = (
        "python3 - <<'PY'\n"
        "import socket\n"
        f"host={host!r}; port={port}\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "sock.settimeout(1.0)\n"
        "rc = sock.connect_ex((host, port))\n"
        "sock.close()\n"
        "raise SystemExit(0 if rc == 0 else 1)\n"
        "PY"
    )
    while time.time() < deadline:
        code, _, _ = run(ssh, probe, timeout=10, check=False)
        if code == 0:
            return
        time.sleep(0.5)
    raise RuntimeError(f"timeout waiting for {host}:{port} from {label}")


def stop_remote_stack(ssh: paramiko.SSHClient, *, root: str) -> None:
    cmd = f"""
set +e
if [ -d {shlex.quote(root)}/run ]; then
  for pidfile in {shlex.quote(root)}/run/*.pid; do
    [ -f "$pidfile" ] || continue
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      sleep 0.2
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  done
fi
pkill -f {shlex.quote(root)} 2>/dev/null || true
tc qdisc del dev lo root 2>/dev/null || true
tc qdisc del dev $(ip -4 route show default | awk '{{print $5}}' | head -n1) root 2>/dev/null || true
exit 0
"""
    run(ssh, cmd, timeout=30, check=False)


def stop_named(ssh: paramiko.SSHClient, *, root: str, name: str) -> None:
    cmd = f"""
set +e
pidfile={shlex.quote(root)}/run/{name}.pid
if [ -f "$pidfile" ]; then
  pid=$(cat "$pidfile" 2>/dev/null)
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    sleep 0.2
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
fi
exit 0
"""
    run(ssh, cmd, timeout=10, check=False)


def start_bg(
    ssh: paramiko.SSHClient,
    *,
    root: str,
    name: str,
    cmd: str,
    ready_host: str | None = None,
    ready_port: int | None = None,
    ready_label: str,
) -> None:
    stop_named(ssh, root=root, name=name)
    remote_cmd = f"""
set -e
mkdir -p {shlex.quote(root)}/logs {shlex.quote(root)}/run
nohup {cmd} > {shlex.quote(root)}/logs/{name}.log 2>&1 < /dev/null &
echo $! > {shlex.quote(root)}/run/{name}.pid
"""
    run(ssh, remote_cmd, timeout=20)
    if ready_host is not None and ready_port is not None:
        wait_port(ssh, ready_host, ready_port, timeout_s=30.0, label=ready_label)


def route_info(ssh: paramiko.SSHClient, dest_ip: str) -> tuple[str, str]:
    _, out, _ = run(ssh, f"ip -4 route get {shlex.quote(dest_ip)}", timeout=10)
    dev_match = re.search(r"\bdev\s+(\S+)", out)
    src_match = re.search(r"\bsrc\s+(\S+)", out)
    if not dev_match or not src_match:
        raise RuntimeError(f"unable to parse route info for {dest_ip}: {out}")
    return dev_match.group(1), src_match.group(1)


def clear_netem(ssh: paramiko.SSHClient, dev: str) -> None:
    run(ssh, f"tc qdisc del dev {shlex.quote(dev)} root 2>/dev/null || true", timeout=10, check=False)


def apply_interconnect_netem(ssh: paramiko.SSHClient, *, dev: str, dest_ip: str, profile_spec: str) -> None:
    cmd = f"""
set -e
tc qdisc replace dev {shlex.quote(dev)} root handle 1: prio bands 4
tc qdisc replace dev {shlex.quote(dev)} parent 1:4 handle 40: netem {profile_spec}
tc filter del dev {shlex.quote(dev)} parent 1:0 protocol ip prio 1 2>/dev/null || true
tc filter add dev {shlex.quote(dev)} protocol ip parent 1:0 prio 1 u32 match ip dst {shlex.quote(dest_ip)}/32 flowid 1:4
"""
    run(ssh, cmd, timeout=20)


def apply_single_host_netem(ssh: paramiko.SSHClient, *, profile_spec: str, ports: list[int]) -> None:
    parts = [
        "set -e",
        "tc qdisc replace dev lo root handle 1: prio bands 4",
        f"tc qdisc replace dev lo parent 1:4 handle 40: netem {profile_spec}",
        "tc filter del dev lo parent 1:0 protocol ip prio 1 2>/dev/null || true",
    ]
    for port in ports:
        parts.append(
            f"tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip dport {port} 0xffff flowid 1:4"
        )
        parts.append(
            f"tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip sport {port} 0xffff flowid 1:4"
        )
    run(ssh, "\n".join(parts), timeout=20)


@contextmanager
def maybe_netem(
    *,
    mode: str,
    profile_name: str | None,
    server_ssh: paramiko.SSHClient,
    client_ssh: paramiko.SSHClient,
    server_ip: str,
    client_ip: str | None,
    server_ports: list[int],
) -> None:
    if not profile_name:
        yield
        return

    profile_spec = NETEM_PROFILES[profile_name]
    if mode == "single-host":
        apply_single_host_netem(server_ssh, profile_spec=profile_spec, ports=server_ports)
        try:
            yield
        finally:
            clear_netem(server_ssh, "lo")
        return

    assert client_ip is not None
    server_dev, _ = route_info(server_ssh, client_ip)
    client_dev, _ = route_info(client_ssh, server_ip)
    apply_interconnect_netem(client_ssh, dev=client_dev, dest_ip=server_ip, profile_spec=profile_spec)
    try:
        apply_interconnect_netem(server_ssh, dev=server_dev, dest_ip=client_ip, profile_spec=profile_spec)
    except Exception:
        clear_netem(client_ssh, client_dev)
        raise
    try:
        yield
    finally:
        clear_netem(server_ssh, server_dev)
        clear_netem(client_ssh, client_dev)


def summarize_curve(samples: list[dict]) -> dict:
    if not samples:
        return {
            "curve_points": 0,
            "curve_head_mbps": None,
            "curve_avg_mbps": None,
            "curve_peak_mbps": None,
            "curve_min_mbps": None,
            "curve_tail_mbps": None,
        }
    mbps_values = [float(sample["mbps"]) for sample in samples]
    head = mbps_values[: min(5, len(mbps_values))]
    tail = mbps_values[-min(5, len(mbps_values)) :]
    return {
        "curve_points": len(mbps_values),
        "curve_head_mbps": round(sum(head) / len(head), 2),
        "curve_avg_mbps": round(sum(mbps_values) / len(mbps_values), 2),
        "curve_peak_mbps": round(max(mbps_values), 2),
        "curve_min_mbps": round(min(mbps_values), 2),
        "curve_tail_mbps": round(sum(tail) / len(tail), 2),
    }


def median_value(values: list[float | None]) -> float | None:
    usable = sorted(value for value in values if value is not None)
    if not usable:
        return None
    mid = len(usable) // 2
    if len(usable) % 2 == 1:
        return usable[mid]
    return (usable[mid - 1] + usable[mid]) / 2.0


def format_metric(value: float | None) -> str:
    return f"{value:.2f}" if isinstance(value, (int, float)) else "n/a"


def format_delta(current: float | None, baseline: float | None, *, higher_is_better: bool = True) -> str:
    if current is None or baseline is None or baseline == 0:
        return "n/a"
    raw = ((current - baseline) / baseline) * 100.0
    if not higher_is_better:
        raw = -raw
    sign = "+" if raw >= 0 else ""
    return f"{sign}{raw:.2f}%"


def write_sing_client_config(*, server: str, server_name: str, server_port: int, user: str, socks_port: int) -> str:
    return json.dumps(
        {
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [
                {
                    "type": "anytls",
                    "tag": "proxy",
                    "server": server,
                    "server_port": server_port,
                    "password": user,
                    "tls": {"enabled": True, "server_name": server_name, "insecure": True},
                }
            ],
            "route": {"final": "proxy"},
        },
        indent=2,
    )


def start_sing_clients(
    client_ssh: paramiko.SSHClient,
    *,
    client_root: str,
    impl_name: str,
    server_host: str,
    server_name: str,
    server_port: int,
    client_count: int,
) -> list[str]:
    sftp = client_ssh.open_sftp()
    proxies: list[str] = []
    try:
        for index in range(client_count):
            socks_port = PORTS["socks_base"] + index
            cfg_path = f"{client_root}/config/{impl_name}.client-{index}.json"
            put_text(
                sftp,
                cfg_path,
                write_sing_client_config(
                    server=server_host,
                    server_name=server_name,
                    server_port=server_port,
                    user=USERS[index],
                    socks_port=socks_port,
                ),
            )
            start_bg(
                client_ssh,
                root=client_root,
                name=f"client-{index}",
                cmd=f"{client_root}/bin/sing-box run -c {cfg_path}",
                ready_host="127.0.0.1",
                ready_port=socks_port,
                ready_label="client",
            )
            proxies.append(f"127.0.0.1:{socks_port}")
    finally:
        sftp.close()
    return proxies


def stop_sing_clients(client_ssh: paramiko.SSHClient, *, client_root: str, client_count: int) -> None:
    for index in range(client_count):
        stop_named(client_ssh, root=client_root, name=f"client-{index}")


def run_compare(
    client_ssh: paramiko.SSHClient,
    *,
    client_root: str,
    run_id: str,
    scenario: Scenario,
    impl_name: str,
    attempt: int,
    proxies: list[str],
    local_run: pathlib.Path,
) -> tuple[dict, dict | None, pathlib.Path, pathlib.Path | None]:
    target_port = PORTS["sink"] if scenario.mode in ("upload", "idle") else PORTS["source"]
    slug = f"{scenario.name}-{impl_name}-attempt-{attempt}"
    remote_stdout = f"{client_root}/results/{run_id}-{slug}.json"
    remote_curve = None if not scenario.capture_curve else f"{client_root}/results/{run_id}-{slug}.curve.json"
    cmd = [
        "python3",
        f"{client_root}/bin/benchmark_compare_socks.py",
        "--proxies",
        ",".join(proxies),
        "--target",
        f"127.0.0.1:{target_port}",
        "--mode",
        scenario.mode,
        "--seconds",
        str(scenario.seconds),
        "--parallel",
        str(scenario.parallel),
        "--chunk-size",
        str(1024 if scenario.mode == "idle" else UPLOAD_CHUNK),
    ]
    if scenario.warmup_seconds is not None:
        cmd.extend(["--measure-warmup-seconds", str(scenario.warmup_seconds)])
    if remote_curve:
        cmd.extend(["--curve-file", remote_curve, "--sample-interval", str(SAMPLE_INTERVAL)])

    stdout_local = local_run / pathlib.Path(remote_stdout).name
    stderr_local = local_run / f"{run_id}-{slug}.stderr.txt"
    shell_cmd = "set -o pipefail; " + " ".join(shlex.quote(part) for part in cmd) + f" | tee {shlex.quote(remote_stdout)}"
    code, stdout_text, stderr_text = run(client_ssh, shell_cmd, timeout=scenario.seconds + 120, check=False)
    stdout_local.write_text(stdout_text, encoding="utf-8")
    if stderr_text.strip():
        stderr_local.write_text(stderr_text, encoding="utf-8")

    metrics = None
    if stdout_text.strip():
        with contextlib.suppress(json.JSONDecodeError):
            metrics = json.loads(stdout_text)
    if metrics is None:
        detail = stderr_text.strip() or stdout_text.strip() or "no output"
        metrics = {
            "mode": scenario.mode,
            "parallel": scenario.parallel,
            "duration": float(scenario.seconds),
            "measure_warmup_seconds": scenario.warmup_seconds or 0.0,
            "bytes": 0,
            "mbps": 0.0,
            "pps": 0.0,
            "connect_ms": None,
            "first_byte_ms": None,
            "status": "fail",
            "error": f"compare_socks exited with {code}: {detail[:1000]}",
        }

    curve_summary = None
    curve_local = None
    sftp = client_ssh.open_sftp()
    try:
        if remote_curve and code == 0 and metrics.get("status") != "fail":
            curve_local = local_run / pathlib.Path(remote_curve).name
            sftp.get(remote_curve, str(curve_local))
            curve_data = json.loads(curve_local.read_text(encoding="utf-8"))
            curve_summary = summarize_curve(curve_data.get("samples", []))
    finally:
        sftp.close()
    return metrics, curve_summary, stdout_local, curve_local


def current_node_config(*, panel_port: int, cert_path: str, key_path: str) -> str:
    return "\n".join(
        [
            "[panel]",
            f'url = "http://127.0.0.1:{panel_port}"',
            'token = "bench-token"',
            "node_id = 1",
            "timeout_seconds = 5",
            "",
            "[node]",
            'listen_ip = "0.0.0.0"',
            "",
            "[tls]",
            f'cert_path = "{cert_path}"',
            f'key_path = "{key_path}"',
            "reload_interval_seconds = 600",
            "",
            "[outbound]",
            'dns_resolver = "system"',
            'ip_strategy = "system"',
            "",
            "[report]",
            "status_interval_seconds = 600",
            "min_traffic_bytes = 0",
            "",
            "[log]",
            'level = "warn"',
            "",
        ]
    )


def sing_server_config(*, server_name: str, cert_path: str, key_path: str) -> str:
    return json.dumps(
        {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "anytls",
                    "tag": "anytls-in",
                    "listen": "0.0.0.0",
                    "listen_port": PORTS["sing"],
                    "users": [{"name": user, "password": user} for user in USERS],
                    "padding_scheme": [],
                    "tls": {
                        "enabled": True,
                        "server_name": server_name,
                        "certificate_path": cert_path,
                        "key_path": key_path,
                    },
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        },
        indent=2,
    )


def install_remote_layout(
    *,
    server_ssh: paramiko.SSHClient,
    client_ssh: paramiko.SSHClient,
    server_root: str,
    client_root: str,
    assets: dict,
    server_name: str,
) -> None:
    for ssh, root in ((server_ssh, server_root), (client_ssh, client_root)):
        run(ssh, f"mkdir -p {shlex.quote(root)}/{{bin,config,logs,results,run}}")

    server_sftp = server_ssh.open_sftp()
    client_sftp = client_ssh.open_sftp()
    try:
        put_file(server_sftp, pathlib.Path(assets["current_server"]), f"{server_root}/bin/noders-anytls-current")
        put_file(server_sftp, pathlib.Path(assets["v031_server"]), f"{server_root}/bin/noders-anytls-v0.0.31")
        put_file(server_sftp, pathlib.Path(assets["sing"]), f"{server_root}/bin/sing-box")
        put_file(server_sftp, pathlib.Path(assets["bench"]), f"{server_root}/bin/bench_anytls")

        put_file(client_sftp, pathlib.Path(assets["sing"]), f"{client_root}/bin/sing-box")
        put_file(client_sftp, pathlib.Path(assets["compare_script"]), f"{client_root}/bin/benchmark_compare_socks.py")

        mock_panel = """#!/usr/bin/env python3
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

parser = argparse.ArgumentParser()
parser.add_argument('--listen', required=True)
parser.add_argument('--server-port', type=int, required=True)
parser.add_argument('--server-name', required=True)
parser.add_argument('--users', required=True)
args = parser.parse_args()
host, port = args.listen.rsplit(':', 1)
users = [item for item in args.users.split(',') if item]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return
    def _auth(self):
        qs = parse_qs(urlparse(self.path).query)
        return qs.get('token', [''])[0] == 'bench-token'
    def _json(self, payload, code=200):
        raw = json.dumps(payload).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        if not self._auth():
            self._json({'error': 'forbidden'}, 403)
            return
        path = urlparse(self.path).path
        if path.endswith('/config'):
            self._json({'protocol': 'anytls', 'server_port': args.server_port, 'server_name': args.server_name, 'padding_scheme': [], 'routes': [], 'base_config': {'pull_interval': 600, 'push_interval': 600}})
            return
        if path.endswith('/user'):
            self._json({'users': [{'id': idx + 1, 'uuid': user, 'speed_limit': 0, 'device_limit': 0} for idx, user in enumerate(users)]})
            return
        if path.endswith('/alivelist'):
            self._json({'alive': {}})
            return
        self._json({'error': 'not found'}, 404)
    def do_POST(self):
        if not self._auth():
            self._json({'error': 'forbidden'}, 403)
            return
        length = int(self.headers.get('Content-Length', '0'))
        if length:
            self.rfile.read(length)
        self._json({'ok': True})

httpd = ThreadingHTTPServer((host, int(port)), Handler)
httpd.serve_forever()
"""
        put_text(server_sftp, f"{server_root}/bin/mock_panel.py", mock_panel, 0o755)
        cert_path = f"{server_root}/config/tls.crt"
        key_path = f"{server_root}/config/tls.key"
        put_text(server_sftp, f"{server_root}/config/current.toml", current_node_config(panel_port=PORTS["panel_current"], cert_path=cert_path, key_path=key_path))
        put_text(server_sftp, f"{server_root}/config/v0.0.31.toml", current_node_config(panel_port=PORTS["panel_v031"], cert_path=cert_path, key_path=key_path))
        put_text(server_sftp, f"{server_root}/config/sing-box.json", sing_server_config(server_name=server_name, cert_path=cert_path, key_path=key_path))
    finally:
        server_sftp.close()
        client_sftp.close()


def prepare_servers(server_ssh: paramiko.SSHClient, *, server_root: str, server_name: str) -> None:
    run(
        server_ssh,
        f"""
set -e
openssl req -x509 -nodes -newkey rsa:2048 -days 7 \\
  -keyout {shlex.quote(server_root)}/config/tls.key \\
  -out {shlex.quote(server_root)}/config/tls.crt \\
  -subj {shlex.quote('/CN=' + server_name)} >/dev/null 2>&1
chmod 600 {shlex.quote(server_root)}/config/tls.key
""",
        timeout=60,
    )

    _, out, _ = run(
        server_ssh,
        "ss -ltn | awk 'NR>1 {print $4}' | egrep '(:21080|:21081|:29080|:29081|:24443|:24444|:24445)$' || true",
        timeout=10,
        check=False,
    )
    if out.strip():
        raise RuntimeError(f"expected benchmark ports to be free on server, found listeners:\n{out}")

    start_bg(server_ssh, root=server_root, name="source", cmd=f"{server_root}/bin/bench_anytls source --listen 127.0.0.1:{PORTS['source']}", ready_host="127.0.0.1", ready_port=PORTS["source"], ready_label="server")
    start_bg(server_ssh, root=server_root, name="sink", cmd=f"{server_root}/bin/bench_anytls sink --listen 127.0.0.1:{PORTS['sink']}", ready_host="127.0.0.1", ready_port=PORTS["sink"], ready_label="server")
    start_bg(server_ssh, root=server_root, name="panel-current", cmd=f"python3 {server_root}/bin/mock_panel.py --listen 127.0.0.1:{PORTS['panel_current']} --server-port {PORTS['current']} --server-name {shlex.quote(server_name)} --users {shlex.quote(','.join(USERS))}", ready_host="127.0.0.1", ready_port=PORTS["panel_current"], ready_label="server")
    start_bg(server_ssh, root=server_root, name="panel-v031", cmd=f"python3 {server_root}/bin/mock_panel.py --listen 127.0.0.1:{PORTS['panel_v031']} --server-port {PORTS['v031']} --server-name {shlex.quote(server_name)} --users {shlex.quote(','.join(USERS))}", ready_host="127.0.0.1", ready_port=PORTS["panel_v031"], ready_label="server")
    start_bg(server_ssh, root=server_root, name="noders-current", cmd=f"{server_root}/bin/noders-anytls-current {server_root}/config/current.toml", ready_host="127.0.0.1", ready_port=PORTS["current"], ready_label="server")
    start_bg(server_ssh, root=server_root, name="noders-v031", cmd=f"{server_root}/bin/noders-anytls-v0.0.31 {server_root}/config/v0.0.31.toml", ready_host="127.0.0.1", ready_port=PORTS["v031"], ready_label="server")
    start_bg(server_ssh, root=server_root, name="sing-box", cmd=f"{server_root}/bin/sing-box run -c {server_root}/config/sing-box.json", ready_host="127.0.0.1", ready_port=PORTS["sing"], ready_label="server")


def build_markdown(summary: dict) -> str:
    lines = [
        f"# Real Host Benchmark {summary['run_id']}",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Server host: `{summary['server_host']}` ({summary['server_ip']})",
        f"- Client host: `{summary['client_host']}` ({summary['client_ip']})",
        f"- Current commit: `{summary['current_commit']}`",
        f"- SingBox: `{summary['sing_box_version']}`",
        f"- Ping avg: `{summary['ping'].get('avg_ms')} ms` packet loss `{summary['ping'].get('packet_loss')}`",
        "",
    ]
    for row in summary["scenario_rows"]:
        lines.extend(
            [
                f"## {row['name']}",
                "",
                f"- Mode: `{row['mode']}`",
                f"- Profile: `{row['profile'] or 'clean'}`",
                "",
                "| Impl | Mbps | Tail Mbps | Connect ms | First byte ms | Status |",
                "|---|---:|---:|---:|---:|---|",
            ]
        )
        for impl in ["current", "v0.0.31", "SingBox"]:
            metrics = row["implementations"][impl]
            lines.append(
                f"| {impl} | {format_metric(metrics.get('mbps'))} | {format_metric(metrics.get('curve_tail_mbps'))} | "
                f"{format_metric(metrics.get('connect_ms'))} | {format_metric(metrics.get('first_byte_ms'))} | {metrics.get('status', 'n/a')} |"
            )
        lines.append("")
    return "\n".join(lines)


def current_commit() -> str:
    return os.popen(f'git -C "{ROOT}" rev-parse --short HEAD').read().strip()


def ping_summary(ssh: paramiko.SSHClient, host: str, *, local_run: pathlib.Path) -> dict:
    _, out, _ = run(ssh, f"ping -c 10 {shlex.quote(host)}", timeout=30)
    (local_run / "ping.txt").write_text(out, encoding="utf-8")
    ping_match = re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms", out)
    packet_loss_match = re.search(r"(\d+% packet loss)", out)
    return {
        "min_ms": float(ping_match.group(1)) if ping_match else None,
        "avg_ms": float(ping_match.group(2)) if ping_match else None,
        "max_ms": float(ping_match.group(3)) if ping_match else None,
        "mdev_ms": float(ping_match.group(4)) if ping_match else None,
        "packet_loss": packet_loss_match.group(1) if packet_loss_match else "unknown",
    }


def aggregate_scenarios(*, scenarios: list[Scenario], raw_results: list[dict]) -> list[dict]:
    scenario_rows: list[dict] = []
    for scenario in scenarios:
        scenario_items = [item for item in raw_results if item["scenario"] == scenario.name]
        row = {
            "name": scenario.name,
            "mode": scenario.mode,
            "profile": scenario.profile,
            "attempts": scenario.attempts,
            "implementations": {},
        }
        for impl_name in ["current", "v0.0.31", "SingBox"]:
            impl_rows = [item for item in scenario_items if item["impl"] == impl_name]
            mbps_values = [item["metrics"].get("mbps") for item in impl_rows]
            connect_values = [item["metrics"].get("connect_ms") for item in impl_rows]
            first_byte_values = [item["metrics"].get("first_byte_ms") for item in impl_rows]
            tail_values = [
                item["curve"].get("curve_tail_mbps")
                for item in impl_rows
                if item.get("curve") and item["curve"].get("curve_tail_mbps") is not None
            ]
            statuses = [item["metrics"].get("status") for item in impl_rows]
            row["implementations"][impl_name] = {
                "attempt_count": len(impl_rows),
                "status": f"pass {sum(1 for status in statuses if status == 'pass')}/{len(statuses)}",
                "mbps": round(median_value(mbps_values), 2) if median_value(mbps_values) is not None else None,
                "connect_ms": round(median_value(connect_values), 2) if median_value(connect_values) is not None else None,
                "first_byte_ms": round(median_value(first_byte_values), 2) if median_value(first_byte_values) is not None else None,
                "curve_tail_mbps": round(median_value(tail_values), 2) if median_value(tail_values) is not None else None,
                "attempt_rows": impl_rows,
            }
        scenario_rows.append(row)
    return scenario_rows


def collect_remote_artifacts(
    *,
    ssh: paramiko.SSHClient,
    root: str,
    local_dir: pathlib.Path,
    run_id: str,
) -> None:
    sftp = ssh.open_sftp()
    local_dir.mkdir(parents=True, exist_ok=True)
    try:
        for remote_subdir in ("logs", "results"):
            try:
                for entry in sftp.listdir_attr(f"{root}/{remote_subdir}"):
                    if remote_subdir == "results" and run_id not in entry.filename:
                        continue
                    sftp.get(f"{root}/{remote_subdir}/{entry.filename}", str(local_dir / entry.filename))
            except IOError:
                continue
    finally:
        sftp.close()


def main() -> None:
    args = parse_args()
    password = resolve_password(args)
    scenarios = build_scenarios(args)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    local_run = pathlib.Path(args.output_dir) if args.output_dir else RESULTS_ROOT / run_id
    local_run.mkdir(parents=True, exist_ok=True)

    server_root = f"{args.remote_root.rstrip('/')}/server"
    client_root = f"{args.remote_root.rstrip('/')}/client"
    server_name = args.nyc_host

    print("[phase] prepare local assets", flush=True)
    assets = ensure_local_assets(sing_version=args.sing_version)
    print("[phase] resolve hosts", flush=True)
    server_ip = socket.gethostbyname(args.nyc_host)
    client_host = args.nyc_host if args.mode == "single-host" else args.brn_host
    assert client_host is not None
    client_ip = socket.gethostbyname(client_host)

    summary = {
        "run_id": run_id,
        "mode": args.mode,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "server_host": args.nyc_host,
        "server_ip": server_ip,
        "client_host": client_host,
        "client_ip": client_ip,
        "current_commit": current_commit(),
        "sing_box_version": assets["sing_tag"],
        "ports": PORTS,
        "selected_scenarios": [scenario.name for scenario in scenarios],
    }

    print("[phase] connect remote hosts", flush=True)
    server_ssh = ssh_connect(args.nyc_host, username=args.username, password=password)
    client_ssh = ssh_connect(client_host, username=args.username, password=password)
    try:
        print("[phase] reset remote state", flush=True)
        stop_remote_stack(server_ssh, root=server_root)
        stop_remote_stack(client_ssh, root=client_root)
        print("[phase] install remote layout", flush=True)
        install_remote_layout(
            server_ssh=server_ssh,
            client_ssh=client_ssh,
            server_root=server_root,
            client_root=client_root,
            assets=assets,
            server_name=server_name,
        )
        print("[phase] prepare remote servers", flush=True)
        prepare_servers(server_ssh, server_root=server_root, server_name=server_name)

        connect_host = "127.0.0.1" if args.mode == "single-host" else server_ip
        print("[phase] wait server ports from client", flush=True)
        for port in [PORTS["current"], PORTS["v031"], PORTS["sing"]]:
            wait_port(client_ssh, connect_host, port, timeout_s=30.0, label="client")

        print("[phase] baseline ping", flush=True)
        ping_host = "127.0.0.1" if args.mode == "single-host" else args.nyc_host
        summary["ping"] = ping_summary(client_ssh, ping_host, local_run=local_run)

        raw_results: list[dict] = []
        impls = [("current", PORTS["current"]), ("v0.0.31", PORTS["v031"]), ("SingBox", PORTS["sing"])]
        server_ports = [PORTS["current"], PORTS["v031"], PORTS["sing"]]
        for scenario in scenarios:
            print(f"[scenario] {scenario.name} attempts={scenario.attempts}", flush=True)
            with maybe_netem(
                mode=args.mode,
                profile_name=scenario.profile,
                server_ssh=server_ssh,
                client_ssh=client_ssh,
                server_ip=server_ip,
                client_ip=None if args.mode == "single-host" else client_ip,
                server_ports=server_ports,
            ):
                for attempt in range(1, scenario.attempts + 1):
                    order = impls if attempt % 2 == 1 else list(reversed(impls))
                    for impl_name, port in order:
                        print(f"[run] {scenario.name} attempt {attempt} {impl_name}", flush=True)
                        proxies = start_sing_clients(
                            client_ssh,
                            client_root=client_root,
                            impl_name=f"{scenario.name}-{impl_name.lower().replace('.', '-')}",
                            server_host=connect_host,
                            server_name=server_name,
                            server_port=port,
                            client_count=scenario.parallel,
                        )
                        try:
                            metrics, curve_summary, stdout_file, curve_file = run_compare(
                                client_ssh,
                                client_root=client_root,
                                run_id=run_id,
                                scenario=scenario,
                                impl_name=impl_name.lower().replace(".", "-"),
                                attempt=attempt,
                                proxies=proxies,
                                local_run=local_run,
                            )
                        finally:
                            stop_sing_clients(client_ssh, client_root=client_root, client_count=scenario.parallel)
                        raw_results.append(
                            {
                                "scenario": scenario.name,
                                "impl": impl_name,
                                "attempt": attempt,
                                "metrics": metrics,
                                "curve": curve_summary,
                                "stdout_file": stdout_file.name,
                                "curve_file": curve_file.name if curve_file else None,
                            }
                        )

        summary["attempts"] = raw_results
        summary["scenario_rows"] = aggregate_scenarios(scenarios=scenarios, raw_results=raw_results)
        summary["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        (local_run / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (local_run / "report.md").write_text(build_markdown(summary), encoding="utf-8")
        collect_remote_artifacts(ssh=server_ssh, root=server_root, local_dir=local_run / "server", run_id=run_id)
        collect_remote_artifacts(ssh=client_ssh, root=client_root, local_dir=local_run / "client", run_id=run_id)
    finally:
        with contextlib.suppress(Exception):
            stop_remote_stack(server_ssh, root=server_root)
        with contextlib.suppress(Exception):
            stop_remote_stack(client_ssh, root=client_root)
        server_ssh.close()
        client_ssh.close()

    print(json.dumps({"run_id": run_id, "local_run": str(local_run)}, indent=2))


if __name__ == "__main__":
    main()
