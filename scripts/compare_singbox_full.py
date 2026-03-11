#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import re
import socket
import subprocess
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable

import psutil
import socketserver


ROOT = pathlib.Path(__file__).resolve().parents[1]
SING_ROOT = ROOT.parent / "sing-box_mod"
BENCH_ROOT = ROOT / "benchmark"
RUN_ROOT = BENCH_ROOT / "full-compare"
DEFAULT_SNI = "localhost"
USERS = [f"bench-user-uuid-{index:02d}" for index in range(1, 17)]
DEFAULT_PADDING_SCHEME = [
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
]

SOCKS_RESULT_RE = re.compile(
    r"mode=(?P<mode>\S+) parallel=(?P<parallel>\d+) chunk=(?P<chunk>\d+) "
    r"bytes=(?P<bytes>\d+) mbps=(?P<mbps>[0-9.]+) pps=(?P<pps>[0-9.]+)"
)
DIRECT_RESULT_RE = re.compile(
    r"mode=(?P<mode>\S+) parallel=(?P<parallel>\d+) users=(?P<users>\d+) duration=(?P<seconds>\d+)s "
    r"uploaded=(?P<uploaded_mib>\d+) MiB \((?P<upload_mbps>[0-9.]+) Mbps\) "
    r"downloaded=(?P<downloaded_mib>\d+) MiB \((?P<download_mbps>[0-9.]+) Mbps\)"
)
LATENCY_RES = {
    "connect_ms": re.compile(r"avg tcp connect: ([0-9.]+) ms"),
    "handshake_ms": re.compile(r"avg tls handshake: ([0-9.]+) ms"),
    "synack_ms": re.compile(r"avg stream synack: ([0-9.]+) ms"),
    "first_byte_ms": re.compile(r"avg first byte: ([0-9.]+) ms"),
}


@dataclass(frozen=True)
class WeakProfile:
    name: str
    latency_ms: int
    jitter_ms: int
    stall_rate: float = 0.0
    stall_ms: int = 0


@dataclass(frozen=True)
class Case:
    name: str
    driver: str
    transport: str
    mode: str
    chunk_size: int
    parallel: int
    users: int
    seconds: int
    target_kind: str
    weak_profile: WeakProfile | None = None
    corruption: bool = False
    expect_fail_close: bool = False
    scenario_kind: str = "throughput"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Full NodeRS vs sing-box AnyTLS comparison")
    parser.add_argument("--profile", choices=["quick", "standard", "full"], default="full")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--node-binary", default=str(ROOT / "target" / "release" / "noders-anytls.exe"))
    parser.add_argument("--bench-binary", default=str(ROOT / "target" / "release" / "bench_anytls.exe"))
    parser.add_argument("--sing-binary", default=str(BENCH_ROOT / "sing-box.exe"))
    parser.add_argument("--impls", default="NodeRS,SingBox")
    parser.add_argument("subcommand", nargs="?", choices=["corrupt-proxy"], help=argparse.SUPPRESS)
    parser.add_argument("--listen", help=argparse.SUPPRESS)
    parser.add_argument("--upstream", help=argparse.SUPPRESS)
    parser.add_argument("--flip-after-bytes", type=int, default=128 * 1024, help=argparse.SUPPRESS)
    parser.add_argument("--flip-every-bytes", type=int, default=256 * 1024, help=argparse.SUPPRESS)
    return parser.parse_args()


def ensure_dir(path: pathlib.Path) -> pathlib.Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def now_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def reserve_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, host: str = "127.0.0.1", timeout_seconds: float = 20.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return
            except OSError as error:
                last_error = error
                time.sleep(0.2)
    raise RuntimeError(f"port {host}:{port} not ready: {last_error}")


@contextmanager
def started_process(
    command: list[str],
    *,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    cwd: pathlib.Path | None = None,
    ready_port: int | None = None,
    ready_delay: float | None = None,
) -> Iterable[subprocess.Popen[str]]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with open(stdout_path, "w", encoding="utf-8") as stdout_file, open(
        stderr_path,
        "w",
        encoding="utf-8",
    ) as stderr_file:
        process = subprocess.Popen(command, cwd=str(cwd or ROOT), stdout=stdout_file, stderr=stderr_file, text=True)
        try:
            if ready_port is not None:
                wait_port(ready_port)
            elif ready_delay:
                time.sleep(ready_delay)
            yield process
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


class MemorySampler:
    def __init__(self, pid: int):
        self.pid = pid
        self.samples: list[tuple[int, int]] = []
        self.running = False
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while self.running:
            try:
                info = psutil.Process(self.pid).memory_full_info()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            rss = int(getattr(info, "rss", 0) or 0)
            private = int(getattr(info, "private", 0) or getattr(info, "uss", 0) or 0)
            self.samples.append((rss, private))
            time.sleep(0.2)

    def stop(self) -> dict[str, float]:
        self.running = False
        if self.thread is not None:
            self.thread.join(timeout=2)
        if not self.samples:
            return {"peak_rss_mb": 0.0, "avg_rss_mb": 0.0, "peak_private_mb": 0.0, "avg_private_mb": 0.0}
        rss_values = [value[0] for value in self.samples]
        private_values = [value[1] for value in self.samples]
        return {
            "peak_rss_mb": round(max(rss_values) / (1024 * 1024), 2),
            "avg_rss_mb": round(sum(rss_values) / len(rss_values) / (1024 * 1024), 2),
            "peak_private_mb": round(max(private_values) / (1024 * 1024), 2),
            "avg_private_mb": round(sum(private_values) / len(private_values) / (1024 * 1024), 2),
        }


class MockPanel:
    def __init__(self, port: int, node_port: int, log_path: pathlib.Path):
        self.port = port
        self.node_port = node_port
        self.log_path = log_path
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "MockPanel":
        token = "bench-token"
        users = [
            {"id": index + 1, "uuid": user, "speed_limit": 0, "device_limit": 0}
            for index, user in enumerate(USERS)
        ]
        config = {
            "protocol": "anytls",
            "server_port": self.node_port,
            "server_name": DEFAULT_SNI,
            "padding_scheme": [],
            "routes": [],
            "base_config": {"pull_interval": 600, "push_interval": 600},
        }
        alive = {"alive": {}}
        log_path = self.log_path

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write((fmt % args) + "\n")

            def _auth(self) -> bool:
                from urllib.parse import parse_qs, urlparse

                query = parse_qs(urlparse(self.path).query)
                return query.get("token", [""])[0] == token

            def _json(self, payload: Any, code: int = 200) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                from urllib.parse import urlparse

                if not self._auth():
                    self._json({"error": "forbidden"}, 403)
                    return
                path = urlparse(self.path).path
                if path.endswith("/config"):
                    self._json(config)
                elif path.endswith("/user"):
                    self._json({"users": users})
                elif path.endswith("/alivelist"):
                    self._json(alive)
                else:
                    self._json({"error": "not found"}, 404)

            def do_POST(self) -> None:  # noqa: N802
                if not self._auth():
                    self._json({"error": "forbidden"}, 403)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write(f"POST {self.path} {body.decode('utf-8', errors='replace')}\n")
                self._json({"ok": True})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)


def ensure_certificate(cert_path: pathlib.Path, key_path: pathlib.Path) -> None:
    if cert_path.exists() and key_path.exists():
        return
    fallback_cert = BENCH_ROOT / "cert.pem"
    fallback_key = BENCH_ROOT / "key.pem"
    if fallback_cert.exists() and fallback_key.exists():
        cert_path.write_bytes(fallback_cert.read_bytes())
        key_path.write_bytes(fallback_key.read_bytes())
        return
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "3650",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        cwd=str(ROOT),
        check=True,
    )


def ensure_binaries(node_binary: pathlib.Path, bench_binary: pathlib.Path, sing_binary: pathlib.Path, skip_build: bool) -> None:
    if not skip_build:
        subprocess.run(
            ["cargo", "build", "--release", "--bin", "noders-anytls", "--bin", "bench_anytls"],
            cwd=str(ROOT),
            check=True,
        )
    if not sing_binary.exists():
        subprocess.run(
            ["go", "build", "-o", str(sing_binary), ".\\cmd\\sing-box"],
            cwd=str(SING_ROOT),
            check=True,
        )
    if not node_binary.exists() or not bench_binary.exists() or not sing_binary.exists():
        raise FileNotFoundError("required benchmark binaries are missing")


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_toml(path: pathlib.Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def create_node_config(path: pathlib.Path, panel_port: int, cert_path: pathlib.Path, key_path: pathlib.Path) -> None:
    cert_path = cert_path.resolve()
    key_path = key_path.resolve()
    write_toml(
        path,
        "\n".join(
            [
                "[panel]",
                f'url = "http://127.0.0.1:{panel_port}"',
                'token = "bench-token"',
                "node_id = 1",
                "timeout_seconds = 5",
                "",
                "[node]",
                'listen_ip = "127.0.0.1"',
                "",
                "[tls]",
                f'cert_path = "{cert_path.as_posix()}"',
                f'key_path = "{key_path.as_posix()}"',
                f'server_name = "{DEFAULT_SNI}"',
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
            ],
        ),
    )


def create_sing_server_config(path: pathlib.Path, port: int, cert_path: pathlib.Path, key_path: pathlib.Path) -> None:
    cert_path = cert_path.resolve()
    key_path = key_path.resolve()
    write_json(
        path,
        {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "anytls",
                    "tag": "anytls-in",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "users": [{"name": user, "password": user} for user in USERS],
                    "padding_scheme": DEFAULT_PADDING_SCHEME,
                    "tls": {
                        "enabled": True,
                        "server_name": DEFAULT_SNI,
                        "certificate_path": str(cert_path),
                        "key_path": str(key_path),
                    },
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        },
    )


def create_sing_client_config(path: pathlib.Path, listen_port: int, server_port: int, user: str) -> None:
    write_json(
        path,
        {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": listen_port,
                }
            ],
            "outbounds": [
                {
                    "type": "anytls",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "password": user,
                    "tls": {"enabled": True, "server_name": DEFAULT_SNI, "insecure": True},
                }
            ],
            "route": {"final": "proxy"},
        },
    )


def parse_socks_output(text: str) -> dict[str, Any]:
    line = text.strip().splitlines()[0]
    match = SOCKS_RESULT_RE.search(line)
    if not match:
        raise RuntimeError(f"unexpected compare_socks output: {text!r}")
    row = {key: match.group(key) for key in match.groupdict()}
    row["parallel"] = int(row["parallel"])
    row["chunk"] = int(row["chunk"])
    row["bytes"] = int(row["bytes"])
    row["mbps"] = float(row["mbps"])
    row["pps"] = float(row["pps"])
    return row


def parse_direct_output(text: str) -> dict[str, Any]:
    match = DIRECT_RESULT_RE.search(text)
    if not match:
        raise RuntimeError(f"unexpected bench_anytls output: {text!r}")
    row = {key: match.group(key) for key in match.groupdict()}
    for key in ["parallel", "users", "seconds", "uploaded_mib", "downloaded_mib"]:
        row[key] = int(row[key])
    for key in ["upload_mbps", "download_mbps"]:
        row[key] = float(row[key])
    for key, regex in LATENCY_RES.items():
        found = regex.search(text)
        row[key] = float(found.group(1)) if found else None
    return row


def users_csv(count: int) -> str:
    return ",".join(USERS[:count])


def target_for(case: Case, ports: dict[str, int]) -> str:
    if case.target_kind == "sink":
        return f"127.0.0.1:{ports['sink']}"
    if case.target_kind == "source":
        return f"127.0.0.1:{ports['source']}"
    if case.target_kind == "udp-sink":
        return f"[::1]:{ports['udp_sink']}"
    if case.target_kind == "udp-source":
        return f"[::1]:{ports['udp_source']}"
    raise ValueError(case.target_kind)


def direct_mode_for(case: Case) -> str:
    if case.transport == "tcp":
        return case.mode
    if case.transport == "uot":
        return "udp-upload" if case.mode == "upload" else "udp-download"
    raise ValueError(case.transport)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS auth failed")
    try:
        addr = socket.inet_aton(target_host)
        request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
    except OSError:
        host = target_host.encode("utf-8")
        request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + target_port.to_bytes(2, "big")
    sock.sendall(request)
    head = recv_exact(sock, 4)
    if head[1] != 0x00:
        raise RuntimeError(f"SOCKS connect failed reply={head[1]}")
    atyp = head[3]
    if atyp == 1:
        recv_exact(sock, 4)
    elif atyp == 3:
        recv_exact(sock, recv_exact(sock, 1)[0])
    elif atyp == 4:
        recv_exact(sock, 16)
    recv_exact(sock, 2)
    return sock


def run_socks_transfer(mode: str, proxy: tuple[str, int], target: tuple[str, int], seconds: float, chunk_size: int, result: dict[str, int]) -> None:
    sock = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    deadline = time.perf_counter() + seconds
    transferred = 0
    packets = 0
    try:
        if mode == "upload":
            payload = b"\0" * chunk_size
            while time.perf_counter() < deadline:
                sock.sendall(payload)
                transferred += len(payload)
                packets += 1
        else:
            buffered = bytearray()
            while time.perf_counter() < deadline:
                chunk = sock.recv(131072)
                if not chunk:
                    break
                buffered.extend(chunk)
                while len(buffered) >= chunk_size:
                    del buffered[:chunk_size]
                    transferred += chunk_size
                    packets += 1
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.close()
    result["bytes"] = transferred
    result["packets"] = packets


def run_socks_bench(proxies: list[str], target: str, mode: str, seconds: float, parallel: int, chunk_size: int) -> dict[str, Any]:
    target_host, target_port_raw = target.rsplit(":", 1)
    target_tuple = (target_host, int(target_port_raw))
    proxy_tuples = []
    for proxy in proxies:
        host, port = proxy.rsplit(":", 1)
        proxy_tuples.append((host, int(port)))
    threads = []
    results: list[dict[str, int]] = []
    started = time.perf_counter()
    for index in range(parallel):
        result: dict[str, int] = {}
        thread = threading.Thread(
            target=run_socks_transfer,
            args=(mode, proxy_tuples[index % len(proxy_tuples)], target_tuple, seconds, chunk_size, result),
            daemon=True,
        )
        threads.append(thread)
        results.append(result)
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = max(time.perf_counter() - started, 1e-6)
    total_bytes = sum(item.get("bytes", 0) for item in results)
    total_packets = sum(item.get("packets", 0) for item in results)
    return {
        "mode": mode,
        "parallel": parallel,
        "chunk": chunk_size,
        "bytes": total_bytes,
        "mbps": total_bytes * 8 / elapsed / 1_000_000,
        "pps": total_packets / elapsed,
    }


def run_child_with_sampler(
    command: list[str],
    server_pid: int,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    cwd: pathlib.Path | None = None,
    timeout_seconds: float | None = None,
) -> tuple[str, str, dict[str, float], int]:
    sampler = MemorySampler(server_pid)
    with open(stdout_path, "w", encoding="utf-8") as stdout_file, open(stderr_path, "w", encoding="utf-8") as stderr_file:
        process = subprocess.Popen(command, cwd=str(cwd or ROOT), stdout=stdout_file, stderr=stderr_file, text=True)
        sampler.start()
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = -9
        finally:
            memory = sampler.stop()
    return stdout_path.read_text(encoding="utf-8", errors="ignore"), stderr_path.read_text(encoding="utf-8", errors="ignore"), memory, return_code


def build_cases(profile: str) -> list[Case]:
    cases: list[Case] = []
    if profile == "quick":
        socks_sizes = [256, 1024, 32768]
        direct_sizes = [1024, 32768]
        udp_sizes = [1200]
        concurrency_plan = [(16, 4)]
        udp_concurrency = [(16, 4)]
        weak_profiles = [WeakProfile("medium", 80, 20, stall_rate=0.02, stall_ms=120)]
    elif profile == "standard":
        socks_sizes = [256, 1024, 4096, 32768, 65535]
        direct_sizes = [1024, 4096, 32768, 65535]
        udp_sizes = [256, 1200, 1400]
        concurrency_plan = [(16, 4), (64, 16)]
        udp_concurrency = [(16, 4), (64, 16)]
        weak_profiles = [
            WeakProfile("mild", 40, 10, stall_rate=0.005, stall_ms=60),
            WeakProfile("medium", 80, 20, stall_rate=0.02, stall_ms=120),
        ]
    else:
        socks_sizes = [256, 1024, 4096, 16384, 32768, 65535]
        direct_sizes = [1024, 4096, 16384, 32768, 65535]
        udp_sizes = [256, 1200, 1400]
        concurrency_plan = [(16, 4), (64, 16), (250, 16)]
        udp_concurrency = [(16, 4), (64, 16), (250, 16)]
        weak_profiles = [
            WeakProfile("mild", 40, 10, stall_rate=0.005, stall_ms=60),
            WeakProfile("medium", 80, 20, stall_rate=0.02, stall_ms=120),
            WeakProfile("harsh", 120, 30, stall_rate=0.05, stall_ms=200),
        ]

    for mode in ["upload", "download"]:
        target_kind = "sink" if mode == "upload" else "source"
        for chunk in socks_sizes:
            cases.append(Case(f"socks-tcp-size-{mode}-{chunk}", "socks", "tcp", mode, chunk, 1, 1, 4, target_kind))
        for chunk in direct_sizes:
            cases.append(Case(f"direct-tcp-size-{mode}-{chunk}", "direct", "tcp", mode, chunk, 1, 1, 4, target_kind))
        for label, chunk in [("small", 1024), ("medium", 4096), ("large", 32768)]:
            for parallel, users in concurrency_plan:
                cases.append(Case(f"socks-tcp-concurrency-{mode}-{label}-p{parallel}-u{users}", "socks", "tcp", mode, chunk, parallel, users, 6, target_kind))
                cases.append(Case(f"direct-tcp-concurrency-{mode}-{label}-p{parallel}-u{users}", "direct", "tcp", mode, chunk, parallel, users, 6, target_kind))

    for mode in ["upload", "download"]:
        target_kind = "udp-sink" if mode == "upload" else "udp-source"
        for chunk in udp_sizes:
            cases.append(Case(f"direct-uot-size-{mode}-{chunk}", "direct", "uot", mode, chunk, 1, 1, 4, target_kind))
        for parallel, users in udp_concurrency:
            cases.append(Case(f"direct-uot-concurrency-{mode}-p{parallel}-u{users}", "direct", "uot", mode, 1200, parallel, users, 6, target_kind))

    cases.append(Case("direct-tcp-idle-keepalive", "direct", "tcp", "idle", 1024, 4, 4, 45 if profile == "full" else 20, "sink", scenario_kind="idle"))

    for weak in weak_profiles:
        for mode in ["upload", "download"]:
            cases.append(Case(f"direct-tcp-weak-{weak.name}-{mode}", "direct", "tcp", mode, 32768, 4, 4, 10, "sink" if mode == "upload" else "source", weak_profile=weak))
            cases.append(Case(f"direct-uot-weak-{weak.name}-{mode}", "direct", "uot", mode, 1200, 4, 4, 10, "udp-sink" if mode == "upload" else "udp-source", weak_profile=weak))

    cases.extend(
        [
            Case("direct-tcp-corrupt-upload", "direct", "tcp", "upload", 32768, 1, 1, 8, "sink", corruption=True, expect_fail_close=True, scenario_kind="corruption"),
            Case("direct-tcp-corrupt-download", "direct", "tcp", "download", 32768, 1, 1, 8, "source", corruption=True, expect_fail_close=True, scenario_kind="corruption"),
        ],
    )
    return cases


def run_corrupt_proxy(listen: str, upstream: str, flip_after_bytes: int, flip_every_bytes: int) -> None:
    listen_host, listen_port = listen.rsplit(":", 1)
    upstream_host, upstream_port = upstream.rsplit(":", 1)
    listen_addr = (listen_host, int(listen_port))
    upstream_addr = (upstream_host, int(upstream_port))

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            upstream_sock = socket.create_connection(upstream_addr, timeout=10)
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            stop_event = threading.Event()

            def pump(source: socket.socket, dest: socket.socket) -> None:
                seen = 0
                try:
                    while not stop_event.is_set():
                        chunk = source.recv(65536)
                        if not chunk:
                            break
                        data = bytearray(chunk)
                        if seen + len(data) >= flip_after_bytes and flip_every_bytes > 0:
                            start = max(flip_after_bytes - seen, 0)
                            for index in range(start, len(data), flip_every_bytes):
                                data[index] ^= 0x01
                        seen += len(data)
                        dest.sendall(data)
                except OSError:
                    pass
                finally:
                    stop_event.set()
                    try:
                        dest.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            threads = [
                threading.Thread(target=pump, args=(self.request, upstream_sock), daemon=True),
                threading.Thread(target=pump, args=(upstream_sock, self.request), daemon=True),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            upstream_sock.close()

    with socketserver.ThreadingTCPServer(listen_addr, Handler) as server:
        server.allow_reuse_address = True
        server.serve_forever()


class ImplEnvironment:
    def __init__(self, impl: str, run_dir: pathlib.Path, node_binary: pathlib.Path, bench_binary: pathlib.Path, sing_binary: pathlib.Path):
        self.impl = impl
        self.run_dir = ensure_dir(run_dir / impl.lower())
        self.node_binary = node_binary
        self.bench_binary = bench_binary
        self.sing_binary = sing_binary
        self.stack = ExitStack()
        self.server_port = reserve_tcp_port()
        self.panel_port = reserve_tcp_port()
        self.socks_ports = [reserve_tcp_port() for _ in range(4)]
        self.ports = {"sink": reserve_tcp_port(), "source": reserve_tcp_port(), "udp_sink": reserve_tcp_port(), "udp_source": reserve_tcp_port()}
        self.server_process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "ImplEnvironment":
        cert_path = self.run_dir / "cert.pem"
        key_path = self.run_dir / "key.pem"
        ensure_certificate(cert_path, key_path)
        if self.impl == "NodeRS":
            config_path = self.run_dir / "node-config.toml"
            create_node_config(config_path, self.panel_port, cert_path, key_path)
            self.stack.enter_context(MockPanel(self.panel_port, self.server_port, self.run_dir / "panel.log"))
            self.server_process = self.stack.enter_context(
                started_process([str(self.node_binary), str(config_path)], stdout_path=self.run_dir / "server.out.log", stderr_path=self.run_dir / "server.err.log", ready_port=self.server_port),
            )
        else:
            config_path = self.run_dir / "sing-server.json"
            create_sing_server_config(config_path, self.server_port, cert_path, key_path)
            self.server_process = self.stack.enter_context(
                started_process([str(self.sing_binary), "run", "-c", str(config_path)], stdout_path=self.run_dir / "server.out.log", stderr_path=self.run_dir / "server.err.log", ready_port=self.server_port),
            )
        for index, port in enumerate(self.socks_ports):
            config_path = self.run_dir / f"socks-client-{index}.json"
            create_sing_client_config(config_path, port, self.server_port, USERS[index % len(USERS)])
            self.stack.enter_context(
                started_process([str(self.sing_binary), "run", "-c", str(config_path)], stdout_path=self.run_dir / f"socks-client-{index}.out.log", stderr_path=self.run_dir / f"socks-client-{index}.err.log", ready_port=port),
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stack.close()

    @property
    def server_pid(self) -> int:
        assert self.server_process is not None
        return self.server_process.pid

    @property
    def server_endpoint(self) -> str:
        return f"127.0.0.1:{self.server_port}"

    @property
    def socks_proxies(self) -> list[str]:
        return [f"127.0.0.1:{port}" for port in self.socks_ports]


def make_target_manager(case: Case, ports: dict[str, int], out_dir: pathlib.Path):
    if case.target_kind == "sink":
        return started_process([str(ROOT / "target" / "release" / "bench_anytls.exe"), "sink", "--listen", f"127.0.0.1:{ports['sink']}"], stdout_path=out_dir / "sink.out.log", stderr_path=out_dir / "sink.err.log", ready_port=ports["sink"])
    if case.target_kind == "source":
        return started_process([str(ROOT / "target" / "release" / "bench_anytls.exe"), "source", "--listen", f"127.0.0.1:{ports['source']}", "--chunk-size", str(case.chunk_size)], stdout_path=out_dir / f"source-{case.chunk_size}.out.log", stderr_path=out_dir / f"source-{case.chunk_size}.err.log", ready_port=ports["source"])
    if case.target_kind == "udp-sink":
        return started_process([str(ROOT / "target" / "release" / "bench_anytls.exe"), "udp-sink", "--listen", f"[::1]:{ports['udp_sink']}"], stdout_path=out_dir / "udp-sink.out.log", stderr_path=out_dir / "udp-sink.err.log", ready_delay=0.3)
    if case.target_kind == "udp-source":
        return started_process([str(ROOT / "target" / "release" / "bench_anytls.exe"), "udp-source", "--listen", f"[::1]:{ports['udp_source']}", "--payload-size", str(case.chunk_size)], stdout_path=out_dir / f"udp-source-{case.chunk_size}.out.log", stderr_path=out_dir / f"udp-source-{case.chunk_size}.err.log", ready_delay=0.3)
    raise ValueError(case.target_kind)


def run_compare_socks_case(case: Case, env: ImplEnvironment, target: str, case_dir: pathlib.Path) -> dict[str, Any]:
    sampler = MemorySampler(env.server_pid)
    sampler.start()
    try:
        parsed = run_socks_bench(env.socks_proxies, target, case.mode, case.seconds, case.parallel, case.chunk_size)
    finally:
        memory = sampler.stop()
    (case_dir / "client.out.log").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    (case_dir / "client.err.log").write_text("", encoding="utf-8")
    return {
        "impl": env.impl,
        "driver": "socks-sing-client",
        "transport": case.transport,
        "mode": case.mode,
        "scenario": case.name,
        "status": "ok",
        "chunk_size": case.chunk_size,
        "parallel": case.parallel,
        "users": case.users,
        "seconds": case.seconds,
        "upload_mbps": parsed["mbps"] if case.mode == "upload" else 0.0,
        "download_mbps": parsed["mbps"] if case.mode == "download" else 0.0,
        "pps": parsed["pps"],
        "bytes": parsed["bytes"],
        **memory,
    }


def run_direct_case(case: Case, env: ImplEnvironment, target: str, endpoint: str, case_dir: pathlib.Path) -> dict[str, Any]:
    command = [
        str(env.bench_binary),
        "client",
        "--server",
        endpoint,
        "--sni",
        DEFAULT_SNI,
        "--users",
        users_csv(case.users),
        "--target",
        target,
        "--mode",
        "idle" if case.scenario_kind == "idle" else direct_mode_for(case),
        "--seconds",
        str(case.seconds),
        "--parallel",
        str(case.parallel),
        "--chunk-size",
        str(case.chunk_size),
        "--insecure",
    ]
    stdout, stderr, memory, return_code = run_child_with_sampler(
        command,
        env.server_pid,
        case_dir / "client.out.log",
        case_dir / "client.err.log",
        timeout_seconds=case.seconds + 20,
    )
    if case.expect_fail_close:
        return {
            "impl": env.impl,
            "driver": "direct-anytls",
            "transport": case.transport,
            "mode": case.mode,
            "scenario": case.name,
            "status": "timeout" if return_code == -9 else ("fail-close" if return_code != 0 else "unexpected-success"),
            "chunk_size": case.chunk_size,
            "parallel": case.parallel,
            "users": case.users,
            "seconds": case.seconds,
            "error": stderr.strip() or stdout.strip(),
            **memory,
        }
    if return_code != 0:
        raise RuntimeError(f"bench_anytls client failed for {case.name}:\n{stdout}\n{stderr}")
    parsed = parse_direct_output(stdout)
    return {
        "impl": env.impl,
        "driver": "direct-anytls",
        "transport": case.transport,
        "mode": case.mode,
        "scenario": case.name,
        "status": "ok",
        "chunk_size": case.chunk_size,
        "parallel": case.parallel,
        "users": case.users,
        "seconds": case.seconds,
        **parsed,
        **memory,
    }


def idle_memory_row(env: ImplEnvironment) -> dict[str, Any]:
    sampler = MemorySampler(env.server_pid)
    sampler.start()
    time.sleep(1.5)
    return {"impl": env.impl, "driver": "server", "transport": "n/a", "mode": "idle", "scenario": "idle-memory", "status": "ok", **sampler.stop()}


def run_case(case: Case, env: ImplEnvironment) -> dict[str, Any]:
    if env.impl == "SingBox" and case.driver == "direct":
        return {
            "impl": env.impl,
            "driver": "direct-anytls",
            "transport": case.transport,
            "mode": case.mode,
            "scenario": case.name,
            "status": "unsupported",
            "chunk_size": case.chunk_size,
            "parallel": case.parallel,
            "users": case.users,
            "seconds": case.seconds,
            "error": "bench_anytls direct client is not compatible with sing-box inbound in this Windows harness; use socks-sing-client rows for cross-impl comparison",
        }
    case_dir = ensure_dir(env.run_dir / case.name)
    target = target_for(case, env.ports)
    endpoint = env.server_endpoint
    with ExitStack() as stack:
        stack.enter_context(make_target_manager(case, env.ports, case_dir))
        if case.weak_profile is not None:
            weak = case.weak_profile
            weak_port = reserve_tcp_port()
            stack.enter_context(
                started_process(
                    [
                        str(env.bench_binary),
                        "tcp-proxy",
                        "--listen",
                        f"127.0.0.1:{weak_port}",
                        "--upstream",
                        env.server_endpoint,
                        "--latency-ms",
                        str(weak.latency_ms),
                        "--jitter-ms",
                        str(weak.jitter_ms),
                        "--stall-rate",
                        str(weak.stall_rate),
                        "--stall-ms",
                        str(weak.stall_ms),
                    ],
                    stdout_path=case_dir / "weak-proxy.out.log",
                    stderr_path=case_dir / "weak-proxy.err.log",
                    ready_port=weak_port,
                ),
            )
            endpoint = f"127.0.0.1:{weak_port}"
        if case.corruption:
            corrupt_port = reserve_tcp_port()
            stack.enter_context(
                started_process(
                    [
                        sys.executable,
                        str(pathlib.Path(__file__).resolve()),
                        "corrupt-proxy",
                        "--listen",
                        f"127.0.0.1:{corrupt_port}",
                        "--upstream",
                        env.server_endpoint,
                        "--flip-after-bytes",
                        str(16 * 1024),
                        "--flip-every-bytes",
                        str(32 * 1024),
                    ],
                    stdout_path=case_dir / "corrupt-proxy.out.log",
                    stderr_path=case_dir / "corrupt-proxy.err.log",
                    ready_port=corrupt_port,
                ),
            )
            endpoint = f"127.0.0.1:{corrupt_port}"
        row = run_compare_socks_case(case, env, target, case_dir) if case.driver == "socks" else run_direct_case(case, env, target, endpoint, case_dir)
        if case.weak_profile is not None:
            row["weak_profile"] = case.weak_profile.name
        return row


def compare_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row.get("driver"), row.get("transport"), row.get("mode"), row.get("scenario"), row.get("chunk_size"), row.get("parallel"), row.get("users"))


def diff_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keyed: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
    for row in rows:
        keyed.setdefault(compare_key(row), {})[row["impl"]] = row
    diffs: list[dict[str, Any]] = []
    for key, pair in keyed.items():
        node, sing = pair.get("NodeRS"), pair.get("SingBox")
        if not node or not sing:
            continue
        diff = {"driver": key[0], "transport": key[1], "mode": key[2], "scenario": key[3], "chunk_size": key[4], "parallel": key[5], "users": key[6], "node_status": node.get("status"), "sing_status": sing.get("status")}
        for field in ["upload_mbps", "download_mbps", "pps", "peak_rss_mb", "peak_private_mb", "connect_ms", "handshake_ms", "synack_ms", "first_byte_ms"]:
            node_value = node.get(field)
            sing_value = sing.get(field)
            diff[f"node_{field}"] = node_value
            diff[f"sing_{field}"] = sing_value
            if isinstance(node_value, (int, float)) and isinstance(sing_value, (int, float)):
                diff[f"delta_{field}"] = round(node_value - sing_value, 4)
                if sing_value:
                    diff[f"delta_pct_{field}"] = round((node_value - sing_value) / sing_value * 100, 4)
        diffs.append(diff)
    return diffs


def write_csv(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_case_summary(row: dict[str, Any]) -> None:
    parts = [row["impl"], row["scenario"], row["status"]]
    if isinstance(row.get("upload_mbps"), (int, float)):
        parts.append(f"up={row['upload_mbps']:.2f}Mbps")
    if isinstance(row.get("download_mbps"), (int, float)):
        parts.append(f"down={row['download_mbps']:.2f}Mbps")
    if isinstance(row.get("pps"), (int, float)):
        parts.append(f"pps={row['pps']:.2f}")
    print(" | ".join(parts))


def run_suite(args: argparse.Namespace) -> tuple[pathlib.Path, list[dict[str, Any]], list[dict[str, Any]]]:
    run_dir = ensure_dir(pathlib.Path(args.out_dir) if args.out_dir else RUN_ROOT / now_stamp())
    node_binary = pathlib.Path(args.node_binary)
    bench_binary = pathlib.Path(args.bench_binary)
    sing_binary = pathlib.Path(args.sing_binary)
    ensure_binaries(node_binary, bench_binary, sing_binary, args.skip_build)
    cases = build_cases(args.profile)
    rows: list[dict[str, Any]] = []
    for impl in [item.strip() for item in args.impls.split(",") if item.strip()]:
        with ImplEnvironment(impl, run_dir, node_binary, bench_binary, sing_binary) as env:
            idle = idle_memory_row(env)
            rows.append(idle)
            print_case_summary(idle)
            for case in cases:
                try:
                    row = run_case(case, env)
                except Exception as error:  # noqa: BLE001
                    row = {
                        "impl": impl,
                        "driver": "socks-sing-client" if case.driver == "socks" else "direct-anytls",
                        "transport": case.transport,
                        "mode": case.mode,
                        "scenario": case.name,
                        "status": "error",
                        "chunk_size": case.chunk_size,
                        "parallel": case.parallel,
                        "users": case.users,
                        "seconds": case.seconds,
                        "error": str(error),
                    }
                rows.append(row)
                print_case_summary(row)
    diffs = diff_rows(rows)
    write_csv(run_dir / "compare-full.csv", rows)
    write_csv(run_dir / "compare-full-diff.csv", diffs)
    (run_dir / "compare-full.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (run_dir / "compare-full-diff.json").write_text(json.dumps(diffs, indent=2), encoding="utf-8")
    return run_dir, rows, diffs


def main() -> int:
    args = parse_args()
    if args.subcommand == "corrupt-proxy":
        run_corrupt_proxy(args.listen, args.upstream, args.flip_after_bytes, args.flip_every_bytes)
        return 0
    run_dir, rows, diffs = run_suite(args)
    print(f"results: {run_dir}")
    print(f"raw rows: {len(rows)}")
    print(f"diff rows: {len(diffs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
