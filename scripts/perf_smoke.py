#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULT_RE = re.compile(
    r"mode=(?P<mode>\S+) parallel=(?P<parallel>\d+) users=(?P<users>\d+) duration=(?P<duration>\d+)s "
    r"uploaded=(?P<uploaded_mib>\d+) MiB \((?P<uploaded_mbps>[0-9.]+) Mbps\) "
    r"downloaded=(?P<downloaded_mib>\d+) MiB \((?P<downloaded_mbps>[0-9.]+) Mbps\)"
)


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.getsockname()[1]


def wait_tcp(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return
            except OSError as exc:
                last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"port {host}:{port} not ready: {last_error}")


def ensure_tls_materials(temp_root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    cert_path = temp_root / "perf-cert.pem"
    key_path = temp_root / "perf-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert_path, key_path


class MockPanel:
    def __init__(self, port: int, server_port: int) -> None:
        self.port = port
        self.server_port = server_port
        self._httpd = None
        self._thread = None

    def start(self) -> None:
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def _auth(self) -> bool:
                qs = parse_qs(urlparse(self.path).query)
                return qs.get("token", [""])[0] == "bench-token"

            def _json(self, payload: object, code: int = 200) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if not self._auth():
                    self._json({"error": "forbidden"}, 403)
                    return
                path = urlparse(self.path).path
                if path.endswith("/config"):
                    self._json(
                        {
                            "protocol": "anytls",
                            "server_port": panel.server_port,
                            "server_name": "localhost",
                            "padding_scheme": [],
                            "routes": [],
                            "base_config": {"pull_interval": 600, "push_interval": 600},
                        }
                    )
                    return
                if path.endswith("/user"):
                    self._json(
                        {
                            "users": [
                                {
                                    "id": 1,
                                    "uuid": "bench-user-uuid-a",
                                    "speed_limit": 0,
                                    "device_limit": 0,
                                }
                            ]
                        }
                    )
                    return
                if path.endswith("/alivelist"):
                    self._json({"alive": {}})
                    return
                self._json({"error": "not found"}, 404)

            def do_POST(self) -> None:
                if not self._auth():
                    self._json({"error": "forbidden"}, 403)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self._json({"ok": True})

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def start_process(cmd: list[str], stdout_path: pathlib.Path, stderr_path: pathlib.Path) -> subprocess.Popen[str]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    out = open(stdout_path, "w", encoding="utf-8")
    err = open(stderr_path, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, stdout=out, stderr=err, text=True)
    setattr(proc, "_log_handles", (out, err))
    return proc


def stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        for handle in getattr(proc, "_log_handles", ()):
            handle.close()
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    for handle in getattr(proc, "_log_handles", ()):
        handle.close()


def resolve_binary(binary_dir: pathlib.Path, name: str) -> pathlib.Path:
    direct = binary_dir / name
    if direct.exists():
        return direct
    windows = binary_dir / f"{name}.exe"
    if windows.exists():
        return windows
    return direct


def run_client(
    bench_bin: pathlib.Path,
    server_port: int,
    target: str,
    mode: str,
    seconds: int,
    parallel: int,
    chunk_size: int,
    output_dir: pathlib.Path,
) -> dict[str, object]:
    log_path = output_dir / f"{mode}.stdout.log"
    err_path = output_dir / f"{mode}.stderr.log"
    cmd = [
        str(bench_bin),
        "client",
        "--server",
        f"127.0.0.1:{server_port}",
        "--sni",
        "localhost",
        "--user",
        "bench-user-uuid-a",
        "--target",
        target,
        "--mode",
        mode,
        "--seconds",
        str(seconds),
        "--parallel",
        str(parallel),
        "--chunk-size",
        str(chunk_size),
        "--insecure",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    log_path.write_text(completed.stdout, encoding="utf-8")
    err_path.write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"{mode} benchmark failed:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
    match = RESULT_RE.search(completed.stdout)
    if not match:
        raise RuntimeError(f"unexpected benchmark output for {mode}: {completed.stdout!r}")
    result = {key: match.group(key) for key in match.groupdict()}
    result["parallel"] = int(result["parallel"])
    result["users"] = int(result["users"])
    result["duration"] = int(result["duration"])
    result["uploaded_mib"] = int(result["uploaded_mib"])
    result["downloaded_mib"] = int(result["downloaded_mib"])
    result["uploaded_mbps"] = float(result["uploaded_mbps"])
    result["downloaded_mbps"] = float(result["downloaded_mbps"])
    result["stdout_log"] = str(log_path)
    result["stderr_log"] = str(err_path)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local Linux perf smoke benchmark for CI.")
    parser.add_argument("--binary-dir", required=True, help="Directory containing noders-anytls and bench_anytls.")
    parser.add_argument("--output-dir", required=True, help="Directory for logs and JSON results.")
    parser.add_argument("--seconds", type=int, default=4)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--chunk-size", type=int, default=32768)
    parser.add_argument("--min-upload-mbps", type=float, default=float(os.environ.get("NODERS_MIN_UPLOAD_MBPS", "250")))
    parser.add_argument(
        "--min-download-mbps",
        type=float,
        default=float(os.environ.get("NODERS_MIN_DOWNLOAD_MBPS", "250")),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    binary_dir = pathlib.Path(args.binary_dir).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    node_bin = resolve_binary(binary_dir, "noders-anytls")
    bench_bin = resolve_binary(binary_dir, "bench_anytls")
    if not node_bin.exists() or not bench_bin.exists():
        raise FileNotFoundError(f"benchmark binaries missing under {binary_dir}")

    panel_port = reserve_port()
    server_port = reserve_port()
    sink_port = reserve_port()
    source_port = reserve_port()

    panel = MockPanel(panel_port, server_port)
    processes: list[subprocess.Popen[str]] = []
    with tempfile.TemporaryDirectory(prefix="noders-perf-") as temp_dir:
        temp_root = pathlib.Path(temp_dir)
        cert_path, key_path = ensure_tls_materials(temp_root)
        config_path = temp_root / "config.toml"
        config_path.write_text(
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
                    'server_name = "localhost"',
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
            ),
            encoding="utf-8",
        )

        try:
            panel.start()
            node_proc = start_process(
                [str(node_bin), str(config_path)],
                output_dir / "noders-anytls.stdout.log",
                output_dir / "noders-anytls.stderr.log",
            )
            processes.append(node_proc)
            wait_tcp("127.0.0.1", server_port)

            sink_proc = start_process(
                [str(bench_bin), "sink", "--listen", f"127.0.0.1:{sink_port}"],
                output_dir / "sink.stdout.log",
                output_dir / "sink.stderr.log",
            )
            processes.append(sink_proc)
            wait_tcp("127.0.0.1", sink_port)

            source_proc = start_process(
                [
                    str(bench_bin),
                    "source",
                    "--listen",
                    f"127.0.0.1:{source_port}",
                    "--chunk-size",
                    str(args.chunk_size),
                ],
                output_dir / "source.stdout.log",
                output_dir / "source.stderr.log",
            )
            processes.append(source_proc)
            wait_tcp("127.0.0.1", source_port)

            upload = run_client(
                bench_bin,
                server_port,
                f"127.0.0.1:{sink_port}",
                "upload",
                args.seconds,
                args.parallel,
                args.chunk_size,
                output_dir,
            )
            download = run_client(
                bench_bin,
                server_port,
                f"127.0.0.1:{source_port}",
                "download",
                args.seconds,
                args.parallel,
                args.chunk_size,
                output_dir,
            )

            results = {
                "target": binary_dir.name,
                "seconds": args.seconds,
                "parallel": args.parallel,
                "chunk_size": args.chunk_size,
                "thresholds_mbps": {
                    "upload": args.min_upload_mbps,
                    "download": args.min_download_mbps,
                },
                "results": {"upload": upload, "download": download},
            }
            (output_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

            failures = []
            if upload["uploaded_mbps"] < args.min_upload_mbps:
                failures.append(
                    f"upload throughput {upload['uploaded_mbps']:.2f} Mbps is below floor {args.min_upload_mbps:.2f} Mbps"
                )
            if download["downloaded_mbps"] < args.min_download_mbps:
                failures.append(
                    f"download throughput {download['downloaded_mbps']:.2f} Mbps is below floor {args.min_download_mbps:.2f} Mbps"
                )
            if failures:
                raise RuntimeError("; ".join(failures))

            print(json.dumps(results, indent=2))
            return 0
        finally:
            for proc in reversed(processes):
                stop_process(proc)
            panel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
