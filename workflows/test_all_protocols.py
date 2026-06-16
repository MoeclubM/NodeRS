#!/usr/bin/env python3
"""
End-to-end protocol integration test workflow.

For each protocol, this script:
1. Starts a simulated Xboard panel serving that protocol's config
2. Starts NodeRS connected to the panel
3. Waits for NodeRS to pull config and start the Aerion protocol server
4. Starts an Aerion client (same binary, correct subcommand per protocol)
5. Runs SOCKS5 TCP echo test through the full proxy chain

Protocols tested:
  shadowsocks, hysteria2, mieru, naive, trojan, tuic, vless, vmess, anytls

Usage:
  python test_all_protocols.py [--protocol hysteria2] [--only-protocols X,Y]
       [--aerion-bin PATH] [--noders-bin PATH] [--verbose]
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
AERION_DIR = Path("C:/Users/QwQ/Documents/GitHub/Aerion")

PROTOCOLS = [
    "shadowsocks",
    "hysteria2",
    "mieru",
    "naive",
    "trojan",
    "tuic",
    "vless",
    "vmess",
    "anytls",
]

MACHINE_ID = 1
NODE_ID = 42
PANEL_PORT_BASE = 18080
PORT_BASE = 21000
PANEL_TOKEN = "test-token-noders-e2e"

# Which protocols use their own Aerion subcommand vs. "aerion client"
PROTOCOL_SUBCOMMAND = {
    "hysteria2": "hysteria2-client",
    "mieru": "mieru-client",
    "tuic": "tuic-client",
}
PROTOCOL_SUBCOMMAND.update({p: "client" for p in PROTOCOLS if p not in PROTOCOL_SUBCOMMAND})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def free_port():
    """Return an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def kill_process(proc, name="process"):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    except Exception:
        pass


def run_in_background(args, **kwargs):
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8", errors="replace",
        **kwargs,
    )


def wait_for_server(host, port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.3)
    return False


def wait_for_log(proc, marker, timeout=30):
    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        line = proc.stderr.readline()
        if line:
            buf += line
            if marker in line.lower():
                return True, buf
        elif proc.poll() is not None:
            return False, buf + (proc.stdout.read() or "")
        else:
            time.sleep(0.1)
    return False, buf


# ---------------------------------------------------------------------------
# Echo server
# ---------------------------------------------------------------------------


class TcpEchoServer:
    def __init__(self):
        self.socket = None
        self.thread = None
        self.running = False
        self.port = 0

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(5)
        self.port = self.socket.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self.port

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.socket.accept()
                threading.Thread(target=self._echo, args=(conn,), daemon=True).start()
            except Exception:
                break

    def _echo(self, conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Protocol tester
# ---------------------------------------------------------------------------


class ProtocolTester:
    def __init__(self, protocol, aerion_bin, noders_bin, verbose):
        self.protocol = protocol
        self.aerion_bin = aerion_bin
        self.noders_bin = noders_bin
        self.verbose = verbose
        self.panel_proc = None
        self.noders_proc = None
        self.client_proc = None
        self.echo = TcpEchoServer()
        self.workdir = None

    def log(self, msg):
        print(f"  [{self.protocol}] {msg}")

    def run(self):
        self.log("starting...")
        try:
            echo_port = self.echo.start()
            self.log(f"echo on :{echo_port}")

            # 1. Start simulated panel
            panel_port = free_port()
            self.panel_proc = run_in_background([
                sys.executable,
                str(ROOT / "workflows" / "simulated_panel.py"),
                "--protocol", self.protocol,
                "--node-id", str(NODE_ID),
                "--port", str(panel_port),
                "--port-base", str(PORT_BASE),
            ])
            time.sleep(0.5)
            if self.panel_proc.poll() is not None:
                return False, f"panel died: {self.panel_proc.stderr.read()}"

            # 2. Create NodeRS config
            self.workdir = tempfile.mkdtemp(prefix=f"noders-e2e-{self.protocol}-")
            config_path = os.path.join(self.workdir, "config.toml")
            with open(config_path, "w") as f:
                f.write(f"""
[panel]
api = "http://127.0.0.1:{panel_port}"
key = "{PANEL_TOKEN}"
machine_id = {MACHINE_ID}
""")

            # 3. Start NodeRS
            self.noders_proc = run_in_background([
                str(self.noders_bin), config_path,
            ], cwd=self.workdir)

            # 4. Wait for protocol runtime
            found, log_out = wait_for_log(
                self.noders_proc,
                f"{self.protocol} protocol runtime applied",
                timeout=30,
            )
            if not found:
                self._dump_logs(log_out)
                # Check if NodeRS exited with error
                rc = self.noders_proc.poll()
                if rc is not None:
                    return False, f"NodeRS exited with code {rc}: {log_out[-600:]}"
                return False, f"protocol runtime not applied: {log_out[-400:]}"

            # 5. Find the server port from logs
            server_port = self._extract_server_port(log_out)
            if not server_port:
                return False, "could not determine server port"
            if not wait_for_server("127.0.0.1", server_port, timeout=5):
                return False, f"server not reachable on :{server_port}"
            self.log(f"server ready on :{server_port}")

            # 6. Aerion client test
            ok, msg = self._aerion_client_test(server_port, echo_port)
            if not ok:
                return False, f"client test failed: {msg}"
            self.log("client echo: PASS")

            return True, "all checks passed"
        except Exception as exc:
            return False, str(exc)
        finally:
            self.cleanup()

    def _extract_server_port(self, log_out):
        """Try to find the server port from logs or panel output."""
        import re
        for line in log_out.split("\n"):
            m = re.search(r"listening on.*:(\d+)", line, re.IGNORECASE)
            if m:
                return int(m.group(1))
        # Fallback: panel allocates PORT_BASE + 0
        return PORT_BASE

    def _aerion_client_test(self, server_port, echo_port):
        client_port = free_port()
        subcmd = PROTOCOL_SUBCOMMAND[self.protocol]
        args = [str(self.aerion_bin), subcmd]

        if subcmd == "client":
            args += [
                "--protocol", self.protocol,
                "--listen", f"127.0.0.1:{client_port}",
                "--server", f"127.0.0.1:{server_port}",
                "--password", "test-password-1001",
                "--sni", "node-test.local",
                "--insecure",
            ]
            if self.protocol == "shadowsocks":
                args += ["--method", "2022-blake3-aes-128-gcm"]
        elif subcmd == "hysteria2-client":
            args += [
                "--listen", f"127.0.0.1:{client_port}",
                "--server", f"127.0.0.1:{server_port}",
                "--password", "test-password-1001",
                "--sni", "node-test.local",
                "--insecure",
            ]
        elif subcmd == "mieru-client":
            args += [
                "--listen", f"127.0.0.1:{client_port}",
                "--server", f"127.0.0.1:{server_port}",
                "--username", "test-password-1001",
                "--password", "test-password-1001",
            ]
        elif subcmd == "tuic-client":
            args += [
                "--listen", f"127.0.0.1:{client_port}",
                "--server", f"127.0.0.1:{server_port}",
                "--uuid", "a3482e88-686a-4a58-8126-99c9df64b7bf",
                "--password", "test-password-1001",
                "--sni", "node-test.local",
                "--insecure",
            ]

        self.client_proc = run_in_background(args)
        if not wait_for_server("127.0.0.1", client_port, timeout=15):
            stderr_tail = self.client_proc.stderr.read() if self.client_proc.stderr else ""
            rc = self.client_proc.poll()
            return False, f"client did not start (rc={rc}): {stderr_tail[-300:]}"

        return self._socks_echo_test(client_port, echo_port)

    def _socks_echo_test(self, proxy_port, echo_port):
        try:
            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if resp != b"\x05\x00":
                return False, f"bad SOCKS greeting: {resp.hex()}"

            req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port)
            sock.sendall(req)
            resp = sock.recv(10)
            if resp[1] != 0:
                return False, f"SOCKS connect rejected (code={resp[1]})"

            payload = b"hello-e2e-" + self.protocol.encode()[:12]
            sock.sendall(payload)
            echoed = b""
            while len(echoed) < len(payload):
                chunk = sock.recv(len(payload) - len(echoed))
                if not chunk:
                    break
                echoed += chunk
            sock.close()

            if echoed == payload:
                return True, "OK"
            return False, f"echo mismatch: got {echoed[:50]!r}"
        except Exception as exc:
            return False, str(exc)

    def _dump_logs(self, log_output):
        if not self.workdir:
            return
        log_path = os.path.join(self.workdir, "noders.log")
        with open(log_path, "w") as f:
            f.write(log_output)
        self.log(f"logs saved to {log_path}")

    def cleanup(self):
        kill_process(self.client_proc, "aerion-client")
        kill_process(self.noders_proc, "noders")
        kill_process(self.panel_proc, "panel")
        self.echo.stop()
        if self.workdir:
            import shutil
            try:
                shutil.rmtree(self.workdir, ignore_errors=True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="NodeRS + Aerion E2E protocol test")
    parser.add_argument("--protocol", help="Test a single protocol (default: all)")
    parser.add_argument("--only-protocols", help="Comma-separated list of protocols to test")
    parser.add_argument("--aerion-bin", help="Path to aerion binary")
    parser.add_argument("--noders-bin", help="Path to noders binary")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    aerion_bin = args.aerion_bin or str(AERION_DIR / "target" / "debug" / "aerion.exe")
    noders_bin = args.noders_bin or str(ROOT / "target" / "debug" / "noders.exe")

    if not os.path.exists(aerion_bin):
        print(f"ERROR: aerion binary not found: {aerion_bin}")
        print("  Build with: cd Aerion && cargo build")
        return 1
    if not os.path.exists(noders_bin):
        print(f"ERROR: noders binary not found: {noders_bin}")
        print("  Build with: cd NodeRS && cargo build")
        return 1

    if args.only_protocols:
        protocols = [p.strip() for p in args.only_protocols.split(",")]
    elif args.protocol:
        protocols = [args.protocol]
    else:
        protocols = PROTOCOLS

    print("=" * 64)
    print("NodeRS + Aerion Protocol Integration Test")
    print(f"  aerion: {aerion_bin}")
    print(f"  noders: {noders_bin}")
    print(f"  protocols: {protocols}")
    print("=" * 64)

    results = {}
    for proto in protocols:
        print(f"\n--- {proto} ---")
        tester = ProtocolTester(proto, aerion_bin, noders_bin, args.verbose)
        ok, msg = tester.run()
        status = "PASS" if ok else "FAIL"
        print(f"  [{proto}] => {status}: {msg}")
        results[proto] = ok

    print("\n" + "=" * 64)
    n_pass = sum(1 for v in results.values() if v)
    n_fail = len(results) - n_pass
    print(f"RESULTS: {n_pass}/{len(results)} passed, {n_fail} failed")
    for proto, ok in results.items():
        print(f"  {proto:20s} {'PASS' if ok else 'FAIL'}")
    print("=" * 64)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
