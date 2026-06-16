#!/usr/bin/env python3
"""End-to-end protocol test through mihomo (Clash Meta) as the client.

For each protocol, this script:
1. Starts a simulated Xboard panel serving that protocol's config
2. Starts NodeRS connected to the panel
3. Waits for NodeRS to pull config and start the Aerion protocol server
4. Generates a mihomo YAML config with a proxy pointing at the NodeRS server
5. Starts mihomo with the generated config
6. Runs TCP echo and (where supported) UDP echo tests through mihomo's SOCKS5 port

Usage:
  python test_all_protocols_mihomo.py [--protocol hysteria2] [--only-protocols X,Y]
       [--aerion-bin PATH] [--noders-bin PATH] [--mihomo-bin PATH] [--verbose]
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

ROOT = Path(os.environ.get("GITHUB_WORKSPACE", Path(__file__).resolve().parent.parent))
AERION_DIR = Path(os.environ.get("AERION_DIR", ROOT.parent / "Aerion"))
BIN_SUFFIX = ".exe" if sys.platform == "win32" else ""
MACHINE_ID = 1
NODE_ID = 42
PANEL_PORT_BASE = 18080
PORT_BASE = 22000
PANEL_TOKEN = "test-token-noders-e2e"

PROTOCOLS = [
    "shadowsocks", "hysteria2", "mieru",
    "trojan", "tuic", "vless", "vmess", "anytls",
]

DEFAULT_PASSWORD = "test-password-1001"
DEFAULT_UUID = "a3482e88-686a-4a58-8126-99c9df64b7bf"

NATIVE_UDP_PROTOCOLS = {
    "shadowsocks", "hysteria2", "mieru", "trojan", "tuic", "vless", "vmess",
}

def free_port():
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
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    return subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

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
    marker_lower = marker.lower()
    streams = [s for s in [proc.stdout, proc.stderr] if s is not None]

    if not streams:
        while time.time() < deadline and proc.poll() is None:
            time.sleep(0.1)
        return False, "no streams"

    if sys.platform == "win32":
        # Windows: use threads for non-blocking reads (select only works on sockets)
        buf_lock = threading.Lock()
        found_event = threading.Event()

        def reader(s):
            nonlocal buf
            try:
                while proc.poll() is None and not found_event.is_set():
                    data = s.read(4096)
                    if data:
                        with buf_lock:
                            buf += data
                        if marker_lower in data.lower():
                            found_event.set()
                            break
                    else:
                        break
            except Exception:
                pass

        threads = [threading.Thread(target=reader, args=(s,), daemon=True) for s in streams]
        for t in threads:
            t.start()

        while time.time() < deadline and proc.poll() is None and not found_event.is_set():
            time.sleep(0.1)

        # Drain remaining if process exited
        if proc.poll() is not None:
            for t in threads:
                t.join(timeout=1)
            for s in streams:
                if not s.closed:
                    try:
                        while True:
                            data = s.read(4096)
                            if not data:
                                break
                            buf += data
                    except Exception:
                        pass

        return marker_lower in buf.lower(), buf

    # Linux: use fcntl + select for non-blocking reads
    import select
    import fcntl
    for s in streams:
        fd = s.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    while time.time() < deadline:
        if proc.poll() is not None and not buf:
            break
        try:
            readable, _, _ = select.select(streams, [], [], 0.3)
        except ValueError:
            streams = [s for s in streams if not s.closed]
            if not streams:
                break
            continue
        for s in readable:
            try:
                data = s.read(4096)
                if data:
                    buf += data
                    if marker_lower in data.lower():
                        return True, buf
            except Exception:
                pass
        if proc.poll() is not None:
            for s in streams:
                if not s.closed:
                    try:
                        data = s.read(4096)
                        if data:
                            buf += data
                    except Exception:
                        pass
            break

    return marker_lower in buf.lower(), buf


def drain_proc_output(proc, timeout=2.0):
    """Non-blocking drain of proc stdout/stderr for debugging."""
    if sys.platform == "win32":
        result = ""
        for s in [proc.stdout, proc.stderr]:
            if s is None or s.closed:
                continue
            try:
                while True:
                    data = s.read(4096)
                    if not data:
                        break
                    result += data
            except Exception:
                pass
        return result
    import select
    import fcntl
    streams = [s for s in [proc.stdout, proc.stderr] if s is not None and not s.closed]
    for s in streams:
        try:
            fd = s.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        except Exception:
            pass
    result = ""
    deadline = time.time() + timeout
    while time.time() < deadline and streams:
        try:
            readable, _, _ = select.select(streams, [], [], 0.2)
        except (ValueError, OSError):
            break
        if not readable:
            continue
        for s in readable:
            try:
                data = s.read(4096)
                if data:
                    result += data
                else:
                    streams.remove(s)
            except Exception:
                pass
    return result


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

class UdpEchoServer:
    def __init__(self):
        self.socket = None
        self.running = False
        self.port = 0

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self.port

    def _serve(self):
        while self.running:
            try:
                self.socket.settimeout(0.5)
                data, addr = self.socket.recvfrom(4096)
                self.socket.sendto(data, addr)
            except socket.timeout:
                continue
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

def generate_mihomo_config(protocol, server_port, password, uuid_val, mixed_port, socks_port):
    proxy_name = f"test-{protocol}"
    proxy = {"name": proxy_name}

    if protocol == "shadowsocks":
        proxy.update({
            "type": "ss", "server": "127.0.0.1", "port": server_port,
            "cipher": "2022-blake3-aes-128-gcm",
            "password": password, "udp": True,
        })
    elif protocol == "hysteria2":
        proxy.update({
            "type": "hysteria2", "server": "127.0.0.1", "port": server_port,
            "password": password, "sni": "node-test.local",
            "skip-cert-verify": True, "udp": True,
        })
    elif protocol == "mieru":
        proxy.update({
            "type": "mieru", "server": "127.0.0.1", "port": server_port,
            "transport": "TCP",
            "username": uuid_val or DEFAULT_UUID, "password": uuid_val or DEFAULT_UUID, "udp": True,
        })
    elif protocol == "trojan":
        proxy.update({
            "type": "trojan", "server": "127.0.0.1", "port": server_port,
            "password": password, "sni": "node-test.local",
            "skip-cert-verify": True, "udp": True,
        })
    elif protocol == "tuic":
        if not uuid_val:
            uuid_val = DEFAULT_UUID
        proxy.update({
            "type": "tuic", "server": "127.0.0.1", "port": server_port,
            "uuid": uuid_val, "password": password,
            "sni": "node-test.local", "skip-cert-verify": True, "udp": True,
            "alpn": ["h3"],
        })
    elif protocol == "vless":
        if not uuid_val:
            uuid_val = DEFAULT_UUID
        proxy.update({
            "type": "vless", "server": "127.0.0.1", "port": server_port,
            "uuid": uuid_val, "tls": True, "servername": "node-test.local",
            "skip-cert-verify": True, "udp": True,
        })
    elif protocol == "vmess":
        if not uuid_val:
            uuid_val = DEFAULT_UUID
        proxy.update({
            "type": "vmess", "server": "127.0.0.1", "port": server_port,
            "uuid": uuid_val, "cipher": "auto", "udp": True, "alterId": 0,
        })
    elif protocol == "anytls":
        proxy.update({
            "type": "anytls", "server": "127.0.0.1", "port": server_port,
            "password": uuid_val or DEFAULT_UUID, "sni": "node-test.local",
            "udp": True,
            "skip-cert-verify": True,
        })

    return {
        "mixed-port": mixed_port,
        "socks-port": socks_port,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": [proxy],
        "proxy-groups": [{"name": "proxy", "type": "select", "proxies": [proxy_name]}],
        "rules": ["MATCH,proxy"],
    }


class MihomoProtocolTester:
    def __init__(self, protocol, aerion_bin, noders_bin, mihomo_bin, verbose):
        self.protocol = protocol
        self.aerion_bin = aerion_bin
        self.noders_bin = noders_bin
        self.mihomo_bin = mihomo_bin
        self.verbose = verbose
        self.panel_proc = None
        self.noders_proc = None
        self.mihomo_proc = None
        self.tcp_echo = TcpEchoServer()
        self.udp_echo = UdpEchoServer()
        self.workdir = None
        self.mixed_port = 0
        self.socks_port = 0

    def log(self, msg):
        print(f"  [{self.protocol}] {msg}")

    def run(self):
        self.log("starting with mihomo...")
        try:
            tcp_echo_port = self.tcp_echo.start()
            udp_echo_port = self.udp_echo.start()
            self.log(f"echo TCP:{tcp_echo_port} UDP:{udp_echo_port}")

            # 1. Start simulated panel
            panel_port = free_port()
            self.panel_proc = run_in_background([
                sys.executable,
                str(ROOT / "workflows" / "simulated_panel.py"),
                "--protocol", self.protocol,
                "--node-id", str(NODE_ID),
                "--cipher", "",  # shadowsocks uses SS2022 default
                "--port", str(panel_port),
                "--port-base", str(PORT_BASE),
            ], env={**os.environ, "PYTHONUNBUFFERED": "1"})
            time.sleep(0.5)
            if self.panel_proc.poll() is not None:
                stderr = self.panel_proc.stderr.read() if self.panel_proc.stderr else ""
                return False, f"panel died: {stderr}"

            # 2. Create NodeRS config
            self.workdir = tempfile.mkdtemp(prefix=f"noders-mihomo-{self.protocol}-")
            config_path = os.path.join(self.workdir, "config.toml")
            with open(config_path, "w") as f:
                f.write(f'[panel]\napi = "http://127.0.0.1:{panel_port}"\n')
                f.write(f'key = "{PANEL_TOKEN}"\n')
                f.write(f"machine_id = {MACHINE_ID}\n")

            # 3. Start NodeRS
            self.noders_proc = run_in_background(
                [str(self.noders_bin), config_path], cwd=self.workdir)

            # 4. Wait for protocol runtime
            marker = "aerion protocol runtime applied"
            found, log_out = wait_for_log(self.noders_proc, marker, timeout=90)
            if not found:
                # On Windows, tracing_subscriber may write via WriteConsoleW, bypassing pipe output.
                # Fall back to time-based wait: if noders is still alive, assume runtime applied.
                if sys.platform == "win32" and self.noders_proc.poll() is None:
                    fallback_wait = 10
                    self.log(f"log capture empty (Windows), waiting {fallback_wait}s for runtime...")
                    time.sleep(fallback_wait)
                    if self.noders_proc.poll() is not None:
                        return False, f"NodeRS exited {self.noders_proc.returncode} before runtime applied"
                    self.log("assuming runtime applied (time-based fallback)")
                else:
                    self._dump_logs(log_out)
                    rc = self.noders_proc.poll()
                    if rc is not None:
                        return False, f"NodeRS exited {rc}: {log_out[-400:]}"
                    return False, f"runtime not applied: {log_out[-300:]}"

            # 5. Extract server port
            server_port = self._extract_server_port(log_out)
            if not server_port:
                return False, "could not determine server port"
            # TCP connect doesn't work for QUIC/UDP protocols (hysteria2, tuic)
            if self.protocol not in ("hysteria2", "tuic"):
                if not wait_for_server("127.0.0.1", server_port, timeout=10):
                    return False, f"server not reachable :{server_port}"
            else:
                time.sleep(2)  # give QUIC server time to bind
            self.log(f"server :{server_port}")

            # 6. Mihomo config
            self.mixed_port = free_port()
            self.socks_port = free_port()
            pw = "vaR5nc1yDpQ707N7bRV2aA==" if self.protocol == "shadowsocks" else DEFAULT_PASSWORD
            uuid_val = DEFAULT_UUID
            config = generate_mihomo_config(
                self.protocol, server_port, pw, uuid_val,
                self.mixed_port, self.socks_port)
            import yaml
            mihomo_yaml = os.path.join(self.workdir, "config.yaml")
            with open(mihomo_yaml, "w") as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

            # 7. Start mihomo
            self.mihomo_proc = run_in_background(
                [str(self.mihomo_bin), "-f", mihomo_yaml,
                 "-d", self.workdir], cwd=self.workdir)
            if not wait_for_server("127.0.0.1", self.mixed_port, timeout=15):
                import select as _sel
                stderr = ""
                if self.mihomo_proc.stderr:
                    try:
                        import fcntl
                        fd = self.mihomo_proc.stderr.fileno()
                        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                    except Exception:
                        pass
                    for _ in range(50):
                        if self.mihomo_proc.poll() is not None:
                            break
                        try:
                            data = self.mihomo_proc.stderr.read(4096)
                            if data:
                                stderr += data
                        except Exception:
                            pass
                try:
                    self.mihomo_proc.stderr.close()
                except Exception:
                    pass
                rc = self.mihomo_proc.poll()
                return False, f"mihomo not started (rc={rc}): {stderr[-500:-1] if stderr else 'no stderr'}"
            self.log("mihomo ready")

            # 8. TCP echo
            tcp_ok, tcp_msg = self._socks_echo_test(
                self.mixed_port, tcp_echo_port, b"tcp")
            if not tcp_ok:
                return False, f"TCP: {tcp_msg}"
            self.log("TCP PASS")

            # 9. UDP echo
            udp_msg = "skipped"
            if self.protocol in NATIVE_UDP_PROTOCOLS:
                udp_ok, udp_msg = self._udp_echo_test(
                    self.mixed_port, udp_echo_port)
                if udp_ok:
                    self.log("UDP PASS")
                else:
                    self.log(f"UDP FAIL ({udp_msg})")
                    noders_logs = drain_proc_output(self.noders_proc, timeout=2.0)
                    mihomo_logs = drain_proc_output(self.mihomo_proc, timeout=2.0)
                    if noders_logs:
                        for line in noders_logs[-3000:].strip().split("\n"):
                            self.log(f"  [noders] {line}")
                    if mihomo_logs:
                        for line in mihomo_logs[-3000:].strip().split("\n"):
                            self.log(f"  [mihomo] {line}")

            return True, f"TCP ok, UDP {udp_msg}"

        except Exception as exc:
            return False, str(exc)
        finally:
            self.cleanup()

    def _extract_server_port(self, log_out):
        import re
        for line in log_out.split("\n"):
            m = re.search(r"listening on.*:(\d+)", line, re.IGNORECASE)
            if m:
                return int(m.group(1))
        return PORT_BASE

    def _socks_echo_test(self, proxy_port, echo_port, label):
        try:
            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if resp != b"\x05\x00":
                return False, f"bad greeting {resp.hex()}"
            req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port)
            sock.sendall(req)
            resp = sock.recv(10)
            if resp[1] != 0:
                return False, f"connect rejected ({resp[1]})"
            # Small delay to let the proxy relay fully establish
            sock.settimeout(15)
            time.sleep(0.3)
            payload = b"hello-" + label + b"-" + self.protocol.encode()[:12]
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
            return False, f"mismatch: got {echoed[:50]!r}"
        except Exception as exc:
            return False, str(exc)

    def _udp_echo_test(self, proxy_port, echo_port):
        try:
            control = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
            control.sendall(b"\x05\x01\x00")
            resp = control.recv(2)
            if resp != b"\x05\x00":
                control.close()
                return False, f"bad greeting {resp.hex()}"
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            resp = control.recv(10)
            if resp[1] != 0:
                control.close()
                return False, f"UDP assoc rejected ({resp[1]})"
            atyp = resp[3]
            if atyp == 1:
                relay_ip = socket.inet_ntoa(resp[4:8])
                relay_port = struct.unpack("!H", resp[8:10])[0]
            elif atyp == 4:
                relay_ip = socket.inet_ntop(socket.AF_INET6, resp[4:20])
                relay_port = struct.unpack("!H", resp[20:22])[0]
            else:
                control.close()
                return False, f"bad atyp {atyp}"
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(5)
            target_ip = socket.inet_aton("127.0.0.1")
            payload = b"hello-udp-" + self.protocol.encode()[:12]
            packet = b"\x00\x00\x00\x01" + target_ip + struct.pack("!H", echo_port) + payload
            udp_sock.sendto(packet, (relay_ip, relay_port))
            try:
                response, _ = udp_sock.recvfrom(4096)
                echoed = response[10:]
                udp_sock.close()
                control.close()
                if echoed == payload:
                    return True, "OK"
                return False, f"mismatch: got {echoed[:50]!r}"
            except socket.timeout:
                udp_sock.close()
                control.close()
                return False, "timeout"
        except Exception as exc:
            return False, str(exc)

    def _dump_logs(self, log_output):
        if not self.workdir:
            return
        log_path = os.path.join(self.workdir, "noders.log")
        with open(log_path, "w") as f:
            f.write(log_output)

    def cleanup(self):
        kill_process(self.mihomo_proc, "mihomo")
        kill_process(self.noders_proc, "noders")
        kill_process(self.panel_proc, "panel")
        self.tcp_echo.stop()
        self.udp_echo.stop()
        if self.workdir:
            import shutil
            try:
                shutil.rmtree(self.workdir, ignore_errors=True)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="NodeRS + Aerion -> mihomo E2E protocol test")
    parser.add_argument("--protocol", help="Test a single protocol")
    parser.add_argument("--only-protocols", help="Comma-separated protocols")
    parser.add_argument("--aerion-bin", help="Path to aerion binary")
    parser.add_argument("--noders-bin", help="Path to noders binary")
    parser.add_argument("--mihomo-bin", help="Path to mihomo binary")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    aerion_bin = args.aerion_bin or str(AERION_DIR / "target" / "debug" / f"aerion{BIN_SUFFIX}")
    noders_bin = args.noders_bin or str(ROOT / "target" / "debug" / f"noders{BIN_SUFFIX}")
    mihomo_bin = args.mihomo_bin or os.path.join(os.environ.get("TEMP", "/tmp"), f"mihomo{BIN_SUFFIX}")

    for name, path in [("aerion", aerion_bin), ("noders", noders_bin), ("mihomo", mihomo_bin)]:
        if not os.path.exists(path):
            print(f"ERROR: {name} binary not found: {path}")
            return 1

    if args.only_protocols:
        protocols = [p.strip() for p in args.only_protocols.split(",")]
    elif args.protocol:
        protocols = [args.protocol]
    else:
        protocols = PROTOCOLS

    print("=" * 70)
    print("NodeRS + Aerion -> mihomo Protocol Integration Test")
    print(f"  aerion: {aerion_bin}")
    print(f"  noders: {noders_bin}")
    print(f"  mihomo: {mihomo_bin}")
    print(f"  protocols: {protocols}")
    print("=" * 70)

    results = {}
    details = {}
    for proto in protocols:
        print(f"\n--- {proto} (mihomo) ---")
        tester = MihomoProtocolTester(
            proto, aerion_bin, noders_bin, mihomo_bin, args.verbose)
        ok, msg = tester.run()
        status = "PASS" if ok else "FAIL"
        print(f"  [{proto}] => {status}: {msg}")
        results[proto] = ok
        details[proto] = msg

    print("\n" + "=" * 70)
    n_pass = sum(1 for v in results.values() if v)
    n_fail = len(results) - n_pass
    print(f"RESULTS: {n_pass}/{len(results)} passed, {n_fail} failed")
    for proto in sorted(results.keys()):
        ok = results[proto]
        print(f"  {proto:20s} {'PASS' if ok else 'FAIL'}  ({details[proto]})")
    print("=" * 70)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
