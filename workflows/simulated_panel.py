#!/usr/bin/env python3
"""Simulated Xboard Panel for testing NodeRS protocol implementations."""

import argparse
import json
import os
import signal
import sys
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def self_signed_cert_config():
    return {"cert_mode": "self_signed"}


def base_node_config(protocol, server_port, extra=None):
    cfg = {
        "protocol": protocol,
        "listen_ip": "127.0.0.1",
        "server_port": server_port,
        "server_name": "node-test.local",
        "network": "",
        "network_settings": None,
        "tls": 1,
        "tls_settings": {"server_name": "node-test.local", "allow_insecure": True},
        "reality_settings": {},
        "multiplex": None,
        "host": "",
        "cipher": "",
        "plugin": "",
        "plugin_opts": "",
        "server_key": "",
        "flow": "",
        "decryption": "",
        "version": None,
        "up_mbps": None,
        "down_mbps": None,
        "obfs": None,
        "is_obfs": False,
        "obfs_password": "",
        "congestion_control": "",
        "auth_timeout": "",
        "zero_rtt_handshake": False,
        "heartbeat": "30",
        "transport": None,
        "traffic_pattern": "",
        "nonce_pattern": "",
        "alpn": [],
        "packet_encoding": "",
        "global_padding": False,
        "authenticated_length": False,
        "fallbacks": None,
        "fallback": None,
        "fallback_for_alpn": None,
        "ignore_client_bandwidth": False,
        "masquerade": None,
        "udp_relay_mode": "native",
        "udp_over_stream": False,
        "padding_scheme": [],
        "routes": [],
        "custom_outbounds": [],
        "custom_routes": [],
        "cert_config": self_signed_cert_config(),
        "base_config": None,
    }
    if extra:
        cfg.update(extra)
    # Strip keys set to None (for protocols without TLS etc.)
    cfg = {k: v for k, v in cfg.items() if v is not None}
    return cfg


PROTOCOL_CONFIGS = {
    "shadowsocks": lambda port: base_node_config(
        "shadowsocks", port,
        {"network": "tcp,udp", "cipher": "2022-blake3-aes-128-gcm",
         "server_key": "vaR5nc1yDpQ707N7bRV2aA==",
         "tls": None, "tls_settings": None,
         "reality_settings": None, "cert_config": None,
         "udp_relay_mode": "native"}),
    "hysteria2": lambda port: base_node_config(
        "hysteria2", port,
        {"network": "udp", "version": 2, "up_mbps": 100,
         "server_key": "hy2-test-obfs-secret", "congestion_control": "bbr",
         "udp_relay_mode": "native"}),
    "mieru": lambda port: base_node_config(
        "mieru", port,
        {"network": "tcp", "tls": None, "tls_settings": None,
         "reality_settings": None, "cert_config": None}),
    "trojan": lambda port: base_node_config(
        "trojan", port,
        {"network": "tcp", "udp_relay_mode": "native"}),
    "tuic": lambda port: base_node_config(
        "tuic", port,
        {"network": "udp", "congestion_control": "bbr", "udp_relay_mode": "native",
         "alpn": ["h3"]}),
    "vless": lambda port: base_node_config(
        "vless", port,
        {"network": "tcp", "flow": "", "udp_relay_mode": "native"}),
    "vmess": lambda port: base_node_config(
        "vmess", port,
        {"network": "tcp", "tls": None, "tls_settings": None,
         "reality_settings": None, "cert_config": None, "udp_relay_mode": "native"}),
    "anytls": lambda port: base_node_config(
        "anytls", port,
        {"network": "tcp"}),
}

DEFAULT_USERS = [
    {"id": 1001, "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
     "password": "test-password-1001", "alter_id": 0, "speed_limit": 0, "device_limit": 0},
    {"id": 1002, "uuid": "b4593f99-797b-5b69-9237-aa0de075c8cf",
     "password": "test-password-1002", "alter_id": 0, "speed_limit": 0, "device_limit": 0},
]

# Shadowsocks 2022 user PSK keys (base64-encoded 16-byte keys)
SS_USER_KEYS = {
    1001: "vaR5nc1yDpQ707N7bRV2aA==",
    1002: "vaR5nc1yDpQ707N7bRV2aA==",
}


class PanelHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[panel] {self.address_string()} - {format % args}")

    def _send_json(self, status, data):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", f'" + str(int(time.time())) + "')
        self.end_headers()
        self.wfile.write(body)

    def _parse_path(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return parsed.path, {k: v[0] if v else "" for k, v in qs.items()}

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        path, qs = self._parse_path()
        try:
            if path == "/api/v2/server/handshake":
                self._send_json(200, {"websocket": {"enabled": False, "ws_url": ""}})
            elif path == "/api/v2/server/machine/nodes":
                self._send_json(200, {
                    "nodes": [{"id": self.server.node_id, "type": self.server.protocol,
                               "name": f"test-{self.server.protocol}"}],
                    "base_config": None})
            elif path == "/api/v2/server/machine/status":
                self._send_json(200, {})
            elif path == "/api/v2/server/config":
                cfg = self._node_config()
                self._send_json(200, cfg)
            elif path == "/api/v2/server/user":
                if self.server.protocol == "shadowsocks":
                    # Shadowsocks 2022 multi-user TCP requires crate feature; test with 1 user
                    u = dict(DEFAULT_USERS[0])
                    u["password"] = SS_USER_KEYS.get(u["id"], u["password"])
                    self._send_json(200, {"users": [u]})
                else:
                    self._send_json(200, {"users": DEFAULT_USERS})
            elif path == "/api/v2/server/report":
                self._send_json(200, {})
            else:
                self._send_json(404, {"error": f"unknown endpoint: {path}"})
        except Exception as exc:
            print(f"[panel] ERROR: {exc}")
            self._send_json(500, {"error": str(exc)})

    def _node_config(self):
        port = self.server.next_available_port()
        proto = self.server.protocol
        if proto not in PROTOCOL_CONFIGS:
            return {"error": f"unknown protocol: {proto}"}
        cfg = PROTOCOL_CONFIGS[proto](port)
        # Apply cipher override (for mihomo SS2022->legacy fallback)
        if self.server.cipher and self.server.cipher not in ("", "2022-blake3-aes-128-gcm"):
            cfg["cipher"] = self.server.cipher
            # Switch to plaintext password for legacy SS (vs SS2022 base64 key)
            if proto == "shadowsocks":
                cfg["server_key"] = "test-password-1001"
        self.server.last_built_port = port
        return cfg


class SimulatedPanel(HTTPServer):
    def __init__(self, address, handler, protocol, node_id, port_base, cipher=None):
        super().__init__(address, handler)
        self.protocol = protocol
        self.cipher = cipher
        self.node_id = node_id
        self.port_base = port_base
        self.port_offset = 0
        self.last_built_port = 0

    def next_available_port(self):
        port = self.port_base + self.port_offset
        self.port_offset += 1
        self.last_built_port = port
        return port


def main():
    parser = argparse.ArgumentParser(description="Simulated Xboard Panel")
    parser.add_argument("--protocol", default="shadowsocks")
    parser.add_argument("--cipher", default="")
    parser.add_argument("--node-id", type=int, default=42)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--port-base", type=int, default=20000)
    args = parser.parse_args()

    cipher_override = args.cipher.strip() if args.cipher else None

    server = SimulatedPanel(("127.0.0.1", args.port), PanelHandler,
                            protocol=args.protocol, node_id=args.node_id,
                            port_base=args.port_base, cipher=cipher_override)
    print(f"[panel] protocol={args.protocol} node_id={args.node_id} on :{args.port}")
    print(f"[panel] port_base={args.port_base}")

    def shutdown(*_):
        print("\n[panel] shutting down...")
        server.shutdown()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
