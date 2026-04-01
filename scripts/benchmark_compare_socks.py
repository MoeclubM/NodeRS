#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable


UDP_HEADER_RSV = b"\x00\x00"
UDP_HEADER_FRAG = b"\x00"
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass
class WorkerStats:
    bytes: int = 0
    packets: int = 0
    connect_ms: float | None = None
    first_byte_ms: float | None = None
    post_connect_first_byte_ms: float | None = None
    request_sent_ms: float | None = None
    request_to_first_byte_ms: float | None = None


class MeasurementWindow:
    def __init__(self, worker_count: int, duration: float, warmup_seconds: float):
        self.worker_count = max(worker_count, 1)
        self.duration = max(duration, 0.1)
        self.warmup_seconds = max(warmup_seconds, 0.0)
        self._connected = 0
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self.measure_start: float | None = None
        self.stop_time: float | None = None

    def mark_connected(self) -> None:
        with self._lock:
            if self._ready.is_set():
                return
            self._connected += 1
            if self._connected >= self.worker_count:
                self.measure_start = time.perf_counter() + self.warmup_seconds
                self.stop_time = self.measure_start + self.duration
                self._ready.set()

    def wait(self) -> tuple[float, float]:
        self._ready.wait()
        assert self.measure_start is not None
        assert self.stop_time is not None
        return self.measure_start, self.stop_time

    def cancel(self) -> None:
        with self._lock:
            if self._ready.is_set():
                return
            now = time.perf_counter()
            self.measure_start = now
            self.stop_time = now
            self._ready.set()


def mark_request_sent(stats: WorkerStats, started: float) -> None:
    if stats.request_sent_ms is None:
        stats.request_sent_ms = (time.perf_counter() - started) * 1000.0


def mark_first_byte(stats: WorkerStats, started: float) -> None:
    if stats.first_byte_ms is not None:
        return
    first_byte_ms = (time.perf_counter() - started) * 1000.0
    stats.first_byte_ms = first_byte_ms
    if stats.connect_ms is not None:
        stats.post_connect_first_byte_ms = max(first_byte_ms - stats.connect_ms, 0.0)
    if stats.request_sent_ms is not None:
        stats.request_to_first_byte_ms = max(first_byte_ms - stats.request_sent_ms, 0.0)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def recv_until(
    sock: socket.socket,
    marker: bytes,
    *,
    limit: int = 1024 * 1024,
    deadline: float | None = None,
) -> tuple[bytes, bytes]:
    buffer = bytearray()
    while marker not in buffer:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            if deadline is not None and time.perf_counter() >= deadline:
                raise TimeoutError("timed out waiting for marker") from None
            continue
        if not chunk:
            raise EOFError("unexpected EOF while waiting for marker")
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise RuntimeError("marker not found before buffer limit")
    index = buffer.index(marker) + len(marker)
    return bytes(buffer[:index]), bytes(buffer[index:])


def websocket_accept(key: str) -> str:
    digest = hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def websocket_handshake(
    sock: socket.socket,
    target_host: str,
    http_path: str,
    *,
    stats: WorkerStats | None = None,
    started: float | None = None,
) -> bytearray:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {http_path} HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(request)
    if stats is not None and started is not None:
        mark_request_sent(stats, started)
    header, remainder = recv_until(sock, b"\r\n\r\n", deadline=time.perf_counter() + 10.0)
    if not header.startswith(b"HTTP/1.1 101"):
        raise RuntimeError(f"websocket upgrade failed: {header[:120]!r}")
    accept = websocket_accept(key).encode("ascii")
    if b"Sec-WebSocket-Accept: " + accept not in header:
        raise RuntimeError("websocket upgrade missing expected accept header")
    return bytearray(remainder)


def websocket_frame_header(payload_len: int, *, masked: bool) -> bytes:
    header = bytearray([0x82])
    mask_bit = 0x80 if masked else 0x00
    if payload_len < 126:
        header.append(mask_bit | payload_len)
    elif payload_len <= 0xFFFF:
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", payload_len))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", payload_len))
    return bytes(header)


def send_websocket_zero_frame(sock: socket.socket, payload_len: int, *, masked: bool) -> None:
    header = websocket_frame_header(payload_len, masked=masked)
    if masked:
        mask = os.urandom(4)
        payload = (mask * (payload_len // 4 + 1))[:payload_len]
        sock.sendall(header + mask + payload)
        return
    sock.sendall(header + (b"\0" * payload_len))


def recv_websocket_frame(sock: socket.socket, buffer: bytearray) -> tuple[int, bytes]:
    while len(buffer) < 2:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("unexpected EOF while reading websocket frame")
        buffer.extend(chunk)

    first = buffer[0]
    second = buffer[1]
    masked = (second & 0x80) != 0
    payload_len = second & 0x7F
    offset = 2
    if payload_len == 126:
        while len(buffer) < offset + 2:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError("unexpected EOF while reading websocket frame length")
            buffer.extend(chunk)
        payload_len = struct.unpack("!H", buffer[offset : offset + 2])[0]
        offset += 2
    elif payload_len == 127:
        while len(buffer) < offset + 8:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError("unexpected EOF while reading websocket frame length")
            buffer.extend(chunk)
        payload_len = struct.unpack("!Q", buffer[offset : offset + 8])[0]
        offset += 8

    mask = b""
    if masked:
        while len(buffer) < offset + 4:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError("unexpected EOF while reading websocket frame mask")
            buffer.extend(chunk)
        mask = bytes(buffer[offset : offset + 4])
        offset += 4

    frame_end = offset + payload_len
    while len(buffer) < frame_end:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("unexpected EOF while reading websocket frame payload")
        buffer.extend(chunk)

    payload = bytes(buffer[offset:frame_end])
    del buffer[:frame_end]
    if masked:
        payload = bytes(byte ^ mask[index & 3] for index, byte in enumerate(payload))
    return first & 0x0F, payload


def encode_socks5_address(host: str, port: int) -> bytes:
    try:
        addr = socket.inet_aton(host)
        return b"\x01" + addr + port.to_bytes(2, "big")
    except OSError:
        encoded = host.encode("utf-8")
        if len(encoded) > 255:
            raise ValueError("domain name too long for SOCKS5")
        return b"\x03" + bytes([len(encoded)]) + encoded + port.to_bytes(2, "big")


def read_socks5_bound_address(sock: socket.socket) -> tuple[str, int]:
    head = recv_exact(sock, 4)
    if head[1] != 0x00:
        raise RuntimeError(f"SOCKS request failed, reply={head[1]}")
    atyp = head[3]
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 3:
        length = recv_exact(sock, 1)[0]
        host = recv_exact(sock, length).decode("utf-8")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"unsupported SOCKS address type {atyp}")
    port = int.from_bytes(recv_exact(sock, 2), "big")
    return host, port


def socks5_negotiate(proxy_host: str, proxy_port: int) -> tuple[socket.socket, float]:
    started = time.perf_counter()
    sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(b"\x05\x01\x00")
    resp = recv_exact(sock, 2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"SOCKS auth method failed: {resp!r}")
    return sock, (time.perf_counter() - started) * 1000.0


def socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> tuple[socket.socket, float]:
    sock, connect_ms = socks5_negotiate(proxy_host, proxy_port)
    sock.sendall(b"\x05\x01\x00" + encode_socks5_address(target_host, target_port))
    read_socks5_bound_address(sock)
    sock.settimeout(None)
    return sock, connect_ms


def socks5_udp_associate(proxy_host: str, proxy_port: int) -> tuple[socket.socket, tuple[str, int], float]:
    sock, connect_ms = socks5_negotiate(proxy_host, proxy_port)
    sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    relay_host, relay_port = read_socks5_bound_address(sock)
    if relay_host in {"0.0.0.0", "::"}:
        relay_host = proxy_host
    sock.settimeout(None)
    return sock, (relay_host, relay_port), connect_ms


def write_curve_report(
    *,
    mode: str,
    parallel: int,
    chunk_size: int,
    sample_interval: float,
    measurement_window: MeasurementWindow,
    curve_file: str,
    stats: list[WorkerStats],
    done: threading.Event,
) -> None:
    samples: list[dict[str, float | int]] = []
    measure_start, stop_time = measurement_window.wait()
    measurement_seconds = max(stop_time - measure_start, 0.0)
    last_sample = measure_start
    last_bytes = 0

    while True:
        remaining = measure_start - time.perf_counter()
        if remaining <= 0:
            break
        if done.wait(min(remaining, 0.1)):
            break

    while True:
        remaining_until_stop = stop_time - time.perf_counter()
        if remaining_until_stop <= 0:
            break
        if done.wait(min(sample_interval, remaining_until_stop)):
            break
        now = min(time.perf_counter(), stop_time)
        total_bytes = sum(item.bytes for item in stats)
        interval_seconds = max(now - last_sample, 1e-6)
        samples.append(
            {
                "elapsed_seconds": round(min(max(now - measure_start, 0.0), measurement_seconds), 3),
                "total_bytes": total_bytes,
                "mbps": round(((total_bytes - last_bytes) * 8.0) / interval_seconds / 1_000_000.0, 2),
            }
        )
        last_sample = now
        last_bytes = total_bytes

    now = min(time.perf_counter(), stop_time)
    total_bytes = sum(item.bytes for item in stats)
    trailing_interval = max(now - last_sample, 0.0)
    min_trailing_interval = max(sample_interval * 0.25, 0.05)
    if not samples or (total_bytes != last_bytes and trailing_interval >= min_trailing_interval):
        interval_seconds = max(trailing_interval, 1e-6)
        samples.append(
            {
                "elapsed_seconds": round(min(max(now - measure_start, 0.0), measurement_seconds), 3),
                "total_bytes": total_bytes,
                "mbps": round(((total_bytes - last_bytes) * 8.0) / interval_seconds / 1_000_000.0, 2),
            }
        )

    with open(curve_file, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "mode": mode,
                "parallel": parallel,
                "chunk_size": chunk_size,
                "sample_interval_seconds": sample_interval,
                "warmup_seconds": measurement_window.warmup_seconds,
                "measurement_seconds": measurement_seconds,
                "samples": samples,
            },
            handle,
            indent=2,
        )


def record_bytes(stats: WorkerStats, *, measure_start: float, payload_len: int, packet_count: int = 1) -> None:
    if time.perf_counter() >= measure_start:
        stats.bytes += payload_len
        stats.packets += packet_count


def worker_upload(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
) -> None:
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    sock.settimeout(1.0)
    stats.connect_ms = connect_ms
    payload = b"\0" * chunk_size
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                sent = sock.send(payload)
            except (socket.timeout, TimeoutError):
                continue
            if sent <= 0:
                break
            if time.perf_counter() >= measure_start:
                stats.bytes += sent
                stats.packets += 1
    finally:
        with contextlib_suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
        sock.close()


def worker_download(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
) -> None:
    _ = chunk_size
    started = time.perf_counter()
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    sock.settimeout(1.0)
    stats.connect_ms = connect_ms
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                chunk = sock.recv(131072)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                break
            mark_first_byte(stats, started)
            if time.perf_counter() >= measure_start:
                stats.bytes += len(chunk)
                stats.packets += 1
    finally:
        sock.close()


def build_udp_datagram(target_host: str, target_port: int, payload: bytes) -> bytes:
    return UDP_HEADER_RSV + UDP_HEADER_FRAG + encode_socks5_address(target_host, target_port) + payload


def parse_udp_datagram(packet: bytes) -> bytes:
    if len(packet) < 4 or packet[:2] != UDP_HEADER_RSV or packet[2:3] != UDP_HEADER_FRAG:
        raise RuntimeError("invalid SOCKS5 UDP packet header")
    atyp = packet[3]
    offset = 4
    if atyp == 1:
        offset += 4
    elif atyp == 3:
        if len(packet) < offset + 1:
            raise RuntimeError("truncated SOCKS5 UDP domain header")
        offset += 1 + packet[offset]
    elif atyp == 4:
        offset += 16
    else:
        raise RuntimeError(f"unsupported SOCKS5 UDP address type {atyp}")
    offset += 2
    if len(packet) < offset:
        raise RuntimeError("truncated SOCKS5 UDP packet")
    return packet[offset:]


def open_udp_socket(relay: tuple[str, int]) -> socket.socket:
    infos = socket.getaddrinfo(relay[0], relay[1], type=socket.SOCK_DGRAM)
    family, socktype, proto, _, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(1.0)
    sock.connect(sockaddr)
    return sock


def worker_udp_upload(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
) -> None:
    control, relay, connect_ms = socks5_udp_associate(proxy[0], proxy[1])
    udp_sock = open_udp_socket(relay)
    payload = b"\0" * chunk_size
    packet = build_udp_datagram(target[0], target[1], payload)
    stats.connect_ms = connect_ms
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                udp_sock.send(packet)
            except (socket.timeout, TimeoutError):
                continue
            if time.perf_counter() >= measure_start:
                stats.bytes += len(payload)
                stats.packets += 1
    finally:
        udp_sock.close()
        control.close()


def worker_udp_download(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
) -> None:
    _ = chunk_size
    started = time.perf_counter()
    control, relay, connect_ms = socks5_udp_associate(proxy[0], proxy[1])
    udp_sock = open_udp_socket(relay)
    udp_sock.send(build_udp_datagram(target[0], target[1], b"\0"))
    stats.connect_ms = connect_ms
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                packet = udp_sock.recv(65535)
            except (socket.timeout, TimeoutError):
                continue
            if not packet:
                continue
            payload = parse_udp_datagram(packet)
            mark_first_byte(stats, started)
            if time.perf_counter() >= measure_start:
                stats.bytes += len(payload)
                stats.packets += 1
    finally:
        udp_sock.close()
        control.close()


def worker_idle(
    proxy: tuple[str, int],
    target: tuple[str, int],
    duration: float,
    chunk_size: int,
    stats: WorkerStats,
) -> None:
    _ = chunk_size
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    stats.connect_ms = connect_ms
    try:
        time.sleep(duration)
        sock.sendall(b"\0")
    finally:
        sock.close()


def worker_http_upload(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
    *,
    http_path: str,
) -> None:
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    sock.settimeout(1.0)
    stats.connect_ms = connect_ms
    headers = (
        f"POST {http_path} HTTP/1.1\r\n"
        f"Host: {target[0]}\r\n"
        "Connection: close\r\n"
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(headers)
    payload = b"\0" * chunk_size
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                sent = sock.send(payload)
            except (socket.timeout, TimeoutError):
                continue
            if sent <= 0:
                break
            if time.perf_counter() >= measure_start:
                stats.bytes += sent
                stats.packets += 1
    finally:
        with contextlib_suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
        response_deadline = time.perf_counter() + 5.0
        with contextlib_suppress(OSError, EOFError, RuntimeError, TimeoutError):
            recv_until(sock, b"\r\n\r\n", deadline=response_deadline)
        sock.close()


def worker_http_download(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
    *,
    http_path: str,
) -> None:
    _ = chunk_size
    started = time.perf_counter()
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    sock.settimeout(1.0)
    stats.connect_ms = connect_ms
    request = (
        f"GET {http_path} HTTP/1.1\r\n"
        f"Host: {target[0]}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(request)
    mark_request_sent(stats, started)
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        header_deadline = time.perf_counter() + max(10.0, measurement_window.warmup_seconds + 8.0)
        _, remainder = recv_until(sock, b"\r\n\r\n", deadline=header_deadline)
        if remainder:
            mark_first_byte(stats, started)
        if remainder and time.perf_counter() >= measure_start:
            stats.bytes += len(remainder)
            stats.packets += 1
        while time.perf_counter() < stop_time:
            try:
                chunk = sock.recv(131072)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                break
            mark_first_byte(stats, started)
            if time.perf_counter() >= measure_start:
                stats.bytes += len(chunk)
                stats.packets += 1
    finally:
        sock.close()


def worker_ws_upload(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
    *,
    http_path: str,
) -> None:
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    sock.settimeout(1.0)
    stats.connect_ms = connect_ms
    websocket_handshake(sock, target[0], http_path)
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                send_websocket_zero_frame(sock, chunk_size, masked=True)
            except (socket.timeout, TimeoutError):
                continue
            record_bytes(stats, measure_start=measure_start, payload_len=chunk_size)
    finally:
        with contextlib_suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
        sock.close()


def worker_ws_download(
    proxy: tuple[str, int],
    target: tuple[str, int],
    measurement_window: MeasurementWindow,
    chunk_size: int,
    stats: WorkerStats,
    *,
    http_path: str,
) -> None:
    _ = chunk_size
    started = time.perf_counter()
    sock, connect_ms = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    sock.settimeout(1.0)
    stats.connect_ms = connect_ms
    buffer = websocket_handshake(sock, target[0], http_path, stats=stats, started=started)
    measurement_window.mark_connected()
    measure_start, stop_time = measurement_window.wait()
    try:
        while time.perf_counter() < stop_time:
            try:
                opcode, payload = recv_websocket_frame(sock, buffer)
            except (socket.timeout, TimeoutError):
                continue
            if opcode == 0x8:
                break
            if opcode != 0x2 or not payload:
                continue
            mark_first_byte(stats, started)
            record_bytes(stats, measure_start=measure_start, payload_len=len(payload))
    finally:
        sock.close()


def average(values: list[float | None]) -> float | None:
    usable = [value for value in values if value is not None]
    if not usable:
        return None
    return round(sum(usable) / len(usable), 2)


def contextlib_suppress(*exceptions: type[BaseException]):
    class _Suppress:
        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            return exc_type is not None and issubclass(exc_type, exceptions)

    return _Suppress()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxies", required=True, help="comma separated host:port list")
    parser.add_argument("--target", required=True, help="host:port")
    parser.add_argument(
        "--mode",
        choices=[
            "upload",
            "download",
            "idle",
            "udp-upload",
            "udp-download",
            "http-upload",
            "http-download",
            "ws-upload",
            "ws-download",
        ],
        required=True,
    )
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--chunk-size", type=int, default=32768)
    parser.add_argument("--curve-file")
    parser.add_argument("--sample-interval", type=float, default=1.0)
    parser.add_argument("--measure-warmup-seconds", type=float, default=0.0)
    parser.add_argument("--http-path", default="/")
    args = parser.parse_args()

    proxies: list[tuple[str, int]] = []
    for item in args.proxies.split(","):
        host, port = item.rsplit(":", 1)
        proxies.append((host, int(port)))
    target_host, target_port = args.target.rsplit(":", 1)
    target = (target_host, int(target_port))

    stats = [WorkerStats() for _ in range(max(args.parallel, 1))]
    threads: list[threading.Thread] = []
    errors: list[BaseException] = []
    measurement_window = MeasurementWindow(
        len(stats),
        args.seconds,
        args.measure_warmup_seconds if args.mode != "idle" else 0.0,
    )

    curve_done = threading.Event()
    curve_thread = None
    if args.curve_file and args.mode != "idle":
        curve_thread = threading.Thread(
            target=write_curve_report,
            kwargs={
                "mode": args.mode,
                "parallel": max(args.parallel, 1),
                "chunk_size": args.chunk_size,
                "sample_interval": max(args.sample_interval, 0.1),
                "measurement_window": measurement_window,
                "curve_file": args.curve_file,
                "stats": stats,
                "done": curve_done,
            },
            daemon=True,
        )
        curve_thread.start()

    tcp_workers: dict[str, Callable[[tuple[str, int], tuple[str, int], MeasurementWindow, int, WorkerStats], None]] = {
        "upload": worker_upload,
        "download": worker_download,
        "udp-upload": worker_udp_upload,
        "udp-download": worker_udp_download,
    }

    def run_worker(index: int) -> None:
        try:
            proxy = proxies[index % len(proxies)]
            if args.mode == "idle":
                worker_idle(proxy, target, args.seconds, args.chunk_size, stats[index])
            elif args.mode == "http-upload":
                worker_http_upload(
                    proxy,
                    target,
                    measurement_window,
                    args.chunk_size,
                    stats[index],
                    http_path=args.http_path,
                )
            elif args.mode == "http-download":
                worker_http_download(
                    proxy,
                    target,
                    measurement_window,
                    args.chunk_size,
                    stats[index],
                    http_path=args.http_path,
                )
            elif args.mode == "ws-upload":
                worker_ws_upload(
                    proxy,
                    target,
                    measurement_window,
                    args.chunk_size,
                    stats[index],
                    http_path=args.http_path,
                )
            elif args.mode == "ws-download":
                worker_ws_download(
                    proxy,
                    target,
                    measurement_window,
                    args.chunk_size,
                    stats[index],
                    http_path=args.http_path,
                )
            else:
                tcp_workers[args.mode](proxy, target, measurement_window, args.chunk_size, stats[index])
        except BaseException as error:
            errors.append(error)
            measurement_window.cancel()

    for index in range(len(stats)):
        thread = threading.Thread(target=run_worker, args=(index,), daemon=True)
        threads.append(thread)
        thread.start()

    deadline = time.perf_counter() + args.seconds + 30.0
    for thread in threads:
        remaining = max(deadline - time.perf_counter(), 0.1)
        thread.join(remaining)

    stuck = [index for index, thread in enumerate(threads) if thread.is_alive()]
    if stuck:
        measurement_window.cancel()
        curve_done.set()
        raise TimeoutError(f"worker threads did not exit: {stuck}")

    measurement_window.cancel()
    curve_done.set()
    if curve_thread is not None:
        curve_thread.join(timeout=5.0)

    if errors:
        raise errors[0]

    elapsed = max(args.seconds, 1e-6)
    total_bytes = sum(item.bytes for item in stats)
    total_packets = sum(item.packets for item in stats)
    print(
        json.dumps(
            {
                "mode": args.mode,
                "parallel": len(stats),
                "duration": round(args.seconds, 3),
                "measure_warmup_seconds": round(
                    args.measure_warmup_seconds if args.mode != "idle" else 0.0,
                    3,
                ),
                "bytes": total_bytes,
                "mbps": round(total_bytes * 8.0 / elapsed / 1_000_000.0, 2),
                "pps": round(total_packets / elapsed, 2),
                "connect_ms": average([item.connect_ms for item in stats]),
                "first_byte_ms": average([item.first_byte_ms for item in stats]),
                "post_connect_first_byte_ms": average(
                    [item.post_connect_first_byte_ms for item in stats]
                ),
                "request_sent_ms": average([item.request_sent_ms for item in stats]),
                "request_to_first_byte_ms": average(
                    [item.request_to_first_byte_ms for item in stats]
                ),
                "status": "pass",
            }
        )
    )


if __name__ == "__main__":
    main()
