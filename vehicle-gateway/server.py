"""Minimal isolated TCP/UDP sink for synthetic automotive Ethernet fixtures."""

from __future__ import annotations

import socket
import threading


def serve_doip() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 13400))
        server.listen()
        while True:
            connection, _ = server.accept()
            with connection:
                connection.recv(4096)
                connection.sendall(b"\x02\xfd\x80\x02\x00\x00\x00\x05\x10\x01\x0e\x80\x7f")


def serve_someip() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", 30490))
        while True:
            payload, peer = server.recvfrom(4096)
            if payload:
                server.sendto(payload[:16], peer)


if __name__ == "__main__":
    threading.Thread(target=serve_doip, daemon=True).start()
    serve_someip()
