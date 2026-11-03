#!/usr/bin/env python3
#  Copyright (C) 2026 Contributors to AHT
#  SPDX-License-Identifier: Apache-2.0
"""Backpressure-and-accounting TLS fixture for the Try_Write test.

Listens on 127.0.0.1:8779 with a tiny SO_RCVBUF, inherited by every
accepted socket, so a client that keeps writing while this side is not
reading fills its send buffer within a few records. Per connection,
after the TLS handshake, the peer drives the fixture with one-line
application-data commands; everything else it sends is payload:

    HOLD\\n     stop reading the socket (the next command is read
               only after RELEASE's hold time, see below)
    SUM\\n      reply "SUM <bytes> <sha256-hex>\\n" over everything
               received as payload so far, then close with a
               close_notify

HOLD parks this thread for a fixed time. Nothing the client sends in
that window is consumed, which is the deterministic part: the socket
is full by the time the client observes Would_Block, and stays full
until the hold ends. Payload bytes are hashed in arrival order, so
the SUM reply proves what reached the peer: no byte lost, none
duplicated, none reordered. Cert and key are the pair from
scripts/generate_cert.sh; clients connect with Insecure => True.

Prints `READY tlssink 127.0.0.1:8779` once listening.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = 8779
HOLD_SECONDS = 1.5

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


def serve_one(tls: ssl.SSLSocket) -> None:
    digest = hashlib.sha256()
    total = 0
    pending = b""
    while True:
        # Commands are lines; the payload is whatever is not a line
        # that spells a command. The client never puts a newline in
        # its payload.
        data = tls.recv(65536)
        if not data:
            return
        pending += data
        while True:
            nl = pending.find(b"\n")
            if nl < 0:
                # No command in sight: everything so far is payload.
                digest.update(pending)
                total += len(pending)
                pending = b""
                break
            line, pending = pending[:nl], pending[nl + 1:]
            if line == b"HOLD":
                time.sleep(HOLD_SECONDS)
            elif line == b"SUM":
                tls.sendall(
                    f"SUM {total} {digest.hexdigest()}\n".encode())
                try:
                    tls.unwrap()
                except (OSError, ssl.SSLError):
                    pass
                return
            else:
                # A line that is not a command is payload, newline
                # included.
                digest.update(line + b"\n")
                total += len(line) + 1


def main() -> int:
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        print(
            f"FATAL: missing cert/key ({CERT}, {KEY}); "
            "run scripts/generate_cert.sh first",
            file=sys.stderr,
            flush=True,
        )
        return 2

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #  Tiny receive buffer, inherited by accepted sockets, so a HOLD
    #  fills the client's send side after a few records.
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    lsock.bind((HOST, PORT))
    lsock.listen(8)

    print(f"READY tlssink {HOST}:{PORT}", flush=True)

    def handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(30.0)
            tls = ctx.wrap_socket(conn, server_side=True)
            serve_one(tls)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        while True:
            conn, _ = lsock.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        lsock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())