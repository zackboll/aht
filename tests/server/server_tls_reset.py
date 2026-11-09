#!/usr/bin/env python3
#  Copyright (C) 2026 Contributors to AHT
#  SPDX-License-Identifier: Apache-2.0
"""TCP-reset TLS fixture for the receive-side lifecycle test.

Listens on 127.0.0.1:8781. Per connection: TLS handshake, then one
command byte from the client decides how the session ends:

    b"E"  echo: one application record carrying BANNER, then await
          the next command (a session can take several before ending)
    b"R"  reset: SO_LINGER 0 and close, so the kernel sends RST
          instead of FIN; no close_notify, no FIN
    b"H"  half record then reset: the first half of a record carrying
          BANNER, then the RST as for b"R"
    b"C"  clean: close_notify, then FIN
    b"F"  FIN without close_notify

The TLS state lives in memory BIOs, so the record for b"H" is the
fixture's to split, and every byte the socket carries is written by
this file. Reading the command with the SSL layer means the client's
record reaches the server in the same session, so a b"R" follows a
record the client has already had decrypted.

Prints `READY tlsreset 127.0.0.1:8781` once listening.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import sys

HOST = "127.0.0.1"
PORT = 8781
BANNER = b"RESET-FIXTURE-BANNER"

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


def reset_close(conn: socket.socket) -> None:
    # Linger with a zero timeout turns close() into an RST: unsent
    # data is discarded and the peer's next receive fails with
    # ECONNRESET rather than reading an EOF.
    conn.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
    )
    conn.close()


def serve_one(conn: socket.socket, ctx: ssl.SSLContext) -> None:
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=True)

    def flush() -> None:
        pending = outgoing.read()
        if pending:
            conn.sendall(pending)

    def pump(step):
        while True:
            try:
                result = step()
            except ssl.SSLWantReadError:
                flush()
                data = conn.recv(65536)
                if not data:
                    raise ConnectionError("peer closed mid-operation")
                incoming.write(data)
                continue
            flush()
            return result

    pump(tls.do_handshake)

    while True:
        cmd = pump(lambda: tls.read(1))
        if cmd == b"E":
            tls.write(BANNER)
            flush()
        elif cmd == b"R":
            reset_close(conn)
            return
        elif cmd == b"H":
            tls.write(BANNER)
            record = outgoing.read()
            conn.sendall(record[: len(record) // 2])
            reset_close(conn)
            return
        elif cmd == b"C":
            try:
                tls.unwrap()
            except ssl.SSLWantReadError:
                pass
            flush()
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            return
        elif cmd == b"F":
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            return
        else:
            conn.close()
            return


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

    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(8)
    print(f"READY tlsreset {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        conn.settimeout(10.0)
        try:
            serve_one(conn, ctx)
        except (OSError, ssl.SSLError, ConnectionError):
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
