#!/usr/bin/env python3
"""A Schannel client completes a TLS handshake with a local server and exchanges one message each way."""

import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


def serve(listener, context, failures):
    try:
        connection, _ = listener.accept()
        with context.wrap_socket(connection, server_side=True) as tls:
            tls.settimeout(20)
            request = b""
            while len(request) < 4:
                chunk = tls.recv(4 - len(request))
                if not chunk:
                    break
                request += chunk
            if request != b"ping":
                failures.append(f"server received {request!r}")
                return
            tls.sendall(b"pong")
    except Exception as error:
        failures.append(f"server failed: {error}")


def main():
    raven, client, directory = (Path(value).resolve() for value in sys.argv[1:4])
    with tempfile.TemporaryDirectory(prefix="schannel-", dir=os.environ.get("TMPDIR", directory)) as temporary:
        work = Path(temporary)
        certificate, key = work / "certificate.pem", work / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
            "-keyout", str(key), "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        listener = socket.create_server(("127.0.0.1", 0))
        listener.settimeout(20)
        failures = []
        server = threading.Thread(target=serve, args=(listener, context, failures))
        server.start()
        port = listener.getsockname()[1]
        result = subprocess.run([str(raven), "--run-process", "--execution=native", str(client), "--", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=25)
        server.join()
        listener.close()
        if failures:
            raise RuntimeError("; ".join(failures) + f"\n{result.stdout}")
        if "Native entry returned 0 " not in result.stdout:
            raise RuntimeError(f"schannel client failed: {result.stdout}")
    print("Schannel handshake, encryption and decryption completed against a local TLS server")


if __name__ == "__main__":
    main()
