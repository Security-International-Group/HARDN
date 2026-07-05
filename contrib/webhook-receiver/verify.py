#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reference verifier for HARDN signed webhook alerts.

HARDN signs each webhook POST body with HMAC-SHA256 keyed on the value of
HARDN_ALERT_WEBHOOK_SECRET, and sends the digest in the header:

    X-HARDN-Signature: sha256=<hex>

A receiver must recompute the HMAC over the *raw* request body (before any
JSON parsing or re-serialization, which would change the bytes) and compare
it to the header value in constant time.

This module is dependency-free (stdlib only) so it drops into any handler.
The __main__ block is a tiny http.server example; the verify_signature
function is what you actually copy into your service.

Run the demo receiver:

    HARDN_ALERT_WEBHOOK_SECRET=hunter2 python3 verify.py 0.0.0.0 9000

Then point HARDN at it:

    HARDN_ALERT_WEBHOOK_URL=http://127.0.0.1:9000 \\
    HARDN_ALERT_WEBHOOK_SECRET=hunter2 hardn ...
"""

import hashlib
import hmac
import os
import sys


def verify_signature(secret: bytes, body: bytes, header_value: str) -> bool:
    """Return True iff header_value is a valid HARDN signature over body.

    header_value is the raw 'X-HARDN-Signature' header, e.g.
    'sha256=5bdcc1...'. Comparison is constant-time via hmac.compare_digest
    so a timing side channel cannot leak the expected digest.
    """
    if not header_value or not header_value.startswith("sha256="):
        return False
    provided = header_value[len("sha256=") :].strip()
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


def _demo_server(host: str, port: int) -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer

    secret = os.environ.get("HARDN_ALERT_WEBHOOK_SECRET", "").encode()
    if not secret:
        print(
            "Set HARDN_ALERT_WEBHOOK_SECRET before running the demo receiver.",
            file=sys.stderr,
        )
        sys.exit(2)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 (stdlib naming)
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            sig = self.headers.get("X-HARDN-Signature", "")
            if verify_signature(secret, body, sig):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok\n")
                print("verified alert:", body.decode("utf-8", "replace"))
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"bad signature\n")
                print("REJECTED unsigned/forged alert", file=sys.stderr)

        def log_message(self, *_args):
            pass  # quiet the default access log

    HTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
    _demo_server(host, port)
