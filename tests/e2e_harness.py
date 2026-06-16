"""Smoke harness: fake certstream WS + fake n8n webhook receiver.

Spawns both on the loopback. Used for manual end-to-end testing.

Run with: uv run python tests/e2e_harness.py
"""
import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import websockets

CT_PORT = int(os.environ.get("CT_PORT", "19090"))
HOOK_PORT = int(os.environ.get("HOOK_PORT", "19091"))

CERT_EVENT = {
    "message_type": "certificate_update",
    "data": {
        "cert_index": 1,
        "cert_link": "https://ct.googleapis.com/test/get-entries?start=1&end=1",
        "leaf_cert": {
            "all_domains": ["evil.ethereum.org"],
            "fingerprint": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
            "issuer": {"O": "Evil CA", "CN": "Evil", "aggregated": "/O=Evil CA/CN=Evil"},
            "not_before": 1761915088,
            "not_after": 1769694679,
            "serial_number": "DEADBEEF",
            "subject": {"CN": "evil.ethereum.org"},
        },
        "seen": 1761918776.52165,
        "source": {"name": "Test Log", "url": "https://test/"},
        "update_type": "PrecertLogEntry",
    },
}

KNOWN_EVENT = {
    "message_type": "certificate_update",
    "data": {
        "cert_index": 2,
        "cert_link": "https://ct.googleapis.com/test/get-entries?start=2&end=2",
        "leaf_cert": {
            "all_domains": ["foo.ethereum.org"],
            "fingerprint": "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44",
            "issuer": {"O": "Let's Encrypt", "CN": "R10"},
            "not_before": 1761915088,
            "not_after": 1762519888,
            "serial_number": "1234",
            "subject": {"CN": "foo.ethereum.org"},
        },
        "seen": 1761918800.0,
        "source": {"name": "Test Log", "url": "https://test/"},
        "update_type": "PrecertLogEntry",
    },
}

UNWATCHED_EVENT = {
    "message_type": "certificate_update",
    "data": {
        "cert_index": 3,
        "cert_link": "https://ct.googleapis.com/test/get-entries?start=3&end=3",
        "leaf_cert": {
            "all_domains": ["random-other-domain.example.com"],
            "fingerprint": "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC",
            "issuer": {"O": "Some CA", "CN": "X1"},
            "not_before": 1761915088,
            "not_after": 1762519888,
            "serial_number": "5678",
            "subject": {"CN": "random-other-domain.example.com"},
        },
        "seen": 1761918900.0,
        "source": {"name": "Test Log", "url": "https://test/"},
        "update_type": "PrecertLogEntry",
    },
}


class HookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        try:
            payload = json.loads(body)
            print(
                f"WEBHOOK RX: fp={payload.get('fingerprint_sha1')} "
                f"matched={payload.get('matched_entries')} "
                f"issuer={payload.get('issuer_o')}",
                flush=True,
            )
        except Exception as e:
            print(f"WEBHOOK RX: bad json: {e}", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args: object) -> None:
        pass


def start_hook() -> None:
    HTTPServer(("127.0.0.1", HOOK_PORT), HookHandler).serve_forever()


async def ws_handler(ws: websockets.ServerConnection) -> None:
    print("WS client connected, streaming events", flush=True)
    for evt in (CERT_EVENT, KNOWN_EVENT, UNWATCHED_EVENT):
        await ws.send(json.dumps(evt))
        await asyncio.sleep(0.5)
    print("WS finished sending events, idling", flush=True)
    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass


async def main() -> None:
    threading.Thread(target=start_hook, daemon=True).start()
    print(f"HOOK listening on 127.0.0.1:{HOOK_PORT}/", flush=True)

    async with websockets.serve(ws_handler, "127.0.0.1", CT_PORT):
        print(f"WS listening on 127.0.0.1:{CT_PORT}", flush=True)
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
