#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "websockets>=13",
# ]
# ///
import asyncio
import json
import sys
from datetime import datetime, timezone

import websockets

URL = "ws://localhost:8080/full-stream"

KEYWORDS = [
    "ethereum",
    "ethereum.org",
    "ethereum.foundation"
]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def matches(domain: str) -> str | None:
    d = domain.lower().lstrip("*.")
    for kw in KEYWORDS:
        if kw in d:
            return kw
    return None


async def run():
    print(f"Connecting to {URL}...", flush=True)
    print(f"Watching for: {', '.join(KEYWORDS)}", flush=True)
    async for ws in websockets.connect(URL, max_size=None, ping_interval=20):
        print("Connected", flush=True)
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("message_type") != "certificate_update":
                    continue
                domains = msg["data"]["leaf_cert"]["all_domains"]
                hits = [(d, kw) for d in domains if (kw := matches(d))]
                if not hits:
                    continue

                data = msg["data"]
                leaf = data["leaf_cert"]
                issuer = leaf["issuer"].get("O") or leaf["issuer"].get("CN") or "?"
                not_before = leaf["not_before"]
                not_after = leaf["not_after"]
                lifetime_days = (not_after - not_before) / 86400
                seen = datetime.fromtimestamp(data["seen"], tz=timezone.utc).isoformat(timespec="seconds")
                source = data["source"]["name"]
                cert_link = data.get("cert_link", "")

                matched_kws = sorted({kw for _, kw in hits})
                matched_domains = [d for d, _ in hits]
                other = [d for d in domains if d not in set(matched_domains)]

                print(
                    f"[{seen}] {','.join(matched_kws)}\n"
                    f"  matched : {', '.join(matched_domains)}\n"
                    f"  also on : {', '.join(other) if other else '-'}\n"
                    f"  issuer  : {issuer}\n"
                    f"  valid   : {lifetime_days:.0f}d  ({_iso(not_before)} -> {_iso(not_after)})\n"
                    f"  source  : {source}\n"
                    f"  link    : {cert_link}",
                    flush=True,
                )


        except websockets.ConnectionClosed as e:
            print(f"Disconnected ({e}), reconnecting...", file=sys.stderr, flush=True)
            continue


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
