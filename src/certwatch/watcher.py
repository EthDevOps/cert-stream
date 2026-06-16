import asyncio
import json
import logging
from typing import Any

import websockets

from . import metrics
from .db import Store
from .match import matches
from .state import State
from .webhook import Webhook

log = logging.getLogger(__name__)

SEVERITY_INFO = "info"
SEVERITY_SUSPICIOUS = "suspicious"


def _normalize_fingerprint(fp: str) -> str:
    return fp.replace(":", "").lower()


def _build_payload(
    data: dict[str, Any],
    fp: str,
    matched_entries: list[str],
    matched_sans: list[str],
    severity: str,
) -> dict[str, Any]:
    leaf = data["leaf_cert"]
    issuer = leaf.get("issuer") or {}
    not_before = leaf["not_before"]
    not_after = leaf["not_after"]
    return {
        "fingerprint_sha1": fp,
        "severity": severity,
        "matched_entries": sorted(set(matched_entries)),
        "matched_sans": sorted(set(matched_sans)),
        "all_sans": leaf.get("all_domains", []),
        "issuer_o": issuer.get("O"),
        "issuer_cn": issuer.get("CN"),
        "not_before": not_before,
        "not_after": not_after,
        "lifetime_days": round((not_after - not_before) / 86400, 2),
        "source_log": (data.get("source") or {}).get("name"),
        "cert_link": data.get("cert_link"),
        "serial": leaf.get("serial_number"),
        "update_type": data.get("update_type"),
        "seen_at": int(data.get("seen") or 0),
    }


async def _handle_message(
    raw: str | bytes,
    state: State,
    store: Store,
    webhook: Webhook,
) -> None:
    msg = json.loads(raw)
    mtype = msg.get("message_type") or "unknown"
    metrics.CT_MESSAGES.labels(type=mtype).inc()
    if mtype != "certificate_update":
        return
    state.mark_ct_event()

    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    sans = leaf.get("all_domains") or []
    if not sans:
        return

    entries = state.watch_entries
    if not entries:
        return

    matched_entries: set[str] = set()
    matched_sans: set[str] = set()
    for san in sans:
        hit = matches(san, entries)
        if hit:
            matched_entries.update(hit)
            matched_sans.add(san)

    if not matched_entries:
        return

    raw_fp = leaf.get("fingerprint") or ""
    fp = _normalize_fingerprint(raw_fp)
    if not fp:
        log.warning("certificate_update missing fingerprint, skipping")
        return

    # In-process dedup so the precert + final cert pair doesn't emit twice.
    if state.seen_recently(fp):
        log.debug("dedup: already alerted on %s in this run", fp)
        return
    state.record_recent(fp)
    metrics.DEDUPE_CACHE_SIZE.set(state.dedupe_size())

    severity = SEVERITY_INFO if fp in state.known_fingerprints else SEVERITY_SUSPICIOUS

    issuer = leaf.get("issuer") or {}
    issuer_summary = issuer.get("aggregated") or issuer.get("O") or issuer.get("CN")
    payload = _build_payload(data, fp, list(matched_entries), list(matched_sans), severity)

    seen_at = int(data.get("seen") or 0)
    alert_id = await store.insert_alert(
        fingerprint=fp,
        sans=sans,
        matched=sorted(matched_entries),
        issuer=issuer_summary,
        seen_at=seen_at,
        severity=severity,
    )
    metrics.ALERTS.labels(severity=severity).inc()
    log.info(
        "ALERT id=%d severity=%s fp=%s matched=%s issuer=%s",
        alert_id, severity, fp, sorted(matched_entries), issuer_summary,
    )

    delivered = await webhook.deliver(payload)
    if delivered:
        await store.mark_alert_delivered(alert_id)


async def run(
    url: str,
    state: State,
    store: Store,
    webhook: Webhook,
    stop: asyncio.Event,
) -> None:
    log.info("connecting to %s", url)
    metrics.WS_CONNECTED.set(0)
    while not stop.is_set():
        try:
            async with websockets.connect(url, max_size=None, ping_interval=20) as ws:
                log.info("connected to %s", url)
                metrics.WS_CONNECTED.set(1)
                while not stop.is_set():
                    recv_task = asyncio.create_task(ws.recv())
                    stop_task = asyncio.create_task(stop.wait())
                    done, pending = await asyncio.wait(
                        {recv_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
                    )
                    for t in pending:
                        t.cancel()
                    if stop_task in done:
                        break
                    raw = recv_task.result()
                    try:
                        await _handle_message(raw, state, store, webhook)
                    except Exception:
                        log.exception("error handling CT message")
        except websockets.ConnectionClosed as e:
            metrics.WS_CONNECTED.set(0)
            if stop.is_set():
                break
            log.warning("disconnected (%s), reconnecting in 5s", e)
            await asyncio.sleep(5)
        except Exception:
            metrics.WS_CONNECTED.set(0)
            if stop.is_set():
                break
            log.exception("watcher loop crashed, retrying in 5s")
            await asyncio.sleep(5)
    metrics.WS_CONNECTED.set(0)
    log.info("watcher stopped")
