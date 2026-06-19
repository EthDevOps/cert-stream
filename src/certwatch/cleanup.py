import asyncio
import logging
import time

from .db import Store

log = logging.getLogger(__name__)


async def run(
    store: Store,
    interval_s: int,
    alert_retention_s: int,
    stop: asyncio.Event,
) -> None:
    log.info(
        "cleanup loop started: interval=%ds alert_retention=%ds",
        interval_s, alert_retention_s,
    )
    while not stop.is_set():
        try:
            now = int(time.time())
            alert_cutoff = now - alert_retention_s
            removed_alerts = await store.prune_alerts(alert_cutoff)
            if removed_alerts:
                log.info("cleanup pruned %d old alerts", removed_alerts)
        except Exception:
            log.exception("cleanup iteration failed")

        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
            break
        except asyncio.TimeoutError:
            continue
    log.info("cleanup stopped")
