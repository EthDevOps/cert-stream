import asyncio
import logging
import time

from .db import Store
from .state import State

log = logging.getLogger(__name__)


async def run(
    store: Store,
    state: State,
    interval_s: int,
    cert_grace_s: int,
    alert_retention_s: int,
    stop: asyncio.Event,
) -> None:
    log.info(
        "cleanup loop started: interval=%ds cert_grace=%ds alert_retention=%ds",
        interval_s, cert_grace_s, alert_retention_s,
    )
    while not stop.is_set():
        try:
            now = int(time.time())
            cert_cutoff = now - cert_grace_s
            alert_cutoff = now - alert_retention_s
            removed_certs = await store.prune_certs(cert_cutoff)
            removed_alerts = await store.prune_alerts(alert_cutoff)
            if removed_certs or removed_alerts:
                log.info(
                    "cleanup pruned %d expired certs, %d old alerts",
                    removed_certs, removed_alerts,
                )
                await state.refresh_fingerprints()
        except Exception:
            log.exception("cleanup iteration failed")

        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
            break
        except asyncio.TimeoutError:
            continue
    log.info("cleanup stopped")
