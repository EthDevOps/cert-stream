import asyncio
import logging
import time
from collections import OrderedDict

from . import metrics
from .db import Store

log = logging.getLogger(__name__)


class State:
    """In-process cache of watch entries.

    The watch list is reloaded from Postgres on a timer; the watcher reads
    from this cache on every CT event without touching the DB. Known-cert
    lookups go straight to the DB on match (rare path), so there is no
    fingerprint cache here.
    """

    def __init__(self, store: Store, dedupe_capacity: int = 2048):
        self._store = store
        self._lock = asyncio.Lock()
        self.watch_entries: list[str] = []
        self.last_ct_event_at: float | None = None
        self._recent_alerts: OrderedDict[str, None] = OrderedDict()
        self._dedupe_capacity = dedupe_capacity

    async def refresh_all(self) -> None:
        await self.refresh_watch()
        log.info("state refreshed: %d watch entries", len(self.watch_entries))

    async def refresh_watch(self) -> None:
        async with self._lock:
            self.watch_entries = await self._store.snapshot_watch()
        metrics.WATCH_ENTRIES.set(len(self.watch_entries))

    def mark_ct_event(self) -> None:
        self.last_ct_event_at = time.time()
        metrics.LAST_CT_EVENT.set(self.last_ct_event_at)

    def seen_recently(self, fp: str) -> bool:
        if fp in self._recent_alerts:
            self._recent_alerts.move_to_end(fp)
            return True
        return False

    def record_recent(self, fp: str) -> None:
        self._recent_alerts[fp] = None
        self._recent_alerts.move_to_end(fp)
        while len(self._recent_alerts) > self._dedupe_capacity:
            self._recent_alerts.popitem(last=False)

    def dedupe_size(self) -> int:
        return len(self._recent_alerts)
