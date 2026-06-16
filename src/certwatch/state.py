import asyncio
import logging
import time
from collections import OrderedDict

from . import metrics
from .db import Store

log = logging.getLogger(__name__)


class State:
    """In-process caches of watch entries and known fingerprints.

    The API mutates the DB and then calls refresh_*; the watcher reads
    from the caches on every CT event without touching SQLite.
    """

    def __init__(self, store: Store, dedupe_capacity: int = 2048):
        self._store = store
        self._lock = asyncio.Lock()
        self.watch_entries: list[str] = []
        self.known_fingerprints: set[str] = set()
        self.last_ct_event_at: float | None = None
        self._recent_alerts: OrderedDict[str, None] = OrderedDict()
        self._dedupe_capacity = dedupe_capacity

    async def refresh_all(self) -> None:
        async with self._lock:
            self.watch_entries = await self._store.snapshot_watch()
            self.known_fingerprints = await self._store.snapshot_fingerprints()
        self._update_gauges()
        log.info(
            "state refreshed: %d watch entries, %d known fingerprints",
            len(self.watch_entries),
            len(self.known_fingerprints),
        )

    async def refresh_watch(self) -> None:
        async with self._lock:
            self.watch_entries = await self._store.snapshot_watch()
        self._update_gauges()

    async def refresh_fingerprints(self) -> None:
        async with self._lock:
            self.known_fingerprints = await self._store.snapshot_fingerprints()
        self._update_gauges()

    def add_known_fingerprint(self, fp: str) -> None:
        self.known_fingerprints.add(fp)
        self._update_gauges()

    def remove_known_fingerprint(self, fp: str) -> None:
        self.known_fingerprints.discard(fp)
        self._update_gauges()

    def mark_ct_event(self) -> None:
        self.last_ct_event_at = time.time()
        metrics.LAST_CT_EVENT.set(self.last_ct_event_at)

    def _update_gauges(self) -> None:
        metrics.WATCH_ENTRIES.set(len(self.watch_entries))
        metrics.KNOWN_FPS.set(len(self.known_fingerprints))

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
