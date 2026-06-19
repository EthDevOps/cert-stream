import asyncio
import logging

from .state import State

log = logging.getLogger(__name__)


async def run(state: State, interval_s: int, stop: asyncio.Event) -> None:
    log.info("watch refresh loop started: interval=%ds", interval_s)
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
            break
        except asyncio.TimeoutError:
            pass
        try:
            await state.refresh_watch()
        except Exception:
            log.exception("watch refresh failed")
    log.info("watch refresh stopped")
