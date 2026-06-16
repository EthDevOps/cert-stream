import asyncio
import logging
from typing import Any

import httpx

from . import metrics

log = logging.getLogger(__name__)

_BACKOFF = (1.0, 4.0, 16.0)  # seconds between attempts


class Webhook:
    def __init__(self, url: str | None, timeout_s: float):
        self._url = url
        self._timeout = timeout_s
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "Webhook":
        if self._url:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def deliver(self, payload: dict[str, Any]) -> bool:
        """Send payload; return True if delivered, False if all attempts failed."""
        if self._url is None or self._client is None:
            log.warning("webhook unset, dropping alert: %s", payload.get("fingerprint_sha1"))
            return False

        for i, delay in enumerate(_BACKOFF):
            try:
                with metrics.WEBHOOK_DURATION.time():
                    resp = await self._client.post(self._url, json=payload)
                if 200 <= resp.status_code < 300:
                    metrics.WEBHOOK_ATTEMPTS.labels(result="success").inc()
                    return True
                metrics.WEBHOOK_ATTEMPTS.labels(result="failure").inc()
                log.warning(
                    "webhook %s returned %d on attempt %d", self._url, resp.status_code, i + 1
                )
            except httpx.HTTPError as e:
                metrics.WEBHOOK_ATTEMPTS.labels(result="failure").inc()
                log.warning("webhook attempt %d failed: %s", i + 1, e)
            if i < len(_BACKOFF) - 1:
                await asyncio.sleep(delay)
        log.error("webhook delivery exhausted for %s", payload.get("fingerprint_sha1"))
        return False
