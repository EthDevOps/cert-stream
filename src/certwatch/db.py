import json
import logging

import asyncpg

from .match import InvalidDomain, validate_watch_entry

log = logging.getLogger(__name__)


_REQUIRED_TABLES = ("public.certs", "public.alerts", "public.intent_current")


class Store:
    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    @classmethod
    async def open(cls, dsn: str) -> "Store":
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=10)
        async with pool.acquire() as conn:
            for table in _REQUIRED_TABLES:
                exists = await conn.fetchval("SELECT to_regclass($1)", table)
                if exists is None:
                    await pool.close()
                    raise RuntimeError(
                        f"required table {table} not found — apply schema.sql first"
                    )
        return cls(pool)

    async def close(self) -> None:
        await self._pool.close()

    # ---- certs (read-only; written by upstream) ----

    async def has_cert(self, fingerprint_sha1: str) -> bool:
        row = await self._pool.fetchval(
            "SELECT 1 FROM public.certs WHERE fingerprint_sha1 = $1",
            fingerprint_sha1,
        )
        return row is not None

    # ---- alerts ----

    async def insert_alert(
        self,
        fingerprint: str,
        sans: list[str],
        matched: list[str],
        issuer: str | None,
        seen_at: int,
        severity: str,
    ) -> int:
        return await self._pool.fetchval(
            """
            INSERT INTO public.alerts
                (fingerprint, sans, matched, issuer, seen_at, severity)
            VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, $6)
            RETURNING id
            """,
            fingerprint,
            json.dumps(sans),
            json.dumps(matched),
            issuer,
            seen_at,
            severity,
        )

    async def mark_alert_delivered(self, alert_id: int) -> None:
        await self._pool.execute(
            "UPDATE public.alerts SET delivered = TRUE WHERE id = $1", alert_id,
        )

    async def prune_alerts(self, cutoff: int) -> int:
        result = await self._pool.execute(
            "DELETE FROM public.alerts WHERE seen_at < $1", cutoff,
        )
        return _rowcount(result)

    # ---- bulk read for in-process watch cache ----

    async def snapshot_watch(self) -> list[str]:
        rows = await self._pool.fetch("SELECT fqdn FROM public.intent_current")
        out: list[str] = []
        seen: set[str] = set()
        for r in rows:
            raw = r["fqdn"]
            if raw is None:
                continue
            try:
                v = validate_watch_entry(raw)
            except InvalidDomain as e:
                log.warning("skipping invalid intent_current.fqdn %r: %s", raw, e)
                continue
            if v in seen:
                continue
            seen.add(v)
            out.append(v)
        return out


def _rowcount(execute_result: str) -> int:
    # asyncpg execute() returns a status string like "DELETE 3".
    parts = execute_result.split()
    if not parts:
        return 0
    try:
        return int(parts[-1])
    except ValueError:
        return 0
