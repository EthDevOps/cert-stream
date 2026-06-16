import json
import time
from collections.abc import Iterable
from dataclasses import dataclass

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS certs (
  fingerprint_sha1 TEXT PRIMARY KEY,
  serial           TEXT,
  sans             TEXT NOT NULL,
  not_before       INTEGER NOT NULL,
  not_after        INTEGER NOT NULL,
  source           TEXT,
  added_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS certs_not_after ON certs(not_after);

CREATE TABLE IF NOT EXISTS watch_domains (
  value      TEXT PRIMARY KEY,
  note       TEXT,
  added_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL,
  sans        TEXT NOT NULL,
  matched     TEXT NOT NULL,
  issuer      TEXT,
  seen_at     INTEGER NOT NULL,
  delivered   INTEGER NOT NULL DEFAULT 0,
  severity    TEXT NOT NULL DEFAULT 'suspicious'
);
CREATE INDEX IF NOT EXISTS alerts_seen_at ON alerts(seen_at);
"""


@dataclass
class CertRow:
    fingerprint_sha1: str
    serial: str | None
    sans: list[str]
    not_before: int
    not_after: int
    source: str | None
    added_at: int


@dataclass
class WatchRow:
    value: str
    note: str | None
    added_at: int


@dataclass
class AlertRow:
    id: int
    fingerprint: str
    sans: list[str]
    matched: list[str]
    issuer: str | None
    seen_at: int
    delivered: bool
    severity: str


class Store:
    def __init__(self, conn: aiosqlite.Connection):
        self._c = conn

    @classmethod
    async def open(cls, path: str) -> "Store":
        conn = await aiosqlite.connect(path)
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.executescript(SCHEMA)
        await cls._migrate(conn)
        await conn.commit()
        return cls(conn)

    @staticmethod
    async def _migrate(conn: aiosqlite.Connection) -> None:
        # idempotent: add severity column to alerts on pre-existing DBs
        async with conn.execute("PRAGMA table_info(alerts)") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if "severity" not in cols:
            await conn.execute(
                "ALTER TABLE alerts ADD COLUMN severity TEXT NOT NULL DEFAULT 'suspicious'"
            )

    async def close(self) -> None:
        await self._c.close()

    # ---- certs ----

    async def upsert_cert(
        self,
        fingerprint_sha1: str,
        sans: list[str],
        not_before: int,
        not_after: int,
        serial: str | None = None,
        source: str | None = None,
    ) -> None:
        await self._c.execute(
            """
            INSERT INTO certs (fingerprint_sha1, serial, sans, not_before, not_after, source, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint_sha1) DO UPDATE SET
                serial=excluded.serial,
                sans=excluded.sans,
                not_before=excluded.not_before,
                not_after=excluded.not_after,
                source=excluded.source
            """,
            (
                fingerprint_sha1,
                serial,
                json.dumps(sans),
                not_before,
                not_after,
                source,
                int(time.time()),
            ),
        )
        await self._c.commit()

    async def has_cert(self, fingerprint_sha1: str) -> bool:
        async with self._c.execute(
            "SELECT 1 FROM certs WHERE fingerprint_sha1 = ?", (fingerprint_sha1,)
        ) as cur:
            return (await cur.fetchone()) is not None

    async def list_certs(self, limit: int = 100, offset: int = 0) -> list[CertRow]:
        async with self._c.execute(
            "SELECT fingerprint_sha1, serial, sans, not_before, not_after, source, added_at "
            "FROM certs ORDER BY added_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cur:
            rows = await cur.fetchall()
        return [
            CertRow(
                fingerprint_sha1=r[0],
                serial=r[1],
                sans=json.loads(r[2]),
                not_before=r[3],
                not_after=r[4],
                source=r[5],
                added_at=r[6],
            )
            for r in rows
        ]

    async def delete_cert(self, fingerprint_sha1: str) -> int:
        async with self._c.execute(
            "DELETE FROM certs WHERE fingerprint_sha1 = ?", (fingerprint_sha1,)
        ) as cur:
            await self._c.commit()
            return cur.rowcount or 0

    async def prune_certs(self, cutoff: int) -> int:
        async with self._c.execute(
            "DELETE FROM certs WHERE not_after < ?", (cutoff,)
        ) as cur:
            await self._c.commit()
            return cur.rowcount or 0

    # ---- watch ----

    async def add_watch(self, value: str, note: str | None = None) -> None:
        await self._c.execute(
            "INSERT OR REPLACE INTO watch_domains (value, note, added_at) VALUES (?, ?, ?)",
            (value, note, int(time.time())),
        )
        await self._c.commit()

    async def list_watch(self) -> list[WatchRow]:
        async with self._c.execute(
            "SELECT value, note, added_at FROM watch_domains ORDER BY value"
        ) as cur:
            rows = await cur.fetchall()
        return [WatchRow(value=r[0], note=r[1], added_at=r[2]) for r in rows]

    async def list_watch_values(self) -> list[str]:
        async with self._c.execute("SELECT value FROM watch_domains") as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    async def delete_watch(self, value: str) -> int:
        async with self._c.execute(
            "DELETE FROM watch_domains WHERE value = ?", (value,)
        ) as cur:
            await self._c.commit()
            return cur.rowcount or 0

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
        async with self._c.execute(
            "INSERT INTO alerts (fingerprint, sans, matched, issuer, seen_at, severity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (fingerprint, json.dumps(sans), json.dumps(matched), issuer, seen_at, severity),
        ) as cur:
            await self._c.commit()
            assert cur.lastrowid is not None
            return cur.lastrowid

    async def mark_alert_delivered(self, alert_id: int) -> None:
        await self._c.execute(
            "UPDATE alerts SET delivered = 1 WHERE id = ?", (alert_id,)
        )
        await self._c.commit()

    async def list_alerts(
        self, since: int | None = None, limit: int = 100
    ) -> list[AlertRow]:
        if since is None:
            q = (
                "SELECT id, fingerprint, sans, matched, issuer, seen_at, delivered, severity "
                "FROM alerts ORDER BY id DESC LIMIT ?"
            )
            args: tuple = (limit,)
        else:
            q = (
                "SELECT id, fingerprint, sans, matched, issuer, seen_at, delivered, severity "
                "FROM alerts WHERE seen_at >= ? ORDER BY id DESC LIMIT ?"
            )
            args = (since, limit)
        async with self._c.execute(q, args) as cur:
            rows = await cur.fetchall()
        return [
            AlertRow(
                id=r[0],
                fingerprint=r[1],
                sans=json.loads(r[2]),
                matched=json.loads(r[3]),
                issuer=r[4],
                seen_at=r[5],
                delivered=bool(r[6]),
                severity=r[7],
            )
            for r in rows
        ]

    async def prune_alerts(self, cutoff: int) -> int:
        async with self._c.execute(
            "DELETE FROM alerts WHERE seen_at < ?", (cutoff,)
        ) as cur:
            await self._c.commit()
            return cur.rowcount or 0

    # ---- bulk reads for in-process caches ----

    async def snapshot_fingerprints(self) -> set[str]:
        async with self._c.execute("SELECT fingerprint_sha1 FROM certs") as cur:
            rows = await cur.fetchall()
        return {r[0] for r in rows}

    async def snapshot_watch(self) -> list[str]:
        return await self.list_watch_values()
