"""Shared fixtures for DB-backed tests.

These tests require a running Postgres reachable via ``TEST_POSTGRES_DSN``.
When the env var is unset the whole module is skipped so contributors without
a local Postgres aren't blocked.
"""
import os
from pathlib import Path

import pytest

DSN = os.environ.get("TEST_POSTGRES_DSN")

requires_postgres = pytest.mark.skipif(
    not DSN, reason="TEST_POSTGRES_DSN not set"
)


SCHEMA_SQL = (Path(__file__).resolve().parents[1] / "schema.sql").read_text()

# Minimal stand-in for the upstream public.intent_current table; the production
# schema may carry more columns but certwatch only reads `fqdn`.
INTENT_CURRENT_DDL = """
CREATE TABLE IF NOT EXISTS public.intent_current (
  fqdn TEXT PRIMARY KEY
);
"""


async def _reset_db() -> None:
    import asyncpg

    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(SCHEMA_SQL)
        await conn.execute(INTENT_CURRENT_DDL)
        await conn.execute(
            "TRUNCATE public.certs, public.alerts, public.intent_current"
        )
    finally:
        await conn.close()


@pytest.fixture
async def store():
    if not DSN:
        pytest.skip("TEST_POSTGRES_DSN not set")
    from certwatch.db import Store

    await _reset_db()
    s = await Store.open(DSN)
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def seed_intent():
    """Returns a coroutine that inserts FQDNs into public.intent_current."""
    if not DSN:
        pytest.skip("TEST_POSTGRES_DSN not set")
    import asyncpg

    async def _seed(values: list[str]) -> None:
        conn = await asyncpg.connect(DSN)
        try:
            await conn.executemany(
                "INSERT INTO public.intent_current (fqdn) VALUES ($1) ON CONFLICT DO NOTHING",
                [(v,) for v in values],
            )
        finally:
            await conn.close()

    return _seed


@pytest.fixture
async def db_conn():
    """Raw asyncpg connection for tests that need to verify state via SQL."""
    if not DSN:
        pytest.skip("TEST_POSTGRES_DSN not set")
    import asyncpg

    conn = await asyncpg.connect(DSN)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def seed_cert():
    """Returns a coroutine that inserts a row directly into public.certs."""
    if not DSN:
        pytest.skip("TEST_POSTGRES_DSN not set")
    import json
    import time

    import asyncpg

    async def _seed(
        fingerprint_sha1: str,
        sans: list[str],
        not_before: int = 0,
        not_after: int = 2_000_000_000,
        source: str | None = None,
        serial: str | None = None,
    ) -> None:
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(
                """
                INSERT INTO public.certs
                    (fingerprint_sha1, serial, sans, not_before, not_after, source, added_at)
                VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)
                ON CONFLICT (fingerprint_sha1) DO NOTHING
                """,
                fingerprint_sha1,
                serial,
                json.dumps(sans),
                not_before,
                not_after,
                source,
                int(time.time()),
            )
        finally:
            await conn.close()

    return _seed
