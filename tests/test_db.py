import time

import pytest

from certwatch.db import Store


@pytest.fixture
async def store(tmp_path):
    s = await Store.open(str(tmp_path / "t.db"))
    try:
        yield s
    finally:
        await s.close()


async def test_upsert_cert_idempotent(store):
    fp = "a" * 40
    await store.upsert_cert(fp, ["a.example.org"], 1, 100, source="lb1")
    await store.upsert_cert(fp, ["a.example.org", "b.example.org"], 1, 200, source="lb2")
    rows = await store.list_certs()
    assert len(rows) == 1
    assert rows[0].not_after == 200
    assert rows[0].source == "lb2"
    assert "b.example.org" in rows[0].sans


async def test_has_cert(store):
    fp = "b" * 40
    assert not await store.has_cert(fp)
    await store.upsert_cert(fp, ["x.example.org"], 0, 100)
    assert await store.has_cert(fp)


async def test_prune_certs_boundary(store):
    now = int(time.time())
    await store.upsert_cert("c" * 40, ["a"], 0, now - 100)   # expired well past
    await store.upsert_cert("d" * 40, ["b"], 0, now + 100)   # still valid
    removed = await store.prune_certs(now)
    assert removed == 1
    fps = await store.snapshot_fingerprints()
    assert "c" * 40 not in fps
    assert "d" * 40 in fps


async def test_watch_crud(store):
    await store.add_watch("*.example.org", note="prod")
    await store.add_watch("foo.example.com")
    values = await store.snapshot_watch()
    assert set(values) == {"*.example.org", "foo.example.com"}
    n = await store.delete_watch("foo.example.com")
    assert n == 1
    assert await store.snapshot_watch() == ["*.example.org"]


async def test_alert_lifecycle(store):
    aid = await store.insert_alert(
        fingerprint="e" * 40,
        sans=["a.example.org"],
        matched=["*.example.org"],
        issuer="Let's Encrypt",
        seen_at=12345,
        severity="suspicious",
    )
    rows = await store.list_alerts()
    assert len(rows) == 1
    assert rows[0].id == aid
    assert rows[0].delivered is False
    assert rows[0].severity == "suspicious"
    await store.mark_alert_delivered(aid)
    rows = await store.list_alerts()
    assert rows[0].delivered is True


async def test_alert_severity_persists(store):
    await store.insert_alert("a" * 40, ["a"], ["*.x"], None, 1, severity="info")
    await store.insert_alert("b" * 40, ["b"], ["*.x"], None, 2, severity="suspicious")
    rows = await store.list_alerts()
    by_fp = {r.fingerprint: r.severity for r in rows}
    assert by_fp["a" * 40] == "info"
    assert by_fp["b" * 40] == "suspicious"


async def test_alert_prune(store):
    await store.insert_alert("f" * 40, ["a"], ["*.example.org"], None, 100, "suspicious")
    await store.insert_alert("a1" + "0" * 38, ["b"], ["*.example.org"], None, 1000, "info")
    removed = await store.prune_alerts(500)
    assert removed == 1
    rows = await store.list_alerts()
    assert len(rows) == 1
    assert rows[0].seen_at == 1000
