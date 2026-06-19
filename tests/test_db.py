async def test_has_cert(store, seed_cert):
    fp = "b" * 40
    assert not await store.has_cert(fp)
    await seed_cert(fp, ["x.example.org"])
    assert await store.has_cert(fp)


async def test_snapshot_watch_reads_intent_current(store, seed_intent):
    await seed_intent(["example.org", "*.foo.example.com", "Bar.Example.org"])
    entries = await store.snapshot_watch()
    # validate_watch_entry strips leading "*." and lowercases.
    assert set(entries) == {"example.org", "foo.example.com", "bar.example.org"}


async def test_snapshot_watch_skips_invalid(store, seed_intent):
    await seed_intent(["good.example.org", "invalid"])  # 'invalid' has <2 labels
    entries = await store.snapshot_watch()
    assert entries == ["good.example.org"]


async def test_alert_insert_and_mark_delivered(store, db_conn):
    aid = await store.insert_alert(
        fingerprint="e" * 40,
        sans=["a.example.org"],
        matched=["example.org"],
        issuer="Let's Encrypt",
        seen_at=12345,
        severity="suspicious",
    )
    row = await db_conn.fetchrow(
        "SELECT delivered, severity FROM public.alerts WHERE id = $1", aid
    )
    assert row["delivered"] is False
    assert row["severity"] == "suspicious"
    await store.mark_alert_delivered(aid)
    delivered = await db_conn.fetchval(
        "SELECT delivered FROM public.alerts WHERE id = $1", aid
    )
    assert delivered is True


async def test_alert_prune(store, db_conn):
    await store.insert_alert("f" * 40, ["a.example.org"], ["example.org"], None, 100, "suspicious")
    await store.insert_alert("a1" + "0" * 38, ["b.example.org"], ["example.org"], None, 1000, "info")
    removed = await store.prune_alerts(500)
    assert removed == 1
    remaining = await db_conn.fetchval("SELECT count(*) FROM public.alerts")
    assert remaining == 1
    seen_at = await db_conn.fetchval("SELECT seen_at FROM public.alerts")
    assert seen_at == 1000
