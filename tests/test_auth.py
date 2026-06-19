import pytest
from fastapi.testclient import TestClient

from certwatch.api import build_app
from certwatch.state import State


class _StubStore:
    async def snapshot_watch(self) -> list[str]:
        return []


@pytest.fixture
async def client():
    state = State(_StubStore())  # type: ignore[arg-type]
    await state.refresh_all()
    app = build_app(state)
    with TestClient(app) as c:
        yield c


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["watch_entries"] == 0
    assert body["last_ct_event_at"] is None


def test_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "certwatch_" in r.text
