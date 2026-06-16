import pytest
from fastapi.testclient import TestClient

from certwatch.api import Deps, build_app
from certwatch.db import Store
from certwatch.state import State


@pytest.fixture
async def client(tmp_path):
    store = await Store.open(str(tmp_path / "auth.db"))
    state = State(store)
    await state.refresh_all()
    app = build_app(Deps(store=store, state=state, token="s3cret"))
    with TestClient(app) as c:
        yield c
    await store.close()


def test_no_header_returns_401(client):
    assert client.get("/domains").status_code == 401


def test_correct_token_returns_200(client):
    assert client.get("/domains", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_scheme_is_case_insensitive(client):
    for scheme in ("Bearer", "bearer", "BEARER", "BeArEr"):
        r = client.get("/domains", headers={"Authorization": f"{scheme} s3cret"})
        assert r.status_code == 200, f"{scheme!r} should be accepted"


def test_wrong_token_returns_403(client):
    r = client.get("/domains", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403


def test_empty_token_after_scheme_returns_401(client):
    r = client.get("/domains", headers={"Authorization": "Bearer "})
    assert r.status_code == 401


def test_non_bearer_scheme_returns_401(client):
    r = client.get("/domains", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert r.status_code == 401


def test_healthz_is_anonymous(client):
    assert client.get("/healthz").status_code == 200


def test_metrics_is_anonymous(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "certwatch_" in r.text
