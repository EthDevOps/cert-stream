import re
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, field_validator

from .db import Store
from .match import InvalidDomain, validate_watch_entry
from .state import State

_FP_RE = re.compile(r"^[0-9a-f]{40}$")


def _normalize_fp(raw: str) -> str:
    s = raw.replace(":", "").strip().lower()
    if not _FP_RE.match(s):
        raise ValueError("fingerprint must be 40 hex chars (SHA-1)")
    return s


class CertIn(BaseModel):
    fingerprint: str = Field(..., description="SHA-1 fingerprint; colons and case ignored")
    sans: list[str] = Field(..., min_length=1)
    not_before: int
    not_after: int
    serial: str | None = None
    source: str | None = None

    @field_validator("fingerprint")
    @classmethod
    def _v_fp(cls, v: str) -> str:
        try:
            return _normalize_fp(v)
        except ValueError as e:
            raise ValueError(str(e)) from e

    @field_validator("sans")
    @classmethod
    def _v_sans(cls, v: list[str]) -> list[str]:
        return [s.strip().lower().rstrip(".") for s in v if s.strip()]


class CertOut(BaseModel):
    fingerprint_sha1: str
    serial: str | None
    sans: list[str]
    not_before: int
    not_after: int
    source: str | None
    added_at: int


class DomainIn(BaseModel):
    value: str
    note: str | None = None


class DomainOut(BaseModel):
    value: str
    note: str | None
    added_at: int


class AlertOut(BaseModel):
    id: int
    fingerprint: str
    sans: list[str]
    matched: list[str]
    issuer: str | None
    seen_at: int
    delivered: bool
    severity: str


class HealthOut(BaseModel):
    ok: bool
    watch_entries: int
    known_fingerprints: int
    last_ct_event_at: float | None


@dataclass
class Deps:
    store: Store
    state: State
    token: str


def build_app(deps: Deps) -> FastAPI:
    app = FastAPI(title="certwatch", version="0.1.0")

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    async def require_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
        if authorization.removeprefix("Bearer ").strip() != deps.token:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid token")

    AuthDep = Depends(require_token)

    @app.get("/healthz", response_model=HealthOut)
    async def healthz() -> HealthOut:
        return HealthOut(
            ok=True,
            watch_entries=len(deps.state.watch_entries),
            known_fingerprints=len(deps.state.known_fingerprints),
            last_ct_event_at=deps.state.last_ct_event_at,
        )

    @app.post("/certs", status_code=status.HTTP_201_CREATED, dependencies=[AuthDep])
    async def post_cert(body: CertIn) -> dict[str, str]:
        if body.not_after <= body.not_before:
            raise HTTPException(400, "not_after must be > not_before")
        await deps.store.upsert_cert(
            fingerprint_sha1=body.fingerprint,
            sans=body.sans,
            not_before=body.not_before,
            not_after=body.not_after,
            serial=body.serial,
            source=body.source,
        )
        deps.state.add_known_fingerprint(body.fingerprint)
        return {"fingerprint_sha1": body.fingerprint}

    @app.get("/certs", response_model=list[CertOut], dependencies=[AuthDep])
    async def list_certs(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> list[CertOut]:
        rows = await deps.store.list_certs(limit=limit, offset=offset)
        return [
            CertOut(
                fingerprint_sha1=r.fingerprint_sha1,
                serial=r.serial,
                sans=r.sans,
                not_before=r.not_before,
                not_after=r.not_after,
                source=r.source,
                added_at=r.added_at,
            )
            for r in rows
        ]

    @app.delete("/certs/{fp}", dependencies=[AuthDep])
    async def delete_cert(fp: str) -> dict[str, int]:
        try:
            fp_n = _normalize_fp(fp)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        n = await deps.store.delete_cert(fp_n)
        if n == 0:
            raise HTTPException(404, "fingerprint not found")
        deps.state.remove_known_fingerprint(fp_n)
        return {"deleted": n}

    @app.post("/domains", status_code=status.HTTP_201_CREATED, dependencies=[AuthDep])
    async def post_domain(body: DomainIn) -> dict[str, str]:
        try:
            v = validate_watch_entry(body.value)
        except InvalidDomain as e:
            raise HTTPException(400, str(e)) from e
        await deps.store.add_watch(v, body.note)
        await deps.state.refresh_watch()
        return {"value": v}

    @app.get("/domains", response_model=list[DomainOut], dependencies=[AuthDep])
    async def list_domains() -> list[DomainOut]:
        rows = await deps.store.list_watch()
        return [DomainOut(value=r.value, note=r.note, added_at=r.added_at) for r in rows]

    @app.delete("/domains/{value:path}", dependencies=[AuthDep])
    async def delete_domain(value: str) -> dict[str, int]:
        try:
            v = validate_watch_entry(value)
        except InvalidDomain as e:
            raise HTTPException(400, str(e)) from e
        n = await deps.store.delete_watch(v)
        if n == 0:
            raise HTTPException(404, "watch entry not found")
        await deps.state.refresh_watch()
        return {"deleted": n}

    @app.get("/alerts", response_model=list[AlertOut], dependencies=[AuthDep])
    async def list_alerts(
        since: int | None = Query(None, description="unix seconds, return alerts with seen_at >= since"),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[AlertOut]:
        rows = await deps.store.list_alerts(since=since, limit=limit)
        return [
            AlertOut(
                id=r.id,
                fingerprint=r.fingerprint,
                sans=r.sans,
                matched=r.matched,
                issuer=r.issuer,
                seen_at=r.seen_at,
                delivered=r.delivered,
                severity=r.severity,
            )
            for r in rows
        ]

    return app
