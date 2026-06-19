from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from .state import State


class HealthOut(BaseModel):
    ok: bool
    watch_entries: int
    last_ct_event_at: float | None


def build_app(state: State) -> FastAPI:
    app = FastAPI(title="certwatch", version="0.1.0")

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/healthz", response_model=HealthOut)
    async def healthz() -> HealthOut:
        return HealthOut(
            ok=True,
            watch_entries=len(state.watch_entries),
            last_ct_event_at=state.last_ct_event_at,
        )

    return app
