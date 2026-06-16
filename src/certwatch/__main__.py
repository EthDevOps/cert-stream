import asyncio
import logging
import signal
import sys

import uvicorn

from . import api as api_mod
from . import cleanup as cleanup_mod
from . import watcher as watcher_mod
from .config import ConfigError, load
from .db import Store
from .state import State
from .webhook import Webhook

log = logging.getLogger("certwatch")


async def _serve_api(app, host: str, port: int, stop: asyncio.Event) -> None:
    config = uvicorn.Config(app, host=host, port=port, log_level="info", access_log=False)
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    await stop.wait()
    server.should_exit = True
    await server_task


async def _run() -> int:
    try:
        cfg = load()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=cfg.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    store = await Store.open(cfg.db_path)
    state = State(store)
    await state.refresh_all()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    async with Webhook(cfg.webhook_url, cfg.webhook_timeout_s) as webhook:
        deps = api_mod.Deps(store=store, state=state, token=cfg.api_token)
        app = api_mod.build_app(deps)

        tasks = [
            asyncio.create_task(
                watcher_mod.run(cfg.certstream_url, state, store, webhook, stop),
                name="watcher",
            ),
            asyncio.create_task(
                _serve_api(app, cfg.api_host, cfg.api_port, stop),
                name="api",
            ),
            asyncio.create_task(
                cleanup_mod.run(
                    store,
                    state,
                    cfg.cleanup_interval_s,
                    cfg.cleanup_grace_s,
                    cfg.alert_retention_s,
                    stop,
                ),
                name="cleanup",
            ),
        ]

        log.info("certwatch started on %s:%d", cfg.api_host, cfg.api_port)
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        stop.set()
        for t in pending:
            try:
                await asyncio.wait_for(t, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                t.cancel()
        for t in done:
            exc = t.exception()
            if exc:
                log.error("task %s exited with error: %s", t.get_name(), exc)

    await store.close()
    return 0


def main() -> None:
    try:
        rc = asyncio.run(_run())
    except KeyboardInterrupt:
        rc = 0
    sys.exit(rc)


if __name__ == "__main__":
    main()
