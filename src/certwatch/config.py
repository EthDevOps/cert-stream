import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    certstream_url: str
    db_path: str
    api_host: str
    api_port: int
    api_token: str
    webhook_url: str | None
    webhook_timeout_s: float
    cleanup_interval_s: int
    cleanup_grace_s: int
    alert_retention_s: int
    log_level: str


def _env(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    val = os.environ.get(name, default)
    if required and not val:
        raise ConfigError(f"required env var {name} is not set")
    return val


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise ConfigError(f"env var {name} must be an integer, got {raw!r}") from e


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as e:
        raise ConfigError(f"env var {name} must be a number, got {raw!r}") from e


def load() -> Config:
    token = _env("API_TOKEN", required=True)
    assert token is not None
    return Config(
        certstream_url=_env("CERTSTREAM_URL", "ws://localhost:8080/full-stream") or "",
        db_path=_env("DB_PATH", "./certwatch.db") or "./certwatch.db",
        api_host=_env("API_HOST", "127.0.0.1") or "127.0.0.1",
        api_port=_env_int("API_PORT", 8765),
        api_token=token,
        webhook_url=_env("WEBHOOK_URL") or None,
        webhook_timeout_s=_env_float("WEBHOOK_TIMEOUT_S", 10.0),
        cleanup_interval_s=_env_int("CLEANUP_INTERVAL_S", 3600),
        cleanup_grace_s=_env_int("CLEANUP_GRACE_S", 86400),
        alert_retention_s=_env_int("ALERT_RETENTION_S", 30 * 86400),
        log_level=_env("LOG_LEVEL", "INFO") or "INFO",
    )
