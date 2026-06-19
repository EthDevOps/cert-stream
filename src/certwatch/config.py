import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    certstream_url: str
    postgres_dsn: str
    api_host: str
    api_port: int
    webhook_url: str | None
    webhook_timeout_s: float
    cleanup_interval_s: int
    alert_retention_s: int
    suspicious_grace_s: float
    watch_refresh_interval_s: int
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
    dsn = _env("POSTGRES_DSN", required=True)
    assert dsn is not None
    return Config(
        certstream_url=_env("CERTSTREAM_URL", "ws://localhost:8080/full-stream") or "",
        postgres_dsn=dsn,
        api_host=_env("API_HOST", "127.0.0.1") or "127.0.0.1",
        api_port=_env_int("API_PORT", 8765),
        webhook_url=_env("WEBHOOK_URL") or None,
        webhook_timeout_s=_env_float("WEBHOOK_TIMEOUT_S", 10.0),
        cleanup_interval_s=_env_int("CLEANUP_INTERVAL_S", 3600),
        alert_retention_s=_env_int("ALERT_RETENTION_S", 30 * 86400),
        suspicious_grace_s=_env_float("SUSPICIOUS_GRACE_S", 10.0),
        watch_refresh_interval_s=_env_int("WATCH_REFRESH_INTERVAL_S", 60),
        log_level=_env("LOG_LEVEL", "INFO") or "INFO",
    )
