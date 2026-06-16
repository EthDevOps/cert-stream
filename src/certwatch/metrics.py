from prometheus_client import Counter, Gauge, Histogram

CT_MESSAGES = Counter(
    "certwatch_ct_messages_total",
    "Total raw messages received from the certstream WS",
    ["type"],
)

ALERTS = Counter(
    "certwatch_alerts_total",
    "Alerts emitted, classified by severity",
    ["severity"],
)

WEBHOOK_ATTEMPTS = Counter(
    "certwatch_webhook_total",
    "Webhook delivery outcomes",
    ["result"],  # success | failure
)

WEBHOOK_DURATION = Histogram(
    "certwatch_webhook_duration_seconds",
    "Time spent in a single webhook POST attempt",
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
)

KNOWN_FPS = Gauge(
    "certwatch_known_fingerprints",
    "Number of known-good cert fingerprints in inventory",
)

WATCH_ENTRIES = Gauge(
    "certwatch_watch_entries",
    "Number of watch-list entries",
)

LAST_CT_EVENT = Gauge(
    "certwatch_last_ct_event_timestamp_seconds",
    "Unix timestamp of the most recent CT event received",
)

WS_CONNECTED = Gauge(
    "certwatch_ws_connected",
    "1 if the watcher is connected to certstream, else 0",
)

DEDUPE_CACHE_SIZE = Gauge(
    "certwatch_dedupe_cache_size",
    "Number of fingerprints in the in-process LRU dedupe cache",
)
