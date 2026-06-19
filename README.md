# certwatch

Watch CT logs for certs issued for your domains, and diff against an inventory
of certs your own load balancers have issued. Anything left over is a potential
hijack.

## How it works

```
        certstream WS                                    n8n / etc.
              │                                              ▲
              ▼                                              │ POST
       ┌──────────────┐  match on SANs    ┌──────────────┐   │
       │   watcher    ├─────────────────► │   webhook    ├───┘
       └──────┬───────┘  fp not in DB     └──────┬───────┘
              │ ▲                                │
              │ │ has_cert?                      ▼
              │ │                        ┌──────────────┐
              │ └────────── Postgres ────┤   alerts     │
              ▼                          └──────────────┘
       ┌──────────────┐                  ┌────────────────────────┐
       │ /healthz     │                  │ public.intent_current  │
       │ /metrics     │                  │ public.certs           │
       └──────────────┘                  │ (both upstream-managed)│
                                         └────────────────────────┘
```

A single asyncio process runs four concurrent tasks:

1. **watcher** — consumes a [certstream-server](https://github.com/CaliDog/certstream-server) WS feed, matches each cert's SANs against the watch list, and on a hit checks `public.certs` to decide info-vs-suspicious
2. **api** — FastAPI app exposing `/healthz` and `/metrics` only
3. **cleanup** — prunes old alerts
4. **watch refresh** — re-reads `public.intent_current` every `WATCH_REFRESH_INTERVAL_S` seconds

State lives in Postgres. Both the watched-domains list (`public.intent_current`) and the known-cert inventory (`public.certs`) are owned by upstream systems; certwatch only reads from them. The only table certwatch writes to is `public.alerts`.

## Quick start

```bash
uv sync --extra test
psql "$POSTGRES_DSN" -f schema.sql        # create certs + alerts tables
POSTGRES_DSN=postgresql://user:pw@localhost/certwatch uv run -m certwatch
```

The service binds `127.0.0.1:8765` by default. Health check:

```bash
curl http://127.0.0.1:8765/healthz
```

## Configuration (ENV)

| Var                        | Default                              | Notes                                                                |
| -------------------------- | ------------------------------------ | -------------------------------------------------------------------- |
| `POSTGRES_DSN`             | *(required)*                         | Postgres connection string, e.g. `postgresql://user:pw@host:5432/db` |
| `CERTSTREAM_URL`           | `ws://localhost:8080/full-stream`    | Upstream certstream-server                                           |
| `API_HOST`                 | `127.0.0.1`                          | Bind addr                                                            |
| `API_PORT`                 | `8765`                               | Bind port                                                            |
| `WEBHOOK_URL`              | *(unset → observer mode, log only)*  | POST destination for alerts (your n8n endpoint)                      |
| `WEBHOOK_TIMEOUT_S`        | `10`                                 | Per-attempt timeout                                                  |
| `CLEANUP_INTERVAL_S`       | `3600`                               | How often to prune                                                   |
| `ALERT_RETENTION_S`        | `2592000`                            | Keep alerts 30 days                                                  |
| `SUSPICIOUS_GRACE_S`       | `10`                                 | Wait this long for upstream to land an fp in `public.certs` before flagging |
| `WATCH_REFRESH_INTERVAL_S` | `60`                                 | How often to re-read `public.intent_current`                         |
| `LOG_LEVEL`                | `INFO`                               | stdlib logging level                                                 |

## API

The service exposes two anonymous endpoints:

| Endpoint     | Purpose                                                                |
| ------------ | ---------------------------------------------------------------------- |
| `GET /healthz` | Liveness check; returns `{ok, watch_entries, last_ct_event_at}`.       |
| `GET /metrics` | Prometheus text-exposition scrape.                                     |

Inspect the data directly in Postgres:

```sql
-- what we're currently watching
SELECT fqdn FROM public.intent_current;

-- known-good certs (upstream-managed)
SELECT * FROM public.certs;

-- recent alerts (the only table certwatch writes to)
SELECT * FROM public.alerts ORDER BY id DESC LIMIT 50;
```

Match semantics: an entry `example.org` matches `example.org` and any
subdomain (`foo.example.org`, `a.b.example.org`, …). A leading `*.` in the
`intent_current.fqdn` value is stripped on read. SANs with a leading
wildcard (`*.X`) match when their expansions overlap an entry's subtree.

## Webhook payload (sent to `WEBHOOK_URL`)

Every cert whose SANs match the watch list produces a webhook event, classified
by `severity`:

- `info` — fingerprint is in the LB inventory. Doubles as a heartbeat: if you
  stop seeing these in n8n, the CT pipeline is dead or your LBs stopped
  rotating.
- `suspicious` — fingerprint is NOT in inventory. Treat as a potential hijack
  until proven otherwise.

```json
{
  "fingerprint_sha1": "9414f0d3...",
  "severity":        "suspicious",
  "matched_entries": ["ethereum.org"],
  "matched_sans":    ["foo.ethereum.org"],
  "all_sans":        ["foo.ethereum.org", "bar.example.com"],
  "issuer_o":        "Google Trust Services",
  "issuer_cn":       "WE1",
  "not_before":      1761915088,
  "not_after":       1769694679,
  "lifetime_days":   90.0,
  "source_log":      "Google 'Argon2026h1' log",
  "cert_link":       "https://ct.googleapis.com/...",
  "serial":          "B759154194BBEA621172F2F81C1017CD",
  "update_type":     "PrecertLogEntry",
  "seen_at":         1761918776
}
```

A single fingerprint is delivered at most once per process lifetime (in-memory
LRU dedupe of the last 2048 fps), so the precert + final-cert pair that CT
publishes for one issuance produces one webhook event, not two.

Retry policy: 3 attempts with 1s/4s/16s backoff. On final failure the alert
row is left with `delivered=0` and the error is logged.

## Prometheus metrics

`GET /metrics` in the standard text-exposition format.

| Metric                                       | Type      | Labels                              |
| -------------------------------------------- | --------- | ----------------------------------- |
| `certwatch_ct_messages_total`                | counter   | `type` (certificate_update, …)      |
| `certwatch_alerts_total`                     | counter   | `severity` (info, suspicious)       |
| `certwatch_webhook_total`                    | counter   | `result` (success, failure)         |
| `certwatch_webhook_duration_seconds`         | histogram | —                                   |
| `certwatch_watch_entries`                    | gauge     | —                                   |
| `certwatch_last_ct_event_timestamp_seconds`  | gauge     | —                                   |
| `certwatch_ws_connected`                     | gauge     | — (0/1)                             |
| `certwatch_dedupe_cache_size`                | gauge     | —                                   |

Suggested alerts:

- `certwatch_ws_connected == 0 for 5m` → CT feed dead
- `time() - certwatch_last_ct_event_timestamp_seconds > 600` → CT feed dead
  (covers the case where WS is up but log is silent)
- `rate(certwatch_alerts_total{severity="info"}[1h]) == 0 for 24h` → no
  upstream-known certs flowing through CT; either nothing is renewing or detection is broken
- `increase(certwatch_alerts_total{severity="suspicious"}[5m]) > 0` → page
- `rate(certwatch_webhook_total{result="failure"}[5m]) > 0` → n8n down

## Docker

```bash
docker build -t certwatch .

docker run -d --name certwatch \
  -e POSTGRES_DSN=postgresql://user:pw@db.internal:5432/certwatch \
  -e CERTSTREAM_URL=ws://certstream.internal:8080/full-stream \
  -e WEBHOOK_URL=https://n8n.internal/webhook/cert-alerts \
  -p 8765:8765 \
  certwatch
```

The container runs as a non-root user. All state lives in Postgres — apply
`schema.sql` against the target DB once before first start. The image exposes
a Docker HEALTHCHECK against `/healthz`.

## End-to-end smoke test

```bash
# terminal 1 — fake certstream + fake webhook receiver
uv run python tests/e2e_harness.py

# terminal 2 — seed a watch entry in Postgres
psql "$POSTGRES_DSN" -c \
  "INSERT INTO public.intent_current (fqdn) VALUES ('ethereum.org') ON CONFLICT DO NOTHING;"

# terminal 3 — point certwatch at the harness
POSTGRES_DSN="$POSTGRES_DSN" \
  CERTSTREAM_URL=ws://127.0.0.1:19090 \
  WEBHOOK_URL=http://127.0.0.1:19091/hook \
  uv run -m certwatch
```

You'll see the harness print `WEBHOOK RX:` for the unauthorized cert and
nothing for the known/unwatched ones.

## Non-goals

- Web dashboard. Use Grafana over Postgres, or query the `alerts` table directly.
- Pulling directly from CT logs ([SSLMate Cert Spotter](https://github.com/SSLMate/certspotter) does that). certstream is fine as a low-latency signal but it does drop entries occasionally.
- HTTP-driven mutation. The service is a one-way pipe: read from Postgres, push to webhook. Domain and cert inventory are managed elsewhere.
- Replay of failed webhook deliveries. The DB keeps `delivered=false` rows; bolt on a sweep later if needed.
