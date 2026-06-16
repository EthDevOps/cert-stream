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
              │ │                                ▼
              │ │                        ┌──────────────┐
              │ └────────── SQLite ──────┤   alerts     │
              ▼                          └──────────────┘
       ┌──────────────┐
       │  HTTP API    │ ◄── LB deploy-hook pushes (sha1, sans, validity)
       └──────────────┘ ◄── operators add/remove watch domains
```

A single asyncio process runs three concurrent tasks:

1. **watcher** — consumes a [certstream-server](https://github.com/CaliDog/certstream-server) WS feed and matches each cert's SANs against the watch list
2. **api** — FastAPI app for LBs and operators
3. **cleanup** — prunes expired fingerprints and old alerts

State lives in a single SQLite file.

## Quick start

```bash
uv sync --extra test
uv run pytest                            # unit tests
API_TOKEN=changeme uv run -m certwatch   # run it
```

The service binds `127.0.0.1:8765` by default. Health check:

```bash
curl -H 'Authorization: Bearer changeme' http://127.0.0.1:8765/healthz
```

## Configuration (ENV)

| Var                  | Default                              | Notes                                                       |
| -------------------- | ------------------------------------ | ----------------------------------------------------------- |
| `API_TOKEN`          | *(required)*                         | Static bearer token for every API route                     |
| `CERTSTREAM_URL`     | `ws://localhost:8080/full-stream`    | Upstream certstream-server                                  |
| `DB_PATH`            | `./certwatch.db`                     | SQLite file                                                 |
| `API_HOST`           | `127.0.0.1`                          | Bind addr                                                   |
| `API_PORT`           | `8765`                               | Bind port                                                   |
| `WEBHOOK_URL`        | *(unset → observer mode, log only)*  | POST destination for alerts (your n8n endpoint)             |
| `WEBHOOK_TIMEOUT_S`  | `10`                                 | Per-attempt timeout                                         |
| `CLEANUP_INTERVAL_S` | `3600`                               | How often to prune                                          |
| `CLEANUP_GRACE_S`    | `86400`                              | Keep expired certs this long past `not_after`               |
| `ALERT_RETENTION_S`  | `2592000`                            | Keep alerts 30 days                                         |
| `LOG_LEVEL`          | `INFO`                               | stdlib logging level                                        |

## API

All routes require `Authorization: Bearer <API_TOKEN>`.

### Watch domains

```bash
# add an entry — covers the apex and every subdomain (any depth)
curl -H 'Authorization: Bearer t' -H 'Content-Type: application/json' \
  -d '{"value":"ethereum.org","note":"prod"}' \
  http://127.0.0.1:8765/domains

curl -H 'Authorization: Bearer t' http://127.0.0.1:8765/domains
curl -X DELETE -H 'Authorization: Bearer t' http://127.0.0.1:8765/domains/foo.example.com
```

Match semantics: an entry `example.org` matches `example.org` and any
subdomain (`foo.example.org`, `a.b.example.org`, …). A leading `*.` in the
entry is stripped on input. SANs with a leading wildcard (`*.X`) match when
their expansions overlap an entry's subtree.

### Known-good certs (LB inventory)

```bash
curl -H 'Authorization: Bearer t' -H 'Content-Type: application/json' \
  -d '{
    "fingerprint": "AA:BB:CC:...",        # any case, colons optional
    "sans": ["foo.ethereum.org"],
    "not_before": 1761915088,
    "not_after":  1762519888,
    "serial":     "B7591541...",
    "source":     "lb:colo-lb-0"
  }' \
  http://127.0.0.1:8765/certs

curl -H 'Authorization: Bearer t' http://127.0.0.1:8765/certs
curl -X DELETE -H 'Authorization: Bearer t' http://127.0.0.1:8765/certs/<sha1>
```

Upserts on fingerprint (SHA-1, lowercase-hex). Idempotent — safe to re-POST.

For certs your LBs don't manage (e.g. Netlify-issued for some properties),
push them through this same endpoint with `source: "manual:netlify"` or
similar. Anything in the table suppresses the alert.

### Alerts (read-only)

```bash
curl -H 'Authorization: Bearer t' 'http://127.0.0.1:8765/alerts?since=1761900000&limit=50'
```

## LB hook (certbot)

Drop this on every LB at `/etc/letsencrypt/renewal-hooks/deploy/10-certwatch.sh`,
`chmod +x`. Certbot fires it after every successful renewal:

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${CERTWATCH_URL:?must be set}"   # e.g. http://certwatch.internal:8765
: "${CERTWATCH_TOKEN:?must be set}"

CERT="$RENEWED_LINEAGE/cert.pem"

FP=$(openssl x509 -in "$CERT" -noout -fingerprint -sha1 \
     | cut -d= -f2 | tr -d ':' | tr A-F a-f)
SERIAL=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2 | tr A-F a-f)
NB=$(date -u -d "$(openssl x509 -in "$CERT" -noout -startdate | cut -d= -f2)" +%s)
NA=$(date -u -d "$(openssl x509 -in "$CERT" -noout -enddate   | cut -d= -f2)" +%s)
SANS_JSON=$(openssl x509 -in "$CERT" -noout -ext subjectAltName \
            | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' \
            | jq -R . | jq -s -c .)

curl -fsS -X POST "$CERTWATCH_URL/certs" \
  -H "Authorization: Bearer $CERTWATCH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"fingerprint\": \"$FP\",
    \"serial\":      \"$SERIAL\",
    \"sans\":        $SANS_JSON,
    \"not_before\":  $NB,
    \"not_after\":   $NA,
    \"source\":      \"lb:$(hostname)\"
  }"
```

Bulk catch-up (run once per LB to seed the inventory with currently-deployed
certs without waiting for the next renewal cycle):

```bash
for live in /etc/letsencrypt/live/*/cert.pem; do
  RENEWED_LINEAGE="$(dirname "$live")" /etc/letsencrypt/renewal-hooks/deploy/10-certwatch.sh
done
```

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

Anonymous scrape at `GET /metrics` in the standard text-exposition format.

| Metric                                       | Type      | Labels                              |
| -------------------------------------------- | --------- | ----------------------------------- |
| `certwatch_ct_messages_total`                | counter   | `type` (certificate_update, …)      |
| `certwatch_alerts_total`                     | counter   | `severity` (info, suspicious)       |
| `certwatch_webhook_total`                    | counter   | `result` (success, failure)         |
| `certwatch_webhook_duration_seconds`         | histogram | —                                   |
| `certwatch_known_fingerprints`               | gauge     | —                                   |
| `certwatch_watch_entries`                    | gauge     | —                                   |
| `certwatch_last_ct_event_timestamp_seconds`  | gauge     | —                                   |
| `certwatch_ws_connected`                     | gauge     | — (0/1)                             |
| `certwatch_dedupe_cache_size`                | gauge     | —                                   |

Suggested alerts:

- `certwatch_ws_connected == 0 for 5m` → CT feed dead
- `time() - certwatch_last_ct_event_timestamp_seconds > 600` → CT feed dead
  (covers the case where WS is up but log is silent)
- `rate(certwatch_alerts_total{severity="info"}[1h]) == 0 for 24h` → no LB
  certs flowing through CT; either nothing is renewing or detection is broken
- `increase(certwatch_alerts_total{severity="suspicious"}[5m]) > 0` → page
- `rate(certwatch_webhook_total{result="failure"}[5m]) > 0` → n8n down

## Docker

```bash
docker build -t certwatch .

docker run -d --name certwatch \
  -e API_TOKEN=changeme \
  -e CERTSTREAM_URL=ws://certstream.internal:8080/full-stream \
  -e WEBHOOK_URL=https://n8n.internal/webhook/cert-alerts \
  -v certwatch-data:/data \
  -p 8765:8765 \
  certwatch
```

The container runs as a non-root user, persists state in the `/data` volume
(`DB_PATH=/data/certwatch.db` by default), and exposes a Docker HEALTHCHECK
against `/healthz`.

## End-to-end smoke test

```bash
# terminal 1 — fake certstream + fake webhook receiver
uv run python tests/e2e_harness.py

# terminal 2 — point certwatch at the harness
API_TOKEN=t DB_PATH=/tmp/certwatch.db \
  CERTSTREAM_URL=ws://127.0.0.1:19090 \
  WEBHOOK_URL=http://127.0.0.1:19091/hook \
  uv run -m certwatch

# terminal 3 — seed a watch entry
curl -H 'Authorization: Bearer t' -H 'Content-Type: application/json' \
  -d '{"value":"ethereum.org"}' http://127.0.0.1:8765/domains
```

You'll see the harness print `WEBHOOK RX:` for the unauthorized cert and
nothing for the known/unwatched ones.

## Non-goals

- Web dashboard. Use Grafana over the SQLite file or look at `/alerts`.
- Pulling directly from CT logs ([SSLMate Cert Spotter](https://github.com/SSLMate/certspotter) does that). certstream is fine as a low-latency signal but it does drop entries occasionally.
- Per-LB credentials. Single shared bearer is enough for an internal service.
- Replay of failed webhook deliveries. The DB keeps `delivered=0` rows; bolt on a sweep later if needed.
