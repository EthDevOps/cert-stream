-- certwatch Postgres schema.
--
-- Apply once against the target database:
--   psql "$POSTGRES_DSN" -f schema.sql
--
-- public.intent_current is owned by the upstream system and is assumed to
-- exist already; certwatch only reads `fqdn` from it.

CREATE TABLE IF NOT EXISTS public.certs (
  fingerprint_sha1 TEXT PRIMARY KEY,
  serial           TEXT,
  sans             JSONB NOT NULL,
  not_before       BIGINT NOT NULL,
  not_after        BIGINT NOT NULL,
  source           TEXT,
  added_at         BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS certs_not_after ON public.certs(not_after);

CREATE TABLE IF NOT EXISTS public.alerts (
  id          BIGSERIAL PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  sans        JSONB NOT NULL,
  matched     JSONB NOT NULL,
  issuer      TEXT,
  seen_at     BIGINT NOT NULL,
  delivered   BOOLEAN NOT NULL DEFAULT FALSE,
  severity    TEXT NOT NULL DEFAULT 'suspicious'
);
CREATE INDEX IF NOT EXISTS alerts_seen_at ON public.alerts(seen_at);
