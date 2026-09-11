-- Phase 1 migration 0007: rate limiting + challenge authorizer
-- Fixed-window strict counters (the security-critical layer; the Workers Rate
-- Limiting binding is the soft outer layer, configured at deploy time).
CREATE TABLE rate_limits (
  bucket       TEXT NOT NULL,
  key          TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL,
  PRIMARY KEY (bucket, key)
);

-- add_device challenges are co-signed by an active device of the account;
-- the authorizer identity is stored server-side inside the challenge row.
ALTER TABLE auth_challenges ADD COLUMN authorizer_device_id TEXT REFERENCES devices(device_id);
