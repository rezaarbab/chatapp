-- Phase 1 migration 0006: authentication (Device Authentication Key model, design doc section 13)
-- Challenges carry their full verification context; consumed atomically via used_at.
-- Tokens are stored as SHA-256(token) only; the raw token never touches the database.
CREATE TABLE auth_challenges (
  challenge_id TEXT PRIMARY KEY,
  nonce        TEXT NOT NULL UNIQUE,
  purpose      TEXT NOT NULL CHECK (purpose IN ('register','auth','add_device')),
  account_id   TEXT REFERENCES accounts(account_id),
  device_id    TEXT REFERENCES devices(device_id),
  username     TEXT,
  identity_pub TEXT,
  auth_pub     TEXT,
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  used_at      INTEGER,
  CHECK (expires_at > issued_at),
  CHECK (used_at IS NULL OR used_at >= issued_at)
);
CREATE INDEX idx_challenges_expiry ON auth_challenges(expires_at);

CREATE TABLE auth_tokens (
  token_hash TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  issued_at  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (expires_at > issued_at)
);
CREATE INDEX idx_tokens_device ON auth_tokens(device_id);
CREATE INDEX idx_tokens_expiry ON auth_tokens(expires_at);
