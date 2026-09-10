-- Phase 1 migration 0003: prekeys (public keys only; private keys never leave devices)
CREATE TABLE signed_prekeys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  signature  BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (device_id, key_id)
);
CREATE INDEX idx_signed_prekeys_device_time ON signed_prekeys(device_id, created_at);

CREATE TABLE one_time_prekeys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  used_at    INTEGER,
  UNIQUE (device_id, key_id)
);
-- Partial index: serves the atomic single-use pop query (used_at IS NULL only).
CREATE INDEX idx_otp_pop ON one_time_prekeys(device_id, key_id) WHERE used_at IS NULL;

CREATE TABLE kyber_prekeys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  signature  BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  used_at    INTEGER,
  UNIQUE (device_id, key_id)
);
CREATE INDEX idx_kyber_pop ON kyber_prekeys(device_id, key_id) WHERE used_at IS NULL;
