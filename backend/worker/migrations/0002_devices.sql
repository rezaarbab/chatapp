-- Phase 1 migration 0002: devices
-- dev_no = SignalProtocolAddress.deviceId, range 1..127 (libsignal constraint).
-- dev_no is NEVER reused, even after revocation (matches Signal semantics).
-- identity_pub_key = libsignal identity (E2EE only).
-- auth_pub_key = Device Authentication key (server auth only, Ed25519 raw 32 bytes).
CREATE TABLE devices (
  device_id        TEXT PRIMARY KEY,
  account_id       TEXT NOT NULL REFERENCES accounts(account_id),
  dev_no           INTEGER NOT NULL CHECK (dev_no BETWEEN 1 AND 127),
  identity_pub_key BLOB NOT NULL,
  auth_pub_key     BLOB NOT NULL,
  auth_key_alg     TEXT NOT NULL DEFAULT 'Ed25519' CHECK (auth_key_alg = 'Ed25519'),
  registration_id  INTEGER NOT NULL CHECK (registration_id BETWEEN 1 AND 16380),
  label            TEXT,
  created_at       INTEGER NOT NULL,
  last_seen_at     INTEGER,
  revoked_at       INTEGER,
  UNIQUE (account_id, dev_no)
);
CREATE INDEX idx_devices_account ON devices(account_id, revoked_at);
