-- Phase 1 migration 0005: attachments + backups
-- R2 objects are client-encrypted; no plaintext filename/keys/mime in any column.
CREATE TABLE attachments (
  attachment_id  TEXT PRIMARY KEY,
  sender_dev_id  TEXT NOT NULL REFERENCES devices(device_id),
  r2_key         TEXT NOT NULL UNIQUE,
  encrypted_size INTEGER NOT NULL CHECK (encrypted_size > 0),
  state          TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','ready')),
  server_recv_at INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX idx_att_expiry ON attachments(expires_at);

CREATE TABLE attachment_delivery (
  attachment_id TEXT NOT NULL REFERENCES attachments(attachment_id),
  device_id     TEXT NOT NULL REFERENCES devices(device_id),
  delivered_at  INTEGER,
  acked_at      INTEGER,
  PRIMARY KEY (attachment_id, device_id)
);
CREATE INDEX idx_att_delivery_device ON attachment_delivery(device_id);

CREATE TABLE backups (
  backup_id      TEXT PRIMARY KEY,
  account_id     TEXT NOT NULL REFERENCES accounts(account_id),
  r2_key         TEXT NOT NULL UNIQUE,
  encrypted_size INTEGER NOT NULL CHECK (encrypted_size > 0),
  backup_version INTEGER NOT NULL CHECK (backup_version > 0),
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX idx_backups_account ON backups(account_id, created_at);
