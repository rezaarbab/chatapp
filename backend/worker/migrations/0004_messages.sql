-- Phase 1 migration 0004: message queue (delivery state is temporary; deleted on ACK or TTL)
-- D1 BLOB cap is 2 MB; ciphertext is capped at ~1.9 MB. Larger payloads must be attachments.
CREATE TABLE message_queue (
  delivery_id      TEXT PRIMARY KEY,
  logical_msg_id   TEXT NOT NULL,
  sender_dev_id    TEXT NOT NULL REFERENCES devices(device_id),
  recipient_dev_id TEXT NOT NULL REFERENCES devices(device_id),
  seq              INTEGER NOT NULL CHECK (seq > 0),
  ciphertext       BLOB NOT NULL CHECK (length(ciphertext) <= 1900000),
  state            TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','delivered')),
  server_recv_at   INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  UNIQUE (sender_dev_id, logical_msg_id),
  UNIQUE (recipient_dev_id, seq)
);
CREATE INDEX idx_mq_inbox ON message_queue(recipient_dev_id, seq);
CREATE INDEX idx_mq_expiry ON message_queue(expires_at);
