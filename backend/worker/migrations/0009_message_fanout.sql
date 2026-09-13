-- Phase 3 migration 0009: fan-out-capable message_queue + device_seq counters.
--
-- Declared incompatibility fix (PHASE3_MESSAGING_DESIGN.md Appendix B #1): the
-- 0004 constraint UNIQUE (sender_dev_id, logical_msg_id) makes fan-out
-- impossible — one logical message must produce ONE ROW PER RECIPIENT DEVICE
-- sharing the same logical_msg_id. The table is rebuilt with the per-target
-- idempotency key; data is preserved.
--
-- device_seq (Appendix B #2): seq must be a monotonic, NEVER-reused per-device
-- counter. MAX(seq)-based allocation would reuse numbers after the queue head
-- is ACKed (rows are deleted). Backfill computes MAX(seq)+1 per device so any
-- pre-existing row's seq can never be reallocated.
CREATE TABLE message_queue_new (
  delivery_id      TEXT PRIMARY KEY,
  logical_msg_id   TEXT NOT NULL,
  sender_dev_id    TEXT NOT NULL REFERENCES devices(device_id),
  recipient_dev_id TEXT NOT NULL REFERENCES devices(device_id),
  seq              INTEGER NOT NULL CHECK (seq > 0),
  ciphertext       BLOB NOT NULL CHECK (length(ciphertext) <= 1900000),
  state            TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','delivered')),
  server_recv_at   INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  UNIQUE (sender_dev_id, recipient_dev_id, logical_msg_id),
  UNIQUE (recipient_dev_id, seq)
);
INSERT INTO message_queue_new SELECT * FROM message_queue;
DROP TABLE message_queue;
ALTER TABLE message_queue_new RENAME TO message_queue;
CREATE INDEX idx_mq_inbox ON message_queue(recipient_dev_id, seq);
CREATE INDEX idx_mq_expiry ON message_queue(expires_at);

CREATE TABLE device_seq (
  device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
  next_seq  INTEGER NOT NULL CHECK (next_seq > 0)
);
INSERT INTO device_seq (device_id, next_seq)
SELECT d.device_id,
       COALESCE(
         (SELECT MAX(m.seq) + 1 FROM message_queue m WHERE m.recipient_dev_id = d.device_id),
         1
       )
FROM devices d;
