-- Phase 2 migration 0008: mandatory last-resort Kyber prekey.
-- libsignal 0.102.1 cannot construct a PreKeyBundle without a Kyber prekey
-- (verified empirically; see PHASE2_PREKEY_DESIGN.md V2), so a device must
-- always have one servable Kyber key: one-time Kyber prekeys are preferred,
-- and the last-resort row is served (never consumed) when stock is exhausted.
ALTER TABLE kyber_prekeys
  ADD COLUMN is_last_resort INTEGER NOT NULL DEFAULT 0 CHECK (is_last_resort IN (0,1));

-- Exactly one last-resort row per device.
CREATE UNIQUE INDEX idx_kyber_last_resort ON kyber_prekeys(device_id) WHERE is_last_resort = 1;

-- Pop index restricted to one-time (non-last-resort) unused keys.
CREATE INDEX idx_kyber_pop_one_time ON kyber_prekeys(device_id, key_id)
  WHERE is_last_resort = 0 AND used_at IS NULL;
