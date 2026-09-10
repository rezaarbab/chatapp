-- Phase 1 migration 0001: accounts
-- Username lookup is case-sensitive exact match (anti-enumeration: single lookup path).
CREATE TABLE accounts (
  account_id  TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL
);
