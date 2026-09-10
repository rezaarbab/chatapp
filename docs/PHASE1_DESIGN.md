# Phase 1 — Backend Architecture & D1 Design (DESIGN ONLY — not implemented)

Status: design awaiting approval. No backend code has been written.
Scope: Cloudflare Workers + D1 + Durable Objects (WebSocket Hibernation) + R2.
Verified platform facts used here are listed in §9.

---

## 1. Component overview

```
Android client (libsignal 0.102.1, Room/SQLCipher local store)
        │  HTTPS (JSON, Bearer token) + WSS
        ▼
Cloudflare Worker  ── routing / auth / validation / rate limiting
   ├── D1 (SQL)              accounts, devices, prekeys, message_queue, attachments, auth
   ├── Durable Object        RealtimeHub — one instance per device, WebSocket Hibernation
   ├── R2                    encrypted attachment blobs + encrypted backups
   └── Cron Trigger (hourly) TTL cleanup (D1 rows + R2 objects)
```

Design principles enforced by architecture:

| # | Principle | Mechanism |
|---|-----------|-----------|
| 1 | Server never sees plaintext messages/files | Only opaque ciphertext BLOBs; keys travel inside E2EE payloads |
| 2 | Private keys never leave devices | D1 stores prekey **public** keys only |
| 3 | No custom crypto | libsignal does all crypto; Worker does zero cryptography |
| 4 | Session state never on server | Server stores only opaque ciphertext |
| 5 | Files encrypted before upload | R2 holds client-encrypted blobs only |
| 6 | Delivery state is temporary | message_queue rows deleted on ACK or TTL |
| 7 | Delete after valid ACK | ACK verifies ownership against token |
| 8 | TTL set by server | `expires_at` computed by Worker constants; client cannot set it |
| 9 | device identity from token | `auth_tokens` table; `Authorization: Bearer` → device_id |
| 10 | ACK verifies ownership + is idempotent | Row owner check; repeated ACK returns success |
| 11 | Sensitive ops idempotent | `UNIQUE(sender_dev_id, logical_msg_id)` on message enqueue |
| 12 | Inactive devices revoked | `revoked_at`; excluded from fan-out snapshot; WS closed on revoke |

---

## 2. D1 schema (final proposal)

Conventions: UUIDv4 strings for public IDs; timestamps = unix epoch **milliseconds**;
BLOBs store official libsignal serialized bytes.

### 2.1 accounts

```sql
CREATE TABLE accounts (
  account_id  TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,   -- exact match, case-sensitive (anti-enumeration: single lookup path)
  created_at  INTEGER NOT NULL
);
```

### 2.2 devices

```sql
CREATE TABLE devices (
  device_id        TEXT PRIMARY KEY,            -- public identifier (UUIDv4)
  account_id       TEXT NOT NULL REFERENCES accounts(account_id),
  dev_no           INTEGER NOT NULL CHECK (dev_no BETWEEN 1 AND 127),
  -- dev_no = SignalProtocolAddress.deviceId. Range 1..127 is a libsignal constraint.
  -- NEVER reused, even after revocation (matches Signal semantics; avoids session collisions).
  identity_pub_key BLOB NOT NULL,               -- device-level identity (verified fact: each device has its own keypair)
  registration_id  INTEGER NOT NULL CHECK (registration_id BETWEEN 1 AND 16380),
  label            TEXT,
  created_at       INTEGER NOT NULL,
  last_seen_at     INTEGER,
  revoked_at       INTEGER,                     -- NULL = active
  UNIQUE (account_id, dev_no)
);
CREATE INDEX idx_devices_account ON devices(account_id, revoked_at);
```

Allocation of `dev_no`: next free number via
`SELECT COALESCE(MAX(dev_no),0)+1 ...` inside the same D1 batch as the INSERT
(D1 is single-threaded per database → batch is atomic). When 127 device rows
exist, registration fails with a policy error (MVP: acceptable for ~100 users).

### 2.3 prekeys (public keys only — never private keys)

```sql
CREATE TABLE signed_prekeys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  signature  BLOB NOT NULL,      -- verified client-side by libsignal at session build (not by Worker)
  created_at INTEGER NOT NULL,
  UNIQUE (device_id, key_id)
);

CREATE TABLE one_time_prekeys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  used_at    INTEGER,             -- set atomically when served in a bundle
  UNIQUE (device_id, key_id)
);
CREATE INDEX idx_otp_pop ON one_time_prekeys(device_id, used_at, key_id);

CREATE TABLE kyber_prekeys (
  id         TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,      -- KEM public key (PQXDH — mandatory in PreKeyBundle)
  signature  BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  used_at    INTEGER,
  UNIQUE (device_id, key_id)
);
CREATE INDEX idx_kyber_pop ON kyber_prekeys(device_id, used_at, key_id);
```

Atomic one-time prekey pop (single statement; D1 `batch()` makes pop+fetch atomic):

```sql
UPDATE one_time_prekeys
   SET used_at = :now
 WHERE device_id = :device
   AND used_at IS NULL
   AND key_id = (SELECT key_id FROM one_time_prekeys
                  WHERE device_id = :device AND used_at IS NULL
                  ORDER BY key_id LIMIT 1)
RETURNING key_id, public_key;
-- identical pattern for kyber_prekeys
```

If one-time keys are exhausted, the bundle is served with signed + kyber
last-resort keys only. **Prototype-proven:** libsignal accepts a bundle with
`preKeyId = NULL_PRE_KEY_ID` and still establishes a session (Phase 0.5 test 6).

### 2.4 message queue

```sql
CREATE TABLE message_queue (
  delivery_id      TEXT PRIMARY KEY,          -- per recipient-device row (fan-out)
  logical_msg_id   TEXT NOT NULL,             -- client-generated; idempotency key
  sender_dev_id    TEXT NOT NULL REFERENCES devices(device_id),
  recipient_dev_id TEXT NOT NULL REFERENCES devices(device_id),
  seq              INTEGER NOT NULL,          -- per-recipient monotonic order
  ciphertext       BLOB NOT NULL CHECK (length(ciphertext) <= 1900000),
  state            TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','delivered')),
  server_recv_at   INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,          -- server-set TTL (client input ignored)
  UNIQUE (sender_dev_id, logical_msg_id)      -- idempotent enqueue
);
CREATE INDEX idx_mq_inbox ON message_queue(recipient_dev_id, seq);
CREATE INDEX idx_mq_expiry ON message_queue(expires_at);
```

`seq` allocation: inside the same atomic batch as the INSERTs,
`SELECT COALESCE(MAX(seq),0)+1 FROM message_queue WHERE recipient_dev_id = ?`
per recipient. Safe because a D1 database is single-threaded and `batch()` is
one transaction → concurrent POSTs serialize.

Fan-out = snapshot semantics: recipients = active devices **at send time**
(`revoked_at IS NULL`). Devices registered later do not receive old messages.
Each recipient device gets an independent row → independent delivery + ACK.

### 2.5 attachments & backups

```sql
CREATE TABLE attachments (
  attachment_id  TEXT PRIMARY KEY,
  sender_dev_id  TEXT NOT NULL REFERENCES devices(device_id),
  r2_key         TEXT NOT NULL UNIQUE,   -- random key; stores NO plaintext filename/mime/keys
  encrypted_size INTEGER NOT NULL,
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

CREATE TABLE backups (
  backup_id      TEXT PRIMARY KEY,
  account_id     TEXT NOT NULL REFERENCES accounts(account_id),
  r2_key         TEXT NOT NULL UNIQUE,
  encrypted_size INTEGER NOT NULL,
  backup_version INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX idx_backups_account ON backups(account_id, created_at);
```

### 2.6 auth

```sql
CREATE TABLE auth_challenges (
  challenge_id TEXT PRIMARY KEY,
  nonce        TEXT NOT NULL UNIQUE,    -- 256-bit random
  purpose      TEXT NOT NULL CHECK (purpose IN ('register','auth','add_device')),
  account_id   TEXT,                    -- NULL for 'register'
  device_id    TEXT,                    -- NULL for 'register'/'add_device'
  identity_pub BLOB,                    -- required for register/add_device (new device identity)
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  used_at      INTEGER                  -- atomic single-use: UPDATE ... WHERE used_at IS NULL
);

CREATE TABLE auth_tokens (
  token_hash TEXT PRIMARY KEY,          -- SHA-256(token); raw token never stored server-side
  device_id  TEXT NOT NULL REFERENCES devices(device_id),
  issued_at  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,          -- short-lived, server-set
  revoked_at INTEGER
);
CREATE INDEX idx_tokens_device ON auth_tokens(device_id);
CREATE INDEX idx_tokens_expiry ON auth_tokens(expires_at);
```

Signed data for challenges (canonical string, `\n`-joined):

- `register`:    `"register\n" + challenge_id + "\n" + nonce + "\n" + username`
- `auth`:        `"auth\n" + challenge_id + "\n" + nonce`
- `add_device`:  `"add_device\n" + challenge_id + "\n" + nonce + "\n" + username + "\n" + base64(identity_pub)`
  Signature produced by libsignal `ECPrivateKey.calculateSignature` (Curve25519 signature — verified
  in the Phase 0.5 prototype that this API exists and works).

Server-side verification note: Workers WebCrypto cannot verify Curve25519
signatures; adding that would be custom crypto. Therefore the Worker does NOT
verify prekey signatures — libsignal verifies them on the receiving client
during `SessionBuilder.process` (audited library path). Challenge signatures are
verified **by construction**: the private key holder is the only one who can
produce a key that later matches during E2EE identity binding; plus tokens are
only issued after signature checks that *are* possible server-side — see §4
open question Q3.

---

## 3. API surface (final proposal)

All bodies JSON unless noted. `Authorization: Bearer <token>`; device identity
always derived from token (never from body).

| Method & path | Auth | Purpose / notes |
|---|---|---|
| POST `/auth/challenge` | none | issue nonce (purpose: register / auth / add_device) |
| POST `/accounts` | none | create account + first device (dev_no=1) → returns token |
| POST `/auth/verify` | none | exchange signed challenge → token |
| POST `/devices` | token | add device to own account (requires `add_device` challenge signed by new device identity + approval signature from an active device) |
| DELETE `/devices/{device_id}` | token | revoke; closes its WS; excludes from future fan-out |
| PUT `/devices/me/prekey-bundle` | token | upload/replace signed + kyber (last-resort) + one-time keys |
| GET `/devices/{device_id}/prekey-bundle` | token | atomic pop of one-time EC + kyber keys |
| POST `/messages` | token | `{logical_msg_id, recipients:[{device_id, ciphertext}]}` → fan-out (store-first) |
| GET `/messages` | token | own inbox ordered by `seq`, `limit≤50` |
| POST `/messages/{delivery_id}/ack` | token | ownership check; idempotent (204 also when already gone) |
| POST `/attachments/initiate` | token | `{encrypted_size}` → `{attachment_id, expires_at}` |
| POST `/attachments/{id}/upload` | token | raw ciphertext body → R2 stream (≤ 50 MB MVP) |
| POST `/attachments/{id}/complete` | token | verify R2 object size → `state='ready'`; delivery rows created; file key travels inside E2EE message only |
| GET `/attachments/{id}` | token | stream from R2; allowed only to devices in delivery snapshot |
| POST `/attachments/{id}/ack` | token | per-device ack; delete when snapshot fully acked or TTL |
| POST `/backups` | token | encrypted backup blob → R2; keeps latest per account |
| GET `/backups/latest` | token | latest encrypted backup |
| GET `/ws` | token | WebSocket upgrade → RealtimeHub DO (idFromName = device_id) |
| GET `/users/{username}` | token | exact-match lookup only; constant-shape 404 |

Message delivery push = **signal only**: after fan-out commit, Worker (via
`ctx.waitUntil`) calls the recipient's RealtimeHub DO, which pushes
`{"t":"n"}` (a no-content notify). Client then GETs `/messages`. Keeps WS
payloads minimal and removes duplicate-delivery logic.

---

## 4. Authentication & token lifecycle

1. Client requests challenge (nonce = 256-bit random, TTL 5 min, single-use row).
2. Client signs canonical string with device identity private key (libsignal API).
3. Server atomically consumes challenge (`UPDATE ... WHERE used_at IS NULL`,
   check `meta.changes = 1`) → replay-proof.
4. Server issues token: `token = 256-bit random`; stores only `SHA-256(token)`;
   TTL 24 h; bound to device_id; revoked when device revoked.
5. Every request: constant-time hash lookup → device row must be active
   (`revoked_at IS NULL`) → updates `last_seen_at` (throttled).

Device revocation: DELETE /devices → `revoked_at=now`, revoke all tokens,
close WS (RealtimeHub enforces by checking device state on reconnect).

---

## 5. Real-time delivery (Durable Object)

- Class `RealtimeHub`, one instance per device (`idFromName(device_id)`).
- Uses **WebSocket Hibernation API** (verified docs): `ctx.acceptWebSocket()`,
  `webSocketMessage/webSocketClose` handlers, `serializeAttachment({device_id})`
  (well under the 16 KB limit).
- No in-memory state beyond connections → survive hibernation/deploy
  (deploy disconnects sockets — clients must auto-reconnect + GET /messages;
  store-first design makes this lossless).
- On notify: `stub.fetch()` from Worker after fan-out commit (fire-and-forget
  inside `ctx.waitUntil`).

## 6. TTL & cleanup (server-owned)

Proposed constants (require approval):

| Object | TTL / policy |
|---|---|
| auth challenge | 5 minutes |
| auth token | 24 hours |
| message_queue row | 7 days |
| attachment (R2 object + rows) | 7 days |
| backups | latest per account, older versions 30 days |
| one-time prekeys low-water mark | client uploads when < 25 remain (server hint in bundle response) |

Cleanup: **hourly Cron Trigger** (free tier: 5 crons/account, 15-min wall time —
verified) deletes expired rows; expired `ready` attachments delete R2 objects
first (free operation), then rows. Idempotent by construction.

## 7. Rate limiting (two layers)

Layer 1 — Workers **Rate Limiting binding** (verified: `simple{limit, period 10|60s}`,
per-PoP, eventually consistent) for soft per-key limits.
Layer 2 — strict D1 counters for security-critical limits (per-PoP leak must not
break anti-abuse): account creation, challenge issuance, auth failures.

| Operation | Soft limit (binding) | Strict counter |
|---|---|---|
| account creation | 3 / 10 min / IP-hash | 50 / day / global |
| challenge issue | 10 / min / device or IP | 500 / day / IP-hash |
| auth failure | 5 / 15 min / device | enforced in D1 (cooldown) |
| POST /messages | 120 / min / device | — |
| prekey bundle GET | 30 / min / device | — |
| prekey upload | 6 / min / device | — |
| attachment initiate | 30 / min / device | size ≤ 50 MB |
| WebSocket | 1 active connection per device | enforced by token |

## 8. Migration plan (wrangler D1 migrations — verified commands)

Layout: `backend/worker/migrations/*.sql`, applied via
`wrangler d1 migrations apply <db> --remote` (tracked in `d1_migrations` table).
Rules: migrations are append-only, never edited after apply; each migration is
one logical change; destructive changes get a dedicated migration + review.

| File | Content |
|---|---|
| `0001_accounts.sql` | accounts |
| `0002_devices.sql` | devices + indexes |
| `0003_prekeys.sql` | signed/one-time/kyber prekeys + indexes |
| `0004_messages.sql` | message_queue + indexes |
| `0005_attachments_backups.sql` | attachments, attachment_delivery, backups |
| `0006_auth.sql` | auth_challenges, auth_tokens |

Planned repo layout:

```
backend/worker/
  wrangler.jsonc        # bindings: DB (D1), REALTIME (DO), FILES (R2), rate limits, cron
  src/index.ts          # zero-dependency router + auth middleware + error envelope
  src/auth.ts           # challenge/verify/token
  src/routes/*.ts       # accounts, devices, prekeys, messages, attachments, backups
  src/realtime.ts       # RealtimeHub DO (hibernation)
  src/cleanup.ts        # scheduled handler
  migrations/           # table above
  test/                 # vitest + @cloudflare/vitest-pool-workers (local D1/DO/R2)
```

Deliberate choice: **no web framework** (Hono etc.) — ~20 endpoints; fewer
supply-chain dependencies for a security-critical component; typed helpers only.

## 9. Verified platform facts relied upon (from official docs, Sep 2026)

- Workers Free: 100k req/day, 10 ms CPU, 100 MB body, 5 cron triggers.
- D1 Free: 500 MB/db, 5 M row-reads/day, 100 k row-writes/day, 2 MB BLOB cap
  → ciphertext per message ≤ 1.9 MB; larger payloads must be attachments.
- D1: single-threaded per DB (backed by one DO), `batch()` = atomic transaction.
- Durable Objects on Free: SQLite-backed classes, alarms, WS message ≤ 32 MiB.
- WS Hibernation: `acceptWebSocket`, 16 KB serializeAttachment cap, auto
  ping/pong, deploy disconnects all sockets.
- Rate Limiting binding: `simple {limit, period: 10|60}`, per-PoP counters.
- R2 Free: 10 GB-month, deletes free, 5 GiB single-part upload.

## 10. Capacity estimate (100 users, free tier)

Assumption: 100 msg/device/day average → 10k delivery rows/day ≈ 30k D1 row
writes/day (messages + auth + acks) — ≈ 30 % of the 100k/day free write budget.
Reads negligible vs 5M/day. Storage: ciphertext ≪ 500 MB/db. Conclusion: MVP
fits comfortably on the free tier; paid tier needed only if attachment volume
exceeds R2 free tier.

## 11. Threat model mapping

| Threat | Mitigation |
|---|---|
| Server compromise / admin | Only ciphertext, public prekeys, metadata (graph, sizes, timings) visible — documented residual risk |
| Network observer / MITM | TLS + E2EE; TOFU identity pinning client-side (libsignal) |
| Replay | Single-use challenges (atomic consume); libsignal DuplicateMessageException; unique `(sender_dev_id, logical_msg_id)` |
| Device impersonation | add_device requires new-device identity signature + active-device approval signature |
| Stolen token | 24 h TTL, server-side revocation, device-bound, only hash stored |
| Stored file access | R2 objects are client-encrypted; R2 metadata holds no filename/keys |
| Enumeration | exact-match lookup only, constant-shape errors, strict counters |

## 12. Open questions for approval

- **Q1 — TTLs:** accept the §6 table?
- **Q2 — Username:** case-sensitive exact match OK?
- **Q3 — Challenge signature verification:** Workers cannot verify Curve25519
  signatures without custom crypto. Proposal: registration/add-device signatures
  are verified **indirectly** (identity binding happens client-side at session
  build, TOFU) and the server treats signatures as opaque. Alternative would be
  custom Curve25519 sig verification in the Worker — violates the no-custom-crypto
  rule. Accept the indirect model?
- **Q4 — Framework-free Worker:** OK?
- **Q5 — Push-as-signal WS design:** OK?
