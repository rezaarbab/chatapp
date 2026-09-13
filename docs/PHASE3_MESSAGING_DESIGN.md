# Phase 3 Design: Messaging & Message Delivery (E2EE, queue-based)

Status: **APPROVED and IMPLEMENTED (2026-09-13).** Implementation record:
`migrations/0009_message_fanout.sql`, `src/messages.ts`, routes
`GET /accounts/:id/devices`, `POST /messages`, `GET /messages`,
`POST /messages/ack`, revoke integration in `src/devices.ts`, tests
`test/messages.spec.ts` (15) + staging smoke Phase-3 section (lifecycle + two
REAL-D1 concurrency races). Newly discovered during implementation and
declared: Appendix B #9/#10/#11.

Every libsignal behavior this design relies on was verified empirically against
the real `libsignal-client 0.102.1` (same Rust/ffi core as
`libsignal-android:0.102.1`) via a scratch JVM program (Appendix A, 8/8 PASS),
on top of the already-verified Phase 2 facts (PHASE2_PREKEY_DESIGN.md).

---

## 0. Scope

**In scope (this phase):**
- 1:1 E2EE messaging between registered devices, per-device sessions (PQXDH from Phase 2)
- Server-side delivery queue (D1) with per-recipient-device monotonic seq
- Fan-out of one logical message to all active target devices
- Fetch (polling) + ACK + TTL expiry + crash-safe redelivery
- Idempotent send (logical_msg_id), rate limits, queue caps
- Interplay with device revocation
- New endpoint to list a target account's active devices (needed for fan-out)

**Explicitly OUT of scope (declared, later phases unless the user says otherwise):**
- WebSocket / realtime delivery / long-polling — this phase is **polling only**
- Push notifications
- Attachment upload/download flow and backups flow (tables 0005 exist; endpoints come later; this phase only defines the ciphertext size limit that pushes large payloads to attachments)
- Group messaging / sender-key sessions (SenderKeyStore is stubbed)
- Read receipts / typing indicators / delivery reports beyond the internal ACK
- Server-side anything-plaintext (never exists anywhere in this design)
- Retroactive delivery to devices added AFTER a message was sent

---

## 1. E2EE model — what the server sees

- The sender encrypts **separately per recipient device** with that device's
  session (`SessionCipher` bound to `SignalProtocolAddress(account_id, dev_no)`).
  Verified: the same plaintext to two devices yields two completely different
  ciphertexts (Gate3-B); there is no shared/group ciphertext in this phase.
- The server stores and forwards **opaque blobs**. It performs no decryption,
  no signature verification of message payloads, no content inspection.
- Plaintext content (including client metadata like `sent_at`) lives ONLY
  inside the ciphertext; its envelope format is a client-side convention
  (client phase), NOT a server contract.
- Server-visible metadata (complete list, point 10 of the mandate):
  | Field | Why the server needs it |
  |---|---|
  | sender account_id + device_id (+dev_no) | token authentication, routing, abuse control |
  | recipient account/device ids | routing (client supplies device list; server validates) |
  | logical_msg_id (random UUID) | idempotency key — carries no content |
  | seq (server-assigned integer) | per-device ordering |
  | ciphertext length | enforcement of size cap only |
  | server_recv_at / expires_at | TTL management |
- Logging: correlation IDs and statuses only; ciphertext is never logged.

## 2. Send flow (one device → one or many devices)

1. Sender obtains the recipient's active device list:
   `GET /accounts/:account_id/devices` (new endpoint; no keys in response).
2. For each target device: ensure a session exists (Phase 2 bundle flow),
   then `SessionCipher.encrypt(plaintext)` → per-device ciphertext.
   Note (verified Gate3-A): while a session has an unacknowledged prekey
   message, subsequent sends remain PREKEY-type ciphertexts (larger); after the
   receiver replies, ciphertexts become WHISPER (small). Both are opaque to the
   server and both flow through the same endpoint.
3. Sender also includes its OWN other devices as targets when the app wants
   device sync (server treats them like any target — no special casing).
4. `POST /messages` with `{ logical_msg_id, targets: [{device_id, ciphertext_b64}] }`.
5. Server fans out: one `message_queue` row per target, seq assigned per
   recipient device, all in atomic D1 batch(es) — see §4/§6.

## 3. Multi-device & fan-out

- Fan-out is N distinct ciphertexts for N devices (verified necessity, Gate3-B).
- Target cap: **≤ 127 targets per POST** (device space is 1..127 anyway) →
  `413 TOO_MANY_TARGETS`.
- Devices added later receive only later messages (no retroactive delivery).
- A NEW sender device works without receiver reconfiguration — verified
  (Gate3-E/F): the receiver keeps separate sessions per
  `(sender account_id, sender dev_no)`.

## 4. message_queue lifecycle (migration 0009 — REQUIRED schema fix)

**Discovered incompatibility (declared before implementation, same as the CAS
find in Phase 2):** the Phase 1.1 table (0004) has
`UNIQUE (sender_dev_id, logical_msg_id)`, which makes fan-out impossible — one
logical message must produce ONE ROW PER RECIPIENT DEVICE sharing the same
logical_msg_id. Migration 0009 rebuilds the table:

```sql
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
  UNIQUE (sender_dev_id, recipient_dev_id, logical_msg_id),  -- idempotency per (logical msg, target)
  UNIQUE (recipient_dev_id, seq)                             -- strict per-device ordering
);
INSERT INTO message_queue_new SELECT * FROM message_queue;   -- preserve data
DROP TABLE message_queue;
ALTER TABLE message_queue_new RENAME TO message_queue;
CREATE INDEX idx_mq_inbox  ON message_queue(recipient_dev_id, seq);
CREATE INDEX idx_mq_expiry ON message_queue(expires_at);

-- Monotonic per-device sequence counter (never reused, see §6):
CREATE TABLE device_seq (
  device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
  next_seq  INTEGER NOT NULL CHECK (next_seq > 0)
);
INSERT INTO device_seq SELECT device_id, 1 FROM devices;      -- backfill
```

Lifecycle: `queued` → (GET marks) `delivered` → (ACK) row DELETED.
`expires_at = server_recv_at + 7 days`; expired rows are excluded from fetches
and opportunistically purged with a bounded
`DELETE ... WHERE delivery_id IN (SELECT ... WHERE expires_at < ? LIMIT 100)`
inside the fetch path. Queue rows for a device are purged when the device is
revoked (extends the Phase 2 revoke batch).

## 5. logical_msg_id & idempotency

- Sender generates a random UUID per logical message (per send action).
- Uniqueness: `UNIQUE(sender_dev_id, recipient_dev_id, logical_msg_id)`.
- Retry of the same POST (same logical_msg_id): already-stored
  (target, logical) pairs are detected BEFORE the batch (pre-read) and reported
  as `"duplicate"` in the per-target results — never stored twice, never
  double-counted for seq/caps. A crashed sender resumes by re-POSTing the same
  logical_msg_id; only missing targets get queued.
- logical_msg_id is never reused across different logical messages; the server
  does not parse or interpret it.

## 6. Ordering: per-recipient-device seq without races

- seq is **server-assigned** from the `device_seq` counter — NOT derived from
  `MAX(seq)` of surviving rows (ACK deletes rows, so MAX-based allocation would
  reuse numbers after the head of the queue was ACKed — a real client-visible
  bug; the counter table fixes it. This decision is declared, not guessed).
- Allocation per target inside the fan-out batch (one atomic batch per chunk):
  1. `UPDATE device_seq SET next_seq = next_seq + 1 WHERE device_id = ?1`
  2. `INSERT INTO message_queue (...) SELECT ... seq = (SELECT next_seq - 1 FROM device_seq WHERE device_id = ?4) ... WHERE EXISTS (SELECT 1 FROM devices WHERE device_id = ?4 AND revoked_at IS NULL)`
- D1 executes statements one at a time per database (same serialization the
  Phase 2 CAS relies on), and the batch is a single implicit transaction →
  two concurrent sends to the same recipient can never get the same seq, and
  the `UNIQUE(recipient_dev_id, seq)` constraint is the backstop.
- Gaps are possible (revoked-target races, duplicate retries) and harmless:
  clients use seq for ordering only, `logical_msg_id` for identity. seq is
  never reused (counter is never decremented, even when rows are deleted).
- Chunking: the fan-out batch is split into chunks (e.g., ≤ 25 targets per
  batch to stay well inside D1 practical batch limits). Each chunk is atomic;
  a mid-request failure leaves a partial fan-out whose missing targets are
  repaired by the client's idempotent retry of the same logical_msg_id.

## 7. Receive flow, ACK, deletion

- `GET /messages?limit=N` (auth = recipient device's token), default/limit max
  200 rows: `SELECT` the device's non-expired rows ordered by `seq` (states
  `queued` AND `delivered` — redelivery), JOIN `devices` on `sender_dev_id` to
  attach `sender_account_id` + `sender_dev_no` (the client needs the sender
  address to select the session), and mark the returned rows `delivered` in the
  same batch.
- Response rows: `{delivery_id, logical_msg_id, sender_account_id, sender_dev_no,
  seq, ciphertext (b64), server_recv_at, expires_at}`.
- `POST /messages/ack {delivery_ids: [...]}` (auth): `DELETE` rows
  `WHERE delivery_id IN (...) AND recipient_dev_id = auth.device_id` — a device
  can only ACK its own queue. Idempotent; returns `{deleted: n}`.
- Client crash after fetch before ACK → rows are still `delivered` → redelivered
  on next fetch → client decrypts again → libsignal throws
  `DuplicateMessageException` (verified Gate3-D) → client treats as
  "already processed" and ACKs. Client additionally dedupes by `logical_msg_id`.

## 8. Offline recipient

- Rows persist in the queue until fetched+ACKed or expired (7 days). No
  realtime push this phase (declared out of scope): clients poll `GET /messages`.
- The sender gets no delivery/read confirmation in this phase (ACK is internal
  to the recipient device; not exposed to the sender).

## 9. Size & rate limits

| Limit | Value | Error |
|---|---|---|
| ciphertext per target | ≤ 65,536 bytes (plaintext guidance ≤ 64KB; verified overhead: PreKey ≈ +1.8KB, Whisper ≈ +104B) | 413 CIPHERTEXT_TOO_LARGE |
| targets per POST | ≤ 127 | 413 TOO_MANY_TARGETS |
| queued rows per recipient device | ≤ 2,000 (checked pre-batch) | 429 QUEUE_FULL |
| message TTL | 7 days (fixed) | rows expire |
| send rate | 120/min per sender account | 429 RATE_LIMITED |
| fetch rate | 60/min per device | 429 RATE_LIMITED |
| ack rate | 60/min per device | 429 RATE_LIMITED |
| device-list rate | 30/min per account | 429 RATE_LIMITED |
| D1 BLOB hard backstop | 1.9MB (existing CHECK, unchanged) | — |

## 10. Security & metadata design

- Server learns ONLY the metadata listed in §1 — enumerated and minimized; no
  content, no client envelope, no subject/preview, no group info.
- All endpoints require a valid device-bound token (Phase 1 auth); the sender
  identity is server-verified, so cross-account spoofing of `sender_dev_id` is
  impossible; recipients trust the crypto, not the server, for content.
- `logical_msg_id` is client-generated random — no sequence-of-operations leak.
- Ciphertext integrity/confidentiality is entirely libsignal AEAD (verified in
  prototype/gates); tampered blobs fail client-side decrypt.
- Queue metadata (who-talks-to-whom graph, sizes, timing) IS visible to the
  server by necessity — declared residual risk, mitigations: 7-day TTL, no
  third-party analytics, no content-bearing logs.

## 11. Revocation interplay

- **Send-time revoke**: the guarded INSERT (§6) only lands for targets whose
  `revoked_at IS NULL` at insert time; a target revoked mid-flight is reported
  per-target as `"rejected"` (not an error for the whole request).
- **Revoked while queued**: the Phase 2 revoke batch is extended to purge
  `message_queue` rows where `recipient_dev_id` (or `sender_dev_id`) matches —
  revoked devices stop receiving immediately.
- **Fetch/ACK**: revoked devices' tokens are dead (Phase 1) → cannot fetch/ACK.

## 12. Retry, duplication, crash/restart

| Scenario | Behavior |
|---|---|
| Sender network failure mid-send | re-POST same logical_msg_id → per-target `duplicate`/`queued` repair |
| Two targets, one fails validation | valid targets are queued; invalid reported per-target (`rejected`) — no all-or-nothing across targets |
| Receiver crash after fetch, before ACK | redelivery on next fetch; decrypt → `DuplicateMessageException` → treat as success → ACK |
| Receiver offline | rows wait until TTL |
| Same ciphertext delivered twice (server bug/attack) | client-side crypto rejects the duplicate (Gate3-D) |
| Sender retries with NEW logical_msg_id | server cannot dedupe (by design) → client dedupes by envelope content if the app needs it (client-side convention) |

## 13. Endpoint contracts

| Method & path | Auth | Request | Response | Errors |
|---|---|---|---|---|
| `GET /accounts/:id/devices` | Bearer | — | `200 {account_id, devices: [{device_id, dev_no, registration_id}]}` (active only) | 404 ACCOUNT_NOT_FOUND, 401, 429 |
| `POST /messages` | Bearer | `{logical_msg_id: uuid, targets: [{device_id, ciphertext_b64}] (≤127)}` | `200 {results: [{device_id, status: "queued"\|"duplicate"\|"rejected"}]}` | 400 VALIDATION_ERROR, 413 CIPHERTEXT_TOO_LARGE/TOO_MANY_TARGETS, 429 QUEUE_FULL/RATE_LIMITED, 401 |
| `GET /messages?limit=` | Bearer | — | `200 {messages: [{delivery_id, logical_msg_id, sender_account_id, sender_dev_no, seq, ciphertext, server_recv_at, expires_at}]}` | 400, 401, 429 |
| `POST /messages/ack` | Bearer | `{delivery_ids: [uuid] (≤200)}` | `200 {deleted: n}` | 400 VALIDATION_ERROR, 401, 429 |

Notes: unknown/revoked TARGET devices inside `POST /messages` are per-target
`rejected` (uniform, anti-enumeration); an unknown ACCOUNT for the device-list
endpoint is a uniform `404 ACCOUNT_NOT_FOUND`. All responses carry the
correlation ID echo (Phase 1.5 convention).

## 14. Threat model

| Threat | Mitigation |
|---|---|
| Ciphertext replay to the receiver | libsignal duplicate rejection (Gate3-D) + client logical dedupe |
| Duplicate logical message (send retry abuse) | per-target idempotency constraint + pre-read → `duplicate`, never stored twice |
| Sending as another device/account | impossible: sender bound to authenticated device; sender_dev_id set server-side from the token |
| Sending to arbitrary accounts (spam/enum) | auth required + per-target rejection is uniform; device-list endpoint rate-limited; account existence confirmed only to authenticated callers |
| Queue flooding (storage/DoS) | QUEUE_FULL cap 2,000/recipient + send rate 120/min + 7-day TTL + per-request target cap |
| Metadata analysis (social graph, timing, sizes) | residual, inherent to any server-assisted delivery; minimized fields + TTL + no content logs (declared) |
| Tampered ciphertext | AEAD rejects client-side; server stores opaque bytes |
| seq manipulation | server-assigned counter; client treats seq as ordering hint only |
| Revoked device receiving messages | revoke purge + guarded inserts + dead tokens |
| ACK of other devices' rows | ACK scoped to `recipient_dev_id = auth.device_id` |

## 15. libsignal 0.102.1 verification (done BEFORE implementation — Appendix A)

Verified empirically (scratch JVM on the real 0.102.1 jar, 8/8 PASS):
sizes/overhead of both message types, PREKEY-until-ACK behavior, per-recipient
ciphertext independence, out-of-order decrypt (skipped keys), duplicate
rejection (`DuplicateMessageException`), new-sender-device sessions, and
interleaved multi-sender-device sessions — all match the design assumptions.
No incompatibility with libsignal was found in this phase's model.

---

## Appendix A — Gate 3 results (verbatim, 2026-09-13)

```
[PASS] A1: first message is PREKEY_TYPE
[SIZE] PreKeySignalMessage(1KB plaintext) = 2824 bytes
[SIZE] second message (still unacknowledged prekey) = 2824 bytes, type=PREKEY
[PASS] A2: after ACK the sender sends WHISPER
[SIZE] SignalMessage(1KB plaintext) = 1130 bytes
[PASS] A3: 1KB whisper roundtrip
[SIZE] PreKeySignalMessage(1B plaintext) = 1799 bytes
[SIZE] SignalMessage(1B plaintext) = 105 bytes
[PASS] B: same plaintext to 2 devices -> distinct ciphertexts, both decrypt
[PASS] C: out-of-order decrypt 1,3,2 works (skipped message keys)
[PASS] D: re-decrypting the same ciphertext throws DuplicateMessageException
[PASS] E: receiver handles a NEW sender device (dev_no=3) and keeps the old session intact
[PASS] F: interleaved messages from two sender devices decrypt via the right sessions
GATE3 RESULT: 8 checks passed
```

## Appendix B — declared deviations / incompatibilities (explicit list)

1. **Phase 1.1 schema bug (0004)**: `UNIQUE(sender_dev_id, logical_msg_id)`
   forbids fan-out (one logical message → N recipient rows). Fixed by the 0009
   table rebuild with `UNIQUE(sender_dev_id, recipient_dev_id, logical_msg_id)`.
   Data is preserved by the migration.
2. **MAX(seq)-based allocation would reuse numbers** after the queue head is
   ACKed (rows are deleted). New `device_seq` counter table guarantees
   monotonic, never-reused per-device seq; gaps are possible and declared.
3. **seq is consumed even for duplicate retries and revoked-target races**
   (counter increments before the guarded insert). Gaps only; ordering and
   uniqueness unaffected. Accepted trade-off for D1's no-RETURNING constraint.
4. **Fan-out atomicity is per chunk, not per request** (D1 batch-size
   pragmatics); idempotent retries repair partial fan-outs.
5. **Polling only** this phase: no WebSocket/push (declared out of scope).
6. **No delivery confirmation to the sender** this phase (ACK is internal).
7. **Out-of-order decrypt works** in libsignal (verified), but the server
   delivers in seq order anyway; redelivered rows are crypto-duplicates the
   client already tolerates.
8. **Reinstall with a wiped store = NEW device registration** (dev_no
   increments). A device never changes its identity key in place (Phase 1
   model; no identity-change flow exists server-side).
9. **D1 hard limit: ≤ 100 bound parameters per query** (discovered
   empirically during implementation: `SQLITE_ERROR: variable number must be
   between ?1 and ?100`). All `IN(...)` queries are chunked (≤ 90 members per
   query) and the mark-delivered batch is chunked (≤ 50 statements per batch).
   The API contract is unchanged (≤ 127 targets, ≤ 200 ack ids); chunked
   chunks run sequentially and every operation is idempotent (§12).
10. **device_seq backfill refinement**: migration 0009 backfills counters as
    `MAX(seq)+1` per device (not the design sketch's flat `1`), so a
    pre-existing row's seq can never be reallocated — strictly honors the
    "never reuse" invariant.
11. **Post-ACK retry re-queues** (verified by unit test): the idempotency key
    lives in `message_queue`; once a row is consumed (ACKed) a re-POST of the
    same logical_msg_id queues a fresh row with a strictly higher seq. This is
    the §5/§12 queue-scoped dedupe working as designed; client-side safety is
    the §7 contract (client dedupes by logical_msg_id + libsignal
    `DuplicateMessageException` rejection, Gate3-D).
