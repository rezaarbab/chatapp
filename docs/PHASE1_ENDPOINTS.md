# Phase 1 — Endpoint Contracts (design; implementation follows after approval)

Conventions:

- All request/response bodies are `application/json` unless stated otherwise.
- Timestamps are unix epoch **milliseconds** (integers).
- Binary keys/signatures/ciphertexts are **base64 (standard, no wrap)** strings.
- Authenticated calls: `Authorization: Bearer <token>`. The **device identity is
  always derived from the token**; no endpoint accepts a device identity from the body.
- Error envelope (all non-2xx): `{"error": {"code": "<CODE>", "message": "..."}}`
- Challenge TTL **60 s**, access-token TTL **30 min**, message TTL **7 days**,
  attachment TTL **min(7 days, all snapshot devices ACKed)**.

## Error codes

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body / missing or invalid fields |
| 401 | `UNAUTHORIZED` | missing, malformed, or unknown token |
| 401 | `TOKEN_EXPIRED` | token valid once, TTL passed → client re-auths |
| 401 | `DEVICE_REVOKED` | token belongs to a revoked device |
| 401 | `CHALLENGE_EXPIRED` | challenge expired at verify time |
| 401 | `CHALLENGE_USED` | challenge already consumed (atomic) |
| 401 | `INVALID_SIGNATURE` | Ed25519 verification failed |
| 403 | `FORBIDDEN` | authenticated, but not the owner of the target resource |
| 404 | `NOT_FOUND` | resource does not exist (constant shape everywhere incl. user lookup) |
| 409 | `USERNAME_TAKEN` | registration with an existing username |
| 409 | `CONFLICT` | logical_msg_id replay, or recipient-device snapshot stale |
| 413 | `PAYLOAD_TOO_LARGE` | ciphertext > 1.9 MB or attachment > 50 MB |
| 429 | `RATE_LIMITED` | soft/hard limit exceeded |
| 500 | `INTERNAL` | unexpected server error (no detail leakage) |

---

## 1. POST /auth/challenge — public

Request:
```json
{
  "purpose": "register" | "auth" | "add_device",
  "username": "string?",              // required for register/add_device
  "identity_pub": "b64?",             // required for register/add_device (libsignal identity)
  "auth_pub": "b64?",                 // required for register/add_device (Device Auth key)
  "device_id": "uuid?",               // required for auth
  "authorizer_device_id": "uuid?"     // required for add_device
}
```
Response `200`:
```json
{ "challenge_id": "uuid", "nonce": "hex-64", "expires_at": 1700000060000 }
```
Errors: 400 `VALIDATION_ERROR` (unknown purpose / missing fields), 404 `NOT_FOUND`
(auth: unknown device_id; add_device: unknown authorizer device), 429 `RATE_LIMITED`.

Server-side effects: inserts single-use challenge row carrying the full context;
TTL 60 s; nonce = 256-bit random.

## 2. POST /accounts — public (register)

Request:
```json
{ "challenge_id": "uuid", "signature": "b64-64" }
```
The signature covers the canonical `register` context built from the **stored
challenge row** (never re-read from the request).

Response `201`:
```json
{
  "account_id": "uuid",
  "device_id": "uuid",
  "dev_no": 1,
  "token": "b64-32",
  "token_expires_at": 1700000000000
}
```
Errors: 400 `VALIDATION_ERROR`, 401 `CHALLENGE_EXPIRED` / `CHALLENGE_USED` /
`INVALID_SIGNATURE`, 409 `USERNAME_TAKEN`, 429 `RATE_LIMITED`.

Effects: creates account + first device (dev_no=1) inside one D1 batch; issues
token (stores SHA-256 only).

## 3. POST /auth/verify — public (token issuance for an existing device)

Request:
```json
{ "challenge_id": "uuid", "signature": "b64-64" }
```
Response `200`:
```json
{
  "token": "b64-32",
  "account_id": "uuid",
  "device_id": "uuid",
  "token_expires_at": 1700000000000
}
```
Errors: 400 `VALIDATION_ERROR`, 401 `CHALLENGE_EXPIRED` / `CHALLENGE_USED` /
`INVALID_SIGNATURE`, 404 `NOT_FOUND` (unknown challenge), 429 `RATE_LIMITED`.

## 4. POST /devices — token (add device)

Request:
```json
{
  "challenge_id": "uuid",
  "signature": "b64-64",             // new device's auth key over add_device context
  "authorizer_signature": "b64-64",  // active device of same account over same context
  "label": "string?"
}
```
Response `201`:
```json
{ "device_id": "uuid", "dev_no": 4, "token": "b64-32", "token_expires_at": 1700000000000 }
```
Errors: 400 `VALIDATION_ERROR`, 401 (all four challenge errors), 403 `FORBIDDEN`
(authorizer revoked/not same account), 409 `CONFLICT` (dev_no space exhausted:
127 devices), 429.

## 5. DELETE /devices/{device_id} — token

Response `204` (empty).
Errors: 401, 403 `FORBIDDEN` (target device belongs to another account), 404 `NOT_FOUND`.

Effects (one batch): `revoked_at = now` on the device; all its tokens get
`revoked_at = now`; its queued messages/attachments expire naturally via TTL.
Its WS connection is closed by RealtimeHub on next touch. `dev_no` is never reused.

## 6. PUT /devices/me/prekey-bundle — token

Request:
```json
{
  "signed_prekey": { "key_id": 1, "public_key": "b64", "signature": "b64" },
  "kyber_prekeys": [ { "key_id": 1, "public_key": "b64", "signature": "b64" } ],
  "one_time_prekeys": [ { "key_id": 100, "public_key": "b64" } ]
}
```
- `signed_prekey` replaces the current signed prekey (one active per device).
- first kyber prekey = last-resort (kept after use); additional = one-time.
- `one_time_prekeys` batch up to 100 per call.

Response `200`:
```json
{ "remaining_one_time_ec": 100, "remaining_one_time_kyber": 100 }
```
Errors: 400 `VALIDATION_ERROR` (bad lengths/key ids), 401, 429.

## 7. GET /devices/{device_id}/prekey-bundle — token

Response `200`:
```json
{
  "registration_id": 1000,
  "identity_key": "b64",
  "signed_prekey": { "key_id": 1, "public_key": "b64", "signature": "b64" },
  "kyber_prekey":  { "key_id": 1, "public_key": "b64", "signature": "b64" },
  "one_time_prekey": { "key_id": 100, "public_key": "b64" } | null,
  "remaining_one_time_ec": 24,
  "remaining_one_time_kyber": 24
}
```
- Target device must be active; otherwise 404 `NOT_FOUND` (no distinction from
  unknown device — anti-enumeration).
- Atomic pop: EC one-time and Kyber one-time keys are consumed via conditional
  UPDATE (single statement each) within one D1 batch. When exhausted, the bundle
  is served with signed + kyber last-resort keys only (prototype-proven).

Errors: 400 `VALIDATION_ERROR`, 401, 404 `NOT_FOUND`, 429.

## 8. POST /messages — token (store-first fan-out)

Request:
```json
{
  "logical_msg_id": "uuid",             // client-generated idempotency key
  "recipients": [
    { "device_id": "uuid", "ciphertext": "b64" }   // 1..N entries, each ≤ 1.9 MB
  ]
}
```
Response `201`:
```json
{ "deliveries": [ { "device_id": "uuid", "delivery_id": "uuid" } ] }
```
Semantics:
- Snapshot = active devices **at send time**: any recipient device that is
  revoked/unknown → whole request rejected `409 CONFLICT` (code
  `STALE_RECIPIENT_DEVICES`, body lists offenders) → client refreshes directory.
- Rows inserted in ONE D1 batch (atomic): per-recipient `seq = MAX(seq)+1`.
- Replay (same sender + logical_msg_id) → `409 CONFLICT` with the original
  mapping (idempotent retry returns the same delivery_ids).
- TTL stamped server-side; client input cannot extend it.
- After commit, RealtimeHub notify is sent via `ctx.waitUntil` (fire-and-forget).

Errors: 400 `VALIDATION_ERROR`, 401, 409 `CONFLICT` / `STALE_RECIPIENT_DEVICES`,
413 `PAYLOAD_TOO_LARGE`, 429.

## 9. GET /messages — token

Query: `?limit=1..50` (default 20).
Response `200`:
```json
{
  "messages": [
    { "delivery_id": "uuid", "seq": 42, "sender_device_id": "uuid", "ciphertext": "b64", "server_recv_at": 0 }
  ],
  "remaining": 11
}
```
Ordered by `seq` ASC. Rows stay `queued` until ACK (redelivery-safe); `remaining`
lets the client loop. Errors: 401.

## 10. POST /messages/{delivery_id}/ack — token

Response `204` (empty).
- Ownership: the delivery row must belong to the token device → else `403 FORBIDDEN`.
- Idempotent: unknown/already-acked delivery → `204` (same effect).
- Deletion happens inside one batch (row delete + result), TTL cleanup is the fallback.

## 11. Attachments — token

| Step | Contract |
|---|---|
| POST `/attachments/initiate` `{ "encrypted_size": n }` → `201 { "attachment_id", "upload_expires_at" }` | validates `n ≤ 50 MB`; creates `pending` row + TTL |
| POST `/attachments/{id}/upload` (raw ciphertext bytes, token auth) → `204` | only sender device; only while `pending`; streams to R2 `r2_key` |
| POST `/attachments/{id}/complete` → `200 { "attachment_id" }` | verifies R2 object size == encrypted_size; sets `ready`; creates per-device delivery rows for the recipient snapshot carried inside the E2EE message |
| GET `/attachments/{id}` → raw bytes (application/octet-stream) | only devices in the delivery snapshot; `delivered_at` stamped |
| POST `/attachments/{id}/ack` → `204` | per-device; when all snapshot devices ACKed → delete R2 object + rows (TTL fallback) |

Errors: 401/403/404/413/429 as per table; upload with size mismatch → 400 `VALIDATION_ERROR`.

File keys travel **only inside E2EE messages**; the server never sees them.

## 12. Backups — token

| Endpoint | Contract |
|---|---|
| POST `/backups` (raw encrypted blob ≤ 25 MB) → `201 { "backup_id", "backup_version", "created_at" }` | account from token; keeps latest version; older versions expire via TTL |
| GET `/backups/latest` → raw bytes | 404 `NOT_FOUND` if none |

## 13. GET /ws — token (WebSocket upgrade)

- RealtimeHub DO per device (`idFromName(device_id)`), Hibernation API.
- Server pushes `{"t":"n"}` (notify-only, no content). Client reacts by GET /messages.
- Invalid/expired token or revoked device → HTTP 401 before upgrade.

## 14. GET /users/{username} — token

- Exact match only (case-sensitive). Response `200 { "username": "..." }` or
  `404 NOT_FOUND` with identical shape/timing (anti-enumeration). Rate limited.
