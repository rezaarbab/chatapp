# Phase 2 Design: PreKey Infrastructure (PQXDH)

Status: **PROPOSED — awaiting user approval. No implementation has been done.**

Every protocol claim in this document was verified empirically against the real
`org.signal:libsignal-client:0.102.1` (the same Rust/ffi core as
`libsignal-android:0.102.1`) via a scratch JVM program, plus the existing
Phase 0.5-A prototype tests (8/8 green). Verification results are in Appendix A.
No API was guessed.

---

## 0. Verified facts that shape this design (from Appendix A)

| # | Fact (verified on libsignal 0.102.1) | Consequence |
|---|---|---|
| V1 | `PreKeyBundle` constructor signature: `(registrationId, deviceId, preKeyId, preKeyPublic: ECPublicKey?, signedPreKeyId, signedPreKeyPublic: ECPublicKey, signedPreKeySignature: ByteArray, identityKey: IdentityKey, kyberPreKeyId, kyberPreKeyPublic: KEMPublicKey, kyberPreKeySignature: ByteArray)` | Bundle JSON must carry exactly these 11 fields |
| V2 | `kyberPreKeyPublic` / `kyberPreKeySignature` are **non-null** (constructor throws NPE on null) | **A Kyber prekey is MANDATORY in every bundle** → a per-device "last-resort" Kyber prekey is required (stock exhaustion must never make bundles impossible) |
| V3 | `preKeyPublic` (one-time EC) is nullable; `preKeyId = NULL_PRE_KEY_ID = -1` for "absent" | One-time EC prekeys are optional in the bundle |
| V4 | `ECPublicKey.KEY_SIZE = 33`; `serialize()` = 33 bytes, `0x05`-prefixed | Upload/serving format for EC keys = 33-byte serialize() form |
| V5 | PreKey signatures = 64 bytes, computed **over `publicKey.serialize()` (33B / 1569B form)** with the device identity private key | Client uploads exactly these bytes; server never re-computes |
| V6 | `KEMPublicKey.serialize()` = **1569 bytes, first byte `0x08`** (KYBER_1024 type prefix, 1568 raw) | Kyber key validation: len == 1569 && [0] == 0x08 |
| V7 | `KEMKeyType` enum contains **only `KYBER_1024`** in 0.102.1 | Design targets KYBER_1024 (matches prototype) |
| V8 | `SessionBuilder.process()` verifies BOTH the signed-prekey and kyber-prekey signatures client-side (tampered sig → `InvalidKeyException: invalid signature detected`) | Server cannot substitute prekeys without detection (given a trusted identity key) |
| V9 | Bundle without one-time EC prekey but with Kyber works (establish + decrypt OK) | Stock exhaustion of EC one-times degrades gracefully |
| V10 | One-time EC prekey AND one-time Kyber prekey are consumed **receiver-side** on first decrypt (removed from store) | Receiver-side consumption is libsignal behavior; server-side pop prevents the same key being handed to two initiators |
| V11 | Kyber base-key tuple reuse at the receiver throws `ReusedBaseKeyException` (prototype) | Receiver-side replay protection is built into libsignal stores |

---

## 1. Key structures (exact libsignal 0.102.1 API)

All private keys are generated client-side and NEVER leave the device. The
server is a byte-server: it stores and serves opaque blobs, never re-encodes
them (only length/prefix validation).

### 1.1 Signed PreKey (X25519)
- Client: `ECKeyPair.generate()` (org.signal.libsignal.protocol.ecc)
- Record: `SignedPreKeyRecord(keyId, timestamp, keyPair, signature)`
- Signature: `identityKeyPair.privateKey.calculateSignature(signedPub.serialize())`
  → 64 bytes over the 33-byte `0x05`-prefixed public key (V5)
- Upload payload: `{ key_id: int, public_key: b64(33B), signature: b64(64B) }`
- Exactly ONE active per device on the server (new upload replaces; §3.1).

### 1.2 One-Time EC PreKeys (X25519)
- Client: `PreKeyRecord(keyId, ECKeyPair.generate())`
- Upload payload (array): `{ key_id: int, public_key: b64(33B) }` — unsigned (matches Signal)
- Served at most once (server marks used); optional in bundle (V3, V9).

### 1.3 Kyber PreKeys (KEM = KYBER_1024)
- Client: `KEMKeyPair.generate(KEMKeyType.KYBER_1024)`;
  record `KyberPreKeyRecord(keyId, timestamp, kemKeyPair, signature)` where
  `signature = identity.privateKey.calculateSignature(kemPub.serialize())` (1569B form)
- Two roles, distinguished server-side by `is_last_resort`:
  - **One-time Kyber prekeys**: array upload `{ key_id, public_key: b64(1569B), signature: b64(64B) }`;
    consumed at bundle fetch (preferred when in stock).
  - **Last-resort Kyber prekey**: single per device, same shape, upload replaces;
    NEVER consumed at fetch; served only when no unused one-time Kyber remains.
    This exists because of V2 (bundle cannot be built without a Kyber prekey).
- Receiver-side retention rule for our client store: after
  `markKyberPreKeyUsed(...)` the client store MUST delete one-time Kyber keys
  (libsignal behavior) but MUST RETAIN the last-resort key's record (private key
  needed to decrypt future sessions that used it). The store hook is ours to
  implement on Android (prototype's PersistedStore already shows the hook).

### 1.4 Identity key mapping (no server re-encode)
- `devices.identity_pub_key` was registered as RAW 32 bytes in Phase 1.
- Client maps to libsignal via `ECPublicKey.fromPublicKeyBytes(raw32)`
  (verified to exist in 0.102.1) or by prepending `0x05`.
- Signed/Kyber prekey publics are uploaded/stored/served as 33B/1569B
  serialize() forms and fed to `ECPublicKey.deserialize()` /
  `KEMPublicKey.deserialize()` verbatim.

---

## 2. D1 schema (migration `0008_prekeys_lastresort.sql`)

`0003_prekeys.sql` already landed (signed_prekeys / one_time_prekeys /
kyber_prekeys with used_at + partial pop indexes). It is already applied to
staging/production D1, so it is NOT edited; 0008 evolves it:

```sql
-- Phase 2 migration 0008: mandatory last-resort Kyber prekey (libsignal 0.102.1
-- cannot construct a PreKeyBundle without a Kyber prekey) + upload policy indexes.
ALTER TABLE kyber_prekeys
  ADD COLUMN is_last_resort INTEGER NOT NULL DEFAULT 0 CHECK (is_last_resort IN (0,1));

-- exactly one last-resort row per device
CREATE UNIQUE INDEX idx_kyber_last_resort ON kyber_prekeys(device_id) WHERE is_last_resort = 1;

-- pop index restricted to one-time (non-last-resort) unused keys
CREATE INDEX idx_kyber_pop_one_time ON kyber_prekeys(device_id, key_id)
  WHERE is_last_resort = 0 AND used_at IS NULL;
```

Resulting effective schema (for reference):
- `signed_prekeys(device_id, key_id, public_key 33B, signature 64B, created_at)`
  — one row per device enforced by upload policy (replace).
- `one_time_prekeys(device_id, key_id, public_key 33B, created_at, used_at)`
  — UNIQUE(device_id, key_id); pop = `used_at IS NULL` partial index.
- `kyber_prekeys(device_id, key_id, public_key 1569B, signature 64B, created_at,
  used_at, is_last_resort)` — UNIQUE(device_id, key_id); UNIQUE one last-resort
  per device (partial unique index above).

No changes to accounts/devices/auth tables. Reuse of existing conventions:
UUID TEXT ids, INTEGER ms epoch, BLOB keys, snake_case.

---

## 3. Lifecycle

### 3.1 Upload — `POST /prekeys` (auth: Bearer token)
Body (all four fields optional; allows count-probe `{}`):
```jsonc
{
  "signed_prekey":        { "key_id": 1, "public_key": "<b64 33B>", "signature": "<b64 64B>" },
  "last_resort_kyber":    { "key_id": 7, "public_key": "<b64 1569B>", "signature": "<b64 64B>" },
  "one_time_prekeys":       [ { "key_id": 100, "public_key": "<b64 33B>" } ],        // ≤ 100
  "one_time_kyber_prekeys": [ { "key_id": 200, "public_key": "<b64 1569B>", "signature": "<b64 64B>" } ] // ≤ 100
}
```
Semantics (all applied in ONE D1 batch — §4):
- `signed_prekey`: replace-all (batch: DELETE device's signed_prekeys, INSERT new).
- `last_resort_kyber`: retire old (mark `used_at = now`) + insert new row
  (`is_last_resort = 1`).
- one-time arrays: append; idempotent no-op if (device_id, key_id) exists with
  IDENTICAL public_key; `409 KEY_ID_CONFLICT` if same id different bytes.
- Validation → `400 INVALID_PREKEY`: EC pub != 33B/[0]!=0x05; Kyber pub != 1569B/[0]!=0x08;
  signature != 64B; `key_id` not integer 0..16777215 (libsignal Medium range;
  -1/NULL_PRE_KEY_ID forbidden).
- Caps → `413 TOO_MANY_PREKEYS`: >100 per array per upload; >500 stored unused
  one-time EC or >300 unused one-time Kyber per device (count checked before insert).
- Response 200:
```jsonc
{ "signed_prekey_id": 1, "last_resort_kyber_id": 7,
  "one_time_ec_remaining": 41, "one_time_kyber_remaining": 23 }
```
- Rate limit: `prekeys_upload_user` 30/hour keyed by account_id.

### 3.2 Bundle fetch — `GET /devices/:id/prekeys` (auth: Bearer token)
- Target = any ACTIVE device (own or other accounts — needed to start chats).
  Unknown or revoked → uniform `404 DEVICE_NOT_FOUND` (anti-enumeration).
- Rate limit: `prekeys_bundle_user` 60/min keyed by account_id.
- Steps (pop atomically — §4):
  1. `SELECT` device row (account_id, dev_no, registration_id, identity_pub_key,
     revoked_at) JOIN guard `revoked_at IS NULL`.
  2. Pop lowest unused one-time EC (mark used).
  3. Pop lowest unused one-time Kyber (mark used); if none, use last-resort row
     (NO mutation).
  4. Load signed prekey (latest; by policy exactly one row).
- Response 200 (exactly the 11 PreKeyBundle-constructor fields, V1):
```jsonc
{
  "account_id": "<uuid>",            // → SignalProtocolAddress.name
  "device_id": "<uuid>",             // server-side row id (not the protocol deviceId)
  "dev_no": 2,                       // → PreKeyBundle.deviceId (1..127)
  "registration_id": 1234,           // → PreKeyBundle.registrationId
  "identity_pub": "<b64 RAW 32B>",   // → ECPublicKey.fromPublicKeyBytes (§1.4)
  "signed_prekey": { "key_id": 1, "public_key": "<b64 33B>", "signature": "<b64 64B>" },
  "one_time_prekey": { "key_id": 100, "public_key": "<b64 33B>" } | null,   // null when out of stock
  "kyber_prekey": { "key_id": 200, "public_key": "<b64 1569B>", "signature": "<b64 64B>",
                    "last_resort": false }                                    // true when last-resort served
}
```
Client mapping: `preKeyId = one_time_prekey?.key_id ?? PreKeyBundle.NULL_PRE_KEY_ID`,
`preKeyPublic = one_time_prekey ? ECPublicKey.deserialize(b64) : null`.
- If a device has no signed prekey or no last-resort kyber at all (never
  uploaded): `409 PREKEYS_NOT_READY` (initiator should retry later; the device
  must upload after registration before being messaged).

### 3.3 Allocation / mark-used
- EC one-time and one-time Kyber: `used_at = now` set via the CAS loop (§4 A1)
  at fetch time. A row is never served twice (verified on real D1, Appendix C).
- Last-resort Kyber and signed prekey: never marked used server-side.
- Receiver-side consumption on decrypt is libsignal behavior (V10) and is
  independent of the server's mark.

### 3.4 Refill
- Thresholds (client policy, enforced nowhere server-side): when
  `one_time_ec_remaining < 25` or `one_time_kyber_remaining < 25`, upload a
  fresh batch (≤100 each) via `POST /prekeys`; the POST response carries the
  remaining counts (§3.1). A count probe = `POST /prekeys` with `{}`.
- Initial upload happens right after `/accounts` or `POST /devices` (device
  becomes messagable only after `signed_prekey` + `last_resort_kyber` exist).

### 3.5 Expiry & cleanup
- No TTL on prekey rows (they are small, and stale unused keys just sit).
- Storage caps from §3.1 bound abuse; on upload that exceeds a cap the server
  first deletes the OLDEST unused one-time rows beyond the cap, then inserts
  (same batch) — the device's own refill cannot wedge on its own garbage.
- On device revoke: purge ALL prekey rows for the device in the revoke batch
  (§4.4); revoked devices stop being messagable immediately.

---

## 4. Exactly which operations must be atomic, and why

| # | Operation | Atomic unit | Why it must be atomic |
|---|---|---|---|
| A1 | Bundle fetch pop (EC + Kyber one-times) | **CAS loop per pop**: `SELECT` lowest unused → `UPDATE ... SET used_at = ? WHERE device_id = ? AND key_id = ? AND used_at IS NULL` → proceed iff `meta.changes === 1`, else retry (bounded). The remaining bundle reads (device row, signed prekey, last-resort kyber) batch together with a CAS UPDATE attempt. **Design amendment (Gate 1):** the original "single batch" wording was WRONG — a D1 batch cannot feed SELECT results into the next statement's bind; the conditional UPDATE is the actual atomicity primitive (single-statement compare-and-swap), and D1's per-database serialization makes the check-and-set airtight. Transient D1 errors (SQLITE_BUSY under burst) burn one attempt and retry | **Prevent prekey reuse**: two concurrent bundle fetches must never receive the same one-time key (verified on real D1, Appendix C). Reuse would break the X3DH/PQXDH property that a one-time key is used by at most one initiator |
| A2 | Upload | all deletes/inserts/updates of one POST | **No half-uploaded state**: a crash mid-upload must not leave a device with a new signed prekey but stale last-resort, or duplicated counters. All-or-nothing keeps §3.3 invariants |
| A3 | Signed prekey rotation | DELETE old rows + INSERT new row | No window where GET bundle finds zero signed prekeys (`409` to legitimate initiators) |
| A4 | Revoke device | UPDATE devices.revoked_at + DELETE tokens + DELETE prekey rows (existing batch extended) | No window where a revoked device still serves bundles or holds live tokens |
| A5 | add_device / register | unchanged from Phase 1 (device + token already one batch) | unchanged |

Non-atomic and fine: count-probe reads; the two-round-trip upload conflict path
(SELECT then conditional INSERT) — same-device concurrent uploads are the only
participants and the UNIQUE(device_id,key_id) constraint is the backstop
(constraint violation → re-SELECT → idempotent no-op or 409).

---

## 5. Endpoints (summary)

| Method & path | Auth | Purpose | Errors |
|---|---|---|---|
| `POST /prekeys` | Bearer | upload signed / last-resort / one-time batches; `{}` = count probe | 400 INVALID_PREKEY, 409 KEY_ID_CONFLICT, 413 TOO_MANY_PREKEYS, 401 auth errors, 429 |
| `GET /devices/:id/prekeys` | Bearer | fetch PreKeyBundle JSON for an active device | 404 DEVICE_NOT_FOUND, 409 PREKEYS_NOT_READY, 401, 429 |

Both are new routes in `router.ts` (auth: true); handlers live in a new
`src/prekeys.ts`; LIMITS additions in `src/ratelimit.ts`. Error codes follow the
existing `errors.ts` shape (`{ error: { code, message } }`), correlation-ID
logging applies automatically.

---

## 6. Reuse & race-condition prevention (consolidated)

1. **Double-fetch race** → CAS loop (SELECT → conditional UPDATE guarded by
   `used_at IS NULL` → `meta.changes` decides ownership) + D1 per-database
   serialization. Verified against REAL Cloudflare D1 under 40-way concurrency
   (Appendix C): 0 double deliveries across 8 rounds, while the non-atomic
   control delivered the SAME key to 39 of 40 concurrent requests.
2. **Upload id conflict** → UNIQUE(device_id,key_id) + identical-bytes no-op /
   differing-bytes 409 (§3.1).
3. **Signed prekey rotation vs in-flight bundle** → initiator already processed
   an old bundle keeps working: the RECEIVER keeps its signed-prekey private
   key locally (server copy is only for serving new bundles).
4. **Last-resort reuse is intentional and safe**: PQXDH with a repeated Kyber
   key is mitigated receiver-side by libsignal's used-tuple
   (`ReusedBaseKeyException`, V11) and by our client store retaining the
   last-resort record.
5. **Revoke vs in-flight fetch** → bundle query re-checks `revoked_at IS NULL`
   in the same batch; a token revoked mid-flight fails auth anyway.
6. **Cross-account interference** → uploads authenticate to the caller's own
   device; there is no path-scoped upload target.

---

## 7. Backend ↔ libsignal 0.102.1 compatibility (and prototype ties)

- The bundle JSON maps 1:1 onto the verified 11-field constructor (V1); field
  order/validation in §3.2 mirrors it. Prototype test
  `full session establishment and exchange over prekey bundle` proves the exact
  constructor path used by the client.
- `bundle without one-time EC prekey still works` (prototype) = §3.2 null
  one_time_prekey behavior (V9).
- Signature definition (V5) is exactly what the prototype computes
  (`identity.privateKey.calculateSignature(pub.serialize())`), and V8 proves
  the initiator verifies both signatures during `process()`.
- Prototype's `kyber prekey tuple reuse is detected` (V11) validates the
  receiver-side replay story.
- Prototype gap DELIBERATELY carried into this phase: the prototype store keys
  remote identities by `address.name` only. Our Phase 1 model gives each device
  its OWN identity key, so the Android client store MUST key remote identities
  by `(address.name, address.deviceId)` (else a second device of the same
  account trips `UntrustedIdentityException`). This is a client-store
  requirement, documented now, implemented in the client phase.

## 8. Multi-device semantics

- `SignalProtocolAddress.name = account_id (UUID)`,
  `SignalProtocolAddress.deviceId = dev_no (1..127, never reused — migration 0002)`.
- `PreKeyBundle.deviceId = dev_no` — the initiator targets the exact receiving
  device; each (account, dev_no) pair has its own session.
- Each device has its own identity key (Phase 1 design — a DELIBERATE deviation
  from Signal's per-account shared identity; consequences: safety-number-style
  verification would be per-device; documented, unchanged in this phase).
- Bundles are per device; uploading, refill and rotation are per device; the
  account-level account_id only scopes auth (any device's token may fetch any
  active device's bundle).

## 9. Threat model & security edge cases (this phase)

| Threat | Mitigation |
|---|---|
| Malicious server substitutes prekeys (MITM) | Initiator verifies signed+kyber signatures against the bundle's identity key (V8). Residual risk: server swapping identity+prekeys together = classic Signal TOFU problem; addressed by out-of-band safety numbers in a later phase — declared out of scope here |
| One-time stock exhaustion (DoS on forward secrecy) | Rate limits (60/min user) + graceful degradation: bundle still valid via signed + last-resort Kyber (V9); no availability cliff (V2) |
| Bundle-fetch flooding / scraping | per-user rate limit + auth requirement + uniform 404 for unknown/revoked targets |
| Replay of fetched bundle | One-time rows are marked used atomically (A1); replayed OLD bundles contain keys the receiver will only accept once (libsignal replay protection, V10/V11) |
| Malformed/oversized key material | strict lengths/prefixes (33B/0x05, 1569B/0x08, 64B sig, key_id 0..16777215) → 400; array caps → 413 |
| Revoked device still messagable | revoke purges prekeys + tokens (A4); bundle 404 for revoked |
| Enumeration via error shapes | uniform `DEVICE_NOT_FOUND` for unknown AND revoked devices |
| Token theft | prekey endpoints inherit Phase 1 auth: device-bound short-TTL tokens, revocation invalidates immediately |

---

## Appendix A — empirical verification (libsignal-client 0.102.1, JVM scratch, 2026-09-12)

Program: temp-dir scratch Java using the real jar from the Gradle cache +
the Phase 0.5-A prototype `PersistedStore`. Output (verbatim):

```
NULL_PRE_KEY_ID=-1
ECPublicKey.KEY_SIZE=33
EC pub serialize len=33
identity pub serialize len=33
sig len=64
KEM pub serialize len=1569
KEM first byte=8
KEM values=[KYBER_1024]
A: one-time EC + kyber -> establish+decrypt OK, type=3 ecConsumed=true kyberConsumed=true
A: one-time EC + kyber -> reply roundtrip OK
B: signed + kyber only -> establish+decrypt OK, type=3 ecConsumed=true kyberConsumed=true
B: signed + kyber only -> reply roundtrip OK
C: signed only -> IMPOSSIBLE: PreKeyBundle constructor rejects null kyberPreKeyPublic (non-null Kotlin param)
D: signed + one-time EC -> IMPOSSIBLE: PreKeyBundle constructor rejects null kyberPreKeyPublic (non-null Kotlin param)
E: tampered kyber signature -> rejected: InvalidKeyException: invalid signature detected
F: tampered signed-prekey signature -> rejected: InvalidKeyException: invalid signature detected
ALL VARIANTS DONE
```

`javap` of the real jar confirmed: the single public
`PreKeyBundle(int,int,int,ECPublicKey,int,ECPublicKey,byte[],IdentityKey,int,KEMPublicKey,byte[])`
constructor, `NULL_PRE_KEY_ID`, `KEMKeyType` enum contents, `KEMPublicKey.serialize()`,
`KyberPreKeyRecord(id, timestamp, KEMKeyPair, signature)`, `ECPublicKey.fromPublicKeyBytes(byte[])`.

## Appendix B — declared deviations / incompatibilities (explicit list)

1. **Kyber prekey is mandatory in every bundle** (libsignal 0.102.1 constructor,
   verified V2/C/D). The Phase 1.1 schema (0003) has no last-resort concept →
   migration 0008 adds it. WITHOUT this, devices whose one-time Kyber stock is
   empty could not receive ANY new session.
2. **Only `KYBER_1024` exists** in 0.102.1 (no KYBER_768/ML-KEM enums): 1569B
   serialized (0x08 prefix). Bundle/upload sizes sized accordingly.
3. **identity_pub stays raw-32B** (Phase 1 contract unchanged); the client maps
   via `ECPublicKey.fromPublicKeyBytes` — server does not transform keys.
4. **D1: no ON CONFLICT/RETURNING** (established Phase 1.5 finding) → pop =
   CAS loop (SELECT → conditional UPDATE → `meta.changes`), see §4 A1 and Gate 1.
5. **Per-device identity keys** (Phase 1 deviation from Signal) → client store
   must key remote identities by (name, deviceId) — client-phase requirement,
   empirically proven necessary by Gate 2 control (Appendix C).
6. **Client store must retain last-resort Kyber records** after use (our store
   hook decides deletion; libsignal one-time deletion is default behavior V10).
7. **Signed prekey: server keeps only the latest row** (replace on upload) —
   matches Signal server semantics; receivers keep private keys locally.
8. Out of scope, declared: safety-number/out-of-band identity verification
   (server-substitution residual risk), group/sender-key sessions, message
   queueing (Phase 3+).

## Appendix C — Gate verification results (2026-09-12, both gates PASSED)

### Gate 1: atomic prekey allocation on REAL Cloudflare D1

Temporary worker (`chatapp-gate-race-<run_id>`, deleted after) bound to the real
staging D1, using a dedicated self-cleaning table `gate_race_prekeys` (dropped by
final `/reset`; staging app tables untouched). Run: 34712600937 (job 103603961533).

- **CAS algorithm (the Phase 2 design)**: 8 rounds × 10 seeded keys × 40
  concurrent pops. Every round: exactly **10 distinct deliveries + 30 nulls,
  0 duplicates**, and server-side `/stats` confirmed `used = 10` per round
  (`GATE1 RESULT: PASS`). Round 1 had 1 harness fetch failure under the 40-way
  burst (transport-level, runner→edge); correctness held including the
  server-side cross-check — a lost response can only mean the key IS marked used
  server-side, which the `used === distinct` check would flag.
- **Non-atomic control** (SELECT then unconditional UPDATE, two awaits):
  catastrophic double-delivery — e.g. round with **40 concurrent requests, 1
  distinct key** (`duplicates=true` in all 5 control rounds). Proves both that
  the harness detects races and that the CAS guard is REQUIRED; D1 per-statement
  serialization alone does NOT make SELECT-then-UPDATE safe.
- Observed CAS retry counts under 40-way contention on 10 keys: maxRetry ≈ 8-9
  (bounded loop of 15 is sufficient; contention cost is a few extra D1 round
  trips under extreme parallelism, ~0 in realistic traffic).
- Transient D1 errors (`SQLITE_BUSY`-class) under burst were observed and are
  handled by burning one CAS attempt and retrying (implemented in the gate
  worker; must be mirrored in Phase 2 implementation).

### Gate 2: multi-device identity model on real libsignal 0.102.1 (12/12 PASS)

Scratch JVM program (JDK 21, libsignal-client 0.102.1 + prototype store
variant). Account A = UUID string with TWO devices (dev_no 1, 2), each with its
OWN identity key; initiator = device 1 of account B (also UUID name).

1. PASS two devices of one account hold DIFFERENT identity keys
2. PASS B→A.dev1 establish + first message is PREKEY_TYPE
3. PASS A.dev1 decrypts B's first message
4. PASS B→A.dev2 establish with DIFFERENT identity + first message PREKEY_TYPE
5. PASS A.dev2 decrypts B's first message
6. PASS B→A.dev1 session intact after dev2 session (no trust error, delivered)
7. PASS B decrypts reply from A.dev1
8. PASS B decrypts reply from A.dev2
9. PASS initiator store trusts BOTH (acctA,1) and (acctA,2) identities
10. PASS getSubDeviceSessions(account_id) returns both dev_nos {1,2}
11. PASS dev_no=127 (max, bundle without one-time EC) establishes + decrypts
12. PASS CONTROL name-only keying: dev2 bundle after dev1 rejected with
    UntrustedIdentityException (proves (name, deviceId) identity keying is REQUIRED)

Additional confirmed behavior: while the initiator's session to a device has an
unacknowledged prekey message, libsignal legitimately sends PREKEY-type again
(matches the Phase 0.5-A prototype). `SignalProtocolAddress.name = account_id
(UUID)` and `.deviceId = dev_no (1..127)` are fully compatible with the real
API and lifecycle (SessionBuilder, SessionCipher, getSubDeviceSessions).
