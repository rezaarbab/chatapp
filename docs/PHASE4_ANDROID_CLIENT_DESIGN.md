# Phase 4 Design: Android Client Integration (real E2E vertical slice)

Status: **PROPOSED — awaiting user approval. No Phase-4 implementation has been done.**

Goal (user mandate): a REAL vertical slice — one plaintext message typed on Android
device A is encrypted with the real libsignal-android 0.102.1, sent through the real
Cloudflare staging backend, received and decrypted on Android device B — plus the full
lifecycle, crash/restart persistence, and real multi-device. Not a UI phase.

Every libsignal/API claim below is either already proven in CI (Phase 0.5/2/3 artifacts)
or was verified empirically for this design against the real 0.102.1 jar (Appendix A,
Scratch4, 16/16 PASS). Nothing is guessed.

---

## 0. Scope

**In scope:**
- HTTP client layer for the existing Worker API (no backend changes)
- Real account/device registration from Android (challenge → Ed25519 sign → 201)
- Secure persistence: identity, sessions, prekeys, auth key, token, account state — all inside the existing SQLCipher store (AndroidKeyStore-wrapped passphrase)
- Device discovery + PreKeyBundle fetch + real PQXDH session build
- Per-device encrypt → send → queue → receive → decrypt → ACK
- Full lifecycle E2E, crash/restart persistence, multi-device (add_device, self-sync)
- Instrumented tests on the real emulator against the real staging deployment

**Explicitly OUT of scope (declared):**
- Full UI / app screens (instrumented tests only)
- WebSocket / push notification / long-polling
- Attachments, backups, groups, read receipts
- Any backend/API/schema change (Phase 3 contract consumed as-is)
- Account recovery, identity-change flows

## 1. Existing assets (already proven in CI — reused, not rewritten)

| Asset | Proof |
|---|---|
| `SqlCipherProtocolStore` — full `SignalProtocolStore` on SQLCipher (identity, sessions, prekeys, signed/kyber prekeys, sender keys; records stored as official serialized bytes) | `android/`, CI green since Phase 0.5-B |
| `DatabaseKeyManager` — 32B passphrase, non-exportable AndroidKeyStore AES-GCM wrap; reopen-after-restart works | `CryptoOnDeviceTest.keystoreWrappedPassphraseReopensEncryptedDatabaseAfterRestart` |
| libsignal-android 0.102.1 natives load on the API-34 emulator; PQXDH session build + PREKEY→WHISPER transition + one-time prekey consumption on device | `CryptoOnDeviceTest` (CI, emulator) |
| Tink Ed25519 (tink-android 1.23): raw 32B pub export, raw 64B RFC-8032 signatures over the canonical context string, verified server-side by WebCrypto | `AuthInteropInstrumentedTest` + `interop.spec.ts` |
| Server contract (auth, prekeys, messages) | Phases 1–3, `docs/PHASE2_PREKEY_DESIGN.md`, `docs/PHASE3_MESSAGING_DESIGN.md` |

## 2. API contract consumed by the Android client (complete, as implemented in Phase 3)

Base URL: `https://chatapp-staging.aacc32351.workers.dev` (public staging; overridable via instrumentation arg `stagingUrl`). All requests: JSON; `Authorization: Bearer <token>` where noted; responses echo `x-correlation-id`.

| # | Endpoint | Auth | Request | Success response | Errors |
|---|---|---|---|---|---|
| 1 | `POST /auth/challenge` | — | `{purpose, username?, identity_pub?, auth_pub?, device_id?, authorizer_device_id?}` (`identity_pub`/`auth_pub` = b64 of raw 32B) | `200 {challenge_id, nonce, expires_at}` | 400/404/409/429 |
| 2 | `POST /accounts` | — | `{challenge_id, signature (b64 64B), registration_id (1..16380)}` | `201 {account_id, device_id, dev_no, token, token_expires_at}` | 401/409/429 |
| 3 | `POST /auth/verify` | — | `{challenge_id, signature}` (purpose `auth`, context = v1\|auth\|…) | `200 {token, account_id, device_id, token_expires_at}` | 401/404/429 |
| 4 | `POST /devices` | — | `{challenge_id, signature, authorizer_signature, registration_id}` | `201 {device_id, dev_no, token, token_expires_at}` | 401/403/404/429 |
| 5 | `DELETE /devices/:id` | Bearer | — | `204` | 403/404/401 |
| 6 | `POST /prekeys` | Bearer | `{signed_prekey, last_resort_kyber, one_time_prekeys[], one_time_kyber_prekeys[]}` — key_id `0..16777215`; EC pub = b64(**33B**, 0x05 prefix); Kyber pub = b64(**1569B**, 0x08); signatures = b64(**64B**) over the pub's serialize() bytes; one-time EC carries NO signature | `200 {signed_prekey_id, last_resort_kyber_id, one_time_ec_remaining, one_time_kyber_remaining}` | 400/409/413/429 |
| 7 | `GET /devices/:id/prekeys` | Bearer | — | `200 {account_id, device_id, dev_no, registration_id, identity_pub (b64 raw 32B), signed_prekey{key_id,public_key,signature}, one_time_prekey{key_id,public_key}\|null, kyber_prekey{key_id,public_key,signature,last_resort}}` | 404/409/429 |
| 8 | `GET /accounts/:id/devices` | Bearer | — | `200 {account_id, devices:[{device_id, dev_no, registration_id}]}` (active only) | 404/429 |
| 9 | `POST /messages` | Bearer | `{logical_msg_id (UUID), targets:[{device_id, ciphertext_b64}] (≤127; ciphertext ≤ 65536B)}` | `200 {results:[{device_id, status: "queued"\|"duplicate"\|"rejected"}]}` | 400/413/429/401 |
| 10 | `GET /messages?limit=` | Bearer | — | `200 {messages:[{delivery_id, logical_msg_id, sender_account_id, sender_dev_no, seq, ciphertext (b64), server_recv_at, expires_at}]}` (ordered by seq; redelivered until ACK) | 400/429 |
| 11 | `POST /messages/ack` | Bearer | `{delivery_ids:[string] (≤200)}` | `200 {deleted: n}` | 400/429 |

**Canonical challenge context strings** (verified byte-identical to Worker `buildContext`):
- register: `v1|register|challenge_id|nonce|username|identity_pub_b64|auth_pub_b64`
- auth: `v1|auth|challenge_id|nonce|account_id|device_id`
- add_device: `v1|add_device|challenge_id|nonce|username|identity_pub_b64|auth_pub_b64|authorizer_device_id`
The signature is Ed25519 over the UTF-8 bytes of this string, base64'd (raw 64B, Tink NO_PREFIX).

## 3. Client architecture (new code, no UI)

```
android/src/main/kotlin/chatapp/android/
├── crypto/                      (existing)
│   ├── SqlCipherProtocolStore.kt   (+ 3 additive tables, see §8)
│   └── DatabaseKeyManager.kt
├── net/ChatApiClient.kt         HTTP client: HttpURLConnection + org.json (ZERO new deps)
│                                base URL injectable; correlation ids; no retry storms (single retry on IOException)
├── account/AccountManager.kt    registration/auth-challenge signing; token+account state persistence
├── protocol/PreKeyManager.kt    prekey generation, upload, refill thresholds; bundle → PreKeyBundle mapping
└── protocol/Messaging.kt        session-ensure → encrypt-per-target; fetch → decryptAny → persist → ACK

android/src/androidTest/kotlin/chatapp/android/e2e/Phase4E2ETest.kt   (the vertical slice, real staging)
```

Build changes (declared): `tink-android` moves from `androidTestImplementation` to `implementation` (it is already proven on-device; signing is needed by main code). No other new dependency.

## 4. Registration flow (device → real account)

1. Open SQLCipher store (identity keypair auto-generated on first open; `registration_id` = SecureRandom 1..16380 — already in the store, matches server validation).
2. Generate Ed25519 auth keypair (Tink `Ed25519Parameters`, raw 32B pub); private keyset stored ONLY in the SQLCipher DB (`auth_keyset` table).
3. `POST /auth/challenge` `{purpose:"register", username, identity_pub: b64(identityKey.publicKey.publicKeyBytes /* raw 32B — Appendix A:1 */), auth_pub: b64(authPub32)}`.
4. Sign the canonical register context (§2) with Tink → `signature`.
5. `POST /accounts {challenge_id, signature, registration_id}` → persist `{account_id, device_id, dev_no, token, token_expires_at, username}` in the SQLCipher `account_state` table.
6. PreKey upload (§5). Username: `u_<15 random alphanumerics>` (matches server regex).

## 5. PreKey generation / upload / refill (device → server wire format, all shapes verified)

- `signed_prekey`: `SignedPreKeyRecord(id, now, ECKeyPair.generate(), identityPriv.calculateSignature(pub.serialize()))` → `{key_id, public_key: b64(33B), signature: b64(64B)}`.
- `last_resort_kyber`: `KyberPreKeyRecord(id, now, KEMKeyPair.generate(KYBER_1024), sig over pub.serialize())` → `{key_id, public_key: b64(1569B), signature: b64(64B)}`.
- `one_time_prekeys`: 100 EC `PreKeyRecord`s per upload → `[{key_id, public_key: b64(33B)}]` (no signature — server contract).
- `one_time_kyber_prekeys`: 50 signed Kyber records per upload.
- key_ids: random in 0..16777215 (collision-safe: server 409 → regenerate).
- **Refill policy**: after every receive-batch, if `one_time_ec_remaining < 25` (or kyber < 15), upload a top-up batch. Upload response's remaining counts drive the threshold (no guessing — server is authoritative).

## 6. Session establish + send (sender side)

1. `GET /accounts/:recipientAccount/devices` → target devices (active only).
2. For each target device:
   - If `store.containsSession(SignalProtocolAddress(recipientAccount, devNo))` is false → `GET /devices/:deviceId/prekeys` → map to `PreKeyBundle` **exactly as verified in Appendix A:4**:
     - `identity_pub` b64→raw32→`ECPublicKey.fromPublicKeyBytes`→`IdentityKey`
     - EC pubs b64→33B→`ECPublicKey(bytes)`; Kyber pub b64→1569B→`KEMPublicKey(bytes)`; sigs b64→64B
     - `one_time_prekey == null` → `PreKeyBundle.NULL_PRE_KEY_ID` + null pub (bundle without one-time is valid — Phase 2 verified)
   - `SessionBuilder(store, remoteAddr, ownAddr).process(bundle)` (signature verification is inside libsignal — tampered bundles fail client-side, Phase 2 verified).
3. `SessionCipher(store, ownAddr, remoteAddr).encrypt(plaintextBytes)` → `ciphertext_b64 = b64(ciphertextMessage.serialize())`.
4. `POST /messages {logical_msg_id: UUID.randomUUID(), targets:[…]}` — one ciphertext per target device (Gate3-B: ciphertexts are per-device, never shared).
5. Self-sync: own account's other devices are included as targets — server treats them like any target (Phase 3 §2.3).

## 7. Receive / decrypt / ACK (receiver side)

1. `GET /messages?limit=200`.
2. Per row: `remoteAddr = SignalProtocolAddress(sender_account_id, sender_dev_no)`.
3. **decryptAny** (verified, Appendix A:5): the wire bytes of BOTH message types start with the same version byte (0x44) — type cannot be sniffed. Strategy: `try new SignalMessage(bytes)` → on `InvalidMessageException` → `new PreKeySignalMessage(bytes)`; cross-construction throws deterministically (16/16 evidence), so this fallback is sound. `SessionCipher.decrypt(...)` then returns plaintext.
4. Persist plaintext to the local `messages` mirror **before** ACK (crash-safety, §8).
5. `DuplicateMessageException` → treat as already-processed (Phase 3 §12 contract; Gate3-D) → still ACKed.
6. `POST /messages/ack {delivery_ids:[…]}` (chunked ≤ 90 per request — mirrors the server's own D1-chunking behavior).
7. Refill check (§5). Client ACK-scope and redelivery semantics come from the server (Phase 3 §7) — no client assumptions.

## 8. Persistence & crash/restart model

Additive SQLCipher tables (no change to existing schema):
- `account_state (id=1, account_id, device_id, dev_no, registration_id, username, token, token_expires_at)`
- `auth_keyset (id=1, keyset BLOB)` — Tink serialized keyset (private), inside SQLCipher only
- `messages (delivery_id TEXT PRIMARY KEY, logical_msg_id, sender_account_id, sender_dev_no, seq, plaintext BLOB, received_at)`

Restart guarantees (test scenario §10-T3):
- passphrase re-unwrapped from AndroidKeyStore (proven on-device in Phase 0.5-B)
- identity/sessions/prekeys survive (proven on-device)
- token + account state survive → no re-registration needed
- previously decrypted messages survive in the local mirror
- crash between fetch and ACK → server redelivers (`delivered` rows re-served) → decrypt → `DuplicateMessageException` → treated as processed → ACK (server contract, Phase 3 §7/§12)

## 9. Multi-device (real add_device, real self-sync)

Account A: device A1 (dev_no 1, registered). Device A2:
1. Generate fresh identity+auth keys, open a SECOND SQLCipher store (separate DB file, separate alias).
2. `POST /auth/challenge {purpose:"add_device", username, identity_pub, auth_pub, authorizer_device_id: A1.deviceId}`.
3. A2 signs the add_device context with ITS auth key → `signature`; **A1 signs the same context with ITS auth key** → `authorizer_signature` (read from A1's SQLCipher `auth_keyset`).
4. `POST /devices` → A2 gets `dev_no=2` + token → prekey upload (§5).
5. A1 sends one logical message with targets `[B1, A2]` → both decrypt (self-sync verified real).

## 10. Test plan (instrumented, real emulator → real staging)

Shared `Phase4Fixture` (lazy singleton per test class): registers account A (device A1) and account B (device B1) exactly once per run — rate-limit budget: 2 registrations (+1 add_device) per run, inside `accountsIp` 3/10min. Tokens reused across test methods (worker TTL = 30 min default).

| Test | Mandate item | Steps (all real HTTP to staging) |
|---|---|---|
| T0 `stagingReachable` | risk probe | `GET /devices/me` without token → 401 shape proves reachability + auth wall (hard-fails fast with diagnostics if the emulator cannot reach workers.dev) |
| T1 `fullLifecycle` | #6, #7 | A1: register → prekey upload → discovery of B → bundle fetch → session build → encrypt "…" → send (status queued). B1: fetch → decryptAny → plaintext equal → local persist → ACK → second fetch empty. Then B1 replies; A1 decrypts reply; next A1→B1 message is WHISPER-type (session acknowledged) |
| T2 `multiDeviceSelfSync` | #9 | A2 = real add_device (dual signatures, §9) → prekey upload → A1 sends one logical msg to `[B1, A2]` → A2 AND B1 both decrypt the same logical message |
| T3 `restartPersistence` | #8 | close both stores → reopen via KeyStore unwrap → session still present → A1→B1 WHISPER decrypt OK → token/account state intact → mirror rows intact |
| T4 `redeliveryAfterCrashBeforeAck` | #7, #8 | A1→B1 send; B1 fetch (marks delivered) **without ACK** → close store → reopen → fetch again → same rows redelivered → decrypt → `DuplicateMessageException` treated as processed → ACK → empty |

All tests log statuses only — never ciphertext, plaintext, tokens, or keys (user rule #6). CI: the existing `android-instrumented` job runs them on the emulator; `stagingUrl` passed as instrumentation runner argument (`-PstagingUrl` → `testInstrumentationRunnerArguments`), defaulting to the public staging URL.

## 11. Rate-limit budget (declared)

Per CI run (worst case): registrations 2 (`accountsIp` 3/10min — inside), challenges ~6 (`challengeIp` 10/min per IP — inside), sends ≤ 10 (`messageSendAccount` 120/min — inside), fetches ≤ 12, acks ≤ 8, bundles ≤ 4, device-lists ≤ 4 (all inside). Rate-limit 429 in any test = hard failure with diagnostics (no retry-hiding).

## 12. Risks / declared unknowns (honest list)

1. **Emulator → workers.dev reachability** on the GitHub Actions emulator: highly likely (emulator NAT uses the runner's network; the runner already reaches Cloudflare), but NOT yet proven end-to-end. Mitigation: T0 runs first and hard-fails with diagnostics if unreachable → per user rule: stop and report, no workaround without approval.
2. Emulator clock skew vs. server time: token TTL 30 min and challenge TTL 5 min tolerate seconds-level skew; T0 asserts a sane baseline (401 shape, not 500).
3. Staging is shared state: tests use random usernames/UUIDs; no cleanup needed (TTL queues, unique accounts; `accountsGlobal` 50/24h budget is ample for one run).

## 13. Mandate mapping (user's 10 points)

1. API contract documented → §2
2. Real registration → §4
3. Secure store integration → §1/§8 (existing SQLCipher store + additive tables)
4. Device discovery + bundle → §6 step 1–2
5. Real session creation → §6 (PQXDH via SessionBuilder)
6. A→B real message → §6/§7 + T1
7. Full lifecycle E2E → §10 T1
8. Crash/restart persistence → §8 + T3/T4
9. Multi-device (≥2 devices, one account) → §9 + T2
10. No UI/WebSocket/push/attachment/group/backup → §0

---

## Appendix A — Gate 4 (design-time) results (Scratch4, real libsignal-client 0.102.1 jar, 16/16 PASS)

```
[PASS] EC serialize = 33 bytes, 0x05 prefix
[PASS] EC getPublicKeyBytes = 32 bytes (raw, no prefix)
[PASS] EC serialize == 0x05 || raw32
[PASS] ECPublicKey.fromPublicKeyBytes(raw32) roundtrips
[INFO] new ECPublicKey(33B serialize) accepted: true
[INFO] new ECPublicKey(32B raw) accepted: false
[PASS] EXACTLY ONE accepted form (ambiguity ruled out)
[PASS] ctor(33B) roundtrips
[PASS] IdentityKey serialize = 33B 0x05
[PASS] IdentityKey raw = 32B
[PASS] IdentityKey(ECPublicKey.fromPublicKeyBytes(raw32)) works
[INFO] new IdentityKey(33B serialize) accepted: true
[INFO] new IdentityKey(32B raw) accepted: false
[PASS] KEM serialize = 1569B, 0x08 prefix
[PASS] new KEMPublicKey(1569B serialize) accepted
[PASS] bundle built from server byte-shapes processes + encrypts
[PASS] receiver decrypts with this mapping
[INFO] PreKeySignalMessage first byte = 0x44
[INFO] SignalMessage first byte       = 0x44
[PASS] first bytes are IDENTICAL (single-byte discriminator ruled out)
[INFO] SignalMessage(prekeyBlob) ctor threw: InvalidMessageException
[INFO] PreKeySignalMessage(whisperBlob) ctor threw: InvalidMessageException
[PASS] cross-construction throws deterministically (fallback decode is sound)
[PASS] fallback decode decrypts WHISPER correctly
SCRATCH4 RESULT: 16 checks passed
```

Key findings from Appendix A (each rules out a naive guess):
1. Raw-32 constructors REJECTED for `ECPublicKey`/`IdentityKey`; only the 33B serialize() form (or `fromPublicKeyBytes` for raw) is accepted → mapping §6 is the only correct path.
2. **Both wire formats start with byte 0x44** → the receiver CANNOT sniff the message type; the try/catch fallback (§7.3) is verified deterministic instead.
3. The exact server byte-shapes (raw-32 identity, 33B EC, 1569B KEM, 64B sigs) build a working PreKeyBundle → session → encrypt → decrypt.

## Appendix B — declared implementation decisions

1. **HTTP stack**: `HttpURLConnection` + built-in `org.json` — zero new dependencies; the slice makes ≤ 12 endpoint calls, no need for OkHttp/Retrofit (supply-chain minimalism; can be revisited in a UI phase).
2. **Tink moves to `implementation`** (already a CI-proven on-device dependency).
3. **Shared test fixture** (one registration set per run) instead of per-test registration — required by the real `accountsIp` limit; keeps tests honest (no test-only server changes).
4. **No backend changes whatsoever** — Phase 3 contract consumed as-is; the only server-visible additions are new accounts/devices/messages created by the tests.
5. **No UI** — instrumented tests are the vertical slice; screens come in a later phase.
6. **Token/auth-key storage inside SQLCipher** (not SharedPreferences, not EncryptedSharedPreferences) — one encrypted-at-rest location, one unwrap path (AndroidKeyStore), already restart-proven.
