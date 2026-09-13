# Phase 5 Design: Android App Productization & UI

Status: **PROPOSED — awaiting user approval. No Phase-5 implementation has been done.**

Goal (user mandate): a REAL, usable messenger app — installable APK where a real user can:
create account → open chat → send message → receive message → close app → reopen →
messages & sessions persist. All build/test/e2e on GitHub Actions (local machine stays cool).

Everything below is grounded in the existing, CI-proven Phase 4 assets. Every external
version/dependency claim is verified against the live artifact indexes (Appendix A) or
deferred to the CI verification build (§14) — nothing guessed.

---

## 0. Scope

**In scope:** `:app` module (Compose UI, ViewModels, Repository), onboarding, conversation
list, real chat screen, device management, encrypted history display, in-scope polling,
loading/error/retry, lifecycle/restart, navigation/state, multi-device UI, security rules,
UI + e2e tests, full CI/CD.

**Explicitly OUT of scope (user mandate):** WebSocket, push notification, attachment,
group, backup, voice/video call, read receipt. Backend/API changes only if a blocker is
proven — none found (see §15); the Phase 3 contract is consumed as-is.

---

## 1. Module structure decision (evidence-based)

**Decision: keep `:android` as-is (library) + add a new `:app` application module.**

Evidence:
1. `:android` is `com.android.library` (android/build.gradle.kts:2); the entire green CI
   chain (8 instrumented tests incl. T0–T4, AAR artifact, interop fixture extraction) runs
   against that shape. Converting it to an app would rewrite `connectedAndroidTest` wiring,
   the AAR upload, and risk the proven pipeline for zero functional gain.
2. The library layer is protocol/crypto — it must stay UI-free so "no plaintext above the
   repository boundary" (§12) is structurally enforceable, not just a convention.
3. Precedent: the app module is a standard productization pattern; Phase 4 tests keep
   working unchanged because they live in `:android`'s androidTest.

```
:app (com.android.application — NEW)
  src/main/kotlin/chatapp/app/
    ui/                 Compose screens (stateless, preview-able)
    vm/                 OnboardingViewModel, ConversationsViewModel, ChatViewModel,
                        DevicesViewModel (no Context, no libsignal, no SQL types)
    AppContainer.kt     manual DI (4 collaborators — no Hilt, §2)
    MainActivity.kt     single-activity, FLAG_SECURE (§12)
    ChatApplication.kt  owns ClientRuntime lifecycle (§9)

:android (library — unchanged APIs; additive only, §6)
  net/ChatApiClient, account/AccountManager, protocol/{PreKeyManager,Messaging},
  crypto/{SqlCipherProtocolStore, DatabaseKeyManager}
  + additive: repo/ConversationRepository.kt, runtime/ClientRuntime.kt, repo/OutboxStore (in SQLCipher)
```

**Layer law:** ViewModels see only repository-owned data classes and sealed states.
Plaintext bytes may surface as: (a) UI text for display, (b) rows in the SQLCipher mirror.
Nothing else. No composable ever imports `chatapp.android.*`.

## 2. UI stack — verified (no unverified dependency enters)

Current repo state (evidence): zero UI dependencies anywhere; Gradle 8.14.3, AGP 8.7.3,
Kotlin 2.2.20, compileSdk 35, minSdk 26, desugaring on.

| Component | Version (verified, Appendix A) | Role |
|---|---|---|
| `org.jetbrains.kotlin.plugin.compose` | **2.2.20** (Maven Central POM fetched OK — exact match to our Kotlin) | compose compiler plugin |
| `androidx.compose:compose-bom` | **2026.08.00** (latest stable, 2026‑08‑12) | UI + material3 + ui-test-junit4 |
| `androidx.activity:activity-compose` | **1.13.0** (stable 2026‑03) | single-activity host |
| `androidx.lifecycle:viewmodel-compose` + `runtime-compose` | **2.10.0** (stable 2025‑11) | VM + StateFlow collection |
| `androidx.navigation:navigation-compose` | **2.9.8** (stable 2026‑04) | in-app navigation (§10) |
| `androidx.work:work-runtime-ktx` | **2.11.2** (stable 2026‑03) | app-start catch-up work only (§7) |

Rejected (evidence-based): Hilt/DI framework (the entire graph is 5 objects — a framework is
pure supply-chain risk), Retrofit/OkHttp (`ChatApiClient` is CI-proven; swapping = risk with no
gain), Room (would fork the encrypted-store into a second schema system; the SQLCipher store is
proven and additive-DDL idempotent), XML/Fragment (dead-end for a new app, worse testability).

Unit-test additions (JVM, `:app/test`): `kotlinx-coroutines-test` (matches the coroutines
version BOM pulls — no separate pin) + JUnit4 already in the build.

**Unverified risk (declared, not hidden):** whether BOM 2026.08.00 requires `compileSdk 36`
on AGP 8.7.3 cannot be confirmed from this network (dl.google.com index paths 404 — Appendix A).
Verification is the FIRST implementation step (§14 spike). Fallback ladder, in order:
(a) use BOM **2026.06.01**; (b) bump `:app`-only compileSdk (library untouched, minSdk 26
unchanged); (c) stop and report per mandate. No silent workaround — each rung is reported.

## 3. Onboarding — account creation & login

Screens: `Welcome` → `Register` | `AddDevice` | (`AuthRefresh` shown only when needed).

- **Register:** username field with live client-side validation of the server's real rule
  `^[A-Za-z0-9_-]{1,64}$` (router.ts:39). Flow: `AccountManager.register` (UNCHANGED) →
  `PreKeyManager.uploadBatch` (UNCHANGED) → home. Server errors map to user text:
  `409 USERNAME_TAKEN` → "نام قبلاً گرفته شده", `429` → back-off message with retry button,
  transport → "خطای شبکه" + retry.
- **AddDevice (login on a second device):** username + authorizer device id typed manually
  (no QR/push in scope). Calls `AccountManager.addDevice` + authorizer signing closure —
  the dual-signature flow exactly as proven by T2. The authorizer's signature happens on the
  OTHER device — out-of-scope for one phone; Phase 5 ships the *device-side* of the flow
  (new device) plus a "show my device id" panel on the authorizer side so the human can copy it.
- **AuthRefresh:** if a token expired and silent re-issue (§6) fails, a single screen explains
  and retries — never a dead end, because identity + auth keyset live in the encrypted DB.
- If `store.loadAccountState() != null` on launch → onboarding skipped entirely (§9).

## 4. Conversation list

- Source: local encrypted mirror ONLY (works offline) — new additive view-layer query in the
  repository (§6), grouping `messages` + `contacts` rows by peer.
- Row: peer username, last-message preview, relative time, per-peer unread marker
  (last local receive time vs mirror rows), last outbound state (§8).
- "New chat": username entry → validates regex → creates a pending contact row; first send
  performs real discovery (server has no username-lookup endpoint — §15.1, honest label in UI:
  "گیرنده با اولین پیام شناسایی می‌شود"). `404` on send → "حساب یافت نشد" and the pending
  contact is deleted.
- Multi-device self-sync rows (sender = own account, other dev_no) render as a synthetic
  "همه دستگاه‌های من" conversation (§11).

## 5. Chat screen

- Message list merged from two queries: encrypted mirror (peer-scoped) + outbox (pending
  sends), ordered by time; bubbles left/right; per-message send state (§8).
- Send path: ViewModel → `ConversationRepository.send(peer, text)` →
  `Messaging.send` (UNCHANGED protocol logic) on `Dispatchers.IO`; plaintext is inserted to
  `outbox` BEFORE the network call (crash-safe), transitioned on result.
- Receive path: poller (§7) → `Messaging.receive()` → mirror insert → Flow emission →
  list updates. Self-sync messages land in the same peer thread.
- Input box disabled while a registration-less state exists; otherwise always enabled
  (send queues offline into outbox as `pending` — §8).

## 6. Storage & history (SQLCipher — additive only)

The existing `messages` mirror stays the single source of truth. Additive DDL (same
idempotent `CREATE TABLE IF NOT EXISTS` pattern as `account_state`/`auth_keyset` in Phase 4):

```sql
outbox   (local_id PK, recipient_username, plaintext BLOB, state pending|sent|failed,
          logical_msg_id NULL, error NULL, created_at, updated_at)
contacts (username PK, account_id NULL, confirmed_at, last_activity_at)
```

`ConversationRepository` (in the library, so it's testable by `:android` instrumented tests
without UI) exposes ONLY:
`registerState(): Flow<AppState>`, `conversations(): Flow<List<ConversationRow>>`,
`thread(peer): Flow<List<ThreadItem>>`, `send(...)`, `retry(localId)`, `markSeen(peer)`.
All SQL stays inside `SqlCipherProtocolStore` (same file, same passphrase, same transaction
scope). UI never touches a Cursor.

**Token refresh (additive to `AccountManager`):** `refreshToken()` = challenge `purpose:"auth"`
solved with the stored Tink auth keyset → `POST /auth/verify` (endpoint exists and is
worker-tested: router.ts:233–269) → new token persisted. Called by the repository on `401`
with `token_expires_at` near/past, exactly once per failure burst. This ADDS a method; it
does not modify any existing behavior.

## 7. Polling & refresh — inside what Android actually allows

(No WebSocket/push — mandate.)

- **Foreground (app visible):** coroutine ticker, base interval **60 s** (fits production
  `messageFetchDevice` 60/min even at multiplier=1 — ratelimit.ts:21), jittered ±10%.
  Error backoff: ×2 per consecutive failure, cap 10 min, reset on success — this repairs the
  Phase-4-declared "retry is limited" risk inside the new layer without touching
  `ChatApiClient`'s contract.
- **Backgrounded process (alive):** interval stretches to 300 s; no foreground service
  (Play-policy-sensitive, heavy, and out of the mandate's spirit); Doze may still pause it —
  declared, not hidden.
- **Process death:** NO delivery until next launch. On launch/start: WorkManager
  `OneTimeWorkRequest` (expedited) does fetch+ack catch-up + prekey refill check
  (`refillIfNeeded` EXISTS in PreKeyManager) before the UI finishes its first frame of data.
  Server TTL 7 days (messages.ts:23) means nothing is lost — only delayed; the conversations
  header honestly shows "آخرین همگام‌سازی HH:MM".

## 8. Loading / error / retry states

Sealed types, one per concern, owned by ViewModels:
- `SendState`: `Pending → Sent(queued|duplicate) | Failed(reason, retryable)` — mapped from
  `Messaging.SentMessage.serverStatus` (messages.ts:39: `queued|duplicate|rejected`) and
  `ChatApiClient.ApiException`. `rejected` (revoked recipient) surfaces as a final-state
  bubble with an explanatory icon — no auto-resend (a revoked device must not be retried).
- `SyncState`: `Idle | Syncing | Backoff(until) | Error(kind)` — global poller state.
- `Outbox recovery on launch:` `pending` rows from a previous process resume automatically
  (one attempt each, then `failed` with manual retry button).
- Manual retry = new `logical_msg_id` (server status engine is idempotent per logical id;
  reusing a logical id would read as `duplicate`, which means "already delivered", not
  "please resend" — this is exactly why retry allocates a fresh UUID).

## 9. App lifecycle & restart

Proven baseline (T3, CI): token, sessions, mirror survive process restart via KeyStore
unwrap of the SQLCipher passphrase. Phase 5 only adds the glue:
- `ChatApplication.onCreate` → build `ClientRuntime` (open store with the app's fixed alias —
  NOT the per-test aliases; managers; repository; poller) — guarded so a failed open
  (e.g. KeyStore wiped by OS) routes to a single honest error screen with "بازنشانی"
  (wipe-and-restart) as the only recovery — wiping is a user decision, never automatic.
- `MainActivity` holds no state; everything observable is in ViewModels/Flows → rotation,
  process death + recreation (SavedStateHandle only for navigation args like peer username).
- E2E restart acceptance is a CI test (§13 T‑R).

## 10. Navigation & state management

- Single activity; `NavHost` with routes: `welcome`, `register`, `addDevice`, `home` (bottom
  tabs: conversations, devices), `chat/{peer}`, each arg primitive (peer username).
- State: Kotlin `StateFlow` exclusively (compose runtime-compose `collectAsStateWithLifecycle`
  — lifecycle-aware collection is the one non-obvious correctness point; it is the documented
  purpose of that artifact). No RxJava, no LiveData (both would be new deps with zero need).
- Back stack: system back from chat → home; VMs are navigation-scoped, poller is app-scoped.

## 11. Multi-device & self-sync UI

- `Devices` tab lists `GET /accounts/:id/devices` results (existing endpoint): dev_no,
  "این دستگاه" marker (compare with local `account_state.device_id`), revoke button per other
  device (`DELETE /devices/:id` — existing, router.ts:473) with an irreversible-action dialog.
- Revoking SELF is deliberately hidden behind a typed-confirmation dialog (server makes it
  unrecoverable for that device's keyset).
- add_device entry point lives here (authorizer side: shows own `device_id` for copying;
  joining side: the §3 flow).
- Self-sync: inbound messages with `sender_account_id == my account` && other `dev_no` are
  shown in the "همه دستگاه‌های من" thread (§4) — the T2-proven self-sync surfaced in UI.

## 12. Security — UI layer

- **Zero new log calls in `:app` and in repository code.** Existing layers already
  never-log (Phase 4 rule #6). CI check: a workflow step greps `:app` + `repo/` for
  `Log\.` / `println` and fails if found (positive enforcement, not review memory).
- `FLAG_SECURE` on MainActivity (screenshots/recents redacted).
- `android:allowBackup="false"` (KeyStore-wrapped passphrase is un-restorable by design; a
  restored SQLCipher file would be a brick — prevention beats bricking).
- Token/keys never leave the library: ViewModels receive only display data; the repository
  is the sole caller of `AccountState.token`.
- Previews in the conversation list show plaintext — that IS the product function — but only
  in-app; FLAG_SECURE covers recents thumbnails; nothing is written to system logcat.

## 13. Tests (all runnable in GitHub Actions)

| Suite | Module/runner | What it proves |
|---|---|---|
| VM unit tests | `:app/test` JVM, coroutines-test; repository faked via a hand-written interface (ChatApiClient itself untouched — fake lives at the repository boundary) | state transitions, error mapping (409/429/401/rejected), backoff timing, outbox resume |
| Repository instrumented tests | `:android` androidTest (existing emulator job) | real SQLCipher DDL idempotence, outbox↔mirror flows, refreshToken against real staging |
| Compose UI tests | `:app` androidTest `createAndroidComposeRule` on the CI emulator | onboarding render+validation, list rendering from seeded mirror, chat send→bubble, error banners |
| **App e2e (acceptance)** | `:app` androidTest driving the REAL `MainActivity` on the CI emulator + real staging; counterpart = a `TestDevice` helper (proven Phase-4 pattern) running in-process as user B | the mandate's goal journey end-to-end: register → chat → send → B replies (driver) → UI receives → **kill process → relaunch → messages + session persist → second send is WHISPER-fast** |
| Existing T0–T4 + worker + interop | unchanged jobs | regression guard that productization broke nothing protocol-side |

Acceptance names (future implementation references): `A1 accountThroughUI`,
`A2 sendReceiveRealBackend`, `A3 restartPersistence`, `A4 multiDeviceSelfSyncUI`.

## 14. CI/CD plan for Phase 5 (all on GitHub Actions)

Existing pipelines stay (deploy-staging, prototype-tests, worker-tests, android-instrumented
with T0–T4 + interop). Additions:

1. **`app-build`** (new job, no emulator — fast, runs first):
   `:app:assembleDebug` + `:app:testDebugUnitTest` + the §12 no-log grep. Uploads
   `app-debug.apk` as artifact (the installable deliverable).
2. **`app-e2e`** (new job, emulator-runner pattern already proven in this repo):
   boots API-34 emulator → installs debug APK + androidTest APK → runs §13 acceptance suite
   against real staging (staging URL via instrumentation arg, same as today).
3. **Version-verification spike is implementation step 0** (before any UI code): a commit
   that ONLY adds `:app` skeleton + §2 dependency lines → CI must resolve & build. Any
   resolution/compileSdk failure → stop, report evidence, propose fallback rung (§2), await
   approval. Results documented in the Phase-5 implementation log after every step
   (user mandate), with run links.
4. Concurrency: `app-build` ~2 min on ubuntu runner; `app-e2e` ~7 min (emulator boot
   dominates — already proven in current CI). Local machine: zero builds required.
5. Artifacts per run: `app-debug.apk`, unit test reports, e2e JUnit XML + logcat, plus the
   existing android-test-reports.

Definition of done for Phase 5 = green CI including A1–A4 + downloadable APK that a human
sideloads and uses against staging.

## 15. Incompatibilities / gaps found (reported per mandate — none block the design)

1. **No username→account_id lookup endpoint** (Phase 4 report, still true: username only
   exists in register/challenge paths). Phase 5 consumes the contract as-is: discovery at
   first send (§4), account_id cached in `contacts` on success. A future
   `GET /accounts/by-username/:name` would improve UX but is a backend change → NOT proposed
   without your explicit approval.
2. **`GET /accounts/:id/devices` omits revoked devices and labels** (messages.ts:412 returns
   device_id/dev_no/registration_id only). UI labels devices locally as "Device #dev_no";
   revoked devices are invisible rather than shown-greyed. Acceptable for MVP; changing the
   response = backend change → not proposed.
3. **dl.google.com artifact-index fetch 404s from this machine** (group-index.xml and
   per-version POM paths rejected). Versions in §2 were verified via the mvnrepository index
   (mirror of Google Maven) + direct Maven Central POM for the Kotlin plugin. Authoritative
   verification = the §14 spike build. This is a tooling/network limitation, reported for
   transparency — it is why §2 declares a fallback ladder instead of asserting certainty.
4. **No incompatibility found between Compose 2.2.20-plugin/SQLCipher 4.17/libsignal 0.102.1
   at the library level** — they do not share artifact space (Compose is UI-only; both crypto
   libs are native/VM-layer), but the spike still proves the combined APK builds and the
   e2e proves them co-running on the emulator.

---

## Appendix A — version evidence (fetched 2026-09-13)

- `org.jetbrains.kotlin.plugin.compose:2.2.20` — Maven Central POM **fetched directly, 200**
  (repo1.maven.org/.../2.2.20/...pom). Exact match to project Kotlin 2.2.20.
- Compose BOM stable line (mvnrepository index of Google Maven): 2026.08.00 (2026-08-12),
  2026.06.01 (2026-07-01) — chosen 2026.08.00, fallback 2026.06.01.
- activity-compose: 1.13.0 stable (2026-03-11); 1.14.0-alpha only → chosen 1.13.0.
- navigation-compose: 2.9.8 stable (2026-04-22); 2.10.0 (2026-08-26, ~2 wk) → chosen 2.9.8
  (soak time over novelty).
- lifecycle (viewmodel-compose / runtime-compose): 2.10.0 stable (2025-11-19); 2.11.0
  (2026-06-17) → chosen 2.10.0 (soak).
- work-runtime-ktx: 2.11.2 stable (2026-03-25); 2.12 only pre-release → chosen 2.11.2.
- Direct dl.google.com POM/index fetches: **404** (Appendix item 3) — final numbers are
  verified by Gradle resolution in the §14 spike; a mismatch = stop-and-report, per mandate.
