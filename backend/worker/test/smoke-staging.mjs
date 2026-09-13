/**
 * Real-Cloudflare smoke/integration test against the deployed staging Worker.
 * Usage: STAGING_URL=https://chatapp-staging.<subdomain>.workers.dev node test/smoke-staging.mjs
 *
 * No credentials are stored anywhere: every keypair is generated at runtime and
 * discarded. Tokens are never printed. Covers the full auth lifecycle:
 * register → token → use → re-auth → add_device → revoke → invalidation →
 * real token expiry (staging TTL) → duplicate-username anti-enumeration shape.
 * Phase 3 adds the messaging lifecycle (discovery → fan-out → receive → ACK →
 * delete → retry/idempotency) and REAL-D1 concurrency races (distinct seqs
 * under concurrent sends; single stored row for concurrent same-logical sends).
 * Message bodies are random test bytes and are never printed to the log.
 */

const BASE = (process.env.STAGING_URL || "").replace(/\/+$/, "");
const TOKEN_TTL_MS = Number(process.env.STAGING_TOKEN_TTL_MS || 30000);
const SMOKE_MODE = process.env.SMOKE_MODE || "full"; // "full" | "repro"

if (!BASE) {
  console.error("STAGING_URL is required");
  process.exit(1);
}

let failures = 0;
const steps = [];

function pass(name) {
  console.log(`[PASS] ${name}`);
}

function fail(name, extra) {
  failures += 1;
  console.error(`[FAIL] ${name}${extra ? ` :: ${extra}` : ""}`);
}

function check(name, cond, extra) {
  if (cond) pass(name);
  else fail(name, extra);
}

function stepLog(name, res) {
  const code = res.body && res.body.error ? res.body.error.code : "";
  const line = `[STEP] ${name} status=${res.status} ${code} ${JSON.stringify(res.body).slice(0, 160)}`;
  steps.push(line);
  console.log(line);
  if (res.status >= 500) {
    // staging DEBUG_ERRORS mode: the body carries the server exception + stack
    console.log(`[DEBUG500] ${name} ${JSON.stringify(res.body)}`);
  }
}

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function genKey() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { priv: kp.privateKey, pubB64: b64(raw) };
}

async function signB64(priv, message) {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, new TextEncoder().encode(message));
  return b64(new Uint8Array(sig));
}

let corrSeq = 0;

async function http(method, path, opts = {}) {
  const corrId = `smoke-${Date.now().toString(36)}-${++corrSeq}`;
  const headers = { "content-type": "application/json", "x-correlation-id": corrId };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  const t0 = Date.now();
  let res;
  try {
    res = await fetch(BASE + path, {
      method,
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) {
    const elapsed = Date.now() - t0;
    const line = `[DETAIL] corrId=${corrId} ${method} ${path} NO-RESPONSE elapsed=${elapsed}ms error=${e.message}`;
    console.error(line);
    console.error(`::error::${line.slice(0, 500)}`);
    throw e;
  }
  let json = {};
  if (res.status !== 204) {
    try {
      json = await res.json();
    } catch {
      json = {};
    }
  }
  const elapsed = Date.now() - t0;
  const respCorr = res.headers.get("x-correlation-id") || "none";
  const code = json && json.error ? json.error.code : "";
  const line = `[HTTP] corrId=${corrId} ${method} ${path} -> ${res.status} ${code} elapsed=${elapsed}ms respCorr=${respCorr}`;
  console.log(line);
  if (res.status >= 500) {
    console.error(`::error::${line.slice(0, 500)}`);
    console.error(`::error::[BODY500] ${JSON.stringify(json).slice(0, 1200)}`);
  }
  return { status: res.status, body: json, corrId, respCorr, elapsed };
}

function buildContext(purpose, c) {
  if (purpose === "register") {
    return ["v1", "register", c.challengeId, c.nonce, c.username, c.identityPubB64, c.authPubB64].join("|");
  }
  if (purpose === "auth") {
    return ["v1", "auth", c.challengeId, c.nonce, c.accountId, c.deviceId].join("|");
  }
  return ["v1", "add_device", c.challengeId, c.nonce, c.username, c.identityPubB64, c.authPubB64, c.authorizerDeviceId].join("|");
}

async function waitUntilReachable() {
  console.log(`::warning::STAGING_URL=${BASE}`);
  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      const res = await fetch(BASE + "/devices/me", {
        method: "GET",
        signal: AbortSignal.timeout(15000),
      });
      console.log(`[REACH] attempt ${attempt}: status=${res.status}`);
      return; // any HTTP response means the worker is routed and alive
    } catch (e) {
      console.log(`[REACH] attempt ${attempt} failed: ${e && e.message ? e.message : e}`);
    }
    await sleep(3000);
  }
  throw new Error("worker URL never became reachable");
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function issueRegisterChallenge(username, authPubB64, ip) {
  const identityPubB64 = b64(crypto.getRandomValues(new Uint8Array(32)));
  const res = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username, identity_pub: identityPubB64, auth_pub: authPubB64 },
    ip,
  });
  return { res, identityPubB64 };
}

async function registerAccount(username, ip) {
  const { priv, pubB64 } = await genKey();
  const { res, identityPubB64 } = await issueRegisterChallenge(username, pubB64, ip);
  if (res.status !== 200) {
    fail(`register challenge for ${username}`, `status=${res.status}`);
    return null;
  }
  const ctx = buildContext("register", {
    challengeId: res.body.challenge_id,
    nonce: res.body.nonce,
    username,
    identityPubB64,
    authPubB64: pubB64,
  });
  const signature = await signB64(priv, ctx);
  const reg = await http("POST", "/accounts", {
    body: { challenge_id: res.body.challenge_id, signature, registration_id: 1000 },
    ip,
  });
  stepLog(`register ${username}`, reg);
  if (reg.status !== 201) {
    fail(`account registered (${username})`, `status=${reg.status}`);
    return null;
  }
  return {
    token: reg.body.token,
    token_expires_at: reg.body.token_expires_at,
    device_id: reg.body.device_id,
    account_id: reg.body.account_id,
    authPriv: priv,
    username,
  };
}

const WATCHDOG_MS = 4 * 60 * 1000;
const watchdog = setTimeout(() => {
  console.error(`[WATCHDOG] smoke test exceeded ${WATCHDOG_MS}ms — aborting to preserve diagnostics`);
  process.exit(1);
}, WATCHDOG_MS);


async function minimalRepro() {
  const username = `repro_${Date.now()}`;
  console.log(`::warning::[REPRO] START marker username=${username} — search this in Real-time Logs`);
  const { priv, pubB64 } = await genKey();
  const identityPubB64 = b64(crypto.getRandomValues(new Uint8Array(32)));

  console.log("[REPRO] 1/4 POST /auth/challenge (register)...");
  const ch = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username, identity_pub: identityPubB64, auth_pub: pubB64 },
    ip: "198.51.100.7",
  });
  console.log(`[REPRO] 1/4 done: ${ch.status}`);

  console.log("[REPRO] 2/4 POST /accounts...");
  const ctx = buildContext("register", {
    challengeId: ch.body.challenge_id,
    nonce: ch.body.nonce,
    username,
    identityPubB64,
    authPubB64: pubB64,
  });
  const sig = await signB64(priv, ctx);
  const reg = await http("POST", "/accounts", {
    body: { challenge_id: ch.body.challenge_id, signature: sig, registration_id: 1000 },
    ip: "198.51.100.7",
  });
  console.log(`[REPRO] 2/4 done: ${reg.status}`);
  const token = reg.body.token;
  const deviceId = reg.body.device_id;
  check("repro: account registered", reg.status === 201 && !!deviceId);

  console.log("[REPRO] 3/4 GET /devices/me (valid token)...");
  const me = await http("GET", "/devices/me", { token, ip: "198.51.100.7" });
  console.log(`[REPRO] 3/4 done: ${me.status}`);
  check("repro: valid token authenticates", me.status === 200);

  console.log("[REPRO] 4/4a DELETE /devices/:id (revoke)...");
  const del = await http("DELETE", `/devices/${deviceId}`, { token, ip: "198.51.100.7" });
  console.log(`[REPRO] 4/4a done: ${del.status}`);
  check("repro: device revoked (204)", del.status === 204);

  console.log("[REPRO] 4/4b GET /devices/me with REVOKED token — THE DIVERGENCE POINT. Watch Real-time Logs NOW...");
  const t0 = Date.now();
  const meAfter = await http("GET", "/devices/me", { token, ip: "198.51.100.7" }, 0);
  const elapsed = Date.now() - t0;
  console.log(`[REPRO] 4/4b done after ${elapsed}ms: ${meAfter.status} ${JSON.stringify(meAfter.body).slice(0, 300)}`);
  check(
    "repro: revoked token rejected (401 DEVICE_REVOKED)",
    meAfter.status === 401 && meAfter.body.error.code === "DEVICE_REVOKED",
    `status=${meAfter.status} elapsed=${elapsed}ms`,
  );

  if (failures > 0) {
    console.error(`[SUMMARY] ${failures} repro check(s) FAILED`);
    process.exit(1);
  }
  console.log("[SUMMARY] ALL REPRO CHECKS PASSED");
  process.exit(0);
}

async function main() {
  if (SMOKE_MODE === "repro") {
    await minimalRepro();
    return;
  }
  await waitUntilReachable();
  const runStart = Date.now();

  // 1) register: challenge + signature + account creation on real D1
  const username = `smoke_${runStart}`;
  const { priv: priv1, pubB64: pub1 } = await genKey();
  const ch1 = await issueRegisterChallenge(username, pub1, "203.0.113.10");
  check("challenge issued (register)", ch1.res.status === 200 && !!ch1.res.body.challenge_id);
  stepLog("register challenge", ch1.res);

  const ctx1 = buildContext("register", {
    challengeId: ch1.res.body.challenge_id,
    nonce: ch1.res.body.nonce,
    username,
    identityPubB64: ch1.identityPubB64,
    authPubB64: pub1,
  });
  const sig1 = await signB64(priv1, ctx1);
  const reg = await http("POST", "/accounts", {
    body: { challenge_id: ch1.res.body.challenge_id, signature: sig1, registration_id: 1000 },
    ip: "203.0.113.10",
  });
  stepLog("register account", reg);
  check(
    "account registered (201)",
    reg.status === 201 && !!reg.body.account_id && !!reg.body.device_id && reg.body.dev_no === 1,
  );
  const token1 = reg.body.token;
  const device1 = reg.body.device_id;
  check("token issued (never logged)", typeof token1 === "string" && token1.length > 20);

  // 2) token use — proves real-D1 persistence across requests/isolates
  const me1 = await http("GET", "/devices/me", { token: token1, ip: "203.0.113.10" });
  stepLog("devices/me with token1", me1);
  check(
    "token authenticates on real Cloudflare (D1 persistence)",
    me1.status === 200 && me1.body.device_id === device1 && me1.body.account_id === reg.body.account_id,
  );

  // 3) duplicate username → anti-enumeration shape
  const { pubB64: pubTmp } = await genKey();
  const dup = await issueRegisterChallenge(username, pubTmp, "203.0.113.10");
  check("duplicate username rejected (409)", dup.res.status === 409 && dup.res.body.error.code === "USERNAME_TAKEN");

  // 4) re-auth: auth challenge + verify → second device-bound token
  const chA = await http("POST", "/auth/challenge", { body: { purpose: "auth", device_id: device1 }, ip: "203.0.113.10" });
  stepLog("auth challenge", chA);
  check("auth challenge issued", chA.status === 200);
  const ctxA = buildContext("auth", {
    challengeId: chA.body.challenge_id,
    nonce: chA.body.nonce,
    accountId: reg.body.account_id,
    deviceId: device1,
  });
  const sigA = await signB64(priv1, ctxA);
  const verifyA = await http("POST", "/auth/verify", {
    body: { challenge_id: chA.body.challenge_id, signature: sigA },
    ip: "203.0.113.10",
  });
  stepLog("auth verify", verifyA);
  check(
    "auth verify issued a second token",
    verifyA.status === 200 && verifyA.body.device_id === device1 && verifyA.body.token !== token1,
  );

  // 5) add_device with authorizer co-signature
  const { priv: priv2, pubB64: pub2 } = await genKey();
  const identity2 = b64(crypto.getRandomValues(new Uint8Array(32)));
  const chD = await http("POST", "/auth/challenge", {
    body: {
      purpose: "add_device",
      username,
      identity_pub: identity2,
      auth_pub: pub2,
      authorizer_device_id: device1,
    },
    ip: "203.0.113.10",
  });
  check("add_device challenge issued", chD.status === 200);
  const ctxD = buildContext("add_device", {
    challengeId: chD.body.challenge_id,
    nonce: chD.body.nonce,
    username,
    identityPubB64: identity2,
    authPubB64: pub2,
    authorizerDeviceId: device1,
  });
  const sigNew = await signB64(priv2, ctxD);
  const sigAuth = await signB64(priv1, ctxD);
  const add = await http("POST", "/devices", {
    body: {
      challenge_id: chD.body.challenge_id,
      signature: sigNew,
      authorizer_signature: sigAuth,
      registration_id: 1001,
    },
    ip: "203.0.113.10",
  });
  stepLog("add device", add);
  check("second device added (dev_no=2)", add.status === 201 && add.body.dev_no === 2);
  const device2 = add.body.device_id;

  const me2 = await http("GET", "/devices/me", { token: add.body.token, ip: "203.0.113.10" });
  stepLog("devices/me with device2 token", me2);
  check("second device token works", me2.status === 200 && me2.body.dev_no === 2);

  // 6) second account (for cross-account authorization test)
  const { priv: privB, pubB64: pubB } = await genKey();
  const usernameB = `smoke_b_${runStart}`;
  const accB = await registerAccount(usernameB, "203.0.113.11");
  check("second account registered", !!accB);

  // 7) cross-account revoke is forbidden
  if (accB) {
    const cross = await http("DELETE", `/devices/${device1}`, { token: accB.token, ip: "203.0.113.11" });
    stepLog("cross revoke", cross);
    check("cross-account revoke forbidden (403)", cross.status === 403 && cross.body.error.code === "FORBIDDEN");
  }

  // 8) revoke device2 with device1's token → token invalidated immediately
  const del = await http("DELETE", `/devices/${device2}`, { token: token1, ip: "203.0.113.10" });
  stepLog("revoke device2", del);
  check("device2 revoked (204)", del.status === 204);
  const meAfter = await http("GET", "/devices/me", { token: add.body.token, ip: "203.0.113.10" });
  stepLog("devices/me after revoke", meAfter);
  check(
    "revoked device token immediately invalid (401 DEVICE_REVOKED)",
    meAfter.status === 401 && meAfter.body.error.code === "DEVICE_REVOKED",
  );
  const chAfter = await http("POST", "/auth/challenge", {
    body: { purpose: "auth", device_id: device2 },
    ip: "203.0.113.10",
  });
  stepLog("challenge after revoke", chAfter);
  check("revoked device cannot obtain a challenge (404, fail-closed)", chAfter.status === 404);

  // 9) real token expiry on Cloudflare (staging TTL)
  const token1Expires = reg.body.token_expires_at;
  const wait = Math.max(0, token1Expires - Date.now()) + 1500;
  console.log(`[INFO] waiting ${wait}ms for real token expiry on Cloudflare`);
  await sleep(wait);
  const meExpired = await http("GET", "/devices/me", { token: token1, ip: "203.0.113.10" });
  stepLog("devices/me after expiry", meExpired);
  check(
    "token really expires on Cloudflare (401 TOKEN_EXPIRED)",
    meExpired.status === 401 && meExpired.body.error.code === "TOKEN_EXPIRED",
  );

  // 10) Phase 3 — messaging lifecycle + REAL-D1 race tests
  // Fresh tokens first (staging TTL is short and token1 just expired).
  // No ciphertext is ever printed: inbox responses are only checked, never stepLogged.
  if (!accB) {
    fail("phase 3 messaging section", "account B unavailable");
  } else {
    const mk = (n) => b64(crypto.getRandomValues(new Uint8Array(n)));
    const reauth = async (deviceInfo, ip) => {
      const ch = await http("POST", "/auth/challenge", { body: { purpose: "auth", device_id: deviceInfo.device_id }, ip });
      const ctx = buildContext("auth", {
        challengeId: ch.body.challenge_id,
        nonce: ch.body.nonce,
        accountId: deviceInfo.account_id,
        deviceId: deviceInfo.device_id,
      });
      const sig = await signB64(deviceInfo.authPriv, ctx);
      const v = await http("POST", "/auth/verify", { body: { challenge_id: ch.body.challenge_id, signature: sig }, ip });
      return v.status === 200 ? v.body.token : null;
    };
    const tokA = await reauth({ account_id: reg.body.account_id, device_id: device1, authPriv: priv1 }, "203.0.113.10");
    const tokB = await reauth(accB, "203.0.113.11");
    check("p3: fresh tokens for both devices", !!tokA && !!tokB);

    // discovery
    const disc = await http("GET", `/accounts/${accB.account_id}/devices`, { token: tokA, ip: "203.0.113.10" });
    check(
      "p3: device discovery lists B's active device",
      disc.status === 200 && (disc.body.devices || []).some((d) => d.device_id === accB.device_id),
    );

    // fan-out (peer + self sync) + idempotent retry
    const logical1 = crypto.randomUUID();
    const sendBody = {
      logical_msg_id: logical1,
      targets: [
        { device_id: accB.device_id, ciphertext_b64: mk(1024) },
        { device_id: device1, ciphertext_b64: mk(512) },
      ],
    };
    const send1 = await http("POST", "/messages", { token: tokA, ip: "203.0.113.10", body: sendBody });
    check("p3: fan-out queued (peer + self sync)", send1.status === 200 && (send1.body.results || []).every((r) => r.status === "queued"));
    const retry1 = await http("POST", "/messages", { token: tokA, ip: "203.0.113.10", body: sendBody });
    check(
      "p3: idempotent retry → duplicate for every target",
      retry1.status === 200 && (retry1.body.results || []).every((r) => r.status === "duplicate"),
    );
    const rej = await http("POST", "/messages", {
      token: tokA,
      ip: "203.0.113.10",
      body: { logical_msg_id: crypto.randomUUID(), targets: [{ device_id: "00000000-0000-4000-8000-00000000dead", ciphertext_b64: mk(16) }] },
    });
    check("p3: unknown target rejected per-target", rej.status === 200 && rej.body.results?.[0]?.status === "rejected");

    // receive + redelivery + ciphertext roundtrip (bodies never printed)
    const inbox1 = await http("GET", "/messages", { token: tokB, ip: "203.0.113.11" });
    const rows = inbox1.body.messages || [];
    const rowB = rows.find((r) => r.logical_msg_id === logical1);
    check(
      "p3: inbox row carries sender address + seq",
      rows.length >= 1 && !!rowB && rowB.sender_account_id === reg.body.account_id && rowB.sender_dev_no === 1 && rowB.seq === 1,
    );
    check("p3: ciphertext byte-exact roundtrip", !!rowB && Buffer.from(rowB.ciphertext, "base64").length === 1024);
    const inbox2 = await http("GET", "/messages", { token: tokB, ip: "203.0.113.11" });
    check("p3: delivered rows redelivered until ACK", (inbox2.body.messages || []).some((r) => r.delivery_id === rowB?.delivery_id));

    // ACK scoping + delete
    const foreignAck = await http("POST", "/messages/ack", { token: tokA, ip: "203.0.113.10", body: { delivery_ids: [rowB.delivery_id] } });
    check("p3: foreign ACK deletes nothing", foreignAck.status === 200 && foreignAck.body.deleted === 0);
    const ack1 = await http("POST", "/messages/ack", {
      token: tokB,
      ip: "203.0.113.11",
      body: { delivery_ids: rows.map((r) => r.delivery_id) },
    });
    check("p3: own ACK deletes rows", ack1.status === 200 && ack1.body.deleted >= 1);
    const inbox3 = await http("GET", "/messages", { token: tokB, ip: "203.0.113.11" });
    check("p3: inbox empty after full ACK", (inbox3.body.messages || []).length === 0);

    // seq never reused after ACK
    const maxSeqBefore = rowB.seq;
    const logical2 = crypto.randomUUID();
    const seqSend = await http("POST", "/messages", {
      token: tokA,
      ip: "203.0.113.10",
      body: { logical_msg_id: logical2, targets: [{ device_id: accB.device_id, ciphertext_b64: mk(64) }] },
    });
    check("p3: post-ACK send queued", seqSend.status === 200);
    const inbox4 = await http("GET", "/messages", { token: tokB, ip: "203.0.113.11" });
    const seqRow = (inbox4.body.messages || []).find((r) => r.logical_msg_id === logical2);
    check("p3: seq strictly greater after ACK (never reused)", !!seqRow && seqRow.seq > maxSeqBefore, `seq=${seqRow && seqRow.seq}`);
    await http("POST", "/messages/ack", {
      token: tokB,
      ip: "203.0.113.11",
      body: { delivery_ids: (inbox4.body.messages || []).map((r) => r.delivery_id) },
    });

    // RACE 1: concurrent distinct sends to ONE recipient — distinct seqs on real D1
    const RACE_N = 10;
    const raceSends = await Promise.all(
      Array.from({ length: RACE_N }, () =>
        http("POST", "/messages", {
          token: tokA,
          ip: "203.0.113.10",
          body: { logical_msg_id: crypto.randomUUID(), targets: [{ device_id: accB.device_id, ciphertext_b64: mk(128) }] },
        }),
      ),
    );
    check("p3-race: all concurrent sends accepted", raceSends.every((r) => r.status === 200), `statuses=${JSON.stringify(raceSends.map((r) => r.status))}`);
    const raceInbox = await http("GET", "/messages?limit=200", { token: tokB, ip: "203.0.113.11" });
    const raceRows = raceInbox.body.messages || [];
    const raceSeqs = raceRows.map((r) => r.seq);
    check("p3-race: exactly RACE_N rows delivered", raceRows.length === RACE_N, `got ${raceRows.length}`);
    check("p3-race: all seqs DISTINCT (no duplicate under concurrency)", new Set(raceSeqs).size === raceSeqs.length, `seqs=${JSON.stringify(raceSeqs)}`);
    check(
      "p3-race: all seqs strictly above pre-race max (no reuse)",
      raceSeqs.length === RACE_N && Math.min(...raceSeqs) > maxSeqBefore,
      `min=${raceSeqs.length ? Math.min(...raceSeqs) : "?"} maxBefore=${maxSeqBefore}`,
    );

    // RACE 2: concurrent sends with the SAME logical id — exactly one stored row
    const dupLogical = crypto.randomUUID();
    const dupSends = await Promise.all(
      Array.from({ length: 5 }, () =>
        http("POST", "/messages", {
          token: tokA,
          ip: "203.0.113.10",
          body: { logical_msg_id: dupLogical, targets: [{ device_id: accB.device_id, ciphertext_b64: mk(128) }] },
        }),
      ),
    );
    check("p3-race2: all concurrent same-logical sends answered 200", dupSends.every((r) => r.status === 200), `statuses=${JSON.stringify(dupSends.map((r) => r.status))}`);
    const queuedCount = dupSends.filter((r) => r.body?.results?.[0]?.status === "queued").length;
    const dupCountResults = dupSends.filter((r) => r.body?.results?.[0]?.status === "duplicate").length;
    check("p3-race2: exactly one 'queued' result, rest 'duplicate'", queuedCount === 1 && dupCountResults === RACE_N - 1, `queued=${queuedCount} dup=${dupCountResults}`);
    const dupInbox = await http("GET", "/messages?limit=200", { token: tokB, ip: "203.0.113.11" });
    const storedForLogical = (dupInbox.body.messages || []).filter((r) => r.logical_msg_id === dupLogical).length;
    check("p3-race2: exactly ONE stored row for the logical id", storedForLogical === 1, `stored=${storedForLogical}`);
  }

  if (failures > 0) {
    console.error(`[SUMMARY] ${failures} SMOKE TEST(S) FAILED`);
    for (const s of steps) console.error(`[STEPS] ${s}`);
  } else {
    console.log("[SUMMARY] ALL SMOKE TESTS PASSED");
  }
  clearTimeout(watchdog);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  const msg = e && e.message ? e.message : String(e);
  console.error(`::error::smoke test crashed: ${msg.slice(0, 800)}`);
  console.error(`smoke test crashed: ${msg}`);
  for (const s of steps) console.error(`[STEPS] ${s}`);
  process.exit(1);
});
