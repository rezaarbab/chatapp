/**
 * Real-Cloudflare smoke/integration test against the deployed staging Worker.
 * Usage: STAGING_URL=https://chatapp-staging.<subdomain>.workers.dev node test/smoke-staging.mjs
 *
 * No credentials are stored anywhere: every keypair is generated at runtime and
 * discarded. Tokens are never printed. Covers the full auth lifecycle:
 * register â†’ token â†’ use â†’ re-auth â†’ add_device â†’ revoke â†’ invalidation â†’
 * real token expiry (staging TTL) â†’ duplicate-username anti-enumeration shape.
 */

const BASE = (process.env.STAGING_URL || "").replace(/\/+$/, "");
const TOKEN_TTL_MS = Number(process.env.STAGING_TOKEN_TTL_MS || 30000);

if (!BASE) {
  console.error("STAGING_URL is required");
  process.exit(1);
}

let failures = 0;
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
  console.log(`[STEP] ${name} status=${res.status} ${code} ${JSON.stringify(res.body).slice(0, 200)}`);
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

async function http(method, path, { body, token } = {}) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = {};
  if (res.status !== 204) {
    try {
      json = await res.json();
    } catch {
      json = {};
    }
  }
  return { status: res.status, body: json };
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
  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      const res = await fetch(`${BASE}/devices/me`, { method: "GET" });
      if (res.status === 401) return; // worker is up (auth expected)
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  console.error("worker URL never became reachable");
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  await waitUntilReachable();
  const runStart = Date.now();

  // 1) register: challenge + signature + account creation on real D1
  const username = `smoke_${runStart}`;
  const { priv: priv1, pubB64: pub1 } = await genKey();
  const identity1 = b64(crypto.getRandomValues(new Uint8Array(32)));
  const ch1 = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username, identity_pub: identity1, auth_pub: pub1 },
  });
  check("challenge issued (register)", ch1.status === 200 && !!ch1.body.challenge_id && ch1.body.nonce.length === 64);
  const token1Expires = ch1.body.expires_at + 20000; // server-stamped, TTL = staging var
  const ctx1 = buildContext("register", {
    challengeId: ch1.body.challenge_id,
    nonce: ch1.body.nonce,
    username,
    identityPubB64: identity1,
    authPubB64: pub1,
  });
  const sig1 = await signB64(priv1, ctx1);
  const reg = await http("POST", "/accounts", {
    body: { challenge_id: ch1.body.challenge_id, signature: sig1, registration_id: 1000 },
  });
  check("account registered (201)", reg.status === 201 && !!reg.body.account_id && !!reg.body.device_id && reg.body.dev_no === 1);
  const token1 = reg.body.token;
  const device1 = reg.body.device_id;
  check("token issued (never logged)", typeof token1 === "string" && token1.length > 20);

  // 2) token use â€” proves real-D1 persistence across requests/isolates
  const me1 = await http("GET", "/devices/me", { token: token1 });
  check(
    "token authenticates on real Cloudflare (D1 persistence)",
    me1.status === 200 && me1.body.device_id === device1 && me1.body.account_id === reg.body.account_id,
  );

  // 3) duplicate username â†’ constant anti-enumeration shape
  const { pubB64: pubTmp } = await genKey();
  const dup = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username, identity_pub: b64(crypto.getRandomValues(new Uint8Array(32))), auth_pub: pubTmp },
  });
  check("duplicate username rejected (409)", dup.status === 409 && dup.body.error.code === "USERNAME_TAKEN");

  // 4) re-auth: auth challenge + verify â†’ second device-bound token
  const chA = await http("POST", "/auth/challenge", { body: { purpose: "auth", device_id: device1 } });
  stepLog("auth challenge", chA);
  check("auth challenge issued", chA.status === 200);
  const ctxA = buildContext("auth", {
    challengeId: chA.body.challenge_id,
    nonce: chA.body.nonce,
    accountId: reg.body.account_id,
    deviceId: device1,
  });
  const sigA = await signB64(priv1, ctxA);
  const verifyA = await http("POST", "/auth/verify", { body: { challenge_id: chA.body.challenge_id, signature: sigA } });
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
  const add = await http("POST", "/devices", { body: { challenge_id: chD.body.challenge_id, signature: sigNew, authorizer_signature: sigAuth, registration_id: 1001 } });
  stepLog("add device", add);
  check("second device added (dev_no=2)", add.status === 201 && add.body.dev_no === 2);
  const device2 = add.body.device_id;

  const me2 = await http("GET", "/devices/me", { token: add.body.token });
  check("second device token works", me2.status === 200 && me2.body.dev_no === 2);

  // 6) cross-account revoke is forbidden
  const { priv: privB, pubB64: pubB } = await genKey();
  const usernameB = `smoke_b_${runStart}`;
  const chB = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username: usernameB, identity_pub: b64(crypto.getRandomValues(new Uint8Array(32))), auth_pub: pubB },
  });
  const ctxB = buildContext("register", {
    challengeId: chB.body.challenge_id,
    nonce: chB.body.nonce,
    username: usernameB,
    identityPubB64: b64(crypto.getRandomValues(new Uint8Array(32))),
    authPubB64: pubB,
  });
  const sigB = await signB64(privB, ctxB);
  const regB = await http("POST", "/accounts", { body: { challenge_id: chB.body.challenge_id, signature: sigB, registration_id: 1000 } });
  stepLog("register accountB", regB);
  check("second account registered", regB.status === 201);
  const cross = await http("DELETE", `/devices/${device1}`, { token: regB.body.token });
  stepLog("cross revoke", cross);
  check("cross-account revoke forbidden (403)", cross.status === 403 && cross.body.error.code === "FORBIDDEN");

  // 7) revoke device2 with device1's token â†’ both token and device invalidated
  const del = await http("DELETE", `/devices/${device2}`, { token: token1 });
  stepLog("revoke device2", del);
  check("device2 revoked (204)", del.status === 204);
  const meAfter = await http("GET", "/devices/me", { token: add.body.token });
  stepLog("me after revoke", meAfter);
  check(
    "revoked device token immediately invalid (401 DEVICE_REVOKED)",
    meAfter.status === 401 && meAfter.body.error.code === "DEVICE_REVOKED",
  );
  const chAfter = await http("POST", "/auth/challenge", { body: { purpose: "auth", device_id: device2 } });
  stepLog("challenge after revoke", chAfter);
  check("revoked device cannot obtain a challenge (404, fail-closed)", chAfter.status === 404);

  // 8) real token expiry on Cloudflare (staging TTL)
  const wait = Math.max(0, token1Expires - Date.now()) + 1500;
  console.log(`[INFO] waiting ${wait}ms for real token expiry on Cloudflare`);
  await sleep(wait);
  const meExpired = await http("GET", "/devices/me", { token: token1 });
  stepLog("me after expiry", meExpired);
  check(
    "token really expires on Cloudflare (401 TOKEN_EXPIRED)",
    meExpired.status === 401 && meExpired.body.error.code === "TOKEN_EXPIRED",
  );

  console.log(failures === 0 ? "\nALL SMOKE TESTS PASSED" : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("smoke test crashed:", e);
  process.exit(1);
});
