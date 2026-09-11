import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildContext } from "../src/auth";
import { checkRateLimit } from "../src/ratelimit";

/**
 * Phase 1.3 — Authentication & Token Lifecycle (HTTP-level via SELF.fetch).
 * All signatures in tests are produced with the official WebCrypto Ed25519 —
 * the exact primitive the Worker uses for verification.
 */

type Json = Record<string, any>;

const migrations = JSON.parse(
  (globalThis as Record<string, unknown>).MIGRATIONS as string,
) as { name: string; sql: string }[];

function b64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function genKey(): Promise<{ priv: CryptoKey; pubB64: string }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { priv: kp.privateKey, pubB64: b64(raw) };
}

async function signB64(priv: CryptoKey, message: string): Promise<string> {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, new TextEncoder().encode(message));
  return b64(new Uint8Array(sig));
}

async function http(
  method: string,
  path: string,
  opts: { body?: Json; token?: string; ip?: string } = {},
): Promise<{ status: number; body: Json }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "CF-Connecting-IP": opts.ip ?? "1.2.3.4",
  };
  if (opts.token) headers["authorization"] = `Bearer ${opts.token}`;
  const res = await SELF.fetch(`https://example.com${path}`, {
    method,
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let body: Json = {};
  if (res.status !== 204) {
    try {
      body = (await res.json()) as Json;
    } catch {
      body = {};
    }
  }
  return { status: res.status, body };
}

function setNow(ms: number | null) {
  (env as Record<string, unknown>).NOW_OVERRIDE_MS = ms === null ? "" : String(ms);
}

let usernameCounter = 0;
function nextUsername(prefix: string): string {
  usernameCounter += 1;
  return `${prefix}_${usernameCounter}`;
}

interface RegisterChallengeResult {
  status: number;
  body: Json;
  identityPubB64: string;
}

async function issueRegisterChallenge(
  username: string,
  authPubB64: string,
  ip: string,
): Promise<RegisterChallengeResult> {
  const identityPubB64 = b64(crypto.getRandomValues(new Uint8Array(32)));
  const res = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username, identity_pub: identityPubB64, auth_pub: authPubB64 },
    ip,
  });
  return { status: res.status, body: res.body, identityPubB64 };
}

interface Registered {
  token: string;
  token_expires_at: number;
  device_id: string;
  account_id: string;
  authPriv: CryptoKey;
  username: string;
}

async function registerAccount(username: string, ip: string): Promise<Registered> {
  const { priv, pubB64 } = await genKey();
  const ch = await issueRegisterChallenge(username, pubB64, ip);
  expect(ch.status).toBe(200);
  const ctx = buildContext("register", {
    challengeId: ch.body.challenge_id,
    nonce: ch.body.nonce,
    username,
    identityPubB64: ch.identityPubB64,
    authPubB64: pubB64,
  });
  const signature = await signB64(priv, ctx);
  const reg = await http("POST", "/accounts", {
    body: { challenge_id: ch.body.challenge_id, signature, registration_id: 1000 },
    ip,
  });
  expect(reg.status).toBe(201);
  return {
    token: reg.body.token,
    token_expires_at: reg.body.token_expires_at,
    device_id: reg.body.device_id,
    account_id: reg.body.account_id,
    authPriv: priv,
    username,
  };
}

beforeAll(async () => {
  for (const m of migrations) {
    await env.DB.exec(m.sql);
  }
});

afterAll(() => {
  setNow(null);
});

describe("registration", () => {
  it("registers an account and binds the token to its device", async () => {
    const acc = await registerAccount(nextUsername("user"), "10.0.0.1");
    const me = await http("GET", "/devices/me", { token: acc.token, ip: "10.0.0.1" });
    expect(me.status).toBe(200);
    expect(me.body.device_id).toBe(acc.device_id);
    expect(me.body.account_id).toBe(acc.account_id);
    expect(me.body.dev_no).toBe(1);
  });

  it("rejects duplicate username at challenge time", async () => {
    const username = nextUsername("dup");
    const { pubB64 } = await genKey();
    const first = await issueRegisterChallenge(username, pubB64, "10.0.0.2");
    expect(first.status).toBe(200);
    const second = await issueRegisterChallenge(username, pubB64, "10.0.0.2");
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe("USERNAME_TAKEN");
  });

  it("rejects invalid register signature and creates nothing", async () => {
    const username = nextUsername("badsig");
    const { pubB64 } = await genKey();
    const attacker = await genKey();
    const ch = await issueRegisterChallenge(username, pubB64, "10.0.0.3");
    expect(ch.status).toBe(200);
    const ctx = buildContext("register", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      username,
      identityPubB64: ch.identityPubB64,
      authPubB64: pubB64,
    });
    const wrongSig = await signB64(attacker.priv, ctx);
    const reg = await http("POST", "/accounts", {
      body: { challenge_id: ch.body.challenge_id, signature: wrongSig, registration_id: 1000 },
      ip: "10.0.0.3",
    });
    expect(reg.status).toBe(401);
    expect(reg.body.error.code).toBe("INVALID_SIGNATURE");
    // nothing was created — the username is still free
    const again = await issueRegisterChallenge(username, pubB64, "10.0.0.3");
    expect(again.status).toBe(200);
  });

  it("rejects an expired register challenge", async () => {
    const username = nextUsername("expired");
    const { priv, pubB64 } = await genKey();
    const ch = await issueRegisterChallenge(username, pubB64, "10.0.0.4");
    expect(ch.status).toBe(200);
    setNow(Number(ch.body.expires_at) + 1);
    try {
      const ctx = buildContext("register", {
        challengeId: ch.body.challenge_id,
        nonce: ch.body.nonce,
        username,
        identityPubB64: ch.identityPubB64,
        authPubB64: pubB64,
      });
      const signature = await signB64(priv, ctx);
      const reg = await http("POST", "/accounts", {
        body: { challenge_id: ch.body.challenge_id, signature, registration_id: 1000 },
        ip: "10.0.0.4",
      });
      expect(reg.status).toBe(401);
      expect(reg.body.error.code).toBe("CHALLENGE_EXPIRED");
    } finally {
      setNow(null);
    }
  });
});

describe("auth verify and token lifecycle", () => {
  it("issues a fresh device-bound token via auth challenge", async () => {
    const acc = await registerAccount(nextUsername("auth"), "10.1.0.1");
    const ch = await http("POST", "/auth/challenge", {
      body: { purpose: "auth", device_id: acc.device_id },
      ip: "10.1.0.1",
    });
    expect(ch.status).toBe(200);
    const ctx = buildContext("auth", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      accountId: acc.account_id,
      deviceId: acc.device_id,
    });
    const signature = await signB64(acc.authPriv, ctx);
    const verify = await http("POST", "/auth/verify", {
      body: { challenge_id: ch.body.challenge_id, signature },
      ip: "10.1.0.1",
    });
    expect(verify.status).toBe(200);
    expect(verify.body.device_id).toBe(acc.device_id);
    expect(verify.body.account_id).toBe(acc.account_id);

    const me = await http("GET", "/devices/me", { token: verify.body.token, ip: "10.1.0.1" });
    expect(me.status).toBe(200);
    expect(me.body.device_id).toBe(acc.device_id);
  });

  it("rejects an auth signature produced by a different key", async () => {
    const acc = await registerAccount(nextUsername("wrong"), "10.1.0.2");
    const ch = await http("POST", "/auth/challenge", {
      body: { purpose: "auth", device_id: acc.device_id },
      ip: "10.1.0.2",
    });
    const attacker = await genKey();
    const ctx = buildContext("auth", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      accountId: acc.account_id,
      deviceId: acc.device_id,
    });
    const signature = await signB64(attacker.priv, ctx);
    const verify = await http("POST", "/auth/verify", {
      body: { challenge_id: ch.body.challenge_id, signature },
      ip: "10.1.0.2",
    });
    expect(verify.status).toBe(401);
    expect(verify.body.error.code).toBe("INVALID_SIGNATURE");
  });

  it("consumes a challenge exactly once", async () => {
    const acc = await registerAccount(nextUsername("once"), "10.1.0.3");
    const ch = await http("POST", "/auth/challenge", {
      body: { purpose: "auth", device_id: acc.device_id },
      ip: "10.1.0.3",
    });
    const ctx = buildContext("auth", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      accountId: acc.account_id,
      deviceId: acc.device_id,
    });
    const signature = await signB64(acc.authPriv, ctx);
    const first = await http("POST", "/auth/verify", {
      body: { challenge_id: ch.body.challenge_id, signature },
      ip: "10.1.0.3",
    });
    expect(first.status).toBe(200);
    const second = await http("POST", "/auth/verify", {
      body: { challenge_id: ch.body.challenge_id, signature },
      ip: "10.1.0.3",
    });
    expect(second.status).toBe(401);
    expect(second.body.error.code).toBe("CHALLENGE_USED");
  });

  it("rejects expired tokens with TOKEN_EXPIRED", async () => {
    const acc = await registerAccount(nextUsername("exp"), "10.1.0.4");
    const me = await http("GET", "/devices/me", { token: acc.token, ip: "10.1.0.4" });
    expect(me.status).toBe(200);
    setNow(Number(acc.token_expires_at) + 1);
    try {
      const expired = await http("GET", "/devices/me", { token: acc.token, ip: "10.1.0.4" });
      expect(expired.status).toBe(401);
      expect(expired.body.error.code).toBe("TOKEN_EXPIRED");
    } finally {
      setNow(null);
    }
  });
});

describe("revocation", () => {
  it("invalidates all tokens of a revoked device immediately and fail-closed", async () => {
    const acc = await registerAccount(nextUsername("rev"), "10.2.0.1");

    // pre-issue an unused auth challenge for the same device
    const ch = await http("POST", "/auth/challenge", {
      body: { purpose: "auth", device_id: acc.device_id },
      ip: "10.2.0.1",
    });
    expect(ch.status).toBe(200);

    const del = await http("DELETE", `/devices/${acc.device_id}`, {
      token: acc.token,
      ip: "10.2.0.1",
    });
    expect(del.status).toBe(204);

    // existing token: rejected immediately
    const me = await http("GET", "/devices/me", { token: acc.token, ip: "10.2.0.1" });
    expect(me.status).toBe(401);
    expect(me.body.error.code).toBe("DEVICE_REVOKED");

    // pre-issued challenge: verify is fail-closed even though it was unused
    const ctx = buildContext("auth", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      accountId: acc.account_id,
      deviceId: acc.device_id,
    });
    const signature = await signB64(acc.authPriv, ctx);
    const verify = await http("POST", "/auth/verify", {
      body: { challenge_id: ch.body.challenge_id, signature },
      ip: "10.2.0.1",
    });
    expect(verify.status).toBe(401);
    expect(verify.body.error.code).toBe("DEVICE_REVOKED");

    // revoked device cannot obtain a new challenge either
    const challenge2 = await http("POST", "/auth/challenge", {
      body: { purpose: "auth", device_id: acc.device_id },
      ip: "10.2.0.1",
    });
    expect(challenge2.status).toBe(404);
  });

  it("blocks a revoked authorizer from adding devices", async () => {
    const authorizer = await registerAccount(nextUsername("authz"), "10.2.1.1");
    const del = await http("DELETE", `/devices/${authorizer.device_id}`, {
      token: authorizer.token,
      ip: "10.2.1.1",
    });
    expect(del.status).toBe(204);
    const { pubB64 } = await genKey();
    const ch = await http("POST", "/auth/challenge", {
      body: {
        purpose: "add_device",
        username: authorizer.username,
        identity_pub: b64(crypto.getRandomValues(new Uint8Array(32))),
        auth_pub: pubB64,
        authorizer_device_id: authorizer.device_id,
      },
      ip: "10.2.1.1",
    });
    expect(ch.status).toBe(404);
  });
});

describe("cross-device and cross-account authorization", () => {
  it("device A cannot revoke device B of a different account", async () => {
    const accA = await registerAccount(nextUsername("aaa"), "10.3.0.1");
    const accB = await registerAccount(nextUsername("bbb"), "10.3.0.2");
    const cross = await http("DELETE", `/devices/${accB.device_id}`, {
      token: accA.token,
      ip: "10.3.0.1",
    });
    expect(cross.status).toBe(403);
    expect(cross.body.error.code).toBe("FORBIDDEN");
    const meB = await http("GET", "/devices/me", { token: accB.token, ip: "10.3.0.2" });
    expect(meB.status).toBe(200); // untouched
  });

  it("tokens are strictly device-bound", async () => {
    const accA = await registerAccount(nextUsername("binda"), "10.3.1.1");
    const accB = await registerAccount(nextUsername("bindb"), "10.3.1.2");
    const meA = await http("GET", "/devices/me", { token: accA.token, ip: "10.3.1.1" });
    expect(meA.body.device_id).toBe(accA.device_id);
    expect(meA.body.device_id).not.toBe(accB.device_id);
  });

  it("add_device requires an authorizer of the SAME account", async () => {
    const accA = await registerAccount(nextUsername("owna"), "10.3.2.1");
    const accB = await registerAccount(nextUsername("ownb"), "10.3.2.2");
    const { pubB64 } = await genKey();
    const ch = await http("POST", "/auth/challenge", {
      body: {
        purpose: "add_device",
        username: accA.username,
        identity_pub: b64(crypto.getRandomValues(new Uint8Array(32))),
        auth_pub: pubB64,
        authorizer_device_id: accB.device_id, // authorizer from ANOTHER account
      },
      ip: "10.3.2.3",
    });
    expect(ch.status).toBe(404);
  });

  it("add_device with a valid authorizer yields dev_no=2 and a working token", async () => {
    const acc = await registerAccount(nextUsername("add"), "10.3.3.1");
    const { priv: priv2, pubB64: authPub2 } = await genKey();
    const identityPub2 = b64(crypto.getRandomValues(new Uint8Array(32)));
    const ch = await http("POST", "/auth/challenge", {
      body: {
        purpose: "add_device",
        username: acc.username,
        identity_pub: identityPub2,
        auth_pub: authPub2,
        authorizer_device_id: acc.device_id,
      },
      ip: "10.3.3.1",
    });
    expect(ch.status).toBe(200);
    const ctx = buildContext("add_device", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      username: acc.username,
      identityPubB64: identityPub2,
      authPubB64: authPub2,
      authorizerDeviceId: acc.device_id,
    });
    const sigNew = await signB64(priv2, ctx);
    const sigAuth = await signB64(acc.authPriv, ctx);
    const add = await http("POST", "/devices", {
      body: {
        challenge_id: ch.body.challenge_id,
        signature: sigNew,
        authorizer_signature: sigAuth,
        registration_id: 1001,
      },
      ip: "10.3.3.1",
    });
    expect(add.status).toBe(201);
    expect(add.body.dev_no).toBe(2);

    const me = await http("GET", "/devices/me", { token: add.body.token, ip: "10.3.3.1" });
    expect(me.status).toBe(200);
    expect(me.body.account_id).toBe(acc.account_id);
    expect(me.body.dev_no).toBe(2);
  });

  it("add_device rejects a tampered authorizer signature", async () => {
    const acc = await registerAccount(nextUsername("tamper"), "10.3.4.1");
    const { priv: priv2, pubB64: authPub2 } = await genKey();
    const identityPub2 = b64(crypto.getRandomValues(new Uint8Array(32)));
    const ch = await http("POST", "/auth/challenge", {
      body: {
        purpose: "add_device",
        username: acc.username,
        identity_pub: identityPub2,
        auth_pub: authPub2,
        authorizer_device_id: acc.device_id,
      },
      ip: "10.3.4.1",
    });
    const ctx = buildContext("add_device", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      username: acc.username,
      identityPubB64: identityPub2,
      authPubB64: authPub2,
      authorizerDeviceId: acc.device_id,
    });
    const sigNew = await signB64(priv2, ctx);
    const attacker = await genKey();
    const badAuthSig = await signB64(attacker.priv, ctx);
    const add = await http("POST", "/devices", {
      body: {
        challenge_id: ch.body.challenge_id,
        signature: sigNew,
        authorizer_signature: badAuthSig,
        registration_id: 1002,
      },
      ip: "10.3.4.1",
    });
    expect(add.status).toBe(401);
    expect(add.body.error.code).toBe("INVALID_SIGNATURE");
  });
});

describe("rate limiting (initial strict mechanism)", () => {
  it("limits account registration per source and resets with the window", async () => {
    const ip = "10.9.9.9";
    for (let i = 0; i < 3; i++) {
      const acc = await registerAccount(nextUsername("rate"), ip);
      expect(acc.token).toBeTruthy();
    }
    // 4th registration from the same source is rejected; its challenge stays
    // unused because the rate limit is checked BEFORE challenge consumption.
    const { priv, pubB64 } = await genKey();
    const username = nextUsername("rate");
    const ch = await issueRegisterChallenge(username, pubB64, ip);
    expect(ch.status).toBe(200);
    const ctx = buildContext("register", {
      challengeId: ch.body.challenge_id,
      nonce: ch.body.nonce,
      username,
      identityPubB64: ch.identityPubB64,
      authPubB64: pubB64,
    });
    const signature = await signB64(priv, ctx);
    const reg = await http("POST", "/accounts", {
      body: { challenge_id: ch.body.challenge_id, signature, registration_id: 1000 },
      ip,
    });
    expect(reg.status).toBe(429);
    expect(reg.body.error.code).toBe("RATE_LIMITED");
  });

  it("resets rate-limit windows deterministically (function level)", async () => {
    const limit = { limit: 2, windowMs: 1000 };
    const t0 = 1_700_000_000_000;
    expect(await checkRateLimit(env.DB, "test-bucket", "k", limit, t0)).toBe(true);
    expect(await checkRateLimit(env.DB, "test-bucket", "k", limit, t0 + 500)).toBe(true);
    expect(await checkRateLimit(env.DB, "test-bucket", "k", limit, t0 + 900)).toBe(false);
    // next fixed window: counter resets
    expect(await checkRateLimit(env.DB, "test-bucket", "k", limit, t0 + 1000)).toBe(true);
  });
});

  it("limits challenge issuance per source (10 per minute)", async () => {
    const ip = "10.8.8.8";
    for (let i = 0; i < 10; i++) {
      const { pubB64 } = await genKey();
      const r = await issueRegisterChallenge(nextUsername("chall"), pubB64, ip);
      expect(r.status).toBe(200);
    }
    const { pubB64 } = await genKey();
    const overflow = await issueRegisterChallenge(nextUsername("chall"), pubB64, ip);
    expect(overflow.status).toBe(429);
    expect(overflow.body.error.code).toBe("RATE_LIMITED");
  });
});
