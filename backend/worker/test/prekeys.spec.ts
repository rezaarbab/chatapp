import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildContext } from "../src/auth";
import { applySql, migrationsFromBinding } from "./apply-sql";

/**
 * Phase 2 — PreKey Infrastructure (HTTP-level via SELF.fetch against
 * miniflare D1 with the REAL migration chain, 0001..0008).
 *
 * Coverage per the approved mandate: upload validation, bundle shape
 * (libsignal 0.102.1 compatibility — V1..V9), allocation/exhaustion,
 * last-resort (never consumed), refill, idempotent upload, rotation,
 * revoke purge, dev_no non-reuse, and the CAS race invariant
 * (no one-time prekey ever allocated twice).
 */

type Json = Record<string, any>;

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

async function registerAccount(username: string, ip: string) {
  const { priv, pubB64 } = await genKey();
  const identityPubB64 = b64(crypto.getRandomValues(new Uint8Array(32)));
  const ch = await http("POST", "/auth/challenge", {
    body: { purpose: "register", username, identity_pub: identityPubB64, auth_pub: pubB64 },
    ip,
  });
  expect(ch.status).toBe(200);
  const ctx = buildContext("register", {
    challengeId: ch.body.challenge_id,
    nonce: ch.body.nonce,
    username,
    identityPubB64,
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
    device_id: reg.body.device_id,
    account_id: reg.body.account_id,
    authPriv: priv,
    username,
    identityPubB64,
  };
}

/** Adds a device to an existing account (real add_device flow). Returns its token + ids. */
async function addDevice(
  acc: { username: string; device_id: string; authPriv: CryptoKey },
  ip: string,
): Promise<{ token: string; device_id: string; dev_no: number; identityPubB64: string }> {
  const { priv: privNew, pubB64: authPubNew } = await genKey();
  const identityPubB64 = b64(crypto.getRandomValues(new Uint8Array(32)));
  const ch = await http("POST", "/auth/challenge", {
    body: {
      purpose: "add_device",
      username: acc.username,
      identity_pub: identityPubB64,
      auth_pub: authPubNew,
      authorizer_device_id: acc.device_id,
    },
    ip,
  });
  expect(ch.status).toBe(200);
  const ctx = buildContext("add_device", {
    challengeId: ch.body.challenge_id,
    nonce: ch.body.nonce,
    username: acc.username,
    identityPubB64,
    authPubB64: authPubNew,
    authorizerDeviceId: acc.device_id,
  });
  const sigNew = await signB64(privNew, ctx);
  const sigAuth = await signB64(acc.authPriv, ctx);
  const add = await http("POST", "/devices", {
    body: { challenge_id: ch.body.challenge_id, signature: sigNew, authorizer_signature: sigAuth, registration_id: 1001 },
    ip,
  });
  expect(add.status).toBe(201);
  return { token: add.body.token, device_id: add.body.device_id, dev_no: add.body.dev_no, identityPubB64 };
}

// ---- prekey material builders (libsignal 0.102.1 wire formats, design V4-V7) ----

function ecPubBytes(): Uint8Array {
  const b = crypto.getRandomValues(new Uint8Array(33));
  b[0] = 0x05;
  return b;
}

function kemPubBytes(): Uint8Array {
  const b = crypto.getRandomValues(new Uint8Array(1569));
  b[0] = 0x08;
  return b;
}

function sigBytes(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(64));
}

interface UploadOverrides {
  signed_prekey?: Json | null;
  last_resort_kyber?: Json | null;
  one_time_prekeys?: Json[];
  one_time_kyber_prekeys?: Json[];
}

function ecKey(id: number): Json {
  return { key_id: id, public_key: b64(ecPubBytes()) };
}

function kemKey(id: number): Json {
  return { key_id: id, public_key: b64(kemPubBytes()), signature: b64(sigBytes()) };
}

function signedPreKey(id: number): Json {
  return { key_id: id, public_key: b64(ecPubBytes()), signature: b64(sigBytes()) };
}

function lastResortKey(id: number): Json {
  return { key_id: id, public_key: b64(kemPubBytes()), signature: b64(sigBytes()) };
}

function uploadBody(overrides: UploadOverrides = {}): Json {
  return {
    signed_prekey: overrides.signed_prekey === null ? undefined : (overrides.signed_prekey ?? signedPreKey(1)),
    last_resort_kyber:
      overrides.last_resort_kyber === null ? undefined : (overrides.last_resort_kyber ?? lastResortKey(900)),
    one_time_prekeys: overrides.one_time_prekeys ?? [],
    one_time_kyber_prekeys: overrides.one_time_kyber_prekeys ?? [],
  };
}

async function upload(token: string, body: Json, ip = "10.9.9.1") {
  return http("POST", "/prekeys", { body, token, ip });
}

async function bundle(token: string, deviceId: string, ip = "10.9.9.2") {
  return http("GET", `/devices/${deviceId}/prekeys`, { token, ip });
}

beforeAll(async () => {
  for (const m of migrationsFromBinding()) {
    await applySql(m.sql);
  }
});

afterAll(() => {
  setNow(null);
});

describe("prekey upload validation", () => {
  it("rejects unauthenticated uploads", async () => {
    const res = await upload("not-a-token", uploadBody());
    expect(res.status).toBe(401);
  });

  it("rejects an EC public key with a wrong length or prefix", async () => {
    const acc = await registerAccount(nextUsername("pkv"), "10.8.0.1");
    const badLen = { key_id: 1, public_key: b64(crypto.getRandomValues(new Uint8Array(32))), signature: b64(sigBytes()) };
    const resLen = await upload(acc.token, { signed_prekey: badLen });
    expect(resLen.status).toBe(400);
    expect(resLen.body.error.code).toBe("INVALID_PREKEY");

    const wrongPrefix = crypto.getRandomValues(new Uint8Array(33));
    wrongPrefix[0] = 0x04;
    const badPrefix = { key_id: 1, public_key: b64(wrongPrefix), signature: b64(sigBytes()) };
    const resPrefix = await upload(acc.token, { signed_prekey: badPrefix });
    expect(resPrefix.status).toBe(400);
    expect(resPrefix.body.error.code).toBe("INVALID_PREKEY");
  });

  it("rejects a Kyber public key that is not 1569 bytes with 0x08 prefix", async () => {
    const acc = await registerAccount(nextUsername("pkv2"), "10.8.0.2");
    const short = { key_id: 900, public_key: b64(crypto.getRandomValues(new Uint8Array(1568))), signature: b64(sigBytes()) };
    const resLen = await upload(acc.token, { last_resort_kyber: short });
    expect(resLen.status).toBe(400);

    const wrongPrefix = crypto.getRandomValues(new Uint8Array(1569));
    wrongPrefix[0] = 0x07;
    const bad = { key_id: 900, public_key: b64(wrongPrefix), signature: b64(sigBytes()) };
    const resPrefix = await upload(acc.token, { last_resort_kyber: bad });
    expect(resPrefix.status).toBe(400);
  });

  it("rejects a signature that is not 64 bytes", async () => {
    const acc = await registerAccount(nextUsername("pkv3"), "10.8.0.3");
    const bad = { key_id: 1, public_key: b64(ecPubBytes()), signature: b64(crypto.getRandomValues(new Uint8Array(63))) };
    const res = await upload(acc.token, { signed_prekey: bad });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("INVALID_PREKEY");
  });

  it("rejects out-of-range key_ids (negative, > 24-bit, non-integer)", async () => {
    const acc = await registerAccount(nextUsername("pkv4"), "10.8.0.4");
    for (const keyId of [-1, 16_777_216, 1.5, "7"]) {
      const res = await upload(acc.token, { signed_prekey: { key_id: keyId, public_key: b64(ecPubBytes()), signature: b64(sigBytes()) } });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("INVALID_PREKEY");
    }
  });

  it("rejects uploads larger than the per-batch cap", async () => {
    const acc = await registerAccount(nextUsername("pkv5"), "10.8.0.5");
    const tooMany = Array.from({ length: 101 }, (_, i) => ecKey(i + 1));
    const res = await upload(acc.token, { one_time_prekeys: tooMany });
    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe("TOO_MANY_PREKEYS");
  });

  it("accepts an empty body as a count probe and mutates nothing", async () => {
    const acc = await registerAccount(nextUsername("probe"), "10.8.0.6");
    const before = await upload(acc.token, {});
    expect(before.status).toBe(200);
    expect(before.body.signed_prekey_id).toBeNull();
    expect(before.body.one_time_ec_remaining).toBe(0);
    const after = await upload(acc.token, {});
    expect(after.body).toEqual(before.body);
  });
});

describe("bundle fetch: shape and lifecycle", () => {
  it("409 PREKEYS_NOT_READY before the first upload", async () => {
    const acc = await registerAccount(nextUsername("notready"), "10.8.1.1");
    const other = await registerAccount(nextUsername("notready2"), "10.8.1.2");
    const res = await bundle(other.token, acc.device_id);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe("PREKEYS_NOT_READY");
  });

  it("serves a bundle that mirrors the libsignal 0.102.1 PreKeyBundle constructor (V1)", async () => {
    const acc = await registerAccount(nextUsername("bundle"), "10.8.2.1");
    const up = await upload(acc.token, uploadBody({
      signed_prekey: signedPreKey(7),
      last_resort_kyber: lastResortKey(70),
      one_time_prekeys: [ecKey(10), ecKey(11)],
      one_time_kyber_prekeys: [kemKey(20), kemKey(21)],
    }));
    expect(up.status).toBe(200);
    expect(up.body.signed_prekey_id).toBe(7);
    expect(up.body.last_resort_kyber_id).toBe(70);
    expect(up.body.one_time_ec_remaining).toBe(2);
    expect(up.body.one_time_kyber_remaining).toBe(2);

    const other = await registerAccount(nextUsername("bundle2"), "10.8.2.2");
    const b1 = await bundle(other.token, acc.device_id);
    expect(b1.status).toBe(200);

    // Exact field set of the 11-arg PreKeyBundle constructor (+ server routing ids):
    expect(Object.keys(b1.body).sort()).toEqual(
      ["account_id", "device_id", "dev_no", "identity_pub", "kyber_prekey", "one_time_prekey", "registration_id", "signed_prekey"].sort(),
    );
    expect(b1.body.account_id).toBe(acc.account_id);
    expect(b1.body.device_id).toBe(acc.device_id);
    expect(b1.body.dev_no).toBe(1);
    expect(b1.body.registration_id).toBe(1000);
    expect(b1.body.identity_pub).toBe(acc.identityPubB64); // raw 32B, untouched

    expect(b1.body.signed_prekey.key_id).toBe(7);
    expect(typeof b1.body.signed_prekey.public_key).toBe("string");
    expect(typeof b1.body.signed_prekey.signature).toBe("string");

    // one-time keys are served in key_id order (lowest first)
    expect(b1.body.one_time_prekey.key_id).toBe(10);
    expect(b1.body.kyber_prekey.key_id).toBe(20);
    expect(b1.body.kyber_prekey.last_resort).toBe(false);

    const b2 = await bundle(other.token, acc.device_id);
    expect(b2.body.one_time_prekey.key_id).toBe(11);
    expect(b2.body.kyber_prekey.key_id).toBe(21);
  });

  it("exhaustion degrades gracefully: EC optional (V3/V9), Kyber falls back to last-resort which is NEVER consumed", async () => {
    const acc = await registerAccount(nextUsername("exh"), "10.8.3.1");
    await upload(acc.token, uploadBody({
      signed_prekey: signedPreKey(1),
      last_resort_kyber: lastResortKey(900),
      one_time_prekeys: [ecKey(1)],
      one_time_kyber_prekeys: [kemKey(100)],
    }));
    const other = await registerAccount(nextUsername("exh2"), "10.8.3.2");

    const b1 = await bundle(other.token, acc.device_id);
    expect(b1.body.one_time_prekey.key_id).toBe(1);
    expect(b1.body.kyber_prekey.key_id).toBe(100);
    expect(b1.body.kyber_prekey.last_resort).toBe(false);

    const b2 = await bundle(other.token, acc.device_id);
    expect(b2.body.one_time_prekey).toBeNull(); // EC stock empty -> NULL_PRE_KEY_ID on the client
    expect(b2.body.kyber_prekey.key_id).toBe(900);
    expect(b2.body.kyber_prekey.last_resort).toBe(true);

    const b3 = await bundle(other.token, acc.device_id);
    expect(b3.body.kyber_prekey.key_id).toBe(900); // same last-resort served again
    expect(b3.body.kyber_prekey.last_resort).toBe(true);

    // The last-resort row was NEVER marked used (server-side truth):
    const lr = await env.DB
      .prepare("SELECT used_at FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 1")
      .bind(acc.device_id)
      .first<{ used_at: number | null }>();
    expect(lr?.used_at).toBeNull();

    const probe = await upload(acc.token, {});
    expect(probe.body.one_time_ec_remaining).toBe(0);
    expect(probe.body.one_time_kyber_remaining).toBe(0);
  });

  it("refill after exhaustion restores one-time delivery", async () => {
    const acc = await registerAccount(nextUsername("refill"), "10.8.4.1");
    await upload(acc.token, uploadBody({ one_time_prekeys: [ecKey(1)], one_time_kyber_prekeys: [kemKey(100)] }));
    const other = await registerAccount(nextUsername("refill2"), "10.8.4.2");
    await bundle(other.token, acc.device_id);
    await bundle(other.token, acc.device_id);
    const empty = await bundle(other.token, acc.device_id);
    expect(empty.body.one_time_prekey).toBeNull();

    const refill = await upload(acc.token, uploadBody({
      signed_prekey: null,
      last_resort_kyber: null,
      one_time_prekeys: [ecKey(2), ecKey(3)],
      one_time_kyber_prekeys: [kemKey(101)],
    }));
    expect(refill.status).toBe(200);
    expect(refill.body.one_time_ec_remaining).toBe(2);
    expect(refill.body.one_time_kyber_remaining).toBe(1);

    const again = await bundle(other.token, acc.device_id);
    expect(again.body.one_time_prekey.key_id).toBe(2);
    expect(again.body.kyber_prekey.key_id).toBe(101);
    expect(again.body.kyber_prekey.last_resort).toBe(false);
  });

  it("re-uploading an identical key is an idempotent no-op; different bytes conflict (409)", async () => {
    const acc = await registerAccount(nextUsername("idem"), "10.8.5.1");
    const k = ecKey(5);
    const first = await upload(acc.token, uploadBody({ one_time_prekeys: [k] }));
    expect(first.status).toBe(200);
    expect(first.body.one_time_ec_remaining).toBe(1);

    const dup = await upload(acc.token, uploadBody({ signed_prekey: null, last_resort_kyber: null, one_time_prekeys: [k] }));
    expect(dup.status).toBe(200);
    expect(dup.body.one_time_ec_remaining).toBe(1); // not double-inserted

    const conflict = await upload(acc.token, uploadBody({ signed_prekey: null, last_resort_kyber: null, one_time_prekeys: [ecKey(5)] }));
    expect(conflict.status).toBe(409);
    expect(conflict.body.error.code).toBe("KEY_ID_CONFLICT");
  });

  it("signed prekey rotation replaces the served key and keeps exactly one row", async () => {
    const acc = await registerAccount(nextUsername("rot"), "10.8.6.1");
    await upload(acc.token, uploadBody({ signed_prekey: signedPreKey(1), last_resort_kyber: lastResortKey(900) }));
    const other = await registerAccount(nextUsername("rot2"), "10.8.6.2");
    const before = await bundle(other.token, acc.device_id);
    expect(before.body.signed_prekey.key_id).toBe(1);

    const rotate = await upload(acc.token, uploadBody({ signed_prekey: signedPreKey(2) }));
    expect(rotate.status).toBe(200);
    expect(rotate.body.signed_prekey_id).toBe(2);

    const after = await bundle(other.token, acc.device_id);
    expect(after.body.signed_prekey.key_id).toBe(2);

    const rows = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM signed_prekeys WHERE device_id = ?1")
      .bind(acc.device_id)
      .first<{ n: number }>();
    expect(rows?.n).toBe(1);
  });

  it("last-resort rotation replaces the served key and removes the old row", async () => {
    const acc = await registerAccount(nextUsername("lrrot"), "10.8.7.1");
    await upload(acc.token, uploadBody({ last_resort_kyber: lastResortKey(900) }));
    const other = await registerAccount(nextUsername("lrrot2"), "10.8.7.2");
    const before = await bundle(other.token, acc.device_id);
    expect(before.body.kyber_prekey.key_id).toBe(900);

    const rotate = await upload(acc.token, uploadBody({ signed_prekey: null, last_resort_kyber: lastResortKey(901) }));
    expect(rotate.status).toBe(200);
    expect(rotate.body.last_resort_kyber_id).toBe(901);

    const after = await bundle(other.token, acc.device_id);
    expect(after.body.kyber_prekey.key_id).toBe(901);

    const old = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM kyber_prekeys WHERE device_id = ?1 AND key_id = 900")
      .bind(acc.device_id)
      .first<{ n: number }>();
    expect(old?.n).toBe(0); // replaced rows are deleted, never servable again
  });

  it("multi-device bundles are fully independent (per-device identity, per-device prekeys)", async () => {
    const acc = await registerAccount(nextUsername("multi"), "10.8.8.1");
    const dev2 = await addDevice(acc, "10.8.8.1");
    expect(dev2.dev_no).toBe(2);

    await upload(acc.token, uploadBody({ signed_prekey: signedPreKey(11), last_resort_kyber: lastResortKey(911) }));
    await upload(dev2.token, uploadBody({ signed_prekey: signedPreKey(22), last_resort_kyber: lastResortKey(922) }));

    const other = await registerAccount(nextUsername("multi2"), "10.8.8.2");
    const b1 = await bundle(other.token, acc.device_id);
    const b2 = await bundle(other.token, dev2.device_id);

    expect(b1.status).toBe(200);
    expect(b2.status).toBe(200);
    expect(b1.body.account_id).toBe(acc.account_id);
    expect(b2.body.account_id).toBe(acc.account_id); // same account...
    expect(b1.body.dev_no).toBe(1);
    expect(b2.body.dev_no).toBe(2); // ...different protocol deviceId (dev_no)
    expect(b1.body.identity_pub).not.toBe(b2.body.identity_pub); // per-device identities
    expect(b1.body.signed_prekey.key_id).toBe(11);
    expect(b2.body.signed_prekey.key_id).toBe(22);
    expect(b1.body.kyber_prekey.key_id).not.toBe(b2.body.kyber_prekey.key_id);
  });
});

describe("revoke interaction", () => {
  it("revoked devices stop serving bundles with the same 404 as unknown devices", async () => {
    const acc = await registerAccount(nextUsername("rev"), "10.8.9.1");
    const other = await registerAccount(nextUsername("rev2"), "10.8.9.2");
    await upload(acc.token, uploadBody());

    const rev = await http("DELETE", `/devices/${acc.device_id}`, { token: acc.token, ip: "10.8.9.1" });
    expect(rev.status).toBe(204);

    const revokedBundle = await bundle(other.token, acc.device_id);
    expect(revokedBundle.status).toBe(404);
    expect(revokedBundle.body.error.code).toBe("DEVICE_NOT_FOUND");

    const unknownBundle = await bundle(other.token, crypto.randomUUID());
    expect(unknownBundle.status).toBe(404);
    expect(unknownBundle.body.error.code).toBe("DEVICE_NOT_FOUND");

    // prekey rows are purged server-side (design §4 A4)
    const counts = await env.DB
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM signed_prekeys WHERE device_id = ?1) AS s,
           (SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = ?1) AS o,
           (SELECT COUNT(*) FROM kyber_prekeys WHERE device_id = ?1) AS k`,
      )
      .bind(acc.device_id)
      .first<{ s: number; o: number; k: number }>();
    expect(counts).toEqual({ s: 0, o: 0, k: 0 });
  });

  it("dev_no is never reused after revocation", async () => {
    const acc = await registerAccount(nextUsername("devno"), "10.8.10.1");
    const dev2 = await addDevice(acc, "10.8.10.1");
    expect(dev2.dev_no).toBe(2);
    const rev = await http("DELETE", `/devices/${dev2.device_id}`, { token: acc.token, ip: "10.8.10.1" });
    expect(rev.status).toBe(204);
    const dev3 = await addDevice(acc, "10.8.10.1");
    expect(dev3.dev_no).toBe(3); // NOT 2
  });
});

describe("CAS race invariant: no one-time prekey is ever allocated twice", () => {
  it("40 concurrent bundle fetches over 10 EC + 10 Kyber one-time keys never double-allocate", async () => {
    const acc = await registerAccount(nextUsername("race"), "10.8.11.1");
    const ecKeys = Array.from({ length: 10 }, (_, i) => ecKey(i + 1));
    const kemKeys = Array.from({ length: 10 }, (_, i) => kemKey(100 + i));
    const up = await upload(acc.token, uploadBody({ one_time_prekeys: ecKeys, one_time_kyber_prekeys: kemKeys }));
    expect(up.status).toBe(200);
    expect(up.body.one_time_ec_remaining).toBe(10);
    expect(up.body.one_time_kyber_remaining).toBe(10);

    const other = await registerAccount(nextUsername("race2"), "10.8.11.2");
    const results = await Promise.all(
      Array.from({ length: 40 }, () => bundle(other.token, acc.device_id)),
    );
    for (const r of results) {
      expect(r.status).toBe(200);
    }

    const ecDelivered = results.map((r) => r.body.one_time_prekey?.key_id).filter((k) => k != null);
    const kemDelivered = results
      .map((r) => (r.body.kyber_prekey && r.body.kyber_prekey.last_resort === false ? r.body.kyber_prekey.key_id : null))
      .filter((k) => k != null);

    // THE invariant: no key delivered more than once (CAS + meta.changes ownership).
    expect(new Set(ecDelivered).size).toBe(ecDelivered.length);
    expect(new Set(kemDelivered).size).toBe(kemDelivered.length);
    expect(ecDelivered.length).toBeLessThanOrEqual(10);
    expect(kemDelivered.length).toBeLessThanOrEqual(10);

    // Server-side truth: exactly the delivered keys are marked used, nothing else.
    const ecUsed = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM one_time_prekeys WHERE device_id = ?1 AND used_at IS NOT NULL")
      .bind(acc.device_id)
      .first<{ n: number }>();
    const kemUsed = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 0 AND used_at IS NOT NULL")
      .bind(acc.device_id)
      .first<{ n: number }>();
    expect(ecUsed?.n).toBe(ecDelivered.length);
    expect(kemUsed?.n).toBe(kemDelivered.length);

    // A response lost in transport can only mean the key IS marked used —
    // never an unmarked delivery. used <= 10 always, and last-resort survives.
    const probe = await upload(acc.token, {});
    expect(probe.body.one_time_ec_remaining).toBe(10 - ecDelivered.length);
    expect(probe.body.one_time_kyber_remaining).toBe(10 - kemDelivered.length);
    expect(probe.body.last_resort_kyber_id).toBe(900);

    const lrRow = await env.DB
      .prepare("SELECT used_at FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 1")
      .bind(acc.device_id)
      .first<{ used_at: number | null }>();
    expect(lrRow?.used_at).toBeNull();
  });

  it("sequential pops deliver each key exactly once, then degrade to last-resort", async () => {
    const acc = await registerAccount(nextUsername("seq"), "10.8.12.1");
    await upload(acc.token, uploadBody({
      one_time_prekeys: [ecKey(3), ecKey(1), ecKey(2)],
      one_time_kyber_prekeys: [kemKey(103), kemKey(101), kemKey(102)],
    }));
    const other = await registerAccount(nextUsername("seq2"), "10.8.12.2");
    const delivered: number[] = [];
    const kemDelivered: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await bundle(other.token, acc.device_id);
      expect(res.status).toBe(200);
      if (res.body.one_time_prekey) delivered.push(res.body.one_time_prekey.key_id);
      if (!res.body.kyber_prekey.last_resort) kemDelivered.push(res.body.kyber_prekey.key_id);
    }
    expect(delivered).toEqual([1, 2, 3]); // strict key_id order, no repeats
    expect(kemDelivered).toEqual([101, 102, 103]);
  });
});
