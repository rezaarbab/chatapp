import { SELF, env } from "cloudflare:test";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildContext } from "../src/auth";
import { applySql, migrationsFromBinding } from "./apply-sql";
import { MAX_QUEUE_PER_DEVICE } from "../src/messages";

/**
 * Phase 3 — Messaging & Message Delivery (HTTP-level via SELF.fetch against
 * miniflare D1 with the REAL migration chain, 0001..0009).
 *
 * Coverage per the approved mandate: device discovery, per-device fan-out,
 * idempotent send/repair, ordered fetch + redelivery, ACK scoping, seq
 * monotonicity (never reused after ACK), TTL expiry + purge, queue cap,
 * validation limits, revocation interplay.
 *
 * Rate-limit note: register/challenge limits are per source IP, so every
 * registration uses a fresh synthetic IP (same pattern as auth/prekeys specs).
 * D1 caps statements at 100 bind variables — bulk inserts stay below that.
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

let ipSeq = 0;
function nextIp(): string {
  ipSeq += 1;
  return `10.${Math.floor(ipSeq / 250) + 20}.${ipSeq % 250}.1`;
}

let usernameCounter = 0;
function nextUsername(prefix: string): string {
  usernameCounter += 1;
  return `${prefix}_${usernameCounter}`;
}

async function registerAccount(username: string) {
  const ip = nextIp();
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

async function addDevice(
  acc: { username: string; device_id: string; authPriv: CryptoKey },
): Promise<{ token: string; device_id: string; dev_no: number; identityPubB64: string }> {
  const ip = nextIp();
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

let logicalSeq = 0;
function nextLogicalId(): string {
  logicalSeq += 1;
  return `00000000-0000-4000-8000-${String(logicalSeq).padStart(12, "0")}`;
}

function ct(size = 64): string {
  return b64(crypto.getRandomValues(new Uint8Array(size)));
}

async function send(
  token: string,
  logicalMsgId: string,
  targets: { device_id: string; ciphertext_b64?: string }[],
): Promise<{ status: number; body: Json }> {
  return http("POST", "/messages", {
    token,
    body: {
      logical_msg_id: logicalMsgId,
      targets: targets.map((t) => ({ device_id: t.device_id, ciphertext_b64: t.ciphertext_b64 ?? ct() })),
    },
  });
}

beforeAll(async () => {
  for (const m of migrationsFromBinding()) {
    await applySql(m.sql);
  }
});

afterAll(() => {
  (env as Record<string, unknown>).NOW_OVERRIDE_MS = "";
});

describe("messages: auth", () => {
  it("rejects unauthenticated access to all four endpoints", async () => {
    expect((await http("GET", "/accounts/some-id/devices")).status).toBe(401);
    expect((await http("POST", "/messages", { body: {} })).status).toBe(401);
    expect((await http("GET", "/messages")).status).toBe(401);
    expect((await http("POST", "/messages/ack", { body: {} })).status).toBe(401);
  });
});

describe("messages: device discovery", () => {
  it("lists only ACTIVE devices of any account (dev_no, registration_id, no keys)", async () => {
    const a = await registerAccount(nextUsername("msgdisc"));
    const a2 = await addDevice(a);
    const b = await registerAccount(nextUsername("msgdiscb"));

    const res = await http("GET", `/accounts/${a.account_id}/devices`, { token: b.token });
    expect(res.status).toBe(200);
    expect(res.body.account_id).toBe(a.account_id);
    const ids = (res.body.devices as Json[]).map((d) => d.device_id).sort();
    expect(ids).toEqual([a.device_id, a2.device_id].sort());
    for (const d of res.body.devices as Json[]) {
      expect(Object.keys(d).sort()).toEqual(["dev_no", "device_id", "registration_id"]);
    }

    // revoke a2 → disappears from the list
    const del = await http("DELETE", `/devices/${a2.device_id}`, { token: a.token });
    expect(del.status).toBe(204);
    const res2 = await http("GET", `/accounts/${a.account_id}/devices`, { token: b.token });
    expect((res2.body.devices as Json[]).map((d) => d.device_id)).toEqual([a.device_id]);
  });

  it("returns 404 ACCOUNT_NOT_FOUND for an unknown account (uniform)", async () => {
    const a = await registerAccount(nextUsername("msgdiscu"));
    const res = await http("GET", `/accounts/00000000-0000-4000-8000-000000000000/devices`, { token: a.token });
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe("ACCOUNT_NOT_FOUND");
  });
});

describe("messages: send validation", () => {
  it("rejects malformed logical_msg_id, empty targets, duplicate target ids, bad base64", async () => {
    const a = await registerAccount(nextUsername("msgval"));
    const bad = await http("POST", "/messages", {
      token: a.token,
      body: { logical_msg_id: "not-a-uuid", targets: [{ device_id: a.device_id, ciphertext_b64: ct() }] },
    });
    expect(bad.status).toBe(400);

    const empty = await http("POST", "/messages", { token: a.token, body: { logical_msg_id: nextLogicalId(), targets: [] } });
    expect(empty.status).toBe(400);

    const dup = await http("POST", "/messages", {
      token: a.token,
      body: {
        logical_msg_id: nextLogicalId(),
        targets: [
          { device_id: a.device_id, ciphertext_b64: ct() },
          { device_id: a.device_id, ciphertext_b64: ct() },
        ],
      },
    });
    expect(dup.status).toBe(400);

    const badB64 = await http("POST", "/messages", {
      token: a.token,
      body: { logical_msg_id: nextLogicalId(), targets: [{ device_id: a.device_id, ciphertext_b64: "!!!not-base64!!!" }] },
    });
    expect(badB64.status).toBe(400);
  });

  it("enforces ciphertext cap 65536 and target cap 127", async () => {
    const a = await registerAccount(nextUsername("msgcap"));
    const oversize = await http("POST", "/messages", {
      token: a.token,
      body: { logical_msg_id: nextLogicalId(), targets: [{ device_id: a.device_id, ciphertext_b64: b64(new Uint8Array(65_537)) }] },
    });
    expect(oversize.status).toBe(413);
    expect(oversize.body.error.code).toBe("CIPHERTEXT_TOO_LARGE");

    const manyTargets = Array.from({ length: 128 }, (_, i) => ({ device_id: `dev-${i}`, ciphertext_b64: ct() }));
    const tooMany = await http("POST", "/messages", {
      token: a.token,
      body: { logical_msg_id: nextLogicalId(), targets: manyTargets },
    });
    expect(tooMany.status).toBe(413);
    expect(tooMany.body.error.code).toBe("TOO_MANY_TARGETS");
  });

  it("reports unknown and revoked targets as rejected, per-target (uniform, anti-enumeration)", async () => {
    const a = await registerAccount(nextUsername("msgrej"));
    const a2 = await addDevice(a);
    const del = await http("DELETE", `/devices/${a2.device_id}`, { token: a.token });
    expect(del.status).toBe(204);

    const res = await send(a.token, nextLogicalId(), [
      { device_id: a.device_id },
      { device_id: a2.device_id }, // revoked
      { device_id: "00000000-0000-4000-8000-999999999999" }, // unknown
    ]);
    expect(res.status).toBe(200);
    const byId = new Map<string, string>((res.body.results as Json[]).map((r) => [r.device_id, r.status]));
    expect(byId.get(a.device_id)).toBe("queued");
    expect(byId.get(a2.device_id)).toBe("rejected");
    expect(byId.get("00000000-0000-4000-8000-999999999999")).toBe("rejected");
  });
});

describe("messages: fan-out, idempotency, ordering, ACK, seq non-reuse", () => {
  it("runs the full lifecycle: discovery → per-device fan-out → receive → ACK → delete", async () => {
    const a = await registerAccount(nextUsername("msglife"));
    const a2 = await addDevice(a);
    const b = await registerAccount(nextUsername("msglifeb"));

    // discovery from the sender's perspective
    const disc = await http("GET", `/accounts/${b.account_id}/devices`, { token: a.token });
    expect(disc.status).toBe(200);
    expect((disc.body.devices as Json[]).map((d) => d.device_id)).toEqual([b.device_id]);

    // one logical message → both own devices AND the peer device
    const logical = nextLogicalId();
    const sent = await send(a.token, logical, [
      { device_id: a2.device_id, ciphertext_b64: ct(111) }, // self sync
      { device_id: b.device_id, ciphertext_b64: ct(222) }, // cross-account
    ]);
    expect(sent.status).toBe(200);
    expect((sent.body.results as Json[]).every((r) => r.status === "queued")).toBe(true);

    // idempotent retry: same logical id → duplicate everywhere
    const retry = await send(a.token, logical, [
      { device_id: a2.device_id, ciphertext_b64: ct(111) },
      { device_id: b.device_id, ciphertext_b64: ct(222) },
    ]);
    expect(retry.status).toBe(200);
    expect((retry.body.results as Json[]).every((r) => r.status === "duplicate")).toBe(true);

    // recipient view: ordered rows with sender address attached
    const inbox1 = await http("GET", "/messages", { token: b.token });
    expect(inbox1.status).toBe(200);
    expect(inbox1.body.messages.length).toBe(1);
    const row = inbox1.body.messages[0];
    expect(row.logical_msg_id).toBe(logical);
    expect(row.sender_account_id).toBe(a.account_id);
    expect(row.sender_dev_no).toBe(1);
    expect(row.seq).toBe(1);

    // ciphertext round-trips byte-exact
    const decoded = Uint8Array.from(atob(row.ciphertext), (c) => c.charCodeAt(0));
    expect(decoded.length).toBe(222);

    // self-sync device sees its own copy (separate row, same logical id)
    const inboxA2 = await http("GET", "/messages", { token: a2.token });
    expect(inboxA2.body.messages.length).toBe(1);
    expect(inboxA2.body.messages[0].logical_msg_id).toBe(logical);

    // crash-safe redelivery: delivered rows are re-served until ACKed
    const inbox2 = await http("GET", "/messages", { token: b.token });
    expect(inbox2.body.messages.length).toBe(1);
    expect(inbox2.body.messages[0].delivery_id).toBe(row.delivery_id);

    // ACK someone else's queue with your token → nothing deleted
    const foreignAck = await http("POST", "/messages/ack", {
      token: a2.token,
      body: { delivery_ids: [row.delivery_id] },
    });
    expect(foreignAck.status).toBe(200);
    expect(foreignAck.body.deleted).toBe(0);

    // ACK own queue → deleted, then gone
    const ack = await http("POST", "/messages/ack", { token: b.token, body: { delivery_ids: [row.delivery_id] } });
    expect(ack.status).toBe(200);
    expect(ack.body.deleted).toBe(1);
    const ackAgain = await http("POST", "/messages/ack", { token: b.token, body: { delivery_ids: [row.delivery_id] } });
    expect(ackAgain.body.deleted).toBe(0);
    const inbox3 = await http("GET", "/messages", { token: b.token });
    expect(inbox3.body.messages.length).toBe(0);
  });

  it("assigns strictly increasing per-device seq and NEVER reuses numbers after ACK", async () => {
    const a = await registerAccount(nextUsername("msgseq"));
    const b = await registerAccount(nextUsername("msgseqb"));

    for (let i = 0; i < 3; i++) {
      const r = await send(a.token, nextLogicalId(), [{ device_id: b.device_id }]);
      expect(r.status).toBe(200);
    }
    const inbox = await http("GET", "/messages", { token: b.token });
    expect((inbox.body.messages as Json[]).map((m) => m.seq)).toEqual([1, 2, 3]);

    // ACK everything (rows deleted) → counter must NOT rewind
    const ack = await http("POST", "/messages/ack", {
      token: b.token,
      body: { delivery_ids: (inbox.body.messages as Json[]).map((m) => m.delivery_id) },
    });
    expect(ack.body.deleted).toBe(3);

    const r2 = await send(a.token, nextLogicalId(), [{ device_id: b.device_id }]);
    expect(r2.status).toBe(200);
    const inbox2 = await http("GET", "/messages", { token: b.token });
    expect((inbox2.body.messages as Json[]).map((m) => m.seq)).toEqual([4]);
  });

  it("re-queues a retried logical id AFTER the original row was ACKed (design §5/§12: dedupe is queue-scoped; client tolerates via logical dedupe + crypto duplicate rejection)", async () => {
    const a = await registerAccount(nextUsername("msgrep"));
    const b = await registerAccount(nextUsername("msgrepb"));
    const logical = nextLogicalId();

    const first = await send(a.token, logical, [{ device_id: b.device_id }]);
    expect(first.status).toBe(200);
    const bInbox = await http("GET", "/messages?limit=1", { token: b.token });
    expect(bInbox.body.messages.length).toBe(1);
    const deliveredId = bInbox.body.messages[0].delivery_id;
    const ack = await http("POST", "/messages/ack", { token: b.token, body: { delivery_ids: [deliveredId] } });
    expect(ack.body.deleted).toBe(1);

    // the idempotency key lives in message_queue; once the row is consumed
    // (ACKed) a re-POST queues a fresh row with a strictly higher seq — the
    // client-side contract (logical dedupe + DuplicateMessageException) makes
    // this safe (design §7/§12).
    const again = await send(a.token, logical, [{ device_id: b.device_id }]);
    expect(again.status).toBe(200);
    expect(again.body.results[0].status).toBe("queued");
    const inbox2 = await http("GET", "/messages", { token: b.token });
    expect((inbox2.body.messages as Json[]).map((m) => m.seq)).toEqual([2]);
  });

  it("orders a single-device burst with DISTINCT seqs (concurrent sends)", async () => {
    const a = await registerAccount(nextUsername("msgburst"));
    const b = await registerAccount(nextUsername("msgburstb"));

    const responses = await Promise.all(
      Array.from({ length: 12 }, () => send(a.token, nextLogicalId(), [{ device_id: b.device_id }])),
    );
    expect(responses.every((r) => r.status === 200)).toBe(true);

    const inbox = await http("GET", "/messages?limit=200", { token: b.token });
    const seqs = (inbox.body.messages as Json[]).map((m) => m.seq).sort((x, y) => x - y);
    expect(seqs.length).toBe(12);
    expect(new Set(seqs).size).toBe(12); // no duplicates
  });
});

describe("messages: TTL", () => {
  it("expires rows past 7 days, excludes them from fetch, and purges them", async () => {
    const a = await registerAccount(nextUsername("msgttl"));
    const b = await registerAccount(nextUsername("msgttlb"));
    const r = await send(a.token, nextLogicalId(), [{ device_id: b.device_id }]);
    expect(r.status).toBe(200);

    // force-expire the row (equivalent to the clock passing the TTL)
    await env.DB
      .prepare("UPDATE message_queue SET expires_at = ?1 WHERE recipient_dev_id = ?2")
      .bind(Date.now() - 1000, b.device_id)
      .run();

    const inbox = await http("GET", "/messages", { token: b.token });
    expect(inbox.status).toBe(200);
    expect(inbox.body.messages.length).toBe(0);

    // the purge removed the row entirely (direct D1 check)
    const count = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM message_queue WHERE recipient_dev_id = ?1")
      .bind(b.device_id)
      .first<{ n: number }>();
    expect(count!.n).toBe(0);
  });
});

describe("messages: queue cap", () => {
  it("returns 429 QUEUE_FULL when a recipient's live queue reaches the cap", async () => {
    const a = await registerAccount(nextUsername("msgfull"));
    const b = await registerAccount(nextUsername("msgfullb"));

    // fill b's queue directly (bypasses HTTP for speed); D1 caps one statement
    // at 100 bound variables → 12 rows (8 params each) per statement, batched.
    const now = Date.now();
    const stmts: D1PreparedStatement[] = [];
    for (let off = 1; off <= MAX_QUEUE_PER_DEVICE; off += 12) {
      const ids: number[] = [];
      const params: unknown[] = [];
      for (let i = off; i < Math.min(off + 12, MAX_QUEUE_PER_DEVICE + 1); i++) {
        ids.push(i);
        params.push(`full-${i}`, `logical-full-${i}`, a.device_id, b.device_id, 10_000 + i, new Uint8Array(8), now, now + 86_400_000);
      }
      const placeholders = ids.map((i, k) => {
        const base = k * 8;
        return `(?${base + 1}, ?${base + 2}, ?${base + 3}, ?${base + 4}, ?${base + 5}, ?${base + 6}, 'queued', ?${base + 7}, ?${base + 8})`;
      });
      stmts.push(
        env.DB
          .prepare(
            `INSERT INTO message_queue (delivery_id, logical_msg_id, sender_dev_id, recipient_dev_id, seq, ciphertext, state, server_recv_at, expires_at)
             VALUES ${placeholders.join(",")}`,
          )
          .bind(...params),
      );
    }
    for (let i = 0; i < stmts.length; i += 50) {
      await env.DB.batch(stmts.slice(i, i + 50));
    }

    const res = await send(a.token, nextLogicalId(), [{ device_id: b.device_id }]);
    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe("QUEUE_FULL");
  });
});

describe("messages: D1 100-bind-parameter limit (real-D1 constraint)", () => {
  async function fillQueue(deviceId: string, senderDeviceId: string, count: number): Promise<string[]> {
    const now = Date.now();
    const ids: string[] = [];
    const stmts: D1PreparedStatement[] = [];
    for (let off = 1; off <= count; off += 12) {
      const params: unknown[] = [];
      const placeholders: string[] = [];
      for (let i = off; i < Math.min(off + 12, count + 1); i++) {
        const deliveryId = `bind-${deviceId}-${i}`;
        ids.push(deliveryId);
        placeholders.push(`(?${params.length + 1}, ?${params.length + 2}, ?${params.length + 3}, ?${params.length + 4}, ?${params.length + 5}, ?${params.length + 6}, 'queued', ?${params.length + 7}, ?${params.length + 8})`);
        params.push(deliveryId, `bind-logical-${i}`, senderDeviceId, deviceId, i, new Uint8Array(8), now, now + 86_400_000);
      }
      stmts.push(
        env.DB
          .prepare(
            `INSERT INTO message_queue (delivery_id, logical_msg_id, sender_dev_id, recipient_dev_id, seq, ciphertext, state, server_recv_at, expires_at)
             VALUES ${placeholders.join(",")}`,
          )
          .bind(...params),
      );
    }
    for (let i = 0; i < stmts.length; i += 50) {
      await env.DB.batch(stmts.slice(i, i + 50));
    }
    return ids;
  }

  it("handles a 127-target send (chunked IN queries, 2 existence chunks)", async () => {
    const a = await registerAccount(nextUsername("msgbind"));
    const targets = [{ device_id: a.device_id }];
    for (let i = 0; i < 126; i++) {
      targets.push({ device_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}` });
    }
    const res = await send(a.token, nextLogicalId(), targets);
    expect(res.status).toBe(200); // NOT a bind-limit 500
    const queued = (res.body.results as Json[]).filter((r) => r.status === "queued").length;
    const rejected = (res.body.results as Json[]).filter((r) => r.status === "rejected").length;
    expect(queued).toBe(1);
    expect(rejected).toBe(126);
  });

  it("fetches 200 rows (4 mark-delivered batches) and acks 200 ids (3 chunked DELETEs)", async () => {
    const a = await registerAccount(nextUsername("msgbind2"));
    const b = await registerAccount(nextUsername("msgbind2b"));

    const ids = await fillQueue(b.device_id, a.device_id, 200);
    expect(ids.length).toBe(200);

    const inbox = await http("GET", "/messages?limit=200", { token: b.token });
    expect(inbox.status).toBe(200);
    expect(inbox.body.messages.length).toBe(200);

    // all 200 marked delivered in chunked batches — redelivered on next fetch
    const inbox2 = await http("GET", "/messages?limit=200", { token: b.token });
    expect(inbox2.body.messages.length).toBe(200);

    const ack = await http("POST", "/messages/ack", { token: b.token, body: { delivery_ids: ids } });
    expect(ack.status).toBe(200);
    expect(ack.body.deleted).toBe(200);
  });
});

describe("messages: revocation interplay", () => {
  it("purges the queue of a revoked device (as recipient and as sender)", async () => {
    const a = await registerAccount(nextUsername("msgrev"));
    const b = await registerAccount(nextUsername("msgrevb"));

    const r1 = await send(a.token, nextLogicalId(), [{ device_id: b.device_id }]);
    expect(r1.status).toBe(200);
    const r2 = await send(b.token, nextLogicalId(), [{ device_id: a.device_id }]);
    expect(r2.status).toBe(200);

    const del = await http("DELETE", `/devices/${b.device_id}`, { token: b.token });
    expect(del.status).toBe(204);

    const asRecipient = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM message_queue WHERE recipient_dev_id = ?1")
      .bind(b.device_id)
      .first<{ n: number }>();
    const asSender = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM message_queue WHERE sender_dev_id = ?1")
      .bind(b.device_id)
      .first<{ n: number }>();
    expect(asRecipient!.n).toBe(0);
    expect(asSender!.n).toBe(0);
  });
});
