import { HttpError } from "./errors";
import { asBytes, b64ToBytes, bytesToB64 } from "./util";

/**
 * Phase 3 — Messaging & Message Delivery, per PHASE3_MESSAGING_DESIGN.md.
 *
 * The server is a byte-server: ciphertexts are opaque blobs encrypted by the
 * sender per recipient device (libsignal SessionCipher); the server never
 * decrypts, inspects, or logs them. All invariants below were verified against
 * the real libsignal-client 0.102.1 (design doc Appendix A, Gate 3).
 *
 * Ordering/idempotency invariants:
 *  - seq is server-assigned from the device_seq counter (upsert-allocation in
 *    ONE statement) — never reused, gaps possible and harmless (§6).
 *  - idempotency key: UNIQUE (sender_dev_id, recipient_dev_id, logical_msg_id)
 *    — a retried POST reports already-stored targets as "duplicate" (§5).
 *  - Ciphertext is never logged, in any branch of this file (§10).
 */

export const MAX_CIPHERTEXT_BYTES = 65_536;
export const MAX_TARGETS_PER_SEND = 127;
export const MAX_QUEUE_PER_DEVICE = 2_000;
export const MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_FETCH_LIMIT = 200;
export const MAX_ACK_IDS = 200;
export const FANOUT_CHUNK = 25;
export const MAX_LOGICAL_ID_LEN = 64;
/**
 * Real-D1 constraint (discovered empirically during implementation, documented
 * at d1/platform/limits): at most 100 bound parameters per query. Every IN(...)
 * query and every batch below stays inside this ceiling.
 */
export const MAX_BINDS_PER_QUERY = 100;
const IN_CHUNK = 90; // IN(...) members + a few extra binds stay under the cap
const BATCH_CHUNK = 50; // statements per batch (each statement ≤ ~96 binds)

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type TargetStatus = "queued" | "duplicate" | "rejected";

export interface TargetResult {
  device_id: string;
  status: TargetStatus;
}

interface ValidatedTarget {
  deviceId: string;
  ciphertext: Uint8Array;
}

function validateLogicalMsgId(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_LOGICAL_ID_LEN || !UUID_RE.test(value)) {
    throw new HttpError(400, "VALIDATION_ERROR", "logical_msg_id must be a UUID string");
  }
  return value;
}

function validateTargets(value: unknown): ValidatedTarget[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new HttpError(400, "VALIDATION_ERROR", "targets must be a non-empty array");
  }
  if (value.length > MAX_TARGETS_PER_SEND) {
    throw new HttpError(413, "TOO_MANY_TARGETS", `targets accepts at most ${MAX_TARGETS_PER_SEND} devices per send`);
  }
  const seen = new Set<string>();
  const out: ValidatedTarget[] = [];
  value.forEach((raw, i) => {
    if (!raw || typeof raw !== "object") {
      throw new HttpError(400, "VALIDATION_ERROR", `targets[${i}] must be an object`);
    }
    const t = raw as Record<string, unknown>;
    if (typeof t["device_id"] !== "string" || t["device_id"].length === 0 || t["device_id"].length > 64) {
      throw new HttpError(400, "VALIDATION_ERROR", `targets[${i}].device_id must be a string`);
    }
    if (seen.has(t["device_id"])) {
      throw new HttpError(400, "VALIDATION_ERROR", `targets[${i}].device_id is duplicated`);
    }
    seen.add(t["device_id"]);
    if (typeof t["ciphertext_b64"] !== "string") {
      throw new HttpError(400, "VALIDATION_ERROR", `targets[${i}].ciphertext_b64 must be base64`);
    }
    let bytes: Uint8Array;
    try {
      bytes = b64ToBytes(t["ciphertext_b64"]);
    } catch {
      throw new HttpError(400, "VALIDATION_ERROR", `targets[${i}].ciphertext_b64 is not valid base64`);
    }
    if (bytes.length === 0 || bytes.length > MAX_CIPHERTEXT_BYTES) {
      throw new HttpError(413, "CIPHERTEXT_TOO_LARGE", `targets[${i}] ciphertext must be 1..${MAX_CIPHERTEXT_BYTES} bytes`);
    }
    out.push({ deviceId: t["device_id"], ciphertext: bytes });
  });
  return out;
}

function b64Of(bytes: Uint8Array): string {
  return bytesToB64(bytes);
}

function isUniqueViolation(e: unknown): boolean {
  return /UNIQUE|PRIMARY KEY/i.test(String((e as Error).message || e));
}

function placeholders(from: number, count: number): string {
  return Array.from({ length: count }, (_, i) => `?${from + i}`).join(",");
}

// ---------------------------------------------------------------------------
// Send (POST /messages) — fan-out with per-device seq + idempotency
// ---------------------------------------------------------------------------

/**
 * Allocates the next seq for a device in ONE atomic statement. A missing
 * counter row self-heals (fresh row starts at next_seq=2 → allocated seq=1);
 * concurrent allocators serialize inside SQLite's single-writer engine, and
 * UNIQUE (recipient_dev_id, seq) is the hard backstop.
 */
function allocateSeqStmt(db: D1Database, deviceId: string): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO device_seq (device_id, next_seq) VALUES (?1, 2)
       ON CONFLICT (device_id) DO UPDATE SET next_seq = next_seq + 1`,
    )
    .bind(deviceId);
}

/**
 * Guarded insert (design §6): lands ONLY while the target device is active.
 * Returns meta.changes via the batch result — 0 changes ⇒ revoked mid-flight.
 */
function queueInsertStmt(
  db: D1Database,
  input: { deliveryId: string; logicalMsgId: string; senderDevId: string; target: ValidatedTarget; now: number },
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO message_queue (delivery_id, logical_msg_id, sender_dev_id, recipient_dev_id, seq, ciphertext, state, server_recv_at, expires_at)
       SELECT ?1, ?2, ?3, ?4,
              (SELECT next_seq - 1 FROM device_seq WHERE device_id = ?4),
              ?5, 'queued', ?6, ?6 + ${MESSAGE_TTL_MS}
       WHERE EXISTS (SELECT 1 FROM devices WHERE device_id = ?4 AND revoked_at IS NULL)`,
    )
    .bind(
      input.deliveryId,
      input.logicalMsgId,
      input.senderDevId,
      input.target.deviceId,
      input.target.ciphertext,
      input.now,
    );
}

export async function sendMessages(
  db: D1Database,
  input: { senderDeviceId: string; body: Record<string, unknown>; now: number },
): Promise<{ results: TargetResult[] }> {
  const logicalMsgId = validateLogicalMsgId(input.body["logical_msg_id"]);
  const targets = validateTargets(input.body["targets"]);
  const targetIds = targets.map((t) => t.deviceId);
  const byId = new Map(targets.map((t) => [t.deviceId, t]));
  const status = new Map<string, TargetStatus>();

  // 1) Target existence/activeness — unknown AND revoked report identically
  //    (anti-enumeration, §13). Resolved BEFORE any counter allocation.
  //    IN(...) queries are chunked under the D1 100-bind-parameter limit.
  const activeIds = new Set<string>();
  for (let i = 0; i < targetIds.length; i += IN_CHUNK) {
    const chunk = targetIds.slice(i, i + IN_CHUNK);
    const rows = await db
      .prepare(`SELECT device_id, revoked_at FROM devices WHERE device_id IN (${placeholders(1, chunk.length)})`)
      .bind(...chunk)
      .all<{ device_id: string; revoked_at: number | null }>();
    for (const r of rows.results ?? []) {
      if (r.revoked_at === null) activeIds.add(r.device_id);
    }
  }
  for (const id of targetIds) {
    if (!activeIds.has(id)) status.set(id, "rejected");
  }

  // 2) Idempotency pre-read (§5): already-stored (target, logical) pairs are
  //    "duplicate" — never stored twice, never re-counted for seq.
  const pending = targetIds.filter((id) => !status.has(id));
  if (pending.length > 0) {
    for (let i = 0; i < pending.length; i += IN_CHUNK) {
      const chunk = pending.slice(i, i + IN_CHUNK);
      const stored = await db
        .prepare(
          `SELECT recipient_dev_id FROM message_queue WHERE sender_dev_id = ?1 AND logical_msg_id = ?2
           AND recipient_dev_id IN (${placeholders(3, chunk.length)})`,
        )
        .bind(input.senderDeviceId, logicalMsgId, ...chunk)
        .all<{ recipient_dev_id: string }>();
      for (const r of stored.results ?? []) status.set(r.recipient_dev_id, "duplicate");
    }
  }

  // 3) QUEUE_FULL cap (§9) on live (non-expired) rows only.
  const stillPending = targetIds.filter((id) => !status.has(id));
  if (stillPending.length > 0) {
    for (let i = 0; i < stillPending.length; i += IN_CHUNK) {
      const chunk = stillPending.slice(i, i + IN_CHUNK);
      const counts = await db
        .prepare(
          `SELECT recipient_dev_id, COUNT(*) AS n FROM message_queue
           WHERE recipient_dev_id IN (${placeholders(1, chunk.length)}) AND expires_at > ?${chunk.length + 1}
           GROUP BY recipient_dev_id`,
        )
        .bind(...chunk, input.now)
        .all<{ recipient_dev_id: string; n: number }>();
      for (const r of counts.results ?? []) {
        if (r.n >= MAX_QUEUE_PER_DEVICE) {
          throw new HttpError(429, "QUEUE_FULL", `recipient device queue is full (${MAX_QUEUE_PER_DEVICE})`);
        }
      }
    }
  }

  // 4) Chunked atomic fan-out (§6). A UNIQUE loss against a concurrent retry
  //    of the same logical_msg_id rolls the chunk back atomically; the loop
  //    re-classifies and inserts only the still-missing targets.
  let missing = targetIds.filter((id) => !status.has(id));
  for (let round = 0; round < 3 && missing.length > 0; round++) {
    for (let off = 0; off < missing.length; off += FANOUT_CHUNK) {
      const chunk = missing.slice(off, off + FANOUT_CHUNK);
      const stmts: D1PreparedStatement[] = [];
      const inserts: string[] = [];
      for (const id of chunk) {
        stmts.push(allocateSeqStmt(db, id));
        const deliveryId = crypto.randomUUID();
        stmts.push(queueInsertStmt(db, { deliveryId, logicalMsgId, senderDevId: input.senderDeviceId, target: byId.get(id)!, now: input.now }));
        inserts.push(id);
      }
      try {
        const results = await db.batch(stmts);
        for (let i = 0; i < inserts.length; i++) {
          const insertResult = results[i * 2 + 1];
          if (insertResult.meta.changes === 1) status.set(inserts[i], "queued");
          else status.set(inserts[i], "rejected"); // revoked mid-flight (guarded insert)
        }
      } catch (e) {
        if (!isUniqueViolation(e)) throw e;
        // Concurrent send with the same logical_msg_id won: re-read who is
        // stored now, mark those duplicates, and retry the remainder.
        const re = await db
          .prepare(
            `SELECT recipient_dev_id FROM message_queue WHERE sender_dev_id = ?1 AND logical_msg_id = ?2
             AND recipient_dev_id IN (${chunk.map((_, i) => `?${i + 3}`).join(",")})`,
          )
          .bind(input.senderDeviceId, logicalMsgId, ...chunk)
          .all<{ recipient_dev_id: string }>();
        for (const r of re.results ?? []) status.set(r.recipient_dev_id, "duplicate");
      }
    }
    missing = targetIds.filter((id) => !status.has(id));
  }
  for (const id of missing) {
    // Exhausted rounds: report honestly instead of claiming success.
    status.set(id, "rejected");
  }

  return { results: targetIds.map((id) => ({ device_id: id, status: status.get(id)! })) };
}

// ---------------------------------------------------------------------------
// Receive (GET /messages) — ordered fetch + mark-delivered + TTL purge
// ---------------------------------------------------------------------------

export interface InboxMessage {
  delivery_id: string;
  logical_msg_id: string;
  sender_account_id: string;
  sender_dev_no: number;
  seq: number;
  ciphertext: string;
  server_recv_at: number;
  expires_at: number;
}

export async function fetchMessages(
  db: D1Database,
  input: { deviceId: string; limitParam: string | null; now: number },
): Promise<{ messages: InboxMessage[] }> {
  let limit = MAX_FETCH_LIMIT;
  if (input.limitParam !== null) {
    const parsed = Number(input.limitParam);
    if (!Number.isInteger(parsed) || parsed < 1) {
      throw new HttpError(400, "VALIDATION_ERROR", "limit must be a positive integer");
    }
    limit = Math.min(parsed, MAX_FETCH_LIMIT);
  }

  // Opportunistic bounded TTL purge (§4) — expired rows for anyone, capped.
  const purge = db
    .prepare(
      `DELETE FROM message_queue WHERE delivery_id IN (
         SELECT delivery_id FROM message_queue WHERE expires_at < ?1 LIMIT 100
       )`,
    )
    .bind(input.now);

  // Delivered rows are re-served (crash-safe redelivery, §7); the client
  // tolerates re-decryption via libsignal duplicate rejection (Gate3-D).
  const select = db
    .prepare(
      `SELECT mq.delivery_id, mq.logical_msg_id, mq.seq, mq.ciphertext, mq.server_recv_at, mq.expires_at,
              sd.account_id AS sender_account_id, sd.dev_no AS sender_dev_no
       FROM message_queue mq JOIN devices sd ON sd.device_id = mq.sender_dev_id
       WHERE mq.recipient_dev_id = ?1 AND mq.expires_at > ?2
       ORDER BY mq.seq LIMIT ?3`,
    )
    .bind(input.deviceId, input.now, limit);

  const [purgeRes, selectRes] = await db.batch([purge, select]);
  const rows = (selectRes.results ?? []) as {
    delivery_id: string;
    logical_msg_id: string;
    seq: number;
    ciphertext: unknown;
    server_recv_at: number;
    expires_at: number;
    sender_account_id: string;
    sender_dev_no: number;
  }[];

  // Mark exactly the returned rows delivered, scoped to this device. Batches
  // are chunked under D1 batch/bind practical limits.
  for (let i = 0; i < rows.length; i += BATCH_CHUNK) {
    const updates = rows.slice(i, i + BATCH_CHUNK).map((r) =>
      db.prepare("UPDATE message_queue SET state = 'delivered' WHERE delivery_id = ?1 AND recipient_dev_id = ?2").bind(r.delivery_id, input.deviceId),
    );
    await db.batch(updates);
  }
  void purgeRes;

  return {
    messages: rows.map((r) => ({
      delivery_id: r.delivery_id,
      logical_msg_id: r.logical_msg_id,
      sender_account_id: r.sender_account_id,
      sender_dev_no: r.sender_dev_no,
      seq: r.seq,
      ciphertext: b64Of(asBytes(r.ciphertext)),
      server_recv_at: r.server_recv_at,
      expires_at: r.expires_at,
    })),
  };
}

// ---------------------------------------------------------------------------
// ACK (POST /messages/ack) — delete OWN queue rows only
// ---------------------------------------------------------------------------

export async function ackMessages(
  db: D1Database,
  input: { deviceId: string; body: Record<string, unknown> },
): Promise<{ deleted: number }> {
  const ids = input.body["delivery_ids"];
  if (!Array.isArray(ids) || ids.length === 0) {
    throw new HttpError(400, "VALIDATION_ERROR", "delivery_ids must be a non-empty array");
  }
  if (ids.length > MAX_ACK_IDS) {
    throw new HttpError(400, "VALIDATION_ERROR", `delivery_ids accepts at most ${MAX_ACK_IDS} ids`);
  }
  for (const [i, id] of ids.entries()) {
    if (typeof id !== "string" || id.length === 0 || id.length > 64) {
      throw new HttpError(400, "VALIDATION_ERROR", `delivery_ids[${i}] must be a string`);
    }
  }
  // Chunked under the D1 100-bind limit. Chunks run sequentially; ACK is
  // idempotent, so a partial application across chunks is repaired by retry
  // (design §12) — each chunk itself is a single atomic DELETE.
  let deleted = 0;
  for (let i = 0; i < ids.length; i += IN_CHUNK) {
    const chunk = ids.slice(i, i + IN_CHUNK);
    const res = await db
      .prepare(`DELETE FROM message_queue WHERE recipient_dev_id = ?1 AND delivery_id IN (${placeholders(2, chunk.length)})`)
      .bind(input.deviceId, ...chunk)
      .run();
    deleted += res.meta.changes;
  }
  return { deleted };
}

// ---------------------------------------------------------------------------
// Device discovery (GET /accounts/:id/devices) — active devices only
// ---------------------------------------------------------------------------

export interface AccountDevice {
  device_id: string;
  dev_no: number;
  registration_id: number;
}

export async function listAccountDevices(
  db: D1Database,
  input: { accountId: string },
): Promise<{ account_id: string; devices: AccountDevice[] }> {
  const account = await db
    .prepare("SELECT account_id FROM accounts WHERE account_id = ?1")
    .bind(input.accountId)
    .first<{ account_id: string }>();
  if (!account) {
    throw new HttpError(404, "ACCOUNT_NOT_FOUND", "account not found");
  }
  const rows = await db
    .prepare("SELECT device_id, dev_no, registration_id FROM devices WHERE account_id = ?1 AND revoked_at IS NULL ORDER BY dev_no ASC")
    .bind(input.accountId)
    .all<{ device_id: string; dev_no: number; registration_id: number }>();
  return {
    account_id: input.accountId,
    devices: (rows.results ?? []).map((r) => ({ device_id: r.device_id, dev_no: r.dev_no, registration_id: r.registration_id })),
  };
}

// ---------------------------------------------------------------------------
// Revoke support: purge queue rows (as sender AND recipient) + counter row.
// Joined into the revoke batch by devices.ts (§11).
// ---------------------------------------------------------------------------

export function messagePurgeStatements(db: D1Database, deviceId: string): D1PreparedStatement[] {
  return [
    db.prepare("DELETE FROM message_queue WHERE recipient_dev_id = ?1").bind(deviceId),
    db.prepare("DELETE FROM message_queue WHERE sender_dev_id = ?1").bind(deviceId),
    db.prepare("DELETE FROM device_seq WHERE device_id = ?1").bind(deviceId),
  ];
}
