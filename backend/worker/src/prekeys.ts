import { HttpError } from "./errors";
import { asBytes, b64ToBytes } from "./util";

/**
 * Phase 2 — PreKey Infrastructure (PQXDH), per PHASE2_PREKEY_DESIGN.md.
 *
 * The server is a byte-server: it validates shapes (lengths/prefixes verified
 * against the real libsignal 0.102.1, design doc Appendix A) and stores opaque
 * blobs. It never re-encodes or re-computes cryptographic material.
 *
 * Wire formats (verified, design doc V4-V7):
 *  - X25519 public key: 33 bytes, 0x05 prefix (libsignal serialize() form)
 *  - Kyber-1024 public key: 1569 bytes, 0x08 prefix (libsignal serialize() form)
 *  - signatures: 64 bytes over the serialize() bytes with the identity key
 *  - key_id: integer 0..16777215 (libsignal Medium range; NULL_PRE_KEY_ID = -1)
 */

export const EC_PUB_LEN = 33;
export const KEM_PUB_LEN = 1569;
export const SIG_LEN = 64;
export const MAX_KEY_ID = 16_777_215;
export const MAX_UPLOAD_BATCH = 100;
export const MAX_STORED_ONE_TIME_EC = 500;
export const MAX_STORED_ONE_TIME_KYBER = 300;

interface RawKeyInput {
  key_id: unknown;
  public_key: unknown;
  signature?: unknown;
}

interface ValidatedKey {
  keyId: number;
  pub: Uint8Array;
  sig: Uint8Array | null;
}

function requireKeyId(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_KEY_ID) {
    throw new HttpError(400, "INVALID_PREKEY", `key_id must be an integer in 0..${MAX_KEY_ID}`);
  }
  return value;
}

function requirePubBytes(value: unknown, expectedLen: number, prefix: number, kind: string): Uint8Array {
  if (typeof value !== "string") {
    throw new HttpError(400, "INVALID_PREKEY", `public_key (${kind}) must be base64`);
  }
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(value);
  } catch {
    throw new HttpError(400, "INVALID_PREKEY", `public_key (${kind}) is not valid base64`);
  }
  if (bytes.length !== expectedLen || bytes[0] !== prefix) {
    throw new HttpError(400, "INVALID_PREKEY", `public_key (${kind}) must be ${expectedLen} bytes with 0x${prefix.toString(16)} prefix`);
  }
  return bytes;
}

function requireSigBytes(value: unknown): Uint8Array {
  if (typeof value !== "string") {
    throw new HttpError(400, "INVALID_PREKEY", "signature must be base64");
  }
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(value);
  } catch {
    throw new HttpError(400, "INVALID_PREKEY", "signature is not valid base64");
  }
  if (bytes.length !== SIG_LEN) {
    throw new HttpError(400, "INVALID_PREKEY", `signature must be ${SIG_LEN} bytes`);
  }
  return bytes;
}

function validateKey(raw: RawKeyInput, kind: "ec" | "kem", signed: boolean): ValidatedKey {
  const keyId = requireKeyId(raw.key_id);
  const pub =
    kind === "ec"
      ? requirePubBytes(raw.public_key, EC_PUB_LEN, 0x05, "ec")
      : requirePubBytes(raw.public_key, KEM_PUB_LEN, 0x08, "kyber");
  const sig = signed ? requireSigBytes(raw.signature) : null;
  return { keyId, pub, sig };
}

function validateKeyArray(value: unknown, kind: "ec" | "kem", signed: boolean, field: string): ValidatedKey[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new HttpError(400, "VALIDATION_ERROR", `field ${field} must be an array`);
  }
  if (value.length > MAX_UPLOAD_BATCH) {
    throw new HttpError(413, "TOO_MANY_PREKEYS", `${field} accepts at most ${MAX_UPLOAD_BATCH} keys per upload`);
  }
  return value.map((raw, i) => {
    if (!raw || typeof raw !== "object") {
      throw new HttpError(400, "VALIDATION_ERROR", `${field}[${i}] must be an object`);
    }
    return validateKey(raw as RawKeyInput, kind, signed);
  });
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function countUnusedEc(db: D1Database, deviceId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM one_time_prekeys WHERE device_id = ?1 AND used_at IS NULL")
    .bind(deviceId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function countUnusedKyberOneTime(db: D1Database, deviceId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 0 AND used_at IS NULL")
    .bind(deviceId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function currentSignedPreKeyId(db: D1Database, deviceId: string): Promise<number | null> {
  const row = await db
    .prepare("SELECT key_id FROM signed_prekeys WHERE device_id = ?1 ORDER BY created_at DESC, key_id DESC LIMIT 1")
    .bind(deviceId)
    .first<{ key_id: number }>();
  return row?.key_id ?? null;
}

async function currentLastResortId(db: D1Database, deviceId: string): Promise<number | null> {
  const row = await db
    .prepare("SELECT key_id FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 1 AND used_at IS NULL")
    .bind(deviceId)
    .first<{ key_id: number }>();
  return row?.key_id ?? null;
}

async function remainingCounts(db: D1Database, deviceId: string): Promise<UploadResult> {
  return {
    signed_prekey_id: await currentSignedPreKeyId(db, deviceId),
    last_resort_kyber_id: await currentLastResortId(db, deviceId),
    one_time_ec_remaining: await countUnusedEc(db, deviceId),
    one_time_kyber_remaining: await countUnusedKyberOneTime(db, deviceId),
  };
}

/**
 * Returns keys that genuinely need inserting: stored rows with IDENTICAL bytes
 * are dropped (idempotent no-op per design §3.1); a stored row with the same
 * key_id but DIFFERENT bytes throws 409 before any write happens.
 */
async function filterNewKeys(
  db: D1Database,
  table: "one_time_prekeys" | "kyber_prekeys",
  deviceId: string,
  keys: ValidatedKey[],
): Promise<ValidatedKey[]> {
  if (keys.length === 0) return [];
  const rows = await db
    .prepare(
      table === "one_time_prekeys"
        ? "SELECT key_id, public_key FROM one_time_prekeys WHERE device_id = ?1"
        : "SELECT key_id, public_key FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 0",
    )
    .bind(deviceId)
    .all<{ key_id: number; public_key: unknown }>();
  const stored = new Map<number, Uint8Array>();
  for (const r of rows.results ?? []) stored.set(r.key_id, asBytes(r.public_key));
  const out: ValidatedKey[] = [];
  for (const k of keys) {
    const existing = stored.get(k.keyId);
    if (existing === undefined) {
      out.push(k);
    } else if (!bytesEqual(existing, k.pub)) {
      throw new HttpError(409, "KEY_ID_CONFLICT", `key_id ${k.keyId} already exists for this device with different bytes`);
    }
    // identical bytes -> idempotent no-op
  }
  return out;
}

// ---------------------------------------------------------------------------
// Upload (POST /prekeys)
// ---------------------------------------------------------------------------

export interface UploadResult {
  signed_prekey_id: number | null;
  last_resort_kyber_id: number | null;
  one_time_ec_remaining: number;
  one_time_kyber_remaining: number;
}

export async function uploadPreKeys(
  db: D1Database,
  input: {
    deviceId: string;
    body: Record<string, unknown>;
    now: number;
  },
): Promise<UploadResult> {
  const body = input.body;
  const hasAnyField =
    body["signed_prekey"] !== undefined ||
    body["last_resort_kyber"] !== undefined ||
    body["one_time_prekeys"] !== undefined ||
    body["one_time_kyber_prekeys"] !== undefined;
  if (!hasAnyField) {
    // Empty body = count probe; never mutates (design §3.1).
    return remainingCounts(db, input.deviceId);
  }

  let signed: ValidatedKey | null = null;
  let lastResort: ValidatedKey | null = null;

  if (body["signed_prekey"] !== undefined) {
    if (!body["signed_prekey"] || typeof body["signed_prekey"] !== "object") {
      throw new HttpError(400, "VALIDATION_ERROR", "signed_prekey must be an object");
    }
    signed = validateKey(body["signed_prekey"] as RawKeyInput, "ec", true);
  }
  if (body["last_resort_kyber"] !== undefined) {
    if (!body["last_resort_kyber"] || typeof body["last_resort_kyber"] !== "object") {
      throw new HttpError(400, "VALIDATION_ERROR", "last_resort_kyber must be an object");
    }
    lastResort = validateKey(body["last_resort_kyber"] as RawKeyInput, "kem", true);
  }
  const oneTimeEcRaw = validateKeyArray(body["one_time_prekeys"], "ec", false, "one_time_prekeys");
  const oneTimeKyberRaw = validateKeyArray(body["one_time_kyber_prekeys"], "kem", true, "one_time_kyber_prekeys");

  // Idempotency/conflict resolution happens BEFORE any write (design §3.1).
  const oneTimeEc = await filterNewKeys(db, "one_time_prekeys", input.deviceId, oneTimeEcRaw);
  const oneTimeKyber = await filterNewKeys(db, "kyber_prekeys", input.deviceId, oneTimeKyberRaw);

  // Storage caps: evict the OLDEST unused one-time rows beyond the cap in the
  // same batch, so a device's own refill can never wedge on its own garbage.
  const stmts: D1PreparedStatement[] = [];
  if (signed) {
    // Server keeps only the latest signed prekey (Signal server semantics).
    // An identical re-upload is a no-op; anything else (including the same
    // key_id with new bytes — rotation) is DELETE-all + INSERT in one batch,
    // so there is no UNIQUE self-conflict and no empty window (§4 A3).
    const current = await db
      .prepare("SELECT key_id, public_key, signature FROM signed_prekeys WHERE device_id = ?1 ORDER BY created_at DESC, key_id DESC LIMIT 1")
      .bind(input.deviceId)
      .first<{ key_id: number; public_key: unknown; signature: unknown }>();
    const identical =
      current !== null &&
      current.key_id === signed.keyId &&
      bytesEqual(asBytes(current.public_key), signed.pub) &&
      bytesEqual(asBytes(current.signature), signed.sig!);
    if (!identical) {
      stmts.push(db.prepare("DELETE FROM signed_prekeys WHERE device_id = ?1").bind(input.deviceId));
      stmts.push(
        db
          .prepare(
            "INSERT INTO signed_prekeys (id, device_id, key_id, public_key, signature, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
          )
          .bind(crypto.randomUUID(), input.deviceId, signed.keyId, signed.pub, signed.sig!, input.now),
      );
    }
  }
  if (lastResort) {
    // Same policy as the signed prekey: identical re-upload = no-op; any
    // change = DELETE old last-resort + INSERT replacement in one batch (A2).
    // (Replaced last-resort rows are deleted, not retained: they can never be
    // served again and the receiver keeps its own copy until it is consumed.)
    const current = await db
      .prepare("SELECT key_id, public_key, signature FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 1 AND used_at IS NULL")
      .bind(input.deviceId)
      .first<{ key_id: number; public_key: unknown; signature: unknown }>();
    const identical =
      current !== null &&
      current.key_id === lastResort.keyId &&
      bytesEqual(asBytes(current.public_key), lastResort.pub) &&
      bytesEqual(asBytes(current.signature), lastResort.sig!);
    if (!identical) {
      stmts.push(db.prepare("DELETE FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 1").bind(input.deviceId));
      stmts.push(
        db
          .prepare(
            "INSERT INTO kyber_prekeys (id, device_id, key_id, public_key, signature, created_at, used_at, is_last_resort) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 1)",
          )
          .bind(crypto.randomUUID(), input.deviceId, lastResort.keyId, lastResort.pub, lastResort.sig!, input.now),
      );
    }
  }

  if (oneTimeEc.length > 0) {
    const stored = await countUnusedEc(db, input.deviceId);
    const overflow = stored + oneTimeEc.length - MAX_STORED_ONE_TIME_EC;
    if (overflow > 0) {
      stmts.push(
        db
          .prepare(
            `DELETE FROM one_time_prekeys WHERE id IN (
               SELECT id FROM one_time_prekeys WHERE device_id = ?1 AND used_at IS NULL
               ORDER BY created_at ASC, key_id ASC LIMIT ?2
             )`,
          )
          .bind(input.deviceId, overflow),
      );
    }
    for (const k of oneTimeEc) {
      stmts.push(
        db
          .prepare("INSERT INTO one_time_prekeys (id, device_id, key_id, public_key, created_at, used_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL)")
          .bind(crypto.randomUUID(), input.deviceId, k.keyId, k.pub, input.now),
      );
    }
  }

  if (oneTimeKyber.length > 0) {
    const stored = await countUnusedKyberOneTime(db, input.deviceId);
    const overflow = stored + oneTimeKyber.length - MAX_STORED_ONE_TIME_KYBER;
    if (overflow > 0) {
      stmts.push(
        db
          .prepare(
            `DELETE FROM kyber_prekeys WHERE id IN (
               SELECT id FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 0 AND used_at IS NULL
               ORDER BY created_at ASC, key_id ASC LIMIT ?2
             )`,
          )
          .bind(input.deviceId, overflow),
      );
    }
    for (const k of oneTimeKyber) {
      stmts.push(
        db
          .prepare("INSERT INTO kyber_prekeys (id, device_id, key_id, public_key, signature, created_at, used_at, is_last_resort) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0)")
          .bind(crypto.randomUUID(), input.deviceId, k.keyId, k.pub, k.sig!, input.now),
      );
    }
  }

  // All mutations of one upload land atomically (design §4 A2). Only keys that
  // passed the dedupe check reach this batch; a concurrent same-device upload
  // inserting the identical key_id first causes a UNIQUE failure here — the
  // stored bytes are then identical, so the correct outcome is the no-op
  // success path. Any other UNIQUE failure is a genuine conflict (409).
  if (stmts.length > 0) {
    try {
      await db.batch(stmts);
    } catch (e) {
      const msg = String((e as Error).message || e);
      if (/UNIQUE|PRIMARY KEY/i.test(msg)) {
        const fresh = await remainingCounts(db, input.deviceId);
        const allKnown =
          (signed === null || fresh.signed_prekey_id !== null) &&
          (lastResort === null || fresh.last_resort_kyber_id !== null);
        if (allKnown) {
          // Concurrent identical upload won the race; our batch rolled back
          // atomically and the stored state already equals the desired state.
          return fresh;
        }
        throw new HttpError(409, "KEY_ID_CONFLICT", "key_id conflict for this device");
      }
      throw e;
    }
  }

  return remainingCounts(db, input.deviceId);
}

// ---------------------------------------------------------------------------
// Bundle fetch (GET /devices/:id/prekeys)
// ---------------------------------------------------------------------------

/**
 * CAS pop of the lowest unused one-time key. The conditional UPDATE guarded by
 * `used_at IS NULL` is the atomicity primitive (design §4 A1, amended after the
 * Gate 1 test): D1 executes statements one at a time per database, so
 * check-and-set cannot interleave; `meta.changes === 1` proves THIS request
 * owns the key. A lost race and a transient D1 error both burn one attempt and
 * retry — a transient failure can never become a second delivery of the same
 * key (the UPDATE either changes exactly 1 row or 0 rows).
 */
async function casPopOneTime(
  db: D1Database,
  table: "one_time_prekeys" | "kyber_prekeys",
  deviceId: string,
  now: number,
): Promise<{ key_id: number; public_key: Uint8Array; signature: Uint8Array | null } | null> {
  const selectSql =
    table === "one_time_prekeys"
      ? "SELECT key_id, public_key FROM one_time_prekeys WHERE device_id = ?1 AND used_at IS NULL ORDER BY key_id ASC LIMIT 1"
      : "SELECT key_id, public_key, signature FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 0 AND used_at IS NULL ORDER BY key_id ASC LIMIT 1";
  const updateSql =
    table === "one_time_prekeys"
      ? "UPDATE one_time_prekeys SET used_at = ?1 WHERE device_id = ?2 AND key_id = ?3 AND used_at IS NULL"
      : "UPDATE kyber_prekeys SET used_at = ?1 WHERE device_id = ?2 AND key_id = ?3 AND used_at IS NULL";

  for (let attempt = 0; attempt < 15; attempt++) {
    let row: { key_id: number; public_key: unknown; signature?: unknown } | null = null;
    try {
      row = await db.prepare(selectSql).bind(deviceId).first();
    } catch {
      continue; // transient infrastructure error: retry, never reuse
    }
    if (!row) return null;
    try {
      const res = await db.prepare(updateSql).bind(now, deviceId, row.key_id).run();
      if (res.meta.changes === 1) {
        return {
          key_id: row.key_id,
          public_key: asBytes(row.public_key),
          signature: row.signature !== undefined && row.signature !== null ? asBytes(row.signature) : null,
        };
      }
      // changes === 0: another request won the CAS; retry with the next key.
    } catch {
      // The conditional UPDATE either lands (1 row) or not (0 rows) — a thrown
      // transient error can never have half-committed; safe to retry.
      continue;
    }
  }
  return null;
}

export interface BundleResult {
  account_id: string;
  device_id: string;
  dev_no: number;
  registration_id: number;
  identity_pub: string; // raw 32 bytes, b64 — client maps via ECPublicKey.fromPublicKeyBytes
  signed_prekey: { key_id: number; public_key: string; signature: string };
  one_time_prekey: { key_id: number; public_key: string } | null;
  kyber_prekey: { key_id: number; public_key: string; signature: string; last_resort: boolean };
}

function b64Of(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export async function fetchBundle(
  db: D1Database,
  input: { targetDeviceId: string; now: number },
): Promise<BundleResult> {
  const device = await db
    .prepare(
      "SELECT account_id, dev_no, registration_id, identity_pub_key, revoked_at FROM devices WHERE device_id = ?1",
    )
    .bind(input.targetDeviceId)
    .first<{ account_id: string; dev_no: number; registration_id: number; identity_pub_key: unknown; revoked_at: number | null }>();
  if (!device || device.revoked_at !== null) {
    // Uniform shape for unknown AND revoked devices (anti-enumeration).
    throw new HttpError(404, "DEVICE_NOT_FOUND", "device not found");
  }

  const signed = await db
    .prepare("SELECT key_id, public_key, signature FROM signed_prekeys WHERE device_id = ?1 ORDER BY created_at DESC, key_id DESC LIMIT 1")
    .bind(input.targetDeviceId)
    .first<{ key_id: number; public_key: unknown; signature: unknown }>();

  const lastResort = await db
    .prepare("SELECT key_id, public_key, signature FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 1 AND used_at IS NULL")
    .bind(input.targetDeviceId)
    .first<{ key_id: number; public_key: unknown; signature: unknown }>();

  if (!signed || !lastResort) {
    throw new HttpError(409, "PREKEYS_NOT_READY", "device has not uploaded its prekeys yet");
  }

  const ec = await casPopOneTime(db, "one_time_prekeys", input.targetDeviceId, input.now);
  const kem = await casPopOneTime(db, "kyber_prekeys", input.targetDeviceId, input.now);

  return {
    account_id: device.account_id,
    device_id: input.targetDeviceId,
    dev_no: device.dev_no,
    registration_id: device.registration_id,
    identity_pub: b64Of(asBytes(device.identity_pub_key)),
    signed_prekey: {
      key_id: signed.key_id,
      public_key: b64Of(asBytes(signed.public_key)),
      signature: b64Of(asBytes(signed.signature)),
    },
    one_time_prekey: ec ? { key_id: ec.key_id, public_key: b64Of(ec.public_key) } : null,
    kyber_prekey: {
      key_id: kem ? kem.key_id : lastResort.key_id,
      public_key: b64Of(kem ? kem.public_key : asBytes(lastResort.public_key)),
      signature: b64Of(asBytes(kem ? kem.signature! : lastResort.signature)),
      last_resort: !kem,
    },
  };
}

// ---------------------------------------------------------------------------
// Revoke support: purge all prekey rows for a device (joined into the revoke
// batch — design §4 A4).
// ---------------------------------------------------------------------------

export function purgeStatements(db: D1Database, deviceId: string): D1PreparedStatement[] {
  return [
    db.prepare("DELETE FROM signed_prekeys WHERE device_id = ?1").bind(deviceId),
    db.prepare("DELETE FROM one_time_prekeys WHERE device_id = ?1").bind(deviceId),
    db.prepare("DELETE FROM kyber_prekeys WHERE device_id = ?1").bind(deviceId),
  ];
}
