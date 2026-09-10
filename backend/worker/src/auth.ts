/**
 * Device Authentication primitives (Phase 1 auth core).
 *
 * Crypto policy (approved design §13/§14):
 *  - Ed25519 signatures, verified with the OFFICIAL Workers WebCrypto API only.
 *  - Raw 32-byte public keys, raw 64-byte signatures (RFC 8032) — no conversion.
 *  - No custom primitives, no custom signature formats, no hand-rolled verification.
 */

export interface ChallengeInput {
  purpose: "register" | "auth" | "add_device";
  username?: string | null;
  accountId?: string | null;
  deviceId?: string | null;
  identityPubB64?: string | null;
  authPubB64?: string | null;
  authorizerDeviceId?: string | null;
}

export interface ChallengeRecord {
  challenge_id: string;
  nonce: string;
  purpose: string;
  account_id: string | null;
  device_id: string | null;
  username: string | null;
  identity_pub: string | null;
  auth_pub: string | null;
  issued_at: number;
  expires_at: number;
  used_at: number | null;
}

export type ConsumeResult =
  | { ok: true; row: ChallengeRecord }
  | { ok: false; reason: "not_found" | "expired" | "used" };

/** Canonical challenge context builder (design §13.5). Pure string join — not crypto. */
export function buildContext(
  purpose: "register" | "auth" | "add_device",
  c: {
    challengeId: string;
    nonce: string;
    username?: string | null;
    accountId?: string | null;
    deviceId?: string | null;
    identityPubB64?: string | null;
    authPubB64?: string | null;
    authorizerDeviceId?: string | null;
  },
): string {
  switch (purpose) {
    case "register":
      return ["v1", "register", c.challengeId, c.nonce, c.username, c.identityPubB64, c.authPubB64].join("|");
    case "auth":
      return ["v1", "auth", c.challengeId, c.nonce, c.accountId, c.deviceId].join("|");
    case "add_device":
      return [
        "v1", "add_device", c.challengeId, c.nonce, c.username,
        c.identityPubB64, c.authPubB64, c.authorizerDeviceId,
      ].join("|");
  }
}

/** Official WebCrypto Ed25519 verification. Raw keys/signatures only — no conversion. */
export async function verifyEd25519(
  pubRaw: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    pubRaw as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature as BufferSource, message as BufferSource);
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function randomHex(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Issue a single-use challenge row. TTL is server-owned (60 s per approved design). */
export async function createChallenge(
  db: D1Database,
  input: ChallengeInput,
  now: number,
  ttlMs = 60_000,
): Promise<{ challengeId: string; nonce: string; expiresAt: number }> {
  const challengeId = crypto.randomUUID();
  const nonce = randomHex(32);
  const expiresAt = now + ttlMs;
  await db
    .prepare(
      `INSERT INTO auth_challenges
         (challenge_id, nonce, purpose, account_id, device_id, username, identity_pub, auth_pub, issued_at, expires_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
    )
    .bind(
      challengeId,
      nonce,
      input.purpose,
      input.accountId ?? null,
      input.deviceId ?? null,
      input.username ?? null,
      input.identityPubB64 ?? null,
      input.authPubB64 ?? null,
      now,
      expiresAt,
    )
    .run();
  return { challengeId, nonce, expiresAt };
}

async function getChallenge(db: D1Database, challengeId: string): Promise<ChallengeRecord | null> {
  const row = await db
    .prepare(`SELECT * FROM auth_challenges WHERE challenge_id = ?1`)
    .bind(challengeId)
    .first<Record<string, unknown>>();
  if (!row) return null;
  return {
    challenge_id: row.challenge_id as string,
    nonce: row.nonce as string,
    purpose: row.purpose as string,
    account_id: (row.account_id as string | null) ?? null,
    device_id: (row.device_id as string | null) ?? null,
    username: (row.username as string | null) ?? null,
    identity_pub: (row.identity_pub as string | null) ?? null,
    auth_pub: (row.auth_pub as string | null) ?? null,
    issued_at: row.issued_at as number,
    expires_at: row.expires_at as number,
    used_at: (row.used_at as number | null) ?? null,
  };
}

/**
 * Atomically consume a single-use challenge. The UPDATE is the atomic gate:
 * exactly one concurrent caller can flip `used_at` (meta.changes === 1).
 * Expired challenges can never be consumed; repeated attempts stay rejected.
 */
export async function consumeChallenge(
  db: D1Database,
  challengeId: string,
  now: number,
): Promise<ConsumeResult> {
  const res = await db
    .prepare(
      `UPDATE auth_challenges SET used_at = ?1
        WHERE challenge_id = ?2 AND used_at IS NULL AND expires_at >= ?1`,
    )
    .bind(now, challengeId)
    .run();
  if (res.meta.changes === 1) {
    const row = await getChallenge(db, challengeId);
    return { ok: true, row: row! };
  }
  const row = await getChallenge(db, challengeId);
  if (!row) return { ok: false, reason: "not_found" };
  if (row.expires_at < now) return { ok: false, reason: "expired" };
  return { ok: false, reason: "used" };
}
