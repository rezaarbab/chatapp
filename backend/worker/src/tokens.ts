import { HttpError } from "./errors";
import { b64ToBytes, bytesToB64, randomBytes, sha256 } from "./util";

export const TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes (user-approved)

export interface AuthContext {
  device_id: string;
  account_id: string;
  dev_no: number;
  token_hash: string;
}

/**
 * Issues a device-bound token; only SHA-256(token) is persisted.
 * The raw 256-bit token is returned exactly once and never stored.
 */
export async function issueToken(
  db: D1Database,
  deviceId: string,
  now: number,
  ttlMs = TOKEN_TTL_MS,
): Promise<{ token: string; token_expires_at: number }> {
  const raw = randomBytes(32);
  const token = bytesToB64(raw);
  const hash = await sha256(raw);
  const expires_at = now + ttlMs;
  await db
    .prepare(
      "INSERT INTO auth_tokens (token_hash, device_id, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(hash, deviceId, now, expires_at)
    .run();
  return { token, token_expires_at: expires_at };
}

/**
 * Validates a Bearer token and resolves the device identity FROM THE TOKEN ONLY.
 * Fail-closed ordering: unknown → token revoked → token expired → device revoked.
 * The device row is checked on every request, so revoking a device invalidates
 * all of its tokens immediately, even if a token row were missed.
 */
export async function authenticate(
  db: D1Database,
  authorization: string | null,
  now: number,
): Promise<AuthContext> {
  const match = authorization ? /^Bearer (.+)$/.exec(authorization) : null;
  if (!match) {
    throw new HttpError(401, "UNAUTHORIZED", "missing bearer token");
  }
  let raw: Uint8Array;
  try {
    raw = b64ToBytes(match[1]);
  } catch {
    throw new HttpError(401, "UNAUTHORIZED", "malformed token");
  }
  const hash = await sha256(raw);
  const tokenRow = await db
    .prepare("SELECT device_id, revoked_at, expires_at FROM auth_tokens WHERE token_hash = ?1")
    .bind(hash)
    .first<{ device_id: string; revoked_at: number | null; expires_at: number }>();
  if (!tokenRow) throw new HttpError(401, "UNAUTHORIZED", "invalid token");
  if (tokenRow.revoked_at !== null) {
    throw new HttpError(401, "DEVICE_REVOKED", "token revoked");
  }
  if (tokenRow.expires_at <= now) {
    throw new HttpError(401, "TOKEN_EXPIRED", "token expired");
  }
  const deviceRow = await db
    .prepare("SELECT account_id, dev_no, revoked_at FROM devices WHERE device_id = ?1")
    .bind(tokenRow.device_id)
    .first<{ account_id: string; dev_no: number; revoked_at: number | null }>();
  if (!deviceRow || deviceRow.revoked_at !== null) {
    throw new HttpError(401, "DEVICE_REVOKED", "device revoked");
  }
  return {
    device_id: tokenRow.device_id,
    account_id: deviceRow.account_id,
    dev_no: deviceRow.dev_no,
    token_hash: hash,
  };
}
