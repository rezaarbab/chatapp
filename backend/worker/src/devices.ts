import { HttpError } from "./errors";
import { sha256 } from "./util";
import { issueToken } from "./tokens";

export interface DeviceRowInput {
  deviceId: string;
  accountId: string;
  identityPub: Uint8Array;
  authPub: Uint8Array;
  registrationId: number;
  label: string | null;
}

/** Creates account + first device (dev_no=1) + token in ONE D1 batch (atomic). */
export async function createAccountWithDevice(
  db: D1Database,
  input: {
    accountId: string;
    deviceId: string;
    username: string;
    identityPub: Uint8Array;
    authPub: Uint8Array;
    registrationId: number;
    label: string | null;
    tokenTtlMs: number;
    now: number;
  },
): Promise<{ token: string; token_expires_at: number }> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const token = btoa(String.fromCharCode(...raw));
  const tokenHashHex = await sha256(raw);
  const tokenExpires = input.now + input.tokenTtlMs;

  await db.batch([
    db
      .prepare("INSERT INTO accounts (account_id, username, created_at) VALUES (?1, ?2, ?3)")
      .bind(input.accountId, input.username, input.now),
    db
      .prepare(
        `INSERT INTO devices (device_id, account_id, dev_no, identity_pub_key, auth_pub_key, registration_id, label, created_at, last_seen_at)
         VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?7)`,
      )
      .bind(input.deviceId, input.accountId, input.identityPub, input.authPub, input.registrationId, input.label, input.now),
    db
      .prepare("INSERT INTO auth_tokens (token_hash, device_id, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4)")
      .bind(tokenHashHex, input.deviceId, input.now, tokenExpires),
  ]);
  return { token, token_expires_at: tokenExpires };
}

/**
 * Adds a device under an existing account. dev_no allocation is a single
 * INSERT..SELECT (COALESCE(MAX)+1) â€” atomic under D1's single-threaded engine;
 * the CHECK (dev_no <= 127) rejects when the space is exhausted.
 * The token row joins the same batch (parent-then-child within one transaction).
 */
export async function addDeviceWithToken(
  db: D1Database,
  input: {
    deviceId: string;
    accountId: string;
    identityPub: Uint8Array;
    authPub: Uint8Array;
    registrationId: number;
    label: string | null;
    tokenTtlMs: number;
    now: number;
  },
): Promise<{ token: string; token_expires_at: number; dev_no: number }> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const token = btoa(String.fromCharCode(...raw));
  const tokenHashHex = await sha256(raw);
  const tokenExpires = input.now + input.tokenTtlMs;

  const insert = db
    .prepare(
      `INSERT INTO devices (device_id, account_id, dev_no, identity_pub_key, auth_pub_key, registration_id, label, created_at, last_seen_at)
       SELECT ?1, ?2, COALESCE(MAX(dev_no), 0) + 1, ?3, ?4, ?5, ?6, ?7, ?7 FROM devices WHERE account_id = ?2`,
    )
    .bind(input.deviceId, input.accountId, input.identityPub, input.authPub, input.registrationId, input.label, input.now);
  const tokenInsert = db
    .prepare("INSERT INTO auth_tokens (token_hash, device_id, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(tokenHashHex, input.deviceId, input.now, tokenExpires);
  const results = await db.batch([insert, tokenInsert]);

  const devNoRow = await db
    .prepare("SELECT dev_no FROM devices WHERE device_id = ?1")
    .bind(input.deviceId)
    .first<{ dev_no: number }>();
  return { token, token_expires_at: tokenExpires, dev_no: devNoRow!.dev_no };
}

/**
 * Revokes a device and ALL of its tokens in ONE atomic batch â€” fail-closed:
 * either both land, or neither does. Idempotent (guards on revoked_at IS NULL).
 */
export async function revokeDevice(db: D1Database, deviceId: string, now: number): Promise<void> {
  await db.batch([
    db
      .prepare("UPDATE devices SET revoked_at = ?1 WHERE device_id = ?2 AND revoked_at IS NULL")
      .bind(now, deviceId),
    db
      .prepare("UPDATE auth_tokens SET revoked_at = ?1 WHERE device_id = ?2 AND revoked_at IS NULL")
      .bind(now, deviceId),
  ]);
}


export { issueToken };
