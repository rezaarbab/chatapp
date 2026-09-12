import { HttpError, errorResponse, jsonResponse } from "./errors";
import { checkRateLimit, LIMITS } from "./ratelimit";
import { asBytes, b64ToBytes, bytesToB64, sha256 } from "./util";
import { authenticate, issueToken } from "./tokens";
import { addDeviceWithToken, createAccountWithDevice, revokeDevice } from "./devices";
import { buildContext, consumeChallenge, createChallenge, verifyEd25519 } from "./auth";

interface Env {
  DB: D1Database;
  NOW_OVERRIDE_MS?: string;
  TOKEN_TTL_MS?: string; // staging/test override; production keeps the 30-min default
  DEBUG_ERRORS?: string; // staging only: include exception detail in 500 responses
}

interface AuthInfo {
  device_id: string;
  account_id: string;
  dev_no: number;
}

interface Ctx {
  req: Request;
  url: URL;
  db: D1Database;
  now: number;
  tokenTtlMs: number;
  ipHash: string;
  authorization: string | null;
  body: unknown;
  auth: AuthInfo | null;
}

type Handler = (ctx: Ctx, params: Record<string, string>) => Promise<Response>;

const USERNAME_RE = /^[A-Za-z0-9_-]{1,64}$/;

function requireString(body: Record<string, unknown>, field: string, maxLen = 256): string {
  const v = body[field];
  if (typeof v !== "string" || v.length === 0 || v.length > maxLen) {
    throw new HttpError(400, "VALIDATION_ERROR", `missing or invalid field: ${field}`);
  }
  return v;
}

function requireB64Bytes(body: Record<string, unknown>, field: string, expectedLen: number): Uint8Array {
  const v = body[field];
  if (typeof v !== "string") {
    throw new HttpError(400, "VALIDATION_ERROR", `missing field: ${field}`);
  }
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(v);
  } catch {
    throw new HttpError(400, "VALIDATION_ERROR", `field ${field} is not valid base64`);
  }
  if (bytes.length !== expectedLen) {
    throw new HttpError(400, "VALIDATION_ERROR", `field ${field} must be ${expectedLen} bytes`);
  }
  return bytes;
}

function requireValidUsername(username: string): string {
  if (!USERNAME_RE.test(username)) {
    throw new HttpError(400, "VALIDATION_ERROR", "username must match [A-Za-z0-9_-]{1,64}");
  }
  return username;
}

function requireRegistrationId(body: Record<string, unknown>): number {
  const v = body["registration_id"];
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > 16380) {
    throw new HttpError(400, "VALIDATION_ERROR", "registration_id must be an integer in 1..16380");
  }
  return v;
}

async function requireActiveDevice(db: D1Database, deviceId: string): Promise<{ account_id: string; auth_pub_key: Uint8Array }> {
  const row = await db
    .prepare("SELECT account_id, auth_pub_key, revoked_at FROM devices WHERE device_id = ?1")
    .bind(deviceId)
    .first<{ account_id: string; auth_pub_key: Uint8Array; revoked_at: number | null }>();
  if (!row || row.revoked_at !== null) {
    throw new HttpError(404, "NOT_FOUND", "device not found");
  }
  return row;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

const handleAuthChallenge: Handler = async (ctx) => {
  const body = ctx.body as Record<string, unknown>;
  const purpose = requireString(body, "purpose", 20);
  if (!["register", "auth", "add_device"].includes(purpose)) {
    throw new HttpError(400, "VALIDATION_ERROR", "unknown purpose");
  }

  if (!(await checkRateLimit(ctx.db, "challenge_ip", ctx.ipHash, LIMITS.challengeIp, ctx.now))) {
    throw new HttpError(429, "RATE_LIMITED", "too many challenges");
  }

  let accountId: string | null = null;
  let deviceId: string | null = null;
  let username: string | null = null;
  let identityPub: string | null = null;
  let authPub: string | null = null;
  let authorizerDeviceId: string | null = null;

  if (purpose === "register") {
    username = requireValidUsername(requireString(body, "username", 64));
    identityPub = bytesToB64(requireB64Bytes(body, "identity_pub", 32));
    authPub = bytesToB64(requireB64Bytes(body, "auth_pub", 32));
    const taken = await ctx.db
      .prepare("SELECT 1 FROM accounts WHERE username = ?1")
      .bind(username)
      .first();
    if (taken) throw new HttpError(409, "USERNAME_TAKEN", "username already registered");
  } else if (purpose === "auth") {
    deviceId = requireString(body, "device_id", 64);
    const device = await ctx.db
      .prepare("SELECT account_id, revoked_at FROM devices WHERE device_id = ?1")
      .bind(deviceId)
      .first<{ account_id: string; revoked_at: number | null }>();
    if (!device || device.revoked_at !== null) {
      // fail-closed: a revoked device cannot even obtain a challenge
      throw new HttpError(404, "NOT_FOUND", "device not found");
    }
    accountId = device.account_id;
  } else {
    // add_device
    username = requireValidUsername(requireString(body, "username", 64));
    identityPub = bytesToB64(requireB64Bytes(body, "identity_pub", 32));
    authPub = bytesToB64(requireB64Bytes(body, "auth_pub", 32));
    authorizerDeviceId = requireString(body, "authorizer_device_id", 64);
    const authorizer = await ctx.db
      .prepare("SELECT account_id, revoked_at FROM devices WHERE device_id = ?1")
      .bind(authorizerDeviceId)
      .first<{ account_id: string; revoked_at: number | null }>();
    if (!authorizer || authorizer.revoked_at !== null) {
      throw new HttpError(404, "NOT_FOUND", "authorizer device not found");
    }
    const account = await ctx.db
      .prepare("SELECT account_id FROM accounts WHERE username = ?1")
      .bind(username)
      .first<{ account_id: string }>();
    if (!account || account.account_id !== authorizer.account_id) {
      throw new HttpError(404, "NOT_FOUND", "account not found");
    }
    accountId = account.account_id;
  }

  const created = await createChallenge(
    ctx.db,
    {
      purpose: purpose as "register" | "auth" | "add_device",
      username,
      accountId,
      deviceId,
      identityPubB64: identityPub,
      authPubB64: authPub,
      authorizerDeviceId,
    },
    ctx.now,
  );
  return jsonResponse({
    challenge_id: created.challengeId,
    nonce: created.nonce,
    expires_at: created.expiresAt,
  });
};

const handleRegister: Handler = async (ctx) => {
  const body = ctx.body as Record<string, unknown>;
  const challengeId = requireString(body, "challenge_id", 64);
  const signature = requireB64Bytes(body, "signature", 64);

  if (!(await checkRateLimit(ctx.db, "accounts_ip", ctx.ipHash, LIMITS.accountsIp, ctx.now))) {
    throw new HttpError(429, "RATE_LIMITED", "too many registrations from this source");
  }
  if (!(await checkRateLimit(ctx.db, "accounts_global", "*", LIMITS.accountsGlobal, ctx.now))) {
    throw new HttpError(429, "RATE_LIMITED", "registration capacity reached");
  }

  const consumed = await consumeChallenge(ctx.db, challengeId, ctx.now);
  if (!consumed.ok) {
    throw challengeConsumptionError(consumed.reason);
  }
  if (consumed.row.purpose !== "register") {
    throw new HttpError(401, "INVALID_SIGNATURE", "challenge purpose mismatch");
  }

  // Context is built EXCLUSIVELY from the stored challenge row.
  const context = buildContext("register", {
    challengeId: consumed.row.challenge_id,
    nonce: consumed.row.nonce,
    username: consumed.row.username,
    identityPubB64: consumed.row.identity_pub,
    authPubB64: consumed.row.auth_pub,
  });
  const authPubBytes = b64ToBytes(consumed.row.auth_pub!);
  const ok = await verifyEd25519(authPubBytes, signature, new TextEncoder().encode(context));
  if (!ok) throw new HttpError(401, "INVALID_SIGNATURE", "challenge signature invalid");

  const username = consumed.row.username!;
  const taken = await ctx.db
    .prepare("SELECT 1 FROM accounts WHERE username = ?1")
    .bind(username)
    .first();
  if (taken) throw new HttpError(409, "USERNAME_TAKEN", "username already registered");

  const accountId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const { token, token_expires_at } = await createAccountWithDevice(ctx.db, {
    accountId,
    deviceId,
    username,
    identityPub: b64ToBytes(consumed.row.identity_pub!),
    authPub: authPubBytes,
    registrationId: requireRegistrationId(body),
    label: typeof body["label"] === "string" ? (body["label"] as string).slice(0, 64) : null,
    tokenTtlMs: ctx.tokenTtlMs,
    now: ctx.now,
  });
  return jsonResponse(
    { account_id: accountId, device_id: deviceId, dev_no: 1, token, token_expires_at },
    201,
  );
};

const handleVerify: Handler = async (ctx) => {
  const body = ctx.body as Record<string, unknown>;
  const challengeId = requireString(body, "challenge_id", 64);
  const signature = requireB64Bytes(body, "signature", 64);

  if (!(await checkRateLimit(ctx.db, "verify_ip", ctx.ipHash, LIMITS.verifyIp, ctx.now))) {
    throw new HttpError(429, "RATE_LIMITED", "too many verify attempts");
  }

  const consumed = await consumeChallenge(ctx.db, challengeId, ctx.now);
  if (!consumed.ok) {
    throw challengeConsumptionError(consumed.reason);
  }
  if (consumed.row.purpose !== "auth" || !consumed.row.device_id || !consumed.row.account_id) {
    throw new HttpError(401, "INVALID_SIGNATURE", "challenge purpose mismatch");
  }

  // Fail-closed: the device must still be active at verify time (revocation race).
  const device = await requireActiveDevice(ctx.db, consumed.row.device_id);

  const context = buildContext("auth", {
    challengeId: consumed.row.challenge_id,
    nonce: consumed.row.nonce,
    accountId: consumed.row.account_id,
    deviceId: consumed.row.device_id,
  });
  const ok = await verifyEd25519(asBytes(device.auth_pub_key), signature, new TextEncoder().encode(context));
  if (!ok) throw new HttpError(401, "INVALID_SIGNATURE", "challenge signature invalid");

  const { token, token_expires_at } = await issueToken(ctx.db, consumed.row.device_id, ctx.now, ctx.tokenTtlMs);
  return jsonResponse({
    token,
    account_id: consumed.row.account_id,
    device_id: consumed.row.device_id,
    token_expires_at,
  });
};

const handleAddDevice: Handler = async (ctx) => {
  const body = ctx.body as Record<string, unknown>;
  const challengeId = requireString(body, "challenge_id", 64);
  const signature = requireB64Bytes(body, "signature", 64);
  const authorizerSignature = requireB64Bytes(body, "authorizer_signature", 64);

  const consumed = await consumeChallenge(ctx.db, challengeId, ctx.now);
  if (!consumed.ok) {
    throw challengeConsumptionError(consumed.reason);
  }
  if (consumed.row.purpose !== "add_device") {
    throw new HttpError(401, "INVALID_SIGNATURE", "challenge purpose mismatch");
  }
  const row = consumed.row;
  if (!row.account_id || !row.auth_pub || !row.identity_pub || !row.authorizer_device_id) {
    throw new HttpError(401, "INVALID_SIGNATURE", "challenge context incomplete");
  }

  const authorizer = await requireActiveDevice(ctx.db, row.authorizer_device_id);
  if (authorizer.account_id !== row.account_id) {
    throw new HttpError(403, "FORBIDDEN", "authorizer belongs to a different account");
  }

  const context = buildContext("add_device", {
    challengeId: row.challenge_id,
    nonce: row.nonce,
    username: row.username,
    identityPubB64: row.identity_pub,
    authPubB64: row.auth_pub,
    authorizerDeviceId: row.authorizer_device_id,
  });
  const contextBytes = new TextEncoder().encode(context);

  const reasons: string[] = [];
  let newDeviceOk = false;
  let authorizerOk = false;
  try {
    newDeviceOk = await verifyEd25519(b64ToBytes(row.auth_pub), signature, contextBytes);
  } catch (e) {
    reasons.push(`sigNew threw: ${(e as Error).message}`);
  }
  if (!newDeviceOk) reasons.push("sigNew=false");
  try {
    authorizerOk = await verifyEd25519(asBytes(authorizer.auth_pub_key), authorizerSignature, contextBytes);
  } catch (e) {
    reasons.push(`sigAuth threw: ${(e as Error).message}`);
  }
  if (!authorizerOk) reasons.push("sigAuth=false");
  if (!row.authorizer_device_id) reasons.push("row missing authorizer_device_id");
  if (reasons.length > 0) {
    throw new HttpError(401, "INVALID_SIGNATURE", `add_device failed: ${reasons.join("; ")}`);
  }

  const deviceId = crypto.randomUUID();
  const { token, token_expires_at, dev_no } = await addDeviceWithToken(ctx.db, {
    deviceId,
    accountId: row.account_id,
    identityPub: b64ToBytes(row.identity_pub),
    authPub: b64ToBytes(row.auth_pub),
    registrationId: requireRegistrationId(body),
    label: typeof body["label"] === "string" ? (body["label"] as string).slice(0, 64) : null,
    tokenTtlMs: ctx.tokenTtlMs,
    now: ctx.now,
  });
  return jsonResponse({ device_id: deviceId, dev_no, token, token_expires_at }, 201);
};

const handleRevokeDevice: Handler = async (ctx, params) => {
  const target = params["id"];
  const targetRow = await ctx.db
    .prepare("SELECT account_id FROM devices WHERE device_id = ?1")
    .bind(target)
    .first<{ account_id: string }>();
  if (!targetRow) throw new HttpError(404, "NOT_FOUND", "device not found");
  if (targetRow.account_id !== ctx.auth.account_id) {
    throw new HttpError(403, "FORBIDDEN", "device belongs to another account");
  }
  await revokeDevice(ctx.db, target, ctx.now); // atomic: device + all tokens
  return new Response(null, { status: 204 });
};

const handleDevicesMe: Handler = async (ctx) => {
  const row = await ctx.db
    .prepare("SELECT dev_no, label, created_at, revoked_at FROM devices WHERE device_id = ?1")
    .bind(ctx.auth.device_id)
    .first<{ dev_no: number; label: string | null; created_at: number; revoked_at: number | null }>();
  if (!row || row.revoked_at !== null) {
    throw new HttpError(401, "DEVICE_REVOKED", "device revoked");
  }
  return jsonResponse({
    account_id: ctx.auth.account_id,
    device_id: ctx.auth.device_id,
    dev_no: row.dev_no,
    label: row.label,
    created_at: row.created_at,
  });
};

function challengeConsumptionError(reason: "not_found" | "expired" | "used"): HttpError {
  if (reason === "not_found") return new HttpError(404, "NOT_FOUND", "challenge not found");
  if (reason === "expired") return new HttpError(401, "CHALLENGE_EXPIRED", "challenge expired");
  return new HttpError(401, "CHALLENGE_USED", "challenge already consumed");
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

interface Route {
  method: string;
  segments: string[];
  auth: boolean;
  handler: Handler;
}

function route(method: string, path: string, auth: boolean, handler: Handler): Route {
  return { method, segments: path.split("/").filter(Boolean), auth, handler };
}

const routes: Route[] = [
  route("POST", "auth/challenge", false, handleAuthChallenge),
  route("POST", "accounts", false, handleRegister),
  route("POST", "auth/verify", false, handleVerify),
  route("POST", "devices", false, handleAddDevice),
  route("GET", "devices/me", true, handleDevicesMe),
  route("DELETE", "devices/:id", true, handleRevokeDevice),
];

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const corrId = request.headers.get("x-correlation-id") || "no-corr-id";
  try {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);
    const now = Number(env.NOW_OVERRIDE_MS) > 0 ? Number(env.NOW_OVERRIDE_MS) : Date.now();
    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
    const ipHash = await sha256(new TextEncoder().encode(ip));

    console.log(`[REQ] ${corrId} ${request.method} ${url.pathname}`);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204 });
    }

    const match = routes.find(
      (r) => r.method === request.method && r.segments.length === segments.length &&
        r.segments.every((s, i) => s === segments[i] || s.startsWith(":")),
    );
    if (!match) {
      throw new HttpError(404, "NOT_FOUND", "unknown endpoint");
    }

    let body: unknown = null;
    if (request.method === "POST" || request.method === "PUT") {
      try {
        body = await request.json();
      } catch {
        throw new HttpError(400, "VALIDATION_ERROR", "body must be valid JSON");
      }
    }

    const auth = match.auth
      ? await authenticate(env.DB, request.headers.get("Authorization"), now)
      : null;

    const params: Record<string, string> = {};
    match.segments.forEach((s, i) => {
      if (s.startsWith(":")) params[s.slice(1)] = decodeURIComponent(segments[i]);
    });

    const ctx: Ctx = {
      req: request,
      url,
      db: env.DB,
      now,
      tokenTtlMs: Number(env.TOKEN_TTL_MS) > 0 ? Number(env.TOKEN_TTL_MS) : 30 * 60 * 1000,
      ipHash,
      authorization: request.headers.get("Authorization"),
      body,
      auth,
    };
    const response = await match.handler(ctx, params);
    response.headers.set("x-correlation-id", corrId);
    console.log(`[RES] ${corrId} ${response.status}`);
    return response;
  } catch (e) {
    if (e instanceof HttpError) {
      const res = errorResponse(e);
      res.headers.set("x-correlation-id", corrId);
      console.log(`[RES] ${corrId} ${res.status} ${e.code}`);
      return res;
    }
    if (env.DEBUG_ERRORS === "true" && e instanceof Error) {
      console.log(`[ERR] ${corrId} ${e.message}`);
      const res = jsonResponse(
        {
          error: {
            code: "INTERNAL",
            message: e.message,
            stack: (e.stack || "").slice(0, 1200),
            correlation_id: corrId,
          },
        },
        500,
      );
      res.headers.set("x-correlation-id", corrId);
      console.log(`[RES] ${corrId} 500 INTERNAL`);
      return res;
    }
    const res = errorResponse(e);
    res.headers.set("x-correlation-id", corrId);
    console.log(`[RES] ${corrId} 500 INTERNAL`);
    return res;
  }
}
