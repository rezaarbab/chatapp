import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import {
  b64ToBytes,
  buildContext,
  consumeChallenge,
  createChallenge,
  verifyEd25519,
} from "../src/auth";

/**
 * Tink → WebCrypto interoperability test (user-mandated gate before Phase 1).
 *
 * The fixture is produced at runtime by a real Android instrumented test:
 *   - Ed25519 keypair generated with Google Tink on an emulator
 *   - canonical challenge context signed with Tink PublicKeySign
 *   - raw public key (32 B) and raw signature (64 B) exported as base64
 * It is verified here inside the real workerd runtime with the official
 * WebCrypto API — no conversion, no re-encoding, no custom crypto.
 */

const DDL = `
CREATE TABLE IF NOT EXISTS auth_challenges (
  challenge_id TEXT PRIMARY KEY,
  nonce        TEXT NOT NULL UNIQUE,
  purpose      TEXT NOT NULL CHECK (purpose IN ('register','auth','add_device')),
  account_id   TEXT,
  device_id    TEXT,
  username     TEXT,
  identity_pub TEXT,
  auth_pub     TEXT,
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  used_at      INTEGER
);
`;

const fixture = JSON.parse((globalThis as Record<string, unknown>).TINK_FIXTURE as string) as {
  alg: string;
  context_b64: string;
  pub_b64: string;
  sig_b64: string;
};

beforeAll(async () => {
  await env.DB.exec(DDL);
});

describe("Tink Ed25519 → Workers WebCrypto interop", () => {
  it("verifies a real Tink signature without any conversion", async () => {
    expect(fixture.alg).toBe("Ed25519");
    const pub = b64ToBytes(fixture.pub_b64);
    const sig = b64ToBytes(fixture.sig_b64);
    const ctx = new TextEncoder().encode(atob(fixture.context_b64));
    expect(pub.length).toBe(32);
    expect(sig.length).toBe(64);
    await expect(verifyEd25519(pub, sig, ctx)).resolves.toBe(true);
  });

  it("rejects a tampered signature", async () => {
    const sig = b64ToBytes(fixture.sig_b64);
    sig[0] ^= 0x01;
    const ctx = new TextEncoder().encode(atob(fixture.context_b64));
    await expect(
      verifyEd25519(b64ToBytes(fixture.pub_b64), sig, ctx),
    ).resolves.toBe(false);
  });

  it("rejects a tampered context", async () => {
    const ctxText = atob(fixture.context_b64);
    const tampered = new TextEncoder().encode(ctxText.replace("alice", "malice"));
    await expect(
      verifyEd25519(b64ToBytes(fixture.pub_b64), b64ToBytes(fixture.sig_b64), tampered),
    ).resolves.toBe(false);
  });

  it("rejects a wrong public key", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const wrongPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const ctx = new TextEncoder().encode(atob(fixture.context_b64));
    await expect(verifyEd25519(wrongPub, b64ToBytes(fixture.sig_b64), ctx)).resolves.toBe(false);
  });

  it("rejects a signature replayed onto a different challenge context", async () => {
    // Same signer, different challenge_id/nonce → different canonical bytes → must fail.
    const original = atob(fixture.context_b64);
    const parts = original.split("|");
    parts[2] = "00000000-0000-4000-8000-000000000000"; // different challenge_id
    const replayedCtx = new TextEncoder().encode(parts.join("|"));
    await expect(
      verifyEd25519(b64ToBytes(fixture.pub_b64), b64ToBytes(fixture.sig_b64), replayedCtx),
    ).resolves.toBe(false);
  });
});

describe("challenge lifecycle (atomic single-use, server-owned TTL)", () => {
  it("issues, consumes once, and atomically rejects replayed consumption", async () => {
    const now = 1_700_000_000_000;
    const { challengeId, nonce, expiresAt } = await createChallenge(
      env.DB,
      { purpose: "auth", accountId: "acc-1", deviceId: "dev-1" },
      now,
    );
    expect(expiresAt).toBe(now + 60_000);

    const ctx = buildContext("auth", {
      challengeId,
      nonce,
      accountId: "acc-1",
      deviceId: "dev-1",
    });
    expect(ctx).toContain("v1|auth|");

    const first = await consumeChallenge(env.DB, challengeId, now);
    expect(first.ok).toBe(true);

    const second = await consumeChallenge(env.DB, challengeId, now);
    expect(second).toEqual({ ok: false, reason: "used" });
  });

  it("rejects an expired challenge and never marks it consumed", async () => {
    const now = 1_700_000_000_000;
    const { challengeId } = await createChallenge(
      env.DB,
      { purpose: "auth", accountId: "acc-2", deviceId: "dev-2" },
      now,
    );
    const late = await consumeChallenge(env.DB, challengeId, now + 60_001);
    expect(late).toEqual({ ok: false, reason: "expired" });

    // The expired attempt must not have consumed the row (atomic gate only
    // flips used_at on success), and a further consume is still expired.
    const again = await consumeChallenge(env.DB, challengeId, now + 60_002);
    expect(again).toEqual({ ok: false, reason: "expired" });
  });

  it("rejects an unknown challenge id", async () => {
    const result = await consumeChallenge(env.DB, "does-not-exist", 1_700_000_000_000);
    expect(result).toEqual({ ok: false, reason: "not_found" });
  });
});
