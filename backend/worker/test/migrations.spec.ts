import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { applySql, migrationsFromBinding } from "./apply-sql";

type Row = Record<string, unknown>;

const NOW = 1_700_000_000_000;

beforeAll(async () => {
  for (const m of migrationsFromBinding()) {
    await applySql(m.sql);
  }
});

async function insertAccount(accountId: string, username: string) {
  await env.DB
    .prepare("INSERT INTO accounts (account_id, username, created_at) VALUES (?1, ?2, ?3)")
    .bind(accountId, username, NOW)
    .run();
}

async function insertDevice(deviceId: string, accountId: string, devNo: number, regId = 1000) {
  await env.DB
    .prepare(
      `INSERT INTO devices (device_id, account_id, dev_no, identity_pub_key, auth_pub_key, registration_id, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
    )
    .bind(deviceId, accountId, devNo, new Uint8Array(32), new Uint8Array(32), regId, NOW)
    .run();
}

async function insertMessage(
  deliveryId: string,
  logicalId: string,
  sender: string,
  recipient: string,
  seq: number,
  size = 16,
) {
  await env.DB
    .prepare(
      `INSERT INTO message_queue (delivery_id, logical_msg_id, sender_dev_id, recipient_dev_id, seq, ciphertext, server_recv_at, expires_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
    )
    .bind(deliveryId, logicalId, sender, recipient, seq, new Uint8Array(size), NOW, NOW + 604_800_000)
    .run();
}

describe("migrations: schema", () => {
  it("creates all eleven tables", async () => {
    const { results } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    const names = results.map((r: Row) => r.name as string);
    const expected = [
      "accounts",
      "attachment_delivery",
      "attachments",
      "auth_challenges",
      "auth_tokens",
      "backups",
      "devices",
      "kyber_prekeys",
      "message_queue",
      "one_time_prekeys",
      "signed_prekeys",
    ];
    for (const t of expected) expect(names).toContain(t);
  });

  it("creates inbox/expiry/token indexes and partial prekey pop indexes", async () => {
    const { results } = await env.DB.prepare("SELECT name, sql FROM sqlite_master WHERE type='index'").all();
    const names = results.map((r: Row) => r.name as string);
    expect(names).toContain("idx_mq_inbox");
    expect(names).toContain("idx_mq_expiry");
    expect(names).toContain("idx_tokens_device");
    expect(names).toContain("idx_challenges_expiry");
    const otpPop = results.find((r: Row) => r.name === "idx_otp_pop") as { sql?: string } | undefined;
    expect(String(otpPop?.sql)).toContain("used_at IS NULL");
    const kyberPop = results.find((r: Row) => r.name === "idx_kyber_pop") as { sql?: string } | undefined;
    expect(String(kyberPop?.sql)).toContain("used_at IS NULL");
  });
});

describe("migrations: accounts constraints", () => {
  it("enforces case-sensitive unique usernames", async () => {
    await insertAccount("mig-acc-a", "mig_alice");
    await insertAccount("mig-acc-b", "MIG_ALICE"); // different case → allowed
    await expect(insertAccount("mig-acc-c", "mig_alice")).rejects.toThrow();
  });
});

describe("migrations: devices constraints", () => {
  it("enforces dev_no range 1..127 and per-account uniqueness", async () => {
    await insertAccount("mig-acc-d", "mig_dave");
    await insertDevice("mig-dev-1", "mig-acc-d", 1);
    await expect(insertDevice("mig-dev-2", "mig-acc-d", 0)).rejects.toThrow();
    await expect(insertDevice("mig-dev-3", "mig-acc-d", 128)).rejects.toThrow();
    await expect(insertDevice("mig-dev-4", "mig-acc-d", 1)).rejects.toThrow(); // duplicate (account, dev_no)
  });

  it("allows same dev_no on different accounts and rejects bad registration_id", async () => {
    await insertAccount("mig-acc-e", "mig_eve");
    await insertDevice("mig-dev-6", "mig-acc-e", 1); // same dev_no, different account → allowed
    await expect(insertDevice("mig-dev-7", "mig-acc-e", 2, 0)).rejects.toThrow();
    await expect(insertDevice("mig-dev-8", "mig-acc-e", 2, 16381)).rejects.toThrow();
  });

  it("rejects devices referencing unknown accounts (FK)", async () => {
    await expect(insertDevice("mig-dev-9", "no-such-account", 3)).rejects.toThrow();
  });
});

describe("migrations: prekey constraints", () => {
  it("enforces UNIQUE (device_id, key_id) on all three prekey tables", async () => {
    await insertAccount("mig-acc-f", "mig_fay");
    await insertDevice("mig-dev-10", "mig-acc-f", 1);

    await env.DB
      .prepare("INSERT INTO signed_prekeys (id, device_id, key_id, public_key, signature, created_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)")
      .bind("mig-spk-1", "mig-dev-10", new Uint8Array(32), new Uint8Array(64), NOW)
      .run();
    await expect(
      env.DB
        .prepare("INSERT INTO signed_prekeys (id, device_id, key_id, public_key, signature, created_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)")
        .bind("mig-spk-2", "mig-dev-10", new Uint8Array(32), new Uint8Array(64), NOW)
        .run(),
    ).rejects.toThrow();

    await env.DB
      .prepare("INSERT INTO one_time_prekeys (id, device_id, key_id, public_key, created_at) VALUES (?1, ?2, 1, ?3, ?4)")
      .bind("mig-otpk-1", "mig-dev-10", new Uint8Array(32), NOW)
      .run();
    await expect(
      env.DB
        .prepare("INSERT INTO one_time_prekeys (id, device_id, key_id, public_key, created_at) VALUES (?1, ?2, 1, ?3, ?4)")
        .bind("mig-otpk-2", "mig-dev-10", new Uint8Array(32), NOW)
        .run(),
    ).rejects.toThrow();

    await env.DB
      .prepare("INSERT INTO kyber_prekeys (id, device_id, key_id, public_key, signature, created_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)")
      .bind("mig-kyk-1", "mig-dev-10", new Uint8Array(1184), new Uint8Array(64), NOW)
      .run();
    await expect(
      env.DB
        .prepare("INSERT INTO kyber_prekeys (id, device_id, key_id, public_key, signature, created_at) VALUES (?1, ?2, 1, ?3, ?4, ?5)")
        .bind("mig-kyk-2", "mig-dev-10", new Uint8Array(1184), new Uint8Array(64), NOW)
        .run(),
    ).rejects.toThrow();
  });
});

describe("migrations: message_queue constraints", () => {
  it("rejects oversize ciphertext, invalid state, and FK violations", async () => {
    await insertAccount("mig-acc-g", "mig_gus");
    await insertDevice("mig-dev-11", "mig-acc-g", 1);

    await expect(insertMessage("mig-msg-1", "mig-logical-1", "mig-dev-11", "mig-dev-11", 1, 1_900_001)).rejects.toThrow();
    await insertMessage("mig-msg-2", "mig-logical-2", "mig-dev-11", "mig-dev-11", 1);
    await expect(
      env.DB
        .prepare(
          `INSERT INTO message_queue (delivery_id, logical_msg_id, sender_dev_id, recipient_dev_id, seq, ciphertext, state, server_recv_at, expires_at)
           VALUES (?1, ?2, ?3, ?4, 2, ?5, 'bogus', ?6, ?7)`,
        )
        .bind("mig-msg-3", "mig-logical-3", "mig-dev-11", "mig-dev-11", new Uint8Array(16), NOW, NOW + 604_800_000)
        .run(),
    ).rejects.toThrow();
    await expect(insertMessage("mig-msg-4", "mig-logical-4", "no-such-device", "mig-dev-11", 2)).rejects.toThrow();
  });

  it("enforces idempotency key UNIQUE (sender_dev_id, logical_msg_id)", async () => {
    await expect(insertMessage("mig-msg-5", "mig-logical-2", "mig-dev-11", "mig-dev-11", 5)).rejects.toThrow();
  });

  it("supports atomic single-use prekey pop via conditional UPDATE", async () => {
    await insertAccount("mig-acc-h", "mig_hana");
    await insertDevice("mig-dev-12", "mig-acc-h", 1);
    await env.DB
      .prepare("INSERT INTO one_time_prekeys (id, device_id, key_id, public_key, created_at) VALUES (?1, ?2, 7, ?3, ?4)")
      .bind("mig-otpk-7", "mig-dev-12", new Uint8Array(32), NOW)
      .run();

    const first = await env.DB
      .prepare(
        `UPDATE one_time_prekeys SET used_at = ?1
          WHERE device_id = ?2 AND used_at IS NULL
            AND key_id = (SELECT key_id FROM one_time_prekeys WHERE device_id = ?2 AND used_at IS NULL ORDER BY key_id LIMIT 1)`,
      )
      .bind(NOW, "mig-dev-12")
      .run();
    expect(first.meta.changes).toBe(1);

    const second = await env.DB
      .prepare(
        `UPDATE one_time_prekeys SET used_at = ?1
          WHERE device_id = ?2 AND used_at IS NULL
            AND key_id = (SELECT key_id FROM one_time_prekeys WHERE device_id = ?2 AND used_at IS NULL ORDER BY key_id LIMIT 1)`,
      )
      .bind(NOW, "mig-dev-12")
      .run();
    expect(second.meta.changes).toBe(0); // atomic single-use semantics
  });
});

describe("migrations: auth constraints", () => {
  it("rejects invalid purpose and reversed timestamps on challenges", async () => {
    await expect(
      env.DB
        .prepare(
          `INSERT INTO auth_challenges (challenge_id, nonce, purpose, issued_at, expires_at)
           VALUES ('mig-ch-1', 'nonce-1', 'bogus', ?1, ?1 + 60000)`,
        )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.DB
        .prepare(
          `INSERT INTO auth_challenges (challenge_id, nonce, purpose, issued_at, expires_at)
           VALUES ('mig-ch-2', 'nonce-2', 'auth', ?1, ?1)`,
        )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
  });

  it("rejects tokens with FK violations or non-expiring timestamps", async () => {
    await expect(
      env.DB
        .prepare(
          `INSERT INTO auth_tokens (token_hash, device_id, issued_at, expires_at)
           VALUES ('deadbeef', 'no-such-device', ?1, ?1 + 1800000)`,
        )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
    await expect(
      env.DB
        .prepare(
          `INSERT INTO auth_tokens (token_hash, device_id, issued_at, expires_at)
           VALUES ('deadbeef', 'mig-dev-12', ?1, ?1)`,
        )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
  });

  it("rejects challenges referencing unknown devices (FK)", async () => {
    await expect(
      env.DB
        .prepare(
          `INSERT INTO auth_challenges (challenge_id, nonce, purpose, device_id, issued_at, expires_at)
           VALUES ('mig-ch-3', 'nonce-3', 'auth', 'no-such-device', ?1, ?1 + 60000)`,
        )
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
  });
});
