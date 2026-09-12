import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { applySql } from "./apply-sql";

/**
 * Diagnostic probe for the CAS primitive in the CURRENT test runtime
 * (miniflare D1). Verifies:
 *   1. meta.changes semantics of a guarded UPDATE (1 then 0)
 *   2. the is_last_resort filter of the kyber pop SELECT
 *   3. concurrent pops through the exported casPop path (via HTTP elsewhere)
 */
beforeAll(async () => {
  for (const m of (await import("./apply-sql")).migrationsFromBinding()) {
    await applySql(m.sql);
  }
});

describe("CAS primitive probe", () => {
  it("meta.changes is 1 for a matching guarded UPDATE and 0 for a second one", async () => {
    await env.DB.prepare("DROP TABLE IF EXISTS probe_cas").run();
    await env.DB.prepare("CREATE TABLE probe_cas (id INTEGER PRIMARY KEY, used INTEGER)").run();
    await env.DB.prepare("INSERT INTO probe_cas (id, used) VALUES (1, NULL)").run();

    const r1 = await env.DB.prepare("UPDATE probe_cas SET used = 1 WHERE id = 1 AND used IS NULL").run();
    const r2 = await env.DB.prepare("UPDATE probe_cas SET used = 1 WHERE id = 1 AND used IS NULL").run();
    console.log("[PROBE] first meta:", JSON.stringify(r1.meta));
    console.log("[PROBE] second meta:", JSON.stringify(r2.meta));
    expect(r1.meta.changes).toBe(1);
    expect(r2.meta.changes).toBe(0);
  });

  it("concurrent guarded UPDATEs yield exactly one changes=1", async () => {
    await env.DB.prepare("DROP TABLE IF EXISTS probe_cas2").run();
    await env.DB.prepare("CREATE TABLE probe_cas2 (id INTEGER PRIMARY KEY, used INTEGER)").run();
    await env.DB.prepare("INSERT INTO probe_cas2 (id, used) VALUES (1, NULL)").run();

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        env.DB.prepare("UPDATE probe_cas2 SET used = 1 WHERE id = 1 AND used IS NULL").run(),
      ),
    );
    const winners = results.filter((r) => r.meta.changes === 1);
    console.log("[PROBE] concurrent winners:", winners.length, "of 20");
    expect(winners.length).toBe(1);
  });

  it("kyber one-time SELECT excludes the last-resort row under concurrency", async () => {
    // kyber_prekeys.device_id REFERENCES devices(device_id) — create the parent rows.
    await env.DB
      .prepare("INSERT OR IGNORE INTO accounts (account_id, username, created_at) VALUES ('probe-acct', 'probe_acct', 1)")
      .run();
    await env.DB
      .prepare(
        `INSERT OR IGNORE INTO devices (device_id, account_id, dev_no, identity_pub_key, auth_pub_key, registration_id, created_at)
         VALUES ('probe-device', 'probe-acct', 1, ?1, ?2, 1000, 1)`,
      )
      .bind(new Uint8Array(32), new Uint8Array(32))
      .run();
    const deviceId = "probe-device";
    await env.DB.prepare("DELETE FROM kyber_prekeys WHERE device_id = ?1").bind(deviceId).run();
    await env.DB
      .prepare("INSERT INTO kyber_prekeys (id, device_id, key_id, public_key, signature, created_at, used_at, is_last_resort) VALUES ('p1', ?1, 100, ?2, ?3, 1, NULL, 0)")
      .bind(deviceId, new Uint8Array(1569).fill(1), new Uint8Array(64).fill(2))
      .run();
    await env.DB
      .prepare("INSERT INTO kyber_prekeys (id, device_id, key_id, public_key, signature, created_at, used_at, is_last_resort) VALUES ('p2', ?1, 900, ?2, ?3, 1, NULL, 1)")
      .bind(deviceId, new Uint8Array(1569).fill(3), new Uint8Array(64).fill(4))
      .run();

    const selectSql =
      "SELECT key_id FROM kyber_prekeys WHERE device_id = ?1 AND is_last_resort = 0 AND used_at IS NULL ORDER BY key_id ASC LIMIT 1";
    const pops = await Promise.all(
      Array.from({ length: 30 }, () => env.DB.prepare(selectSql).bind(deviceId).first<{ key_id: number }>()),
    );
    const ids = pops.map((p) => p?.key_id).filter((k) => k != null);
    console.log("[PROBE] concurrent one-time SELECT results:", JSON.stringify([...new Set(ids)]));
    for (const id of ids) {
      expect(id).toBe(100); // NEVER 900
    }
  });
});
