import fs from "node:fs";
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

// The Tink↔WebCrypto fixture is generated at runtime by the Android instrumented
// test (real Ed25519 signing on an emulator) and exported via logcat. It is
// optional here: when absent (pure backend CI), the interop spec is skipped and
// only migration/auth/token/prekey tests run against local miniflare D1.
const fixturePath = new URL("./tink-fixture.json", import.meta.url);
let fixture: unknown = null;
if (fs.existsSync(fixturePath)) {
  fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
}

// Migration files are read on the Node side (fs is unavailable inside workerd)
// and injected as a binding so the migration spec applies exactly what
// `wrangler d1 migrations apply` would apply, in order.
const migrationsDir = new URL("./migrations", import.meta.url);
const migrations = fs
  .readdirSync(migrationsDir)
  .filter((f) => f.endsWith(".sql"))
  .sort()
  .map((name) => ({
    name,
    sql: fs
      .readFileSync(new URL(`./migrations/${name}`, import.meta.url), "utf8")
      .replace(/^--.*$/gm, "")
      .trim(),
  }));

// @cloudflare/vitest-pool-workers 0.22.0 (vitest v4 era) exposes the pool as a
// Vite plugin; the legacy `.../config` subpath no longer exists in that package.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          TINK_FIXTURE: JSON.stringify(fixture),
          MIGRATIONS: JSON.stringify(migrations),
        },
      },
    }),
  ],
});
