import fs from "node:fs";
import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// The Tink→WebCrypto fixture is generated at runtime by the Android instrumented
// test (real Ed25519 signing on an emulator) and exported via adb. It is injected
// into the workerd test context as a binding so tests never hand-roll key material.
const fixturePath = new URL("./tink-fixture.json", import.meta.url);
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: { TINK_FIXTURE: JSON.stringify(fixture) },
        },
      },
    },
  },
});
