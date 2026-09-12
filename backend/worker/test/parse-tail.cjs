const fs = require("fs");
const raw = fs.readFileSync("F:/chatapp/full log.txt", "utf8");

// Split concatenated pretty-printed JSON objects by top-level brace depth.
const events = [];
let depth = 0;
let start = -1;
for (let i = 0; i < raw.length; i++) {
  const ch = raw[i];
  if (ch === '"') {
    // skip string literals (handles escaped quotes)
    i++;
    while (i < raw.length) {
      if (raw[i] === "\\") { i += 2; continue; }
      if (raw[i] === '"') break;
      i++;
    }
    continue;
  }
  if (ch === "{") { if (depth === 0) start = i; depth++; }
  else if (ch === "}") { depth--; if (depth === 0 && start >= 0) { events.push(raw.slice(start, i + 1)); start = -1; } }
}

console.log("total top-level objects:", events.length);
const parsed = events
  .map((s) => { try { return JSON.parse(s); } catch (e) { console.error("PARSE FAIL:", e.message.slice(0, 80)); return null; } })
  .filter(Boolean);

const sorted = parsed.sort((a, b) => (a.eventTimestamp || 0) - (b.eventTimestamp || 0));
for (const e of sorted) {
  const req = e.event && e.event.request;
  const method = req ? req.method : "?";
  const url = req ? req.url : "?";
  const path = url.replace("https://chatapp-staging.aacc32351.workers.dev", "");
  const status = e.event && e.event.response ? e.event.response.status : "?";
  const outcome = e.outcome;
  const excs = (e.exceptions || []).map((x) => x.message).join(" | ");
  const logs = (e.logs || []).map((l) => (l.message || "").toString()).join(" | ");
  console.log(`${method} ${path} -> status=${status} outcome=${outcome}`);
  if (excs) console.log(`   EXCEPTIONS: ${excs.slice(0, 600)}`);
  if (logs) console.log(`   LOGS: ${logs.slice(0, 600)}`);
}
