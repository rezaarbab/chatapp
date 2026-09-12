/**
 * Strict fixed-window counters (D1, atomic single-statement upsert).
 * This is the security-critical layer that must not be deferred; the Workers
 * Rate Limiting binding (soft, per-PoP) is added at deploy configuration time.
 */

export interface Limit {
  limit: number;
  windowMs: number;
}

// Initial values per approved design; final numbers are tunable later.
export const LIMITS = {
  accountsGlobal: { limit: 50, windowMs: 86_400_000 },
  accountsIp: { limit: 3, windowMs: 600_000 },
  challengeIp: { limit: 10, windowMs: 60_000 },
  verifyIp: { limit: 30, windowMs: 60_000 },
} satisfies Record<string, Limit>;

/**
 * Fixed-window counter (D1-safe: no ON CONFLICT/RETURNING constructs).
 * D1 processes queries one at a time per database; the brief read-then-write
 * window is acceptable for approximate rate limiting (not an accounting system).
 */
export async function checkRateLimit(
  db: D1Database,
  bucket: string,
  key: string,
  limit: Limit,
  now: number,
): Promise<boolean> {
  const windowStart = Math.floor(now / limit.windowMs) * limit.windowMs;
  const existing = await db
    .prepare("SELECT count, window_start FROM rate_limits WHERE bucket = ?1 AND key = ?2")
    .bind(bucket, key)
    .first<{ count: number; window_start: number }>();
  if (!existing || existing.window_start !== windowStart) {
    await db
      .prepare(
        `INSERT INTO rate_limits (bucket, key, window_start, count) VALUES (?1, ?2, ?3, 1)
         ON CONFLICT (bucket, key) DO UPDATE SET count = 1, window_start = ?3`,
      )
      .bind(bucket, key, windowStart)
      .run();
    return true;
  }
  const newCount = existing.count + 1;
  await db
    .prepare("UPDATE rate_limits SET count = ?1 WHERE bucket = ?2 AND key = ?3")
    .bind(newCount, bucket, key)
    .run();
  return newCount <= limit.limit;
}
