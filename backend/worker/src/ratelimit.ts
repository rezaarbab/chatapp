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

/** Atomic fixed-window counter. Returns true when the request is allowed. */
export async function checkRateLimit(
  db: D1Database,
  bucket: string,
  key: string,
  limit: Limit,
  now: number,
): Promise<boolean> {
  const windowStart = Math.floor(now / limit.windowMs) * limit.windowMs;
  const row = await db
    .prepare(
      `INSERT INTO rate_limits (bucket, key, window_start, count) VALUES (?1, ?2, ?3, 1)
       ON CONFLICT (bucket, key) DO UPDATE SET
         count = CASE WHEN window_start = ?3 THEN count + 1 ELSE 1 END,
         window_start = ?3
       RETURNING count`,
    )
    .bind(bucket, key, windowStart)
    .first<{ count: number }>();
  return (row?.count ?? 0) <= limit.limit;
}
