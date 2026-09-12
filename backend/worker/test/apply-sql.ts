import { env } from "cloudflare:test";

/**
 * Applies the given SQL to the test D1 database statement-by-statement.
 * `env.DB.exec` is unreliable for multi-statement scripts in the current
 * vitest pool (it can split statements incorrectly), so each statement is
 * prepared and run explicitly. Migration SQL contains no semicolons inside
 * string literals or CHECK expressions, so a plain split is safe here.
 */
export async function applySql(sql: string): Promise<void> {
  const statements = sql
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const statement of statements) {
    await env.DB.prepare(statement).run();
  }
}

export function migrationsFromBinding(): { name: string; sql: string }[] {
  const raw = (env as Record<string, unknown>).MIGRATIONS as string;
  return JSON.parse(raw) as { name: string; sql: string }[];
}
