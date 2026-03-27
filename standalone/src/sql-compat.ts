// ─── SQL Compatibility Layer ──────────────────────────────────────────────────
// Wraps better-sqlite3 to match Cloudflare Durable Object's sql.exec() API.
//
// CF DO API:  sql.exec("SELECT * FROM t WHERE id = ?", id)  → iterable of row objects
// better-sqlite3: db.prepare("...").all(...)                  → array of row objects
//
// This adapter makes all existing Persistia modules (gossip.ts, validator-registry.ts,
// wallet.ts, etc.) work unchanged on a plain Node.js server.

import Database from "better-sqlite3";
import { mkdirSync, existsSync } from "fs";
import { dirname } from "path";

export interface SqlCompat {
  exec(query: string, ...params: any[]): any[];
}

export function createDatabase(dbPath: string): { db: Database.Database; sql: SqlCompat } {
  // Ensure parent directory exists
  const dir = dirname(dbPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const db = new Database(dbPath);

  // Performance pragmas for a validator node
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("cache_size = -64000"); // 64MB cache
  db.pragma("busy_timeout = 5000");

  const sql: SqlCompat = {
    exec(query: string, ...params: any[]): any[] {
      const trimmed = query.trim();

      // Multi-statement execution (CREATE TABLE batches, etc.)
      // Detect by checking for multiple semicolons not inside strings
      if (hasMultipleStatements(trimmed)) {
        db.exec(trimmed);
        return [];
      }

      // Single statement
      const upper = trimmed.toUpperCase();
      const isSelect = upper.startsWith("SELECT") || upper.startsWith("WITH");

      try {
        if (isSelect) {
          const stmt = db.prepare(trimmed);
          return params.length > 0 ? stmt.all(...params) : stmt.all();
        } else {
          const stmt = db.prepare(trimmed);
          if (params.length > 0) {
            stmt.run(...params);
          } else {
            stmt.run();
          }
          return [];
        }
      } catch (e: any) {
        // Handle "table already exists" gracefully (same as CF DO behavior)
        if (e.message?.includes("already exists")) return [];
        // Handle "no column" for ALTER TABLE ADD COLUMN migrations
        if (e.message?.includes("duplicate column")) return [];
        throw e;
      }
    },
  };

  return { db, sql };
}

/**
 * Detect if a SQL string contains multiple statements.
 * Simple heuristic: look for semicolons followed by non-whitespace.
 */
function hasMultipleStatements(sql: string): boolean {
  // Strip comments
  const cleaned = sql.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
  // Split on semicolons and check if more than one non-empty statement
  const stmts = cleaned.split(";").map(s => s.trim()).filter(s => s.length > 0);
  return stmts.length > 1;
}

/**
 * Create a mock DurableObjectState-like wrapper for the standalone node.
 * This lets us pass `{ storage: { sql } }` to code that expects DO state.
 */
export function createMockState(sql: SqlCompat) {
  return {
    storage: {
      sql,
      // DO blockConcurrencyWhile is a no-op in standalone (single-threaded Node.js)
      async blockConcurrencyWhile(fn: () => Promise<void>) {
        await fn();
      },
    },
  };
}
