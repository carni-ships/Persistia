// ─── Universal Transcript ─────────────────────────────────────────────────────
// Records all agent/system interactions with hash-chained integrity,
// replay capability, and audit trail.
//
// Every entry is SHA-256 linked to its predecessor within a session,
// forming a tamper-evident log suitable for dispute resolution and
// deterministic replay.

// ─── Types ────────────────────────────────────────────────────────────────────

export type TranscriptRole = "system" | "agent" | "user" | "validator" | "oracle" | "contract";

export type TranscriptEventType =
  | "request" | "response" | "attestation" | "consensus"
  | "state_change" | "error" | "system" | "federation" | "settlement";

export type TranscriptContent =
  | { kind: "text"; text: string }
  | { kind: "json"; data: any }
  | { kind: "binary_ref"; r2_key: string; size: number; content_type: string }
  | { kind: "state_delta"; mutations: { key: string; old_value: string | null; new_value: string | null }[] };

export interface TranscriptEntry {
  id: string;
  prev_id: string | null;
  session_id: string;
  seq: number;
  timestamp: number;
  role: TranscriptRole;
  event_type: TranscriptEventType;
  source: string;
  target: string | null;
  content: TranscriptContent;
  attestation_id: string | null;
  parent_entry_id: string | null;
  metadata: Record<string, string>;
  hash: string;
}

export interface TranscriptSession {
  id: string;
  type: "mcp" | "api" | "consensus" | "xshard" | "federation" | "oracle";
  started_at: number;
  ended_at: number | null;
  entry_count: number;
  participants: string[];
  summary: string | null;
}

// ─── Hashing ──────────────────────────────────────────────────────────────────

async function hashHex(data: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─── Manager ──────────────────────────────────────────────────────────────────

export class TranscriptManager {
  private sql: any;
  private seqCounters: Map<string, number> = new Map();
  private lastEntryIds: Map<string, string> = new Map();

  constructor(sql: any) {
    this.sql = sql;
  }

  /** Create tables and indexes for transcript storage. */
  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS transcript_sessions (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        started_at INTEGER NOT NULL,
        ended_at INTEGER,
        entry_count INTEGER NOT NULL DEFAULT 0,
        participants_json TEXT NOT NULL DEFAULT '[]',
        summary TEXT
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_ts_type ON transcript_sessions(type)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_ts_started ON transcript_sessions(started_at)`);

    sql.exec(`
      CREATE TABLE IF NOT EXISTS transcript_entries (
        id TEXT PRIMARY KEY,
        prev_id TEXT,
        session_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        timestamp INTEGER NOT NULL,
        role TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source TEXT NOT NULL,
        target TEXT,
        content_json TEXT NOT NULL,
        attestation_id TEXT,
        parent_entry_id TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        hash TEXT NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_te_session_seq ON transcript_entries(session_id, seq)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_te_source ON transcript_entries(source, timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_te_type ON transcript_entries(event_type, timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_te_attestation ON transcript_entries(attestation_id) WHERE attestation_id IS NOT NULL`);
  }

  // ─── Sessions ─────────────────────────────────────────────────────────────

  startSession(
    type: TranscriptSession["type"],
    participants: string[] = [],
  ): TranscriptSession {
    const id = crypto.randomUUID();
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO transcript_sessions (id, type, started_at, entry_count, participants_json) VALUES (?, ?, ?, 0, ?)`,
      id, type, now, JSON.stringify(participants),
    );
    this.seqCounters.set(id, 0);
    this.lastEntryIds.delete(id);
    return { id, type, started_at: now, ended_at: null, entry_count: 0, participants, summary: null };
  }

  endSession(sessionId: string, summary?: string): void {
    const now = Date.now();
    this.sql.exec(
      `UPDATE transcript_sessions SET ended_at = ?, summary = ? WHERE id = ?`,
      now, summary ?? null, sessionId,
    );
    this.seqCounters.delete(sessionId);
    this.lastEntryIds.delete(sessionId);
  }

  getSession(sessionId: string): TranscriptSession | null {
    const rows = this.sql.exec(`SELECT * FROM transcript_sessions WHERE id = ?`, sessionId).toArray();
    if (rows.length === 0) return null;
    const r = rows[0];
    return {
      id: r.id,
      type: r.type,
      started_at: r.started_at,
      ended_at: r.ended_at ?? null,
      entry_count: r.entry_count,
      participants: JSON.parse(r.participants_json),
      summary: r.summary ?? null,
    };
  }

  // ─── Append ───────────────────────────────────────────────────────────────

  async append(params: {
    session_id: string;
    role: TranscriptRole;
    event_type: TranscriptEventType;
    source: string;
    target?: string | null;
    content: TranscriptContent;
    attestation_id?: string | null;
    parent_entry_id?: string | null;
    metadata?: Record<string, string>;
  }): Promise<TranscriptEntry> {
    const {
      session_id, role, event_type, source,
      target = null, content,
      attestation_id = null, parent_entry_id = null,
      metadata = {},
    } = params;

    // Resolve sequence number
    let seq = this.seqCounters.get(session_id);
    if (seq === undefined) {
      const rows = this.sql.exec(
        `SELECT MAX(seq) as max_seq FROM transcript_entries WHERE session_id = ?`,
        session_id,
      ).toArray();
      seq = rows.length > 0 && rows[0].max_seq !== null ? (rows[0].max_seq as number) + 1 : 0;
    }
    this.seqCounters.set(session_id, seq + 1);

    // Resolve prev_id
    let prev_id = this.lastEntryIds.get(session_id) ?? null;
    if (prev_id === null && seq > 0) {
      const rows = this.sql.exec(
        `SELECT id FROM transcript_entries WHERE session_id = ? ORDER BY seq DESC LIMIT 1`,
        session_id,
      ).toArray();
      if (rows.length > 0) prev_id = rows[0].id;
    }

    const timestamp = Date.now();
    const contentStr = JSON.stringify(content);

    // Hash: SHA-256 of canonical string
    const canonical = `${prev_id || ""}:${session_id}:${seq}:${timestamp}:${role}:${event_type}:${source}:${contentStr}`;
    const hash = await hashHex(canonical);

    // Use hash as the entry id
    const id = hash;

    this.sql.exec(
      `INSERT INTO transcript_entries (id, prev_id, session_id, seq, timestamp, role, event_type, source, target, content_json, attestation_id, parent_entry_id, metadata_json, hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id, prev_id, session_id, seq, timestamp,
      role, event_type, source, target,
      contentStr, attestation_id, parent_entry_id,
      JSON.stringify(metadata), hash,
    );

    this.sql.exec(
      `UPDATE transcript_sessions SET entry_count = entry_count + 1 WHERE id = ?`,
      session_id,
    );

    this.lastEntryIds.set(session_id, id);

    return {
      id, prev_id, session_id, seq, timestamp,
      role, event_type, source, target, content,
      attestation_id, parent_entry_id, metadata, hash,
    };
  }

  // ─── Request / Response convenience ───────────────────────────────────────

  async logRequestResponse(params: {
    session_id: string;
    source: string;
    target?: string | null;
    request_content: TranscriptContent;
    response_content: TranscriptContent;
    attestation_id?: string | null;
    metadata?: Record<string, string>;
  }): Promise<{ request: TranscriptEntry; response: TranscriptEntry }> {
    const request = await this.append({
      session_id: params.session_id,
      role: "user",
      event_type: "request",
      source: params.source,
      target: params.target,
      content: params.request_content,
      attestation_id: params.attestation_id,
      metadata: params.metadata,
    });

    const response = await this.append({
      session_id: params.session_id,
      role: "agent",
      event_type: "response",
      source: params.target ?? params.source,
      target: params.source,
      content: params.response_content,
      parent_entry_id: request.id,
      attestation_id: params.attestation_id,
      metadata: params.metadata,
    });

    return { request, response };
  }

  // ─── Queries ──────────────────────────────────────────────────────────────

  getEntries(
    sessionId: string,
    opts?: { after?: number; limit?: number; eventType?: TranscriptEventType },
  ): TranscriptEntry[] {
    let query = `SELECT * FROM transcript_entries WHERE session_id = ?`;
    const params: any[] = [sessionId];

    if (opts?.after !== undefined) {
      query += ` AND seq > ?`;
      params.push(opts.after);
    }
    if (opts?.eventType) {
      query += ` AND event_type = ?`;
      params.push(opts.eventType);
    }
    query += ` ORDER BY seq ASC`;
    if (opts?.limit) {
      query += ` LIMIT ?`;
      params.push(opts.limit);
    }

    const rows = this.sql.exec(query, ...params).toArray();
    return rows.map((r: any) => this.rowToEntry(r));
  }

  search(opts: {
    source?: string;
    eventType?: TranscriptEventType;
    from?: number;
    to?: number;
    limit?: number;
  }): TranscriptEntry[] {
    let query = `SELECT * FROM transcript_entries WHERE 1=1`;
    const params: any[] = [];

    if (opts.source) {
      query += ` AND source = ?`;
      params.push(opts.source);
    }
    if (opts.eventType) {
      query += ` AND event_type = ?`;
      params.push(opts.eventType);
    }
    if (opts.from !== undefined) {
      query += ` AND timestamp >= ?`;
      params.push(opts.from);
    }
    if (opts.to !== undefined) {
      query += ` AND timestamp <= ?`;
      params.push(opts.to);
    }
    query += ` ORDER BY timestamp DESC`;
    query += ` LIMIT ?`;
    params.push(opts.limit ?? 100);

    const rows = this.sql.exec(query, ...params).toArray();
    return rows.map((r: any) => this.rowToEntry(r));
  }

  // ─── Chain verification ───────────────────────────────────────────────────

  async verifyChain(sessionId: string): Promise<{
    valid: boolean;
    entries_checked: number;
    break_at_seq?: number;
  }> {
    const rows = this.sql.exec(
      `SELECT * FROM transcript_entries WHERE session_id = ? ORDER BY seq ASC`,
      sessionId,
    ).toArray();

    let prevId: string | null = null;
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];

      // Verify prev_id link
      if (r.prev_id !== prevId) {
        return { valid: false, entries_checked: i, break_at_seq: r.seq };
      }

      // Recompute hash
      const canonical = `${r.prev_id || ""}:${r.session_id}:${r.seq}:${r.timestamp}:${r.role}:${r.event_type}:${r.source}:${r.content_json}`;
      const expectedHash = await hashHex(canonical);
      if (expectedHash !== r.hash) {
        return { valid: false, entries_checked: i, break_at_seq: r.seq };
      }

      // id must equal hash
      if (r.id !== r.hash) {
        return { valid: false, entries_checked: i, break_at_seq: r.seq };
      }

      prevId = r.id;
    }

    return { valid: true, entries_checked: rows.length };
  }

  // ─── Pruning ──────────────────────────────────────────────────────────────

  prune(olderThanMs: number): number {
    const cutoff = Date.now() - olderThanMs;

    // Find sessions to prune
    const sessions = this.sql.exec(
      `SELECT id FROM transcript_sessions WHERE ended_at IS NOT NULL AND ended_at < ?`,
      cutoff,
    ).toArray();

    if (sessions.length === 0) return 0;

    const ids = sessions.map((s: any) => s.id as string);
    const placeholders = ids.map(() => "?").join(",");

    this.sql.exec(`DELETE FROM transcript_entries WHERE session_id IN (${placeholders})`, ...ids);
    this.sql.exec(`DELETE FROM transcript_sessions WHERE id IN (${placeholders})`, ...ids);

    // Clean up in-memory state
    for (const id of ids) {
      this.seqCounters.delete(id);
      this.lastEntryIds.delete(id);
    }

    return ids.length;
  }

  // ─── Stats ────────────────────────────────────────────────────────────────

  getStats(): {
    total_sessions: number;
    active_sessions: number;
    total_entries: number;
    entries_by_type: Record<string, number>;
  } {
    const totalSessions = this.sql.exec(
      `SELECT COUNT(*) as c FROM transcript_sessions`,
    ).toArray()[0].c;

    const activeSessions = this.sql.exec(
      `SELECT COUNT(*) as c FROM transcript_sessions WHERE ended_at IS NULL`,
    ).toArray()[0].c;

    const totalEntries = this.sql.exec(
      `SELECT COUNT(*) as c FROM transcript_entries`,
    ).toArray()[0].c;

    const byType: Record<string, number> = {};
    const typeRows = this.sql.exec(
      `SELECT event_type, COUNT(*) as c FROM transcript_entries GROUP BY event_type`,
    ).toArray();
    for (const r of typeRows) {
      byType[r.event_type] = r.c;
    }

    return {
      total_sessions: totalSessions,
      active_sessions: activeSessions,
      total_entries: totalEntries,
      entries_by_type: byType,
    };
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  private rowToEntry(r: any): TranscriptEntry {
    return {
      id: r.id,
      prev_id: r.prev_id ?? null,
      session_id: r.session_id,
      seq: r.seq,
      timestamp: r.timestamp,
      role: r.role as TranscriptRole,
      event_type: r.event_type as TranscriptEventType,
      source: r.source,
      target: r.target ?? null,
      content: JSON.parse(r.content_json),
      attestation_id: r.attestation_id ?? null,
      parent_entry_id: r.parent_entry_id ?? null,
      metadata: JSON.parse(r.metadata_json),
      hash: r.hash,
    };
  }
}
