// ─── Durable Queue: Generalized Queue System Backed by SQLite ───────────────
// Provides reliable message queuing with at-least-once delivery, exponential
// backoff retries, dead-letter queues, deduplication, priority ordering,
// and backpressure — all backed by Cloudflare DO SQLite storage.

// ─── Types ───────────────────────────────────────────────────────────────────

export interface QueueConfig {
  name: string;
  maxRetries: number;
  retryBackoffMs: number;
  maxBackoffMs: number;
  visibilityTimeoutMs: number;
  deadLetterQueue?: string;
  maxSize?: number;
  ordered?: boolean;
}

export interface EnqueueOptions {
  partitionKey?: string;
  priority?: number;
  delayMs?: number;
  dedupKey?: string;
  deduplicationWindowMs?: number;
}

export interface EnqueueResult {
  ok: boolean;
  id?: string;
  error?: string;
  queueDepth: number;
}

export interface QueueMessage {
  id: string;
  queue: string;
  partitionKey: string;
  payload: any;
  priority: number;
  attempts: number;
  createdAt: number;
}

export interface QueueStats {
  pending: number;
  processing: number;
  completed: number;
  failed: number;
  dead: number;
  oldestPendingAge: number | null;
}

export interface ProcessResult {
  processed: number;
  succeeded: number;
  failed: number;
}

export type MessageHandler = (message: QueueMessage) => Promise<void>;

// ─── Defaults ────────────────────────────────────────────────────────────────

const DEFAULTS: Omit<QueueConfig, "name"> = {
  maxRetries: 3,
  retryBackoffMs: 1000,
  maxBackoffMs: 300_000,
  visibilityTimeoutMs: 30_000,
  ordered: false,
};

// ─── DurableQueue ────────────────────────────────────────────────────────────

export class DurableQueue {
  private sql: any;
  private config: QueueConfig;

  constructor(sql: any, config: QueueConfig) {
    this.sql = sql;
    this.config = config;
  }

  enqueue<T>(payload: T, opts?: EnqueueOptions): EnqueueResult {
    const now = Date.now();
    const partitionKey = opts?.partitionKey ?? "";
    const priority = opts?.priority ?? 0;
    const delayMs = opts?.delayMs ?? 0;
    const visibleAt = now + delayMs;

    // Backpressure check
    if (this.config.maxSize != null) {
      const [row] = [...this.sql.exec(
        "SELECT COUNT(*) as cnt FROM durable_queue WHERE queue = ? AND status IN ('pending','processing')",
        this.config.name,
      )] as any[];
      if (row.cnt >= this.config.maxSize) {
        return { ok: false, error: "queue_full", queueDepth: row.cnt };
      }
    }

    // Deduplication check
    if (opts?.dedupKey) {
      const windowMs = opts.deduplicationWindowMs ?? 300_000; // 5 min default
      const cutoff = now - windowMs;
      const [existing] = [...this.sql.exec(
        "SELECT id FROM durable_queue WHERE queue = ? AND dedup_key = ? AND created_at > ?",
        this.config.name, opts.dedupKey, cutoff,
      )] as any[];
      if (existing) {
        return { ok: false, error: "duplicate", queueDepth: this.getDepth() };
      }
    }

    const id = crypto.randomUUID();
    this.sql.exec(
      `INSERT INTO durable_queue (id, queue, partition_key, payload, status, priority, attempts, max_retries, created_at, visible_at, dedup_key)
       VALUES (?, ?, ?, ?, 'pending', ?, 0, ?, ?, ?, ?)`,
      id,
      this.config.name,
      partitionKey,
      JSON.stringify(payload),
      priority,
      this.config.maxRetries,
      now,
      visibleAt,
      opts?.dedupKey ?? null,
    );

    return { ok: true, id, queueDepth: this.getDepth() };
  }

  dequeue(batchSize: number = 10): QueueMessage[] {
    const now = Date.now();

    let rows: any[];
    if (this.config.ordered) {
      // FIFO within partition key: pick the oldest pending per partition
      rows = [...this.sql.exec(
        `SELECT * FROM durable_queue
         WHERE queue = ? AND status = 'pending' AND visible_at <= ?
           AND rowid IN (
             SELECT MIN(rowid) FROM durable_queue
             WHERE queue = ? AND status = 'pending' AND visible_at <= ?
             GROUP BY partition_key
           )
         ORDER BY priority ASC, created_at ASC
         LIMIT ?`,
        this.config.name, now, this.config.name, now, batchSize,
      )] as any[];
    } else {
      rows = [...this.sql.exec(
        `SELECT * FROM durable_queue
         WHERE queue = ? AND status = 'pending' AND visible_at <= ?
         ORDER BY priority ASC, created_at ASC
         LIMIT ?`,
        this.config.name, now, batchSize,
      )] as any[];
    }

    if (rows.length === 0) return [];

    // Mark all as processing
    const ids = rows.map((r: any) => r.id);
    for (const id of ids) {
      this.sql.exec(
        "UPDATE durable_queue SET status = 'processing', last_attempted_at = ?, attempts = attempts + 1 WHERE id = ?",
        now, id,
      );
    }

    return rows.map((r: any) => ({
      id: r.id,
      queue: r.queue,
      partitionKey: r.partition_key,
      payload: JSON.parse(r.payload),
      priority: r.priority,
      attempts: r.attempts + 1, // reflect the increment we just did
      createdAt: r.created_at,
    }));
  }

  ack(messageId: string): void {
    const now = Date.now();
    this.sql.exec(
      "UPDATE durable_queue SET status = 'completed', completed_at = ? WHERE id = ?",
      now, messageId,
    );
  }

  nack(messageId: string, error?: string): void {
    const now = Date.now();
    const [row] = [...this.sql.exec(
      "SELECT attempts, max_retries FROM durable_queue WHERE id = ?",
      messageId,
    )] as any[];
    if (!row) return;

    if (row.attempts >= row.max_retries) {
      // Exhausted retries
      if (this.config.deadLetterQueue) {
        // Move to DLQ: change queue name and reset to pending
        this.sql.exec(
          "UPDATE durable_queue SET queue = ?, status = 'dead', completed_at = ?, error = ? WHERE id = ?",
          this.config.deadLetterQueue, now, error ?? null, messageId,
        );
      } else {
        this.sql.exec(
          "UPDATE durable_queue SET status = 'dead', completed_at = ?, error = ? WHERE id = ?",
          now, error ?? null, messageId,
        );
      }
    } else {
      // Retry with exponential backoff
      const backoff = Math.min(
        this.config.retryBackoffMs * Math.pow(2, row.attempts - 1),
        this.config.maxBackoffMs,
      );
      const visibleAt = now + backoff;
      this.sql.exec(
        "UPDATE durable_queue SET status = 'pending', visible_at = ?, error = ? WHERE id = ?",
        visibleAt, error ?? null, messageId,
      );
    }
  }

  async processBatch(handler: MessageHandler, batchSize?: number): Promise<ProcessResult> {
    const messages = this.dequeue(batchSize);
    let succeeded = 0;
    let failed = 0;

    for (const msg of messages) {
      try {
        await handler(msg);
        this.ack(msg.id);
        succeeded++;
      } catch (err: any) {
        this.nack(msg.id, err?.message ?? String(err));
        failed++;
      }
    }

    return { processed: messages.length, succeeded, failed };
  }

  recoverStalled(): number {
    const now = Date.now();
    const cutoff = now - this.config.visibilityTimeoutMs;
    const rows = [...this.sql.exec(
      "SELECT id FROM durable_queue WHERE queue = ? AND status = 'processing' AND last_attempted_at < ?",
      this.config.name, cutoff,
    )] as any[];

    for (const row of rows) {
      this.sql.exec(
        "UPDATE durable_queue SET status = 'pending', visible_at = ? WHERE id = ?",
        now, row.id,
      );
    }

    return rows.length;
  }

  prune(olderThanMs: number): number {
    const cutoff = Date.now() - olderThanMs;
    const rows = [...this.sql.exec(
      "SELECT id FROM durable_queue WHERE status IN ('completed','dead') AND completed_at < ?",
      cutoff,
    )] as any[];

    if (rows.length > 0) {
      for (const row of rows) {
        this.sql.exec("DELETE FROM durable_queue WHERE id = ?", row.id);
      }
    }

    return rows.length;
  }

  getStats(): QueueStats {
    const rows = [...this.sql.exec(
      "SELECT status, COUNT(*) as cnt FROM durable_queue WHERE queue = ? GROUP BY status",
      this.config.name,
    )] as any[];

    const counts: Record<string, number> = {};
    for (const r of rows) {
      counts[r.status] = r.cnt;
    }

    const [oldest] = [...this.sql.exec(
      "SELECT MIN(created_at) as oldest FROM durable_queue WHERE queue = ? AND status = 'pending'",
      this.config.name,
    )] as any[];

    const now = Date.now();
    const oldestPendingAge = oldest?.oldest ? now - oldest.oldest : null;

    return {
      pending: counts["pending"] ?? 0,
      processing: counts["processing"] ?? 0,
      completed: counts["completed"] ?? 0,
      failed: counts["failed"] ?? 0,
      dead: counts["dead"] ?? 0,
      oldestPendingAge,
    };
  }

  getDeadLetters(limit: number = 100): QueueMessage[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM durable_queue WHERE queue = ? AND status = 'dead' ORDER BY completed_at DESC LIMIT ?",
      this.config.name, limit,
    )] as any[];

    return rows.map((r: any) => ({
      id: r.id,
      queue: r.queue,
      partitionKey: r.partition_key,
      payload: JSON.parse(r.payload),
      priority: r.priority,
      attempts: r.attempts,
      createdAt: r.created_at,
    }));
  }

  redriveDeadLetters(limit: number = 100): number {
    const now = Date.now();
    const rows = [...this.sql.exec(
      "SELECT id FROM durable_queue WHERE queue = ? AND status = 'dead' ORDER BY completed_at ASC LIMIT ?",
      this.config.name, limit,
    )] as any[];

    for (const row of rows) {
      this.sql.exec(
        "UPDATE durable_queue SET status = 'pending', attempts = 0, visible_at = ?, completed_at = NULL, error = NULL WHERE id = ?",
        now, row.id,
      );
    }

    return rows.length;
  }

  // ─── Internal ────────────────────────────────────────────────────────────────

  private getDepth(): number {
    const [row] = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM durable_queue WHERE queue = ? AND status IN ('pending','processing')",
      this.config.name,
    )] as any[];
    return row?.cnt ?? 0;
  }
}

// ─── QueueManager ────────────────────────────────────────────────────────────

export class QueueManager {
  private sql: any;
  private queues: Map<string, DurableQueue> = new Map();

  constructor(sql: any) {
    this.sql = sql;
  }

  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS durable_queue (
        id TEXT PRIMARY KEY,
        queue TEXT NOT NULL,
        partition_key TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        priority INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER NOT NULL DEFAULT 3,
        created_at INTEGER NOT NULL,
        visible_at INTEGER NOT NULL,
        last_attempted_at INTEGER,
        completed_at INTEGER,
        error TEXT,
        dedup_key TEXT
      )
    `);
    sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_dq_dequeue
      ON durable_queue (queue, status, visible_at, priority)
    `);
    sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_dq_partition
      ON durable_queue (queue, partition_key, status, created_at)
    `);
    sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_dq_dedup
      ON durable_queue (queue, dedup_key) WHERE dedup_key IS NOT NULL
    `);
    sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_dq_prune
      ON durable_queue (status, completed_at)
    `);
  }

  getQueue(name: string, config?: Partial<Omit<QueueConfig, "name">>): DurableQueue {
    let queue = this.queues.get(name);
    if (!queue) {
      const merged: QueueConfig = { ...DEFAULTS, ...config, name };
      queue = new DurableQueue(this.sql, merged);
      this.queues.set(name, queue);
    }
    return queue;
  }

  listQueues(): Array<{ name: string; stats: QueueStats }> {
    const rows = [...this.sql.exec(
      "SELECT DISTINCT queue FROM durable_queue",
    )] as any[];

    return rows.map((r: any) => {
      const q = this.getQueue(r.queue);
      return { name: r.queue, stats: q.getStats() };
    });
  }

  async processAll(
    handlers: Record<string, MessageHandler>,
    batchSize?: number,
  ): Promise<Record<string, ProcessResult>> {
    const results: Record<string, ProcessResult> = {};
    for (const [name, handler] of Object.entries(handlers)) {
      const queue = this.getQueue(name);
      results[name] = await queue.processBatch(handler, batchSize);
    }
    return results;
  }
}
