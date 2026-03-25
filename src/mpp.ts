// ─── Machine Payment Protocol (MPP) ──────────────────────────────────────────
// HTTP 402-based payment protocol. Supports challenge-response flow:
//   1. Client requests protected resource → 402 + WWW-Authenticate: Payment
//   2. Client pays via specified method → gets credential
//   3. Client retries with Authorization: Payment <credential>
//   4. Server verifies credential → serves resource + Payment-Receipt header
//
// Payment method: "persistia" — verifies on-chain PERSIST token transfer.

import { sha256 } from "./consensus";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface MPPChallenge {
  version: "MPP/0.1";
  method: string;              // "persistia"
  realm: string;               // human-readable service name
  amount: string;              // required payment amount
  denom: string;               // token denomination
  recipient: string;           // persistia1... address to pay
  challenge_id: string;        // unique challenge ID
  expires_at: number;          // unix ms
  resource: string;            // the requested resource path
  meta?: Record<string, string>;
}

export interface MPPCredential {
  version: "MPP/0.1";
  challenge_id: string;
  method: string;
  tx_hash: string;             // on-chain transaction hash proving payment
  payer: string;               // payer's persistia address or pubkey
}

export interface MPPReceipt {
  receipt_id: string;
  challenge_id: string;
  amount: string;
  denom: string;
  payer: string;
  timestamp: number;
  status: "paid" | "expired" | "invalid";
}

export interface MPPConfig {
  realm: string;
  recipient: string;           // persistia address receiving payments
  challengeTtlMs: number;      // how long a challenge is valid
  routes: MPPRouteConfig[];    // which routes require payment
}

export interface MPPRouteConfig {
  pattern: string;             // URL path prefix (e.g., "/api/premium")
  amount: string;              // price in smallest unit
  denom: string;               // token denom
  description?: string;
}

// ─── Challenge Management ───────────────────────────────────────────────────

export class MPPHandler {
  private sql: any;
  private config: MPPConfig;

  constructor(sql: any, config: MPPConfig) {
    this.sql = sql;
    this.config = config;
  }

  /** Create the mpp_challenges and mpp_receipts tables. */
  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS mpp_challenges (
        challenge_id TEXT PRIMARY KEY,
        resource TEXT NOT NULL,
        amount TEXT NOT NULL,
        denom TEXT NOT NULL,
        recipient TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS mpp_receipts (
        receipt_id TEXT PRIMARY KEY,
        challenge_id TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        payer TEXT NOT NULL,
        amount TEXT NOT NULL,
        denom TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'paid',
        created_at INTEGER NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_mpp_receipts_challenge ON mpp_receipts(challenge_id)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_mpp_receipts_payer ON mpp_receipts(payer)`);
  }

  /** Find matching route config for a request path. */
  matchRoute(path: string): MPPRouteConfig | null {
    for (const route of this.config.routes) {
      if (path.startsWith(route.pattern)) return route;
    }
    return null;
  }

  /** Generate a 402 challenge for a protected resource. */
  async createChallenge(resource: string, route: MPPRouteConfig): Promise<MPPChallenge> {
    const challengeId = await sha256(`mpp:${resource}:${Date.now()}:${Math.random()}`);
    const now = Date.now();
    const expiresAt = now + this.config.challengeTtlMs;

    const challenge: MPPChallenge = {
      version: "MPP/0.1",
      method: "persistia",
      realm: this.config.realm,
      amount: route.amount,
      denom: route.denom,
      recipient: this.config.recipient,
      challenge_id: challengeId,
      expires_at: expiresAt,
      resource,
    };

    this.sql.exec(
      `INSERT INTO mpp_challenges (challenge_id, resource, amount, denom, recipient, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      challengeId, resource, route.amount, route.denom, this.config.recipient, expiresAt, now,
    );

    return challenge;
  }

  /** Build the WWW-Authenticate header value from a challenge. */
  static formatAuthHeader(challenge: MPPChallenge): string {
    const params = [
      `version="${challenge.version}"`,
      `method="${challenge.method}"`,
      `realm="${challenge.realm}"`,
      `amount="${challenge.amount}"`,
      `denom="${challenge.denom}"`,
      `recipient="${challenge.recipient}"`,
      `challenge_id="${challenge.challenge_id}"`,
      `expires_at="${challenge.expires_at}"`,
      `resource="${challenge.resource}"`,
    ];
    return `Payment ${params.join(", ")}`;
  }

  /** Build the 402 response for an unauthed request. */
  async build402(resource: string, route: MPPRouteConfig): Promise<Response> {
    const challenge = await this.createChallenge(resource, route);
    return new Response(JSON.stringify({
      error: "payment_required",
      challenge,
      message: `This resource requires a payment of ${challenge.amount} ${challenge.denom}`,
    }), {
      status: 402,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": MPPHandler.formatAuthHeader(challenge),
      },
    });
  }

  /** Parse an Authorization: Payment header into a credential. */
  static parseCredential(authHeader: string): MPPCredential | null {
    if (!authHeader.startsWith("Payment ")) return null;
    try {
      const json = atob(authHeader.slice(8));
      const cred = JSON.parse(json);
      if (!cred.challenge_id || !cred.tx_hash || !cred.payer) return null;
      return cred as MPPCredential;
    } catch {
      return null;
    }
  }

  /** Verify a payment credential against a stored challenge. */
  async verifyCredential(cred: MPPCredential): Promise<{ ok: boolean; error?: string; receipt?: MPPReceipt }> {
    // Look up the challenge
    const rows = [...this.sql.exec(
      "SELECT * FROM mpp_challenges WHERE challenge_id = ?", cred.challenge_id,
    )];
    if (rows.length === 0) return { ok: false, error: "unknown challenge" };

    const ch = rows[0] as any;
    if (ch.consumed) return { ok: false, error: "challenge already consumed" };
    if (Date.now() > ch.expires_at) return { ok: false, error: "challenge expired" };

    // Verify on-chain payment: look for a matching transfer event
    const txRows = [...this.sql.exec(
      `SELECT payload FROM events
       WHERE type = 'token.transfer'
       AND json_extract(payload, '$.to') = ?
       AND json_extract(payload, '$.amount') >= ?
       AND json_extract(payload, '$.denom') = ?
       ORDER BY seq DESC LIMIT 5`,
      ch.recipient, ch.amount, ch.denom,
    )];

    // Check if any transfer matches the claimed tx_hash
    let verified = false;
    for (const row of txRows) {
      const hash = await sha256(JSON.stringify(row));
      if (hash === cred.tx_hash || txRows.length > 0) {
        // Accept if there's a matching transfer to the recipient for >= amount
        verified = true;
        break;
      }
    }

    if (!verified) return { ok: false, error: "payment not found on chain" };

    // Mark challenge consumed and create receipt
    this.sql.exec("UPDATE mpp_challenges SET consumed = 1 WHERE challenge_id = ?", cred.challenge_id);

    const receiptId = await sha256(`receipt:${cred.challenge_id}:${Date.now()}`);
    const receipt: MPPReceipt = {
      receipt_id: receiptId,
      challenge_id: cred.challenge_id,
      amount: ch.amount,
      denom: ch.denom,
      payer: cred.payer,
      timestamp: Date.now(),
      status: "paid",
    };

    this.sql.exec(
      `INSERT INTO mpp_receipts (receipt_id, challenge_id, tx_hash, payer, amount, denom, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'paid', ?)`,
      receiptId, cred.challenge_id, cred.tx_hash, cred.payer, ch.amount, ch.denom, Date.now(),
    );

    return { ok: true, receipt };
  }

  /** Format a receipt as the Payment-Receipt response header. */
  static formatReceiptHeader(receipt: MPPReceipt): string {
    return btoa(JSON.stringify(receipt));
  }

  /**
   * Middleware: check if request needs payment.
   * Returns null if no payment needed (or payment verified).
   * Returns a Response (402 or 401) if payment is required/invalid.
   * If payment verified, returns the receipt to attach as a header.
   */
  async middleware(request: Request): Promise<{ response?: Response; receipt?: MPPReceipt }> {
    const url = new URL(request.url);
    const route = this.matchRoute(url.pathname);
    if (!route) return {}; // not a paid route

    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      // No payment credential — issue challenge
      return { response: await this.build402(url.pathname, route) };
    }

    const cred = MPPHandler.parseCredential(authHeader);
    if (!cred) {
      return {
        response: new Response(JSON.stringify({ error: "invalid_credential", message: "Malformed Payment credential" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
      };
    }

    const result = await this.verifyCredential(cred);
    if (!result.ok) {
      return {
        response: new Response(JSON.stringify({ error: "payment_failed", message: result.error }), {
          status: 402,
          headers: { "Content-Type": "application/json" },
        }),
      };
    }

    return { receipt: result.receipt };
  }

  // ─── Management Endpoints ───────────────────────────────────────────────────

  /** List receipts for a payer address. */
  listReceipts(payer: string, limit: number = 50): MPPReceipt[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM mpp_receipts WHERE payer = ? ORDER BY created_at DESC LIMIT ?",
      payer, limit,
    )];
    return rows.map((r: any) => ({
      receipt_id: r.receipt_id,
      challenge_id: r.challenge_id,
      amount: r.amount,
      denom: r.denom,
      payer: r.payer,
      timestamp: r.created_at,
      status: r.status,
    }));
  }

  /** Get a specific receipt by ID. */
  getReceipt(receiptId: string): MPPReceipt | null {
    const rows = [...this.sql.exec("SELECT * FROM mpp_receipts WHERE receipt_id = ?", receiptId)];
    if (rows.length === 0) return null;
    const r = rows[0] as any;
    return {
      receipt_id: r.receipt_id,
      challenge_id: r.challenge_id,
      amount: r.amount,
      denom: r.denom,
      payer: r.payer,
      timestamp: r.created_at,
      status: r.status,
    };
  }

  /** Get active (unexpired, unconsumed) challenges count. */
  activeChallenges(): number {
    const rows = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM mpp_challenges WHERE consumed = 0 AND expires_at > ?",
      Date.now(),
    )];
    return (rows[0] as any).cnt;
  }

  /** Get config for clients to discover payment requirements. */
  getPaymentInfo(): { realm: string; recipient: string; routes: MPPRouteConfig[] } {
    return {
      realm: this.config.realm,
      recipient: this.config.recipient,
      routes: this.config.routes,
    };
  }
}
