// ─── Wallet: Address Derivation, Account Model, Nonce Tracking ────────────────
// Bech32 addresses compatible with Cosmos ecosystem format.
// Native key type: Ed25519. Architecture supports adding secp256k1 for Keplr.

// ─── Bech32 Encoding ─────────────────────────────────────────────────────────

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GENERATOR[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const ret: number[] = [];
  for (let i = 0; i < 6; i++) ret.push((polymod >> (5 * (5 - i))) & 31);
  return ret;
}

function bech32Encode(hrp: string, data: number[]): string {
  const combined = [...data, ...bech32CreateChecksum(hrp, data)];
  return hrp + "1" + combined.map(d => CHARSET[d]).join("");
}

function bech32VerifyChecksum(hrp: string, data: number[]): boolean {
  return bech32Polymod([...bech32HrpExpand(hrp), ...data]) === 1;
}

export function bech32Decode(str: string): { hrp: string; data: number[] } | null {
  const pos = str.lastIndexOf("1");
  if (pos < 1 || pos + 7 > str.length || str.length > 90) return null;
  const hrp = str.slice(0, pos);
  const data: number[] = [];
  for (let i = pos + 1; i < str.length; i++) {
    const d = CHARSET.indexOf(str[i]);
    if (d === -1) return null;
    data.push(d);
  }
  if (!bech32VerifyChecksum(hrp, data)) return null;
  return { hrp, data: data.slice(0, data.length - 6) };
}

// Convert 8-bit bytes to 5-bit groups
function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    return [];
  }
  return ret;
}

// ─── Address Derivation ──────────────────────────────────────────────────────

const ADDRESS_HRP = "persistia";

/**
 * Derive a Bech32 address from a raw Ed25519 public key.
 * Format: persistia1<bech32(sha256(pubkey)[0:20])>
 * Same derivation scheme as Cosmos SDK (hash + truncate to 20 bytes).
 */
export async function pubkeyToAddress(pubkeyBytes: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", pubkeyBytes);
  const truncated = new Uint8Array(hash).slice(0, 20);
  const words = convertBits(truncated, 8, 5, true);
  return bech32Encode(ADDRESS_HRP, words);
}

/**
 * Derive address from base64-encoded public key.
 */
export async function pubkeyB64ToAddress(pubkeyB64: string): Promise<string> {
  const binary = atob(pubkeyB64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return pubkeyToAddress(bytes);
}

/**
 * Validate a Persistia address.
 */
export function validateAddress(address: string): boolean {
  const decoded = bech32Decode(address.toLowerCase());
  if (!decoded) return false;
  if (decoded.hrp !== ADDRESS_HRP) return false;
  // 20 bytes = 32 five-bit groups (with padding)
  if (decoded.data.length !== 32) return false;
  return true;
}

// ─── Account Types ───────────────────────────────────────────────────────────

export interface Account {
  address: string;
  pubkey: string;          // base64 Ed25519 public key
  key_type: "ed25519" | "secp256k1";
  nonce: number;           // monotonically increasing, for replay protection
  created_at: number;
}

export interface TokenBalance {
  denom: string;
  amount: bigint;
}

// ─── Account Manager ─────────────────────────────────────────────────────────

export class AccountManager {
  private sql: any;

  constructor(sql: any) {
    this.sql = sql;
  }

  /**
   * Get or create an account for a pubkey. Returns the account with its address.
   */
  async getOrCreate(pubkeyB64: string, keyType: "ed25519" | "secp256k1" = "ed25519"): Promise<Account> {
    const rows = [...this.sql.exec("SELECT * FROM accounts WHERE pubkey = ?", pubkeyB64)];
    if (rows.length > 0) {
      const r = rows[0] as any;
      return { address: r.address, pubkey: r.pubkey, key_type: r.key_type, nonce: r.nonce, created_at: r.created_at };
    }

    const address = await pubkeyB64ToAddress(pubkeyB64);
    const now = Date.now();
    this.sql.exec(
      "INSERT OR IGNORE INTO accounts (address, pubkey, key_type, nonce, created_at) VALUES (?, ?, ?, 0, ?)",
      address, pubkeyB64, keyType, now,
    );
    return { address, pubkey: pubkeyB64, key_type: keyType, nonce: 0, created_at: now };
  }

  /**
   * Look up account by address.
   */
  getByAddress(address: string): Account | null {
    const rows = [...this.sql.exec("SELECT * FROM accounts WHERE address = ?", address)];
    if (rows.length === 0) return null;
    const r = rows[0] as any;
    return { address: r.address, pubkey: r.pubkey, key_type: r.key_type, nonce: r.nonce, created_at: r.created_at };
  }

  /**
   * Validate and consume a nonce. Returns true if valid (nonce === expected).
   */
  validateNonce(pubkeyB64: string, nonce: number): boolean {
    const rows = [...this.sql.exec("SELECT nonce FROM accounts WHERE pubkey = ?", pubkeyB64)];
    if (rows.length === 0) return nonce === 0; // first tx, account will be created
    const expected = rows[0].nonce as number;
    return nonce === expected;
  }

  /**
   * Increment nonce after successful event execution.
   */
  incrementNonce(pubkeyB64: string): void {
    this.sql.exec("UPDATE accounts SET nonce = nonce + 1 WHERE pubkey = ?", pubkeyB64);
  }

  /**
   * Get token balance for an account.
   */
  getBalance(address: string, denom: string = "PERSIST"): bigint {
    const rows = [...this.sql.exec(
      "SELECT amount FROM token_balances WHERE address = ? AND denom = ?",
      address, denom,
    )];
    if (rows.length === 0) return 0n;
    return BigInt(rows[0].amount as string);
  }

  /**
   * Get all token balances for an account.
   */
  getAllBalances(address: string): TokenBalance[] {
    const rows = [...this.sql.exec(
      "SELECT denom, amount FROM token_balances WHERE address = ? AND CAST(amount AS INTEGER) > 0",
      address,
    )];
    return rows.map((r: any) => ({ denom: r.denom, amount: BigInt(r.amount as string) }));
  }

  /**
   * Transfer tokens between accounts. Returns error string or null on success.
   */
  transfer(fromAddress: string, toAddress: string, denom: string, amount: bigint): string | null {
    if (amount <= 0n) return "Amount must be positive";
    if (fromAddress === toAddress) return "Cannot transfer to self";

    const fromBal = this.getBalance(fromAddress, denom);
    if (fromBal < amount) return `Insufficient balance: have ${fromBal}, need ${amount}`;

    // Debit sender
    this.sql.exec(
      `INSERT INTO token_balances (address, denom, amount) VALUES (?, ?, ?)
       ON CONFLICT(address, denom) DO UPDATE SET amount = CAST(CAST(amount AS INTEGER) - ? AS TEXT)`,
      fromAddress, denom, (fromBal - amount).toString(), amount.toString(),
    );

    // Credit receiver
    const toBal = this.getBalance(toAddress, denom);
    this.sql.exec(
      `INSERT INTO token_balances (address, denom, amount) VALUES (?, ?, ?)
       ON CONFLICT(address, denom) DO UPDATE SET amount = CAST(CAST(amount AS INTEGER) + ? AS TEXT)`,
      toAddress, denom, (toBal + amount).toString(), amount.toString(),
    );

    return null;
  }

  /**
   * Mint tokens to an address (used for faucet/seed).
   */
  mint(address: string, denom: string, amount: bigint): void {
    const current = this.getBalance(address, denom);
    this.sql.exec(
      `INSERT INTO token_balances (address, denom, amount) VALUES (?, ?, ?)
       ON CONFLICT(address, denom) DO UPDATE SET amount = ?`,
      address, denom, (current + amount).toString(), (current + amount).toString(),
    );
  }

  /**
   * Burn tokens from an address, permanently removing them from circulation.
   * Records the burn in the burn_ledger for audit trail.
   * Returns error string or null on success.
   */
  burn(fromAddress: string, denom: string, amount: bigint, reason: string = "fee"): string | null {
    if (amount <= 0n) return "Amount must be positive";

    const balance = this.getBalance(fromAddress, denom);
    if (balance < amount) return `Insufficient balance: have ${balance}, need ${amount}`;

    // Debit the account
    this.sql.exec(
      `INSERT INTO token_balances (address, denom, amount) VALUES (?, ?, ?)
       ON CONFLICT(address, denom) DO UPDATE SET amount = CAST(CAST(amount AS INTEGER) - ? AS TEXT)`,
      fromAddress, denom, (balance - amount).toString(), amount.toString(),
    );

    // Record in burn ledger
    this.sql.exec(
      `INSERT INTO burn_ledger (address, denom, amount, reason, timestamp)
       VALUES (?, ?, ?, ?, ?)`,
      fromAddress, denom, amount.toString(), reason, Date.now(),
    );

    return null;
  }

  /**
   * Get total tokens burned for a denomination.
   */
  totalBurned(denom: string = "PERSIST"): bigint {
    const rows = [...this.sql.exec(
      "SELECT COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total FROM burn_ledger WHERE denom = ?",
      denom,
    )];
    return BigInt((rows[0] as any).total || 0);
  }

  /**
   * Get burn history, optionally filtered by address.
   */
  burnHistory(opts: { address?: string; denom?: string; limit?: number } = {}): Array<{
    address: string; denom: string; amount: bigint; reason: string; timestamp: number;
  }> {
    const limit = opts.limit || 50;
    let query = "SELECT * FROM burn_ledger";
    const params: any[] = [];
    const clauses: string[] = [];

    if (opts.address) { clauses.push("address = ?"); params.push(opts.address); }
    if (opts.denom) { clauses.push("denom = ?"); params.push(opts.denom); }
    if (clauses.length > 0) query += " WHERE " + clauses.join(" AND ");
    query += " ORDER BY timestamp DESC LIMIT ?";
    params.push(limit);

    const rows = [...this.sql.exec(query, ...params)];
    return rows.map((r: any) => ({
      address: r.address,
      denom: r.denom,
      amount: BigInt(r.amount as string),
      reason: r.reason,
      timestamp: r.timestamp,
    }));
  }

  /** Create burn_ledger table. Call during DO init. */
  static initBurnTable(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS burn_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL,
        denom TEXT NOT NULL,
        amount TEXT NOT NULL,
        reason TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_burn_denom ON burn_ledger(denom)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_burn_address ON burn_ledger(address)`);
  }
}
