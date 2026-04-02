// ─── WASM Smart Contract Runtime ──────────────────────────────────────────────
// NEAR-style register-based ABI with mutation buffering, cross-contract calls,
// and deterministic execution.

import { sha256 } from "./consensus";
import type { AggregationStrategy } from "./oracle";
import { injectFuelMetering, FuelTracker, FUEL_COSTS, DEFAULT_FUEL } from "./wasm-metering";

/**
 * Synchronous SHA-256 for use inside WASM host imports (which cannot be async).
 * Uses the SubtleCrypto-free approach: precomputed via a simple JS implementation.
 * This is a minimal pure-JS SHA-256 for deterministic in-VM hashing.
 */
function sha256Sync(input: Uint8Array | string): string {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  // Simple deterministic hash using the same approach as the WASM fuel metering.
  // For host-side hashing in sync context, we use a lightweight approach.
  // This produces a 256-bit digest that is consistent and deterministic.
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ];
  const rr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  // Pad message
  const bitLen = data.length * 8;
  const padded = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 4, bitLen, false);
  // Process blocks
  for (let off = 0; off < padded.length; off += 64) {
    const w = new Int32Array(64);
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i-15], 7) ^ rr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rr(w[i-2], 17) ^ rr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
    h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
  }
  const toHex = (n: number) => (n >>> 0).toString(16).padStart(8, "0");
  return toHex(h0)+toHex(h1)+toHex(h2)+toHex(h3)+toHex(h4)+toHex(h5)+toHex(h6)+toHex(h7);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{2}/g)!.map(h => parseInt(h, 16)));
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ContractInfo {
  address: string;
  deployer: string;
  wasm_hash: string;
  created_at: number;
  deploy_seq: number;
  locked: boolean;
}

export interface CallResult {
  ok: boolean;
  return_data?: Uint8Array;
  logs: string[];
  error?: string;
  oracle_requests?: OracleRequestEmit[];
  trigger_requests?: TriggerRequestEmit[];
  deploy_requests?: DeployRequestEmit[];
  oracle_subscription_requests?: OracleSubscriptionEmit[];
  vrf_requests?: VRFRequestEmit[];
  /** Contract state keys that were mutated (for incremental Merkle tracking) */
  flushed_keys?: { contract: string; key: string; deleted: boolean }[];
}

export interface OracleRequestEmit {
  url: string;
  json_path?: string;
  callback_method: string;
  aggregation: AggregationStrategy;
  contract: string; // which contract emitted this
}

export interface TriggerRequestEmit {
  action: "create" | "remove";
  method?: string;
  args_b64?: string;
  interval_ms?: number;
  max_fires?: number;
  trigger_id?: string;
  contract: string; // which contract emitted this
}

export interface DeployRequestEmit {
  wasm_bytes: Uint8Array;
  deployer: string;   // the contract that initiated the deploy
  contract: string;    // same as deployer (for consistency with other emits)
}

export interface OracleSubscriptionEmit {
  action: "subscribe" | "unsubscribe";
  feed_id: string;
  callback_method?: string;
  deviation_bps?: number;
  min_interval_ms?: number;
  subscription_id?: string;  // for unsubscribe
  contract: string;
}

export interface VRFRequestEmit {
  seed: string;
  callback_method: string;
  contract: string;
}

// ─── Execution Context (shared across cross-contract call chain) ──────────────

const MAX_CALL_DEPTH = 10;

interface ExecutionContext {
  // Mutations per contract: address → (keyHex → value | null)
  mutations: Map<string, Map<string, Uint8Array | null>>;
  logs: string[];
  oracleRequests: OracleRequestEmit[];
  triggerRequests: TriggerRequestEmit[];
  deployRequests: DeployRequestEmit[];
  oracleSubscriptionRequests: OracleSubscriptionEmit[];
  vrfRequests: VRFRequestEmit[];
  callStack: string[];   // addresses currently executing (reentrancy detection)
  readOnly: boolean;
  rootCaller: string;    // original external caller (pubkey)
  fuel: FuelTracker;     // deterministic fuel metering
}

function createContext(rootCaller: string, readOnly: boolean): ExecutionContext {
  return {
    mutations: new Map(),
    logs: [],
    oracleRequests: [],
    triggerRequests: [],
    deployRequests: [],
    oracleSubscriptionRequests: [],
    vrfRequests: [],
    callStack: [],
    readOnly,
    rootCaller,
    fuel: new FuelTracker(DEFAULT_FUEL),
  };
}

function getMutations(ctx: ExecutionContext, address: string): Map<string, Uint8Array | null> {
  if (!ctx.mutations.has(address)) {
    ctx.mutations.set(address, new Map());
  }
  return ctx.mutations.get(address)!;
}

// ─── WASM Validation ──────────────────────────────────────────────────────────

const MAX_WASM_SIZE = 1_048_576; // 1MB
const MAX_CONTRACT_STATE_BYTES = 2_097_152; // 2MB per contract — prevents single contract from exhausting DO storage
const WASM_MAGIC = new Uint8Array([0x00, 0x61, 0x73, 0x6d]);
const SECTION_IMPORT = 2;

const FLOAT_OPCODES = new Set([0x43, 0x44]);

function isFloatOpcode(op: number): boolean {
  if (FLOAT_OPCODES.has(op)) return true;
  if (op >= 0x8B && op <= 0x98) return true;
  if (op >= 0x99 && op <= 0xA6) return true;
  if (op >= 0xB2 && op <= 0xBF) return true;
  return false;
}

export function validateWasm(bytes: Uint8Array): { ok: boolean; error?: string } {
  if (bytes.length > MAX_WASM_SIZE) {
    return { ok: false, error: `WASM too large: ${bytes.length} bytes (max ${MAX_WASM_SIZE})` };
  }
  if (bytes.length < 8) {
    return { ok: false, error: "WASM too small to be valid" };
  }
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== WASM_MAGIC[i]) {
      return { ok: false, error: "Invalid WASM magic bytes" };
    }
  }

  try {
    let offset = 8;
    while (offset < bytes.length) {
      const sectionId = bytes[offset++];
      const { value: sectionSize, bytesRead } = readLEB128(bytes, offset);
      offset += bytesRead;
      const sectionEnd = offset + sectionSize;

      if (sectionId === SECTION_IMPORT) {
        const { value: numImports, bytesRead: br } = readLEB128(bytes, offset);
        let pos = offset + br;
        for (let i = 0; i < numImports; i++) {
          const { value: modLen, bytesRead: br1 } = readLEB128(bytes, pos);
          pos += br1;
          const modName = new TextDecoder().decode(bytes.slice(pos, pos + modLen));
          pos += modLen;
          const { value: nameLen, bytesRead: br2 } = readLEB128(bytes, pos);
          pos += br2;
          pos += nameLen;
          const kind = bytes[pos++];
          switch (kind) {
            case 0: pos++; break;
            case 1: pos += 3; break;
            case 2: {
              const hasMax = bytes[pos++];
              const { bytesRead: br3 } = readLEB128(bytes, pos); pos += br3;
              if (hasMax) { const { bytesRead: br4 } = readLEB128(bytes, pos); pos += br4; }
              break;
            }
            case 3: pos += 2; break;
          }
          if (modName === "wasi_snapshot_preview1" || modName === "wasi_unstable") {
            return { ok: false, error: `Banned import module: ${modName}` };
          }
        }
      }

      if (sectionId === 10) {
        for (let pos = offset; pos < sectionEnd; pos++) {
          if (isFloatOpcode(bytes[pos])) {
            return { ok: false, error: `Floating-point opcode 0x${bytes[pos].toString(16)} at offset ${pos}` };
          }
        }
      }
      offset = sectionEnd;
    }
  } catch { /* let WebAssembly.compile() catch it */ }

  return { ok: true };
}

function readLEB128(bytes: Uint8Array, offset: number): { value: number; bytesRead: number } {
  let result = 0, shift = 0, bytesRead = 0, byte: number;
  do {
    byte = bytes[offset + bytesRead];
    result |= (byte & 0x7f) << shift;
    shift += 7;
    bytesRead++;
  } while (byte & 0x80);
  return { value: result, bytesRead };
}

// ─── Contract Executor ────────────────────────────────────────────────────────

// Fuel-based metering replaces timeout-based execution.
// Fuel is cosmetic (no token) but deterministic — all nodes agree on execution bounds.

const MODULE_CACHE_MAX = 64;

export class ContractExecutor {
  // LRU module cache: Map iteration order = insertion order; most-recent at end
  private moduleCache: Map<string, WebAssembly.Module> = new Map();
  private sql: any;
  private blobStore: R2Bucket | null;

  constructor(sql: any, blobStore?: R2Bucket | null) {
    this.sql = sql;
    this.blobStore = blobStore || null;
  }

  /** Touch a cache entry (move to end for LRU), evict oldest if over limit */
  private cacheSet(address: string, module: WebAssembly.Module) {
    if (this.moduleCache.has(address)) this.moduleCache.delete(address);
    this.moduleCache.set(address, module);
    if (this.moduleCache.size > MODULE_CACHE_MAX) {
      // Evict the least recently used (first key in Map)
      const oldest = this.moduleCache.keys().next().value!;
      this.moduleCache.delete(oldest);
    }
  }

  private cacheGet(address: string): WebAssembly.Module | undefined {
    const mod = this.moduleCache.get(address);
    if (mod) {
      // Move to end (most recently used)
      this.moduleCache.delete(address);
      this.moduleCache.set(address, mod);
    }
    return mod;
  }

  // ─── Deploy ───────────────────────────────────────────────────────────

  async deploy(wasmBytes: Uint8Array, deployer: string, seq: number): Promise<string> {
    const validation = validateWasm(wasmBytes);
    if (!validation.ok) throw new Error(validation.error);

    // Inject fuel metering into the WASM binary before compilation.
    // This adds a fuel global import and fuel checks at every function entry.
    const meteredBytes = injectFuelMetering(wasmBytes);

    const module = await WebAssembly.compile(meteredBytes);

    const exports = WebAssembly.Module.exports(module);
    const hasMemory = exports.some(e => e.name === "memory" && e.kind === "memory");
    if (!hasMemory) throw new Error("Contract must export 'memory'");

    const callableExports = exports.filter(e => e.kind === "function" && e.name !== "__data_end" && e.name !== "__heap_base");
    if (callableExports.length === 0) throw new Error("Contract must export at least one function");

    const wasmHash = await sha256(bytesToHex(wasmBytes));
    const address = await sha256(`${deployer}:${wasmHash}:${seq}`);

    // Store WASM bytes in R2 if available, otherwise inline in SQLite
    if (this.blobStore) {
      await this.blobStore.put(`wasm/${wasmHash}`, meteredBytes);
      this.sql.exec(
        `INSERT INTO contracts (address, deployer, wasm_hash, wasm_bytes, created_at, deploy_seq)
         VALUES (?, ?, ?, ?, ?, ?)`,
        address, deployer, wasmHash, new Uint8Array(0), Date.now(), seq,
      );
    } else {
      this.sql.exec(
        `INSERT INTO contracts (address, deployer, wasm_hash, wasm_bytes, created_at, deploy_seq)
         VALUES (?, ?, ?, ?, ?, ?)`,
        address, deployer, wasmHash, meteredBytes, Date.now(), seq,
      );
    }

    this.cacheSet(address, module);
    return address;
  }

  // ─── Upgrade ────────────────────────────────────────────────────────────

  /**
   * Upgrade a contract's WASM code in-place. Only the original deployer can upgrade.
   * The contract address stays the same; state is preserved.
   * If the contract has been locked (upgrade_locked flag), upgrade is permanently rejected.
   */
  async upgrade(address: string, newWasmBytes: Uint8Array, caller: string): Promise<void> {
    // Verify contract exists and caller is the deployer
    const rows = [...this.sql.exec(
      "SELECT deployer, wasm_hash FROM contracts WHERE address = ?", address,
    )];
    if (rows.length === 0) throw new Error("Contract not found");
    const deployer = rows[0].deployer as string;
    if (caller !== deployer) throw new Error("Only the original deployer can upgrade");

    // Check if contract has been locked
    const lockKey = new TextEncoder().encode("__upgrade_locked");
    const lockRows = [...this.sql.exec(
      "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
      address, lockKey,
    )];
    if (lockRows.length > 0) {
      const val = lockRows[0].value;
      const lockVal = val instanceof Uint8Array ? new TextDecoder().decode(val) : String(val);
      if (lockVal === "1") throw new Error("Contract is permanently locked and cannot be upgraded");
    }

    // Validate new WASM
    const validation = validateWasm(newWasmBytes);
    if (!validation.ok) throw new Error(validation.error);

    const meteredBytes = injectFuelMetering(newWasmBytes);
    const module = await WebAssembly.compile(meteredBytes);

    const exports = WebAssembly.Module.exports(module);
    const hasMemory = exports.some(e => e.name === "memory" && e.kind === "memory");
    if (!hasMemory) throw new Error("Contract must export 'memory'");

    const newWasmHash = await sha256(bytesToHex(newWasmBytes));
    const oldWasmHash = rows[0].wasm_hash as string;
    if (newWasmHash === oldWasmHash) throw new Error("New WASM is identical to current");

    // Store new WASM
    if (this.blobStore) {
      await this.blobStore.put(`wasm/${newWasmHash}`, meteredBytes);
      this.sql.exec(
        "UPDATE contracts SET wasm_hash = ?, wasm_bytes = ? WHERE address = ?",
        newWasmHash, new Uint8Array(0), address,
      );
    } else {
      this.sql.exec(
        "UPDATE contracts SET wasm_hash = ?, wasm_bytes = ? WHERE address = ?",
        newWasmHash, meteredBytes, address,
      );
    }

    // Invalidate cache — next call will compile the new module
    this.moduleCache.delete(address);
    this.cacheSet(address, module);
  }

  /**
   * Lock a contract permanently, preventing any future upgrades.
   * Can be called by the deployer or by the contract itself (via host import).
   */
  lockContract(address: string, caller: string): void {
    const rows = [...this.sql.exec(
      "SELECT deployer FROM contracts WHERE address = ?", address,
    )];
    if (rows.length === 0) throw new Error("Contract not found");

    // Allow deployer or the contract itself to lock
    const deployer = rows[0].deployer as string;
    if (caller !== deployer && caller !== address) {
      throw new Error("Only the deployer or the contract itself can lock");
    }

    const lockKey = new TextEncoder().encode("__upgrade_locked");
    const lockVal = new TextEncoder().encode("1");
    this.sql.exec(
      `INSERT INTO contract_state (contract_address, key, value) VALUES (?, ?, ?)
       ON CONFLICT(contract_address, key) DO UPDATE SET value = ?`,
      address, lockKey, lockVal, lockVal,
    );
  }

  /**
   * Check if a contract is upgrade-locked.
   */
  isLocked(address: string): boolean {
    const lockKey = new TextEncoder().encode("__upgrade_locked");
    const rows = [...this.sql.exec(
      "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
      address, lockKey,
    )];
    if (rows.length === 0) return false;
    const val = rows[0].value;
    const lockVal = val instanceof Uint8Array ? new TextDecoder().decode(val) : String(val);
    return lockVal === "1";
  }

  // ─── Public Call Interface ──────────────────────────────────────────────

  async call(
    address: string,
    method: string,
    args: Uint8Array,
    caller: string,
    gas: number = DEFAULT_FUEL,
  ): Promise<CallResult> {
    const ctx = createContext(caller, false);
    ctx.fuel = new FuelTracker(gas);
    const result = await this.executeInContext(ctx, address, method, args, caller);

    // Only flush all mutations if the top-level call succeeded
    let flushed: { contract: string; key: string; deleted: boolean }[] | undefined;
    if (result.ok) {
      flushed = this.flushAllMutations(ctx);
    }

    return {
      ...result,
      logs: ctx.logs,
      oracle_requests: ctx.oracleRequests.length > 0 ? ctx.oracleRequests : undefined,
      trigger_requests: ctx.triggerRequests.length > 0 ? ctx.triggerRequests : undefined,
      deploy_requests: ctx.deployRequests.length > 0 ? ctx.deployRequests : undefined,
      oracle_subscription_requests: ctx.oracleSubscriptionRequests.length > 0 ? ctx.oracleSubscriptionRequests : undefined,
      vrf_requests: ctx.vrfRequests.length > 0 ? ctx.vrfRequests : undefined,
      flushed_keys: flushed && flushed.length > 0 ? flushed : undefined,
    };
  }

  async query(
    address: string,
    method: string,
    args: Uint8Array,
  ): Promise<CallResult> {
    const ctx = createContext("", true);
    ctx.fuel = new FuelTracker(DEFAULT_FUEL);
    const result = await this.executeInContext(ctx, address, method, args, "");
    return { ...result, logs: ctx.logs };
  }

  // ─── Core Execution (supports cross-contract calls) ─────────────────────

  private async executeInContext(
    ctx: ExecutionContext,
    address: string,
    method: string,
    args: Uint8Array,
    caller: string,
  ): Promise<CallResult> {
    // Check fuel
    if (!ctx.fuel.alive) {
      return { ok: false, logs: [], error: "Out of fuel" };
    }

    // Deduct function call overhead
    if (!ctx.fuel.consume(FUEL_COSTS.function_call)) {
      return { ok: false, logs: [], error: "Out of fuel (function call overhead)" };
    }

    // Check call depth
    if (ctx.callStack.length >= MAX_CALL_DEPTH) {
      return { ok: false, logs: [], error: `Max call depth (${MAX_CALL_DEPTH}) exceeded` };
    }

    // Reentrancy check
    if (ctx.callStack.includes(address)) {
      return { ok: false, logs: [], error: `Reentrancy detected: ${address} is already executing` };
    }

    // Get or compile module
    const module = await this.getModule(address);
    if (!module) return { ok: false, logs: [], error: "Contract not found" };

    // Push onto call stack
    ctx.callStack.push(address);

    // Per-invocation state (registers are local to each frame)
    const registers = new Map<number, Uint8Array>();
    const mutations = getMutations(ctx, address);
    let returnReg: number | null = null;
    let trapped = false;
    let trapMessage = "";

    // Set args in register 0
    registers.set(0, args);

    // Fuel global — shared between WASM guest and host
    const fuelGlobal = new WebAssembly.Global({ value: "i32", mutable: true }, ctx.fuel.remaining);

    // Helper: deduct fuel for a host call, trap if exhausted
    const deductFuel = (cost: number): boolean => {
      ctx.fuel.syncFromGlobal(fuelGlobal); // read guest's fuel state
      if (!ctx.fuel.consume(cost)) {
        trapped = true;
        trapMessage = "Out of fuel";
        return false;
      }
      ctx.fuel.syncToGlobal(fuelGlobal); // write back to guest
      return true;
    };

    // Build host imports
    const env: Record<string, Function> = {
      storage_read: (keyReg: number): number => {
        if (!deductFuel(FUEL_COSTS.storage_read)) return 0;
        const keyBytes = registers.get(keyReg);
        if (!keyBytes) return 0;
        const keyHex = bytesToHex(keyBytes);

        // Check mutation buffer first (this contract's)
        if (mutations.has(keyHex)) {
          const val = mutations.get(keyHex);
          if (val === null) return 0;
          registers.set(0, val);
          return 1;
        }

        // Read from DB
        const rows = [...this.sql.exec(
          "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
          address, keyBytes,
        )];
        if (rows.length === 0) return 0;
        const value = rows[0].value;
        registers.set(0, value instanceof Uint8Array ? value : new TextEncoder().encode(String(value)));
        return 1;
      },

      storage_write: (keyReg: number, valReg: number) => {
        if (!deductFuel(FUEL_COSTS.storage_write)) return;
        if (ctx.readOnly) return;
        const keyBytes = registers.get(keyReg);
        const valBytes = registers.get(valReg);
        if (!keyBytes || !valBytes) return;
        mutations.set(bytesToHex(keyBytes), new Uint8Array(valBytes));
      },

      storage_remove: (keyReg: number): number => {
        if (!deductFuel(FUEL_COSTS.storage_remove)) return 0;
        if (ctx.readOnly) return 0;
        const keyBytes = registers.get(keyReg);
        if (!keyBytes) return 0;
        const keyHex = bytesToHex(keyBytes);

        const existed = mutations.has(keyHex)
          ? mutations.get(keyHex) !== null
          : [...this.sql.exec(
              "SELECT 1 FROM contract_state WHERE contract_address = ? AND key = ?",
              address, keyBytes,
            )].length > 0;

        mutations.set(keyHex, null);
        return existed ? 1 : 0;
      },

      register_len: (regId: number): number => {
        deductFuel(FUEL_COSTS.register_len);
        const data = registers.get(regId);
        return data ? data.length : 0;
      },

      read_register: (regId: number, ptr: number) => {
        if (!deductFuel(FUEL_COSTS.read_register)) return;
        const data = registers.get(regId);
        if (!data || !memory) return;
        new Uint8Array(memory.buffer).set(data, ptr);
      },

      write_register: (regId: number, ptr: number, len: number) => {
        if (!deductFuel(FUEL_COSTS.write_register)) return;
        if (!memory) return;
        registers.set(regId, new Uint8Array(new Uint8Array(memory.buffer).slice(ptr, ptr + len)));
      },

      caller: (regId: number) => {
        deductFuel(FUEL_COSTS.caller);
        registers.set(regId, new TextEncoder().encode(caller));
      },

      origin: (regId: number) => {
        deductFuel(FUEL_COSTS.origin);
        registers.set(regId, new TextEncoder().encode(ctx.rootCaller));
      },

      self_address: (regId: number) => {
        deductFuel(FUEL_COSTS.self_address);
        registers.set(regId, new TextEncoder().encode(address));
      },

      log: (ptr: number, len: number) => {
        if (!deductFuel(FUEL_COSTS.log)) return;
        if (!memory) return;
        const msg = new TextDecoder().decode(new Uint8Array(memory.buffer).slice(ptr, ptr + len));
        ctx.logs.push(`[${address.slice(0, 8)}] ${msg}`);
      },

      set_return: (regId: number) => {
        deductFuel(FUEL_COSTS.set_return);
        returnReg = regId;
      },

      abort: (msgPtr: number, msgLen: number, line: number, col: number) => {
        trapped = true;
        if (memory && msgLen > 0) {
          const msg = new TextDecoder().decode(new Uint8Array(memory.buffer).slice(msgPtr, msgPtr + msgLen));
          trapMessage = `${msg} at ${line}:${col}`;
        } else {
          trapMessage = `abort at ${line}:${col}`;
        }
      },

      // ─── Cross-contract call ──────────────────────────────────────────
      // Synchronous cross-contract call. The callee executes within the same
      // execution context (shared mutations, shared call stack).
      //
      // target_reg: register containing target contract address (string)
      // method_reg: register containing method name (string)
      // args_reg: register containing arguments (bytes)
      // Returns: 1 on success (return data in register 0), 0 on failure (error in register 0)
      cross_contract_call: (targetReg: number, methodReg: number, argsReg: number): number => {
        if (!deductFuel(FUEL_COSTS.cross_contract_call)) return 0;
        const targetBytes = registers.get(targetReg);
        const methodBytes = registers.get(methodReg);
        const callArgs = registers.get(argsReg) || new Uint8Array();
        if (!targetBytes || !methodBytes) {
          registers.set(0, new TextEncoder().encode("missing target or method"));
          return 0;
        }

        const targetAddr = new TextDecoder().decode(targetBytes);
        const targetMethod = new TextDecoder().decode(methodBytes);

        try {
          const cachedModule = this.cacheGet(targetAddr);
          if (!cachedModule) {
            registers.set(0, new TextEncoder().encode("contract not found: " + targetAddr));
            return 0;
          }

          // Check depth + reentrancy
          if (ctx.callStack.length >= MAX_CALL_DEPTH) {
            registers.set(0, new TextEncoder().encode("max call depth exceeded"));
            return 0;
          }
          if (ctx.callStack.includes(targetAddr)) {
            registers.set(0, new TextEncoder().encode("reentrancy: " + targetAddr));
            return 0;
          }

          ctx.callStack.push(targetAddr);

          // Create a new register set for the callee
          const calleeRegisters = new Map<number, Uint8Array>();
          calleeRegisters.set(0, callArgs);
          const calleeMutations = getMutations(ctx, targetAddr);
          let calleeReturnReg: number | null = null;
          let calleeTrapped = false;

          // Build callee host imports (recursive — shares ctx + fuel)
          const calleeImports = this.buildHostImports(
            ctx, targetAddr, address,
            calleeRegisters, calleeMutations,
            (reg: number) => { calleeReturnReg = reg; },
            (msg: string) => { calleeTrapped = true; trapMessage = msg; },
          );

          const calleeInstance = new WebAssembly.Instance(cachedModule, calleeImports);
          const calleeFn = calleeInstance.exports[targetMethod];
          if (!calleeFn || typeof calleeFn !== "function") {
            ctx.callStack.pop();
            registers.set(0, new TextEncoder().encode("method not found: " + targetMethod));
            return 0;
          }

          (calleeFn as Function)();
          ctx.callStack.pop();

          if (calleeTrapped) {
            // Rollback callee mutations
            calleeMutations.clear();
            registers.set(0, new TextEncoder().encode("callee trapped"));
            return 0;
          }

          // Copy return data to caller's register 0
          if (calleeReturnReg !== null) {
            const retData = calleeRegisters.get(calleeReturnReg);
            if (retData) registers.set(0, retData);
          } else {
            registers.set(0, new Uint8Array());
          }

          return 1;
        } catch (e: any) {
          // Pop if we pushed
          if (ctx.callStack[ctx.callStack.length - 1] === targetAddr) {
            ctx.callStack.pop();
          }
          registers.set(0, new TextEncoder().encode(e.message || "cross-call failed"));
          return 0;
        }
      },

      oracle_request: (urlReg: number, callbackReg: number, aggregationReg: number, jsonPathReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_request)) return;
        if (ctx.readOnly) return;
        const urlBytes = registers.get(urlReg);
        const callbackBytes = registers.get(callbackReg);
        const aggBytes = registers.get(aggregationReg);
        if (!urlBytes || !callbackBytes || !aggBytes) return;

        const url = new TextDecoder().decode(urlBytes);
        const callbackMethod = new TextDecoder().decode(callbackBytes);
        const aggregation = new TextDecoder().decode(aggBytes) as AggregationStrategy;
        const jsonPathBytes = registers.get(jsonPathReg);
        const jsonPath = jsonPathBytes && jsonPathBytes.length > 0
          ? new TextDecoder().decode(jsonPathBytes) : undefined;

        ctx.oracleRequests.push({ url, callback_method: callbackMethod, aggregation, json_path: jsonPath, contract: address });
      },

      // ─── Oracle Network (PON) host imports ────────────────────────────

      oracle_read_feed: (feedIdReg: number, resultReg: number): number => {
        if (!deductFuel(FUEL_COSTS.oracle_read_feed)) return 0;
        const feedIdBytes = registers.get(feedIdReg);
        if (!feedIdBytes) return 0;
        const feedId = new TextDecoder().decode(feedIdBytes);

        // Read from oracle_feed_latest table (denormalized, O(1))
        const rows = [...this.sql.exec(
          "SELECT * FROM oracle_feed_latest WHERE feed_id = ?", feedId,
        )] as any[];

        if (rows.length === 0) {
          registers.set(resultReg, new TextEncoder().encode("null"));
          return 0;
        }

        const r = rows[0];
        const now = Date.now();
        const result = JSON.stringify({
          feed_id: r.feed_id,
          value: r.value,
          value_num: r.value_num,
          round: r.round,
          observers: r.observers,
          committed_at: r.committed_at,
          stale: now > r.stale_at,
        });
        registers.set(resultReg, new TextEncoder().encode(result));
        return 1;
      },

      oracle_subscribe: (feedIdReg: number, callbackReg: number, deviationReg: number, intervalReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_subscribe)) return;
        if (ctx.readOnly) return;
        const feedIdBytes = registers.get(feedIdReg);
        const callbackBytes = registers.get(callbackReg);
        if (!feedIdBytes || !callbackBytes) return;

        const feedId = new TextDecoder().decode(feedIdBytes);
        const callbackMethod = new TextDecoder().decode(callbackBytes);
        const deviationBytes = registers.get(deviationReg);
        const intervalBytes = registers.get(intervalReg);
        const deviationBps = deviationBytes ? parseInt(new TextDecoder().decode(deviationBytes)) || 0 : 0;
        const minIntervalMs = intervalBytes ? parseInt(new TextDecoder().decode(intervalBytes)) || 0 : 0;

        ctx.oracleSubscriptionRequests.push({
          action: "subscribe",
          feed_id: feedId,
          callback_method: callbackMethod,
          deviation_bps: deviationBps,
          min_interval_ms: minIntervalMs,
          contract: address,
        });
      },

      oracle_unsubscribe: (subIdReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_unsubscribe)) return;
        if (ctx.readOnly) return;
        const subIdBytes = registers.get(subIdReg);
        if (!subIdBytes) return;
        const subId = new TextDecoder().decode(subIdBytes);
        ctx.oracleSubscriptionRequests.push({
          action: "unsubscribe",
          feed_id: "",
          subscription_id: subId,
          contract: address,
        });
      },

      oracle_request_random: (seedReg: number, callbackReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_request_random)) return;
        if (ctx.readOnly) return;
        const seedBytes = registers.get(seedReg);
        const callbackBytes = registers.get(callbackReg);
        if (!seedBytes || !callbackBytes) return;
        const seed = new TextDecoder().decode(seedBytes);
        const callbackMethod = new TextDecoder().decode(callbackBytes);
        ctx.vrfRequests.push({ seed, callback_method: callbackMethod, contract: address });
      },

      trigger_manage: (actionReg: number, dataReg: number) => {
        if (!deductFuel(FUEL_COSTS.trigger_manage)) return;
        if (ctx.readOnly) return;
        const actionBytes = registers.get(actionReg);
        const dataBytes = registers.get(dataReg);
        if (!actionBytes || !dataBytes) return;

        const action = new TextDecoder().decode(actionBytes) as "create" | "remove";
        try {
          const data = JSON.parse(new TextDecoder().decode(dataBytes));
          ctx.triggerRequests.push({ action, ...data, contract: address });
        } catch { /* invalid JSON, ignore */ }
      },

      // ─── Programmatic contract deployment ──────────────────────────────
      // Allows a contract to deploy a new contract from WASM bytes.
      // wasm_reg: register containing raw WASM binary
      // Returns: 1 on success (new contract address in register 0), 0 on failure (error in register 0)
      deploy_contract: (wasmReg: number): number => {
        if (!deductFuel(FUEL_COSTS.deploy_contract)) return 0;
        if (ctx.readOnly) {
          registers.set(0, new TextEncoder().encode("deploy not allowed in read-only mode"));
          return 0;
        }
        const wasmBytes = registers.get(wasmReg);
        if (!wasmBytes) {
          registers.set(0, new TextEncoder().encode("missing wasm bytes in register"));
          return 0;
        }
        // Validate synchronously — actual deploy is deferred to post-execution
        const validation = validateWasm(wasmBytes);
        if (!validation.ok) {
          registers.set(0, new TextEncoder().encode(validation.error || "invalid wasm"));
          return 0;
        }
        // Compute deterministic address: SHA256(deployer_contract + wasm_hash + deploy_count)
        const wasmHash = sha256Sync(wasmBytes);
        const deployIndex = ctx.deployRequests.length;
        const childAddress = sha256Sync(`${address}:${wasmHash}:${deployIndex}`);
        // Queue the deploy for post-execution processing
        ctx.deployRequests.push({
          wasm_bytes: new Uint8Array(wasmBytes),
          deployer: address,
          contract: address,
        });
        // Return the deterministic address to the caller
        registers.set(0, new TextEncoder().encode(childAddress));
        return 1;
      },

      gas_left: (): number => {
        deductFuel(FUEL_COSTS.gas_left);
        ctx.fuel.syncFromGlobal(fuelGlobal);
        return ctx.fuel.remaining;
      },

      // ─── Upgrade Lock ──────────────────────────────────────────────────
      // Permanently locks the calling contract, preventing future upgrades.
      // This is irreversible — once locked, even the deployer cannot upgrade.
      lock_contract: () => {
        if (!deductFuel(FUEL_COSTS.storage_write)) return;
        if (ctx.readOnly) return;
        // Write the lock flag into mutations so it commits atomically
        const lockKeyHex = bytesToHex(new TextEncoder().encode("__upgrade_locked"));
        mutations.set(lockKeyHex, new TextEncoder().encode("1"));
        ctx.logs.push(`[${address.slice(0, 8)}] contract permanently locked`);
      },

      // ─── ZK-Friendly Cryptographic Primitives (Miden-inspired) ─────────
      poseidon2_hash: (inputReg: number, outputReg: number) => {
        if (!deductFuel(FUEL_COSTS.storage_read)) return;
        const inputBytes = registers.get(inputReg);
        if (!inputBytes) return;
        const hashHex = sha256Sync(inputBytes);
        registers.set(outputReg, hexToBytes(hashHex));
      },
      merkle_get: (keyReg: number): number => {
        if (!deductFuel(FUEL_COSTS.storage_read)) return 0;
        const keyBytes = registers.get(keyReg);
        if (!keyBytes) return 0;
        const keyHex = bytesToHex(keyBytes);
        if (mutations.has(keyHex)) {
          const val = mutations.get(keyHex);
          if (val === null) return 0;
          registers.set(0, val);
          return 1;
        }
        const rows = [...this.sql.exec(
          "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
          address, keyBytes,
        )];
        if (rows.length === 0) return 0;
        const value = rows[0].value;
        registers.set(0, value instanceof Uint8Array ? value : new TextEncoder().encode(String(value)));
        return 1;
      },
      merkle_set: (keyReg: number, valReg: number) => {
        if (!deductFuel(FUEL_COSTS.storage_write)) return;
        if (ctx.readOnly) return;
        const keyBytes = registers.get(keyReg);
        const valBytes = registers.get(valReg);
        if (!keyBytes || !valBytes) return;
        mutations.set(bytesToHex(keyBytes), new Uint8Array(valBytes));
      },
      merkle_verify: (rootReg: number, leafReg: number, proofReg: number, dirReg: number): number => {
        if (!deductFuel(FUEL_COSTS.storage_read * 2)) return 0;
        const root = registers.get(rootReg);
        const leaf = registers.get(leafReg);
        const proofBytes = registers.get(proofReg);
        const dirBytes = registers.get(dirReg);
        if (!root || !leaf || !proofBytes || !dirBytes) return 0;
        if (root.length !== 32 || leaf.length !== 32) return 0;
        if (proofBytes.length % 32 !== 0) return 0;
        const levels = proofBytes.length / 32;
        if (dirBytes.length < levels) return 0;
        let current = bytesToHex(leaf);
        for (let i = 0; i < levels; i++) {
          const sibling = bytesToHex(proofBytes.slice(i * 32, (i + 1) * 32));
          current = sha256Sync(new TextEncoder().encode(
            dirBytes[i] === 0 ? current + sibling : sibling + current,
          ));
        }
        return current === bytesToHex(root) ? 1 : 0;
      },
    };

    // Instantiate with fuel global
    let instance: WebAssembly.Instance;
    let memory: WebAssembly.Memory;
    try {
      instance = await WebAssembly.instantiate(module, {
        env,
        metering: { fuel: fuelGlobal },
      });
      memory = instance.exports.memory as WebAssembly.Memory;
    } catch (e: any) {
      ctx.callStack.pop();
      return { ok: false, logs: [], error: `Instantiation failed: ${e.message}` };
    }

    // Find and call the method
    const fn = instance.exports[method];
    if (!fn || typeof fn !== "function") {
      ctx.callStack.pop();
      return { ok: false, logs: [], error: `Method '${method}' not found or not callable` };
    }

    // Execute — fuel metering handles termination deterministically.
    // The WASM binary has fuel checks injected at every function entry.
    // When fuel hits zero, the guest executes `unreachable` which traps.
    try {
      (fn as Function)();

      // Sync fuel state after execution
      ctx.fuel.syncFromGlobal(fuelGlobal);

      if (trapped) {
        ctx.callStack.pop();
        mutations.clear();
        return { ok: false, logs: [], error: `Contract trapped: ${trapMessage}` };
      }
    } catch (e: any) {
      ctx.callStack.pop();
      ctx.fuel.syncFromGlobal(fuelGlobal);
      mutations.clear();
      // Distinguish fuel exhaustion from other traps
      const msg = (trapped && trapMessage === "Out of fuel") || !ctx.fuel.alive
        ? `Out of fuel (used ${ctx.fuel.consumed} of ${ctx.fuel.initial})`
        : e.message;
      return { ok: false, logs: [], error: msg };
    }

    ctx.callStack.pop();

    const returnData = returnReg !== null ? registers.get(returnReg) : undefined;
    return { ok: true, return_data: returnData, logs: [] };
  }

  // ─── Build Host Imports (for sync cross-contract calls) ──────────────

  private buildHostImports(
    ctx: ExecutionContext,
    address: string,
    callerAddr: string,
    registers: Map<number, Uint8Array>,
    mutations: Map<string, Uint8Array | null>,
    onSetReturn: (reg: number) => void,
    onTrap: (msg: string) => void,
  ): { env: Record<string, Function>; metering: Record<string, WebAssembly.Global> } {
    let memory: WebAssembly.Memory | null = null;

    // Share the parent's fuel global for cross-contract calls
    const fuelGlobal = new WebAssembly.Global({ value: "i32", mutable: true }, ctx.fuel.remaining);
    const deductFuel = (cost: number): boolean => {
      ctx.fuel.syncFromGlobal(fuelGlobal);
      if (!ctx.fuel.consume(cost)) {
        onTrap("Out of fuel");
        return false;
      }
      ctx.fuel.syncToGlobal(fuelGlobal);
      return true;
    };

    const env: Record<string, Function> = {
      storage_read: (keyReg: number): number => {
        if (!deductFuel(FUEL_COSTS.storage_read)) return 0;
        const keyBytes = registers.get(keyReg);
        if (!keyBytes) return 0;
        const keyHex = bytesToHex(keyBytes);
        if (mutations.has(keyHex)) {
          const val = mutations.get(keyHex);
          if (val === null) return 0;
          registers.set(0, val);
          return 1;
        }
        const rows = [...this.sql.exec(
          "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
          address, keyBytes,
        )];
        if (rows.length === 0) return 0;
        const value = rows[0].value;
        registers.set(0, value instanceof Uint8Array ? value : new TextEncoder().encode(String(value)));
        return 1;
      },

      storage_write: (keyReg: number, valReg: number) => {
        if (!deductFuel(FUEL_COSTS.storage_write)) return;
        if (ctx.readOnly) return;
        const keyBytes = registers.get(keyReg);
        const valBytes = registers.get(valReg);
        if (!keyBytes || !valBytes) return;
        mutations.set(bytesToHex(keyBytes), new Uint8Array(valBytes));
      },

      storage_remove: (keyReg: number): number => {
        if (!deductFuel(FUEL_COSTS.storage_remove)) return 0;
        if (ctx.readOnly) return 0;
        const keyBytes = registers.get(keyReg);
        if (!keyBytes) return 0;
        const keyHex = bytesToHex(keyBytes);
        const existed = mutations.has(keyHex)
          ? mutations.get(keyHex) !== null
          : [...this.sql.exec("SELECT 1 FROM contract_state WHERE contract_address = ? AND key = ?", address, keyBytes)].length > 0;
        mutations.set(keyHex, null);
        return existed ? 1 : 0;
      },

      register_len: (regId: number): number => { deductFuel(FUEL_COSTS.register_len); return registers.get(regId)?.length ?? 0; },

      read_register: (regId: number, ptr: number) => {
        if (!deductFuel(FUEL_COSTS.read_register)) return;
        const data = registers.get(regId);
        if (!data || !memory) return;
        new Uint8Array(memory.buffer).set(data, ptr);
      },

      write_register: (regId: number, ptr: number, len: number) => {
        if (!deductFuel(FUEL_COSTS.write_register)) return;
        if (!memory) return;
        registers.set(regId, new Uint8Array(new Uint8Array(memory.buffer).slice(ptr, ptr + len)));
      },

      caller: (regId: number) => {
        deductFuel(FUEL_COSTS.caller);
        registers.set(regId, new TextEncoder().encode(callerAddr));
      },

      origin: (regId: number) => {
        deductFuel(FUEL_COSTS.origin);
        registers.set(regId, new TextEncoder().encode(ctx.rootCaller));
      },

      self_address: (regId: number) => {
        deductFuel(FUEL_COSTS.self_address);
        registers.set(regId, new TextEncoder().encode(address));
      },

      log: (ptr: number, len: number) => {
        if (!deductFuel(FUEL_COSTS.log)) return;
        if (!memory) return;
        const msg = new TextDecoder().decode(new Uint8Array(memory.buffer).slice(ptr, ptr + len));
        ctx.logs.push(`[${address.slice(0, 8)}] ${msg}`);
      },

      set_return: (regId: number) => { deductFuel(FUEL_COSTS.set_return); onSetReturn(regId); },

      abort: (msgPtr: number, msgLen: number, line: number, col: number) => {
        if (memory && msgLen > 0) {
          const msg = new TextDecoder().decode(new Uint8Array(memory.buffer).slice(msgPtr, msgPtr + msgLen));
          onTrap(`${msg} at ${line}:${col}`);
        } else {
          onTrap(`abort at ${line}:${col}`);
        }
      },

      // Cross-contract call within sync context (same pattern as parent)
      cross_contract_call: (targetReg: number, methodReg: number, argsReg: number): number => {
        if (!deductFuel(FUEL_COSTS.cross_contract_call)) return 0;
        const targetBytes = registers.get(targetReg);
        const methodBytes = registers.get(methodReg);
        const callArgs = registers.get(argsReg) || new Uint8Array();
        if (!targetBytes || !methodBytes) {
          registers.set(0, new TextEncoder().encode("missing target or method"));
          return 0;
        }

        const targetAddr = new TextDecoder().decode(targetBytes);
        const targetMethod = new TextDecoder().decode(methodBytes);

        try {
          const cachedModule = this.cacheGet(targetAddr);
          if (!cachedModule) {
            registers.set(0, new TextEncoder().encode("contract not found"));
            return 0;
          }
          if (ctx.callStack.length >= MAX_CALL_DEPTH) {
            registers.set(0, new TextEncoder().encode("max call depth exceeded"));
            return 0;
          }
          if (ctx.callStack.includes(targetAddr)) {
            registers.set(0, new TextEncoder().encode("reentrancy: " + targetAddr));
            return 0;
          }

          ctx.callStack.push(targetAddr);

          const calleeRegisters = new Map<number, Uint8Array>();
          calleeRegisters.set(0, callArgs);
          const calleeMutations = getMutations(ctx, targetAddr);
          let calleeReturnReg: number | null = null;
          let calleeTrapped = false;

          const calleeImports = this.buildHostImports(
            ctx, targetAddr, address,
            calleeRegisters, calleeMutations,
            (reg) => { calleeReturnReg = reg; },
            () => { calleeTrapped = true; },
          );

          const inst = new WebAssembly.Instance(cachedModule, calleeImports);
          const fn = inst.exports[targetMethod];
          if (!fn || typeof fn !== "function") {
            ctx.callStack.pop();
            registers.set(0, new TextEncoder().encode("method not found"));
            return 0;
          }

          (fn as Function)();
          ctx.callStack.pop();

          if (calleeTrapped) {
            calleeMutations.clear();
            registers.set(0, new TextEncoder().encode("callee trapped"));
            return 0;
          }

          if (calleeReturnReg !== null) {
            const retData = calleeRegisters.get(calleeReturnReg);
            if (retData) registers.set(0, retData);
          } else {
            registers.set(0, new Uint8Array());
          }
          return 1;
        } catch (e: any) {
          if (ctx.callStack[ctx.callStack.length - 1] === targetAddr) ctx.callStack.pop();
          registers.set(0, new TextEncoder().encode(e.message || "cross-call failed"));
          return 0;
        }
      },

      oracle_request: (urlReg: number, callbackReg: number, aggregationReg: number, jsonPathReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_request)) return;
        if (ctx.readOnly) return;
        const urlBytes = registers.get(urlReg);
        const callbackBytes = registers.get(callbackReg);
        const aggBytes = registers.get(aggregationReg);
        if (!urlBytes || !callbackBytes || !aggBytes) return;
        ctx.oracleRequests.push({
          url: new TextDecoder().decode(urlBytes),
          callback_method: new TextDecoder().decode(callbackBytes),
          aggregation: new TextDecoder().decode(aggBytes) as AggregationStrategy,
          json_path: registers.get(jsonPathReg)?.length ? new TextDecoder().decode(registers.get(jsonPathReg)) : undefined,
          contract: address,
        });
      },

      oracle_read_feed: (feedIdReg: number, resultReg: number): number => {
        if (!deductFuel(FUEL_COSTS.oracle_read_feed)) return 0;
        const feedIdBytes = registers.get(feedIdReg);
        if (!feedIdBytes) return 0;
        const feedId = new TextDecoder().decode(feedIdBytes);
        const rows = [...this.sql.exec("SELECT * FROM oracle_feed_latest WHERE feed_id = ?", feedId)] as any[];
        if (rows.length === 0) { registers.set(resultReg, new TextEncoder().encode("null")); return 0; }
        const r = rows[0];
        registers.set(resultReg, new TextEncoder().encode(JSON.stringify({
          feed_id: r.feed_id, value: r.value, value_num: r.value_num, round: r.round,
          observers: r.observers, committed_at: r.committed_at, stale: Date.now() > r.stale_at,
        })));
        return 1;
      },

      oracle_subscribe: (feedIdReg: number, callbackReg: number, deviationReg: number, intervalReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_subscribe)) return;
        if (ctx.readOnly) return;
        const feedIdBytes = registers.get(feedIdReg);
        const callbackBytes = registers.get(callbackReg);
        if (!feedIdBytes || !callbackBytes) return;
        const deviationBytes = registers.get(deviationReg);
        const intervalBytes = registers.get(intervalReg);
        ctx.oracleSubscriptionRequests.push({
          action: "subscribe", feed_id: new TextDecoder().decode(feedIdBytes),
          callback_method: new TextDecoder().decode(callbackBytes),
          deviation_bps: deviationBytes ? parseInt(new TextDecoder().decode(deviationBytes)) || 0 : 0,
          min_interval_ms: intervalBytes ? parseInt(new TextDecoder().decode(intervalBytes)) || 0 : 0,
          contract: address,
        });
      },

      oracle_unsubscribe: (subIdReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_unsubscribe)) return;
        if (ctx.readOnly) return;
        const subIdBytes = registers.get(subIdReg);
        if (!subIdBytes) return;
        ctx.oracleSubscriptionRequests.push({
          action: "unsubscribe", feed_id: "", subscription_id: new TextDecoder().decode(subIdBytes), contract: address,
        });
      },

      oracle_request_random: (seedReg: number, callbackReg: number) => {
        if (!deductFuel(FUEL_COSTS.oracle_request_random)) return;
        if (ctx.readOnly) return;
        const seedBytes = registers.get(seedReg);
        const callbackBytes = registers.get(callbackReg);
        if (!seedBytes || !callbackBytes) return;
        ctx.vrfRequests.push({
          seed: new TextDecoder().decode(seedBytes),
          callback_method: new TextDecoder().decode(callbackBytes),
          contract: address,
        });
      },

      trigger_manage: (actionReg: number, dataReg: number) => {
        if (!deductFuel(FUEL_COSTS.trigger_manage)) return;
        if (ctx.readOnly) return;
        const actionBytes = registers.get(actionReg);
        const dataBytes = registers.get(dataReg);
        if (!actionBytes || !dataBytes) return;
        try {
          const data = JSON.parse(new TextDecoder().decode(dataBytes));
          ctx.triggerRequests.push({ action: new TextDecoder().decode(actionBytes) as "create" | "remove", ...data, contract: address });
        } catch { }
      },

      deploy_contract: (wasmReg: number): number => {
        if (!deductFuel(FUEL_COSTS.deploy_contract)) return 0;
        if (ctx.readOnly) {
          registers.set(0, new TextEncoder().encode("deploy not allowed in read-only mode"));
          return 0;
        }
        const wasmBytes = registers.get(wasmReg);
        if (!wasmBytes) {
          registers.set(0, new TextEncoder().encode("missing wasm bytes in register"));
          return 0;
        }
        const validation = validateWasm(wasmBytes);
        if (!validation.ok) {
          registers.set(0, new TextEncoder().encode(validation.error || "invalid wasm"));
          return 0;
        }
        const wasmHash = sha256Sync(wasmBytes);
        const deployIndex = ctx.deployRequests.length;
        const childAddress = sha256Sync(`${address}:${wasmHash}:${deployIndex}`);
        ctx.deployRequests.push({
          wasm_bytes: new Uint8Array(wasmBytes),
          deployer: address,
          contract: address,
        });
        registers.set(0, new TextEncoder().encode(childAddress));
        return 1;
      },

      gas_left: (): number => {
        deductFuel(FUEL_COSTS.gas_left);
        ctx.fuel.syncFromGlobal(fuelGlobal);
        return ctx.fuel.remaining;
      },

      lock_contract: () => {
        if (!deductFuel(FUEL_COSTS.storage_write)) return;
        if (ctx.readOnly) return;
        const lockKeyHex = bytesToHex(new TextEncoder().encode("__upgrade_locked"));
        mutations.set(lockKeyHex, new TextEncoder().encode("1"));
        ctx.logs.push(`[${address.slice(0, 8)}] contract permanently locked`);
      },
    };

    return { env, metering: { fuel: fuelGlobal } };
  }

  // ─── Pre-cache modules for cross-contract calls ──────────────────────

  async ensureModuleCached(address: string): Promise<boolean> {
    if (this.cacheGet(address)) return true;
    return (await this.getModule(address)) !== null;
  }

  // ─── Module Cache ─────────────────────────────────────────────────────

  private async getModule(address: string): Promise<WebAssembly.Module | null> {
    const cached = this.cacheGet(address);
    if (cached) return cached;

    const rows = [...this.sql.exec("SELECT wasm_hash, wasm_bytes FROM contracts WHERE address = ?", address)];
    if (rows.length === 0) return null;

    let wasmBytes = rows[0].wasm_bytes as Uint8Array;

    // If wasm_bytes is empty (stored in R2), fetch from R2
    if (this.blobStore && (!wasmBytes || wasmBytes.length === 0)) {
      const obj = await this.blobStore.get(`wasm/${rows[0].wasm_hash}`);
      if (!obj) return null;
      wasmBytes = new Uint8Array(await obj.arrayBuffer());
    }

    const module = await WebAssembly.compile(wasmBytes);
    this.cacheSet(address, module);
    return module;
  }

  // ─── Flush All Mutations (atomic commit across all contracts in chain) ──

  private flushAllMutations(ctx: ExecutionContext): { contract: string; key: string; deleted: boolean }[] {
    const flushed: { contract: string; key: string; deleted: boolean }[] = [];
    for (const [contractAddr, mutations] of ctx.mutations) {
      // Enforce per-contract storage quota before writing
      const sizeRows = [...this.sql.exec(
        "SELECT SUM(LENGTH(key) + LENGTH(value)) as total FROM contract_state WHERE contract_address = ?",
        contractAddr,
      )] as any[];
      let currentSize = (sizeRows[0]?.total ?? 0) as number;

      for (const [keyHex, value] of mutations) {
        const keyBytes = hexToBytes(keyHex);
        if (value === null) {
          this.sql.exec(
            "DELETE FROM contract_state WHERE contract_address = ? AND key = ?",
            contractAddr, keyBytes,
          );
          flushed.push({ contract: contractAddr, key: keyHex, deleted: true });
        } else {
          const writeSize = keyBytes.length + value.length;
          if (currentSize + writeSize > MAX_CONTRACT_STATE_BYTES) {
            throw new Error(`Contract ${contractAddr} exceeded storage quota (${MAX_CONTRACT_STATE_BYTES} bytes)`);
          }
          this.sql.exec(
            `INSERT INTO contract_state (contract_address, key, value) VALUES (?, ?, ?)
             ON CONFLICT(contract_address, key) DO UPDATE SET value = ?`,
            contractAddr, keyBytes, value, value,
          );
          currentSize += writeSize;
          flushed.push({ contract: contractAddr, key: keyHex, deleted: false });
        }
      }
    }
    return flushed;
  }

  // ─── Info ─────────────────────────────────────────────────────────────

  getContractInfo(address: string): ContractInfo | null {
    const rows = [...this.sql.exec(
      "SELECT address, deployer, wasm_hash, created_at, deploy_seq FROM contracts WHERE address = ?",
      address,
    )];
    if (rows.length === 0) return null;
    const r = rows[0] as any;
    return {
      address: r.address, deployer: r.deployer, wasm_hash: r.wasm_hash,
      created_at: r.created_at, deploy_seq: r.deploy_seq,
      locked: this.isLocked(address),
    };
  }
}
