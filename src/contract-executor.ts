// ─── WASM Smart Contract Runtime ──────────────────────────────────────────────
// NEAR-style register-based ABI with mutation buffering, cross-contract calls,
// and deterministic execution.

import { sha256 } from "./consensus";
import type { AggregationStrategy } from "./oracle";

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
}

export interface CallResult {
  ok: boolean;
  return_data?: Uint8Array;
  logs: string[];
  error?: string;
  oracle_requests?: OracleRequestEmit[];
  trigger_requests?: TriggerRequestEmit[];
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

// ─── Execution Context (shared across cross-contract call chain) ──────────────

const MAX_CALL_DEPTH = 10;

interface ExecutionContext {
  // Mutations per contract: address → (keyHex → value | null)
  mutations: Map<string, Map<string, Uint8Array | null>>;
  logs: string[];
  oracleRequests: OracleRequestEmit[];
  triggerRequests: TriggerRequestEmit[];
  callStack: string[];   // addresses currently executing (reentrancy detection)
  readOnly: boolean;
  rootCaller: string;    // original external caller (pubkey)
}

function createContext(rootCaller: string, readOnly: boolean): ExecutionContext {
  return {
    mutations: new Map(),
    logs: [],
    oracleRequests: [],
    triggerRequests: [],
    callStack: [],
    readOnly,
    rootCaller,
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

const CALL_TIMEOUT_MS = 5_000;
const DEFAULT_GAS = 1_000_000;

export class ContractExecutor {
  private moduleCache: Map<string, WebAssembly.Module> = new Map();
  private sql: any;

  constructor(sql: any) {
    this.sql = sql;
  }

  // ─── Deploy ───────────────────────────────────────────────────────────

  async deploy(wasmBytes: Uint8Array, deployer: string, seq: number): Promise<string> {
    const validation = validateWasm(wasmBytes);
    if (!validation.ok) throw new Error(validation.error);

    const module = await WebAssembly.compile(wasmBytes);

    const exports = WebAssembly.Module.exports(module);
    const hasMemory = exports.some(e => e.name === "memory" && e.kind === "memory");
    if (!hasMemory) throw new Error("Contract must export 'memory'");

    const callableExports = exports.filter(e => e.kind === "function" && e.name !== "__data_end" && e.name !== "__heap_base");
    if (callableExports.length === 0) throw new Error("Contract must export at least one function");

    const wasmHash = await sha256(bytesToHex(wasmBytes));
    const address = await sha256(`${deployer}:${wasmHash}:${seq}`);

    this.sql.exec(
      `INSERT INTO contracts (address, deployer, wasm_hash, wasm_bytes, created_at, deploy_seq)
       VALUES (?, ?, ?, ?, ?, ?)`,
      address, deployer, wasmHash, wasmBytes, Date.now(), seq,
    );

    this.moduleCache.set(address, module);
    return address;
  }

  // ─── Public Call Interface ──────────────────────────────────────────────

  async call(
    address: string,
    method: string,
    args: Uint8Array,
    caller: string,
    gas: number = DEFAULT_GAS,
  ): Promise<CallResult> {
    const ctx = createContext(caller, false);
    const result = await this.executeInContext(ctx, address, method, args, caller, gas);

    // Only flush all mutations if the top-level call succeeded
    if (result.ok) {
      this.flushAllMutations(ctx);
    }

    return {
      ...result,
      logs: ctx.logs,
      oracle_requests: ctx.oracleRequests.length > 0 ? ctx.oracleRequests : undefined,
      trigger_requests: ctx.triggerRequests.length > 0 ? ctx.triggerRequests : undefined,
    };
  }

  async query(
    address: string,
    method: string,
    args: Uint8Array,
  ): Promise<CallResult> {
    const ctx = createContext("", true);
    const result = await this.executeInContext(ctx, address, method, args, "", 0);
    return { ...result, logs: ctx.logs };
  }

  // ─── Core Execution (supports cross-contract calls) ─────────────────────

  private async executeInContext(
    ctx: ExecutionContext,
    address: string,
    method: string,
    args: Uint8Array,
    caller: string,
    gas: number,
  ): Promise<CallResult> {
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

    // Build host imports
    const env: Record<string, Function> = {
      storage_read: (keyReg: number): number => {
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
        if (ctx.readOnly) return;
        const keyBytes = registers.get(keyReg);
        const valBytes = registers.get(valReg);
        if (!keyBytes || !valBytes) return;
        mutations.set(bytesToHex(keyBytes), new Uint8Array(valBytes));
      },

      storage_remove: (keyReg: number): number => {
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
        const data = registers.get(regId);
        return data ? data.length : 0;
      },

      read_register: (regId: number, ptr: number) => {
        const data = registers.get(regId);
        if (!data || !memory) return;
        new Uint8Array(memory.buffer).set(data, ptr);
      },

      write_register: (regId: number, ptr: number, len: number) => {
        if (!memory) return;
        registers.set(regId, new Uint8Array(new Uint8Array(memory.buffer).slice(ptr, ptr + len)));
      },

      caller: (regId: number) => {
        registers.set(regId, new TextEncoder().encode(caller));
      },

      // Return the original external caller (the user pubkey), not the immediate caller
      origin: (regId: number) => {
        registers.set(regId, new TextEncoder().encode(ctx.rootCaller));
      },

      // Return the current contract's own address
      self_address: (regId: number) => {
        registers.set(regId, new TextEncoder().encode(address));
      },

      log: (ptr: number, len: number) => {
        if (!memory) return;
        const msg = new TextDecoder().decode(new Uint8Array(memory.buffer).slice(ptr, ptr + len));
        ctx.logs.push(`[${address.slice(0, 8)}] ${msg}`);
      },

      set_return: (regId: number) => {
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
        const targetBytes = registers.get(targetReg);
        const methodBytes = registers.get(methodReg);
        const callArgs = registers.get(argsReg) || new Uint8Array();
        if (!targetBytes || !methodBytes) {
          registers.set(0, new TextEncoder().encode("missing target or method"));
          return 0;
        }

        const targetAddr = new TextDecoder().decode(targetBytes);
        const targetMethod = new TextDecoder().decode(methodBytes);

        // We can't do async inside a sync WASM call, so we use a synchronous
        // trampoline pattern: buffer the cross-call request and return a promise
        // marker. However, WASM is synchronous, so we need a different approach.
        //
        // The solution: we pre-compile and cache all modules, and since
        // WebAssembly.instantiate can be sync when the module is already compiled,
        // we can do synchronous cross-contract calls IF we use the sync Module API.
        //
        // For now, we buffer the request and the caller must handle it.
        // In V8/CF Workers, we can't do sync cross-calls from within WASM.
        // Instead, we use a "promise-based trampoline" pattern:

        // Actually, since CF Workers WASM host functions must be synchronous,
        // and cross-contract calls need async module loading, we use a
        // pre-loaded module approach: all modules in the call are pre-cached.
        // The cross_contract_call itself executes synchronously using
        // new WebAssembly.Instance() (sync constructor) with the cached module.

        try {
          const cachedModule = this.moduleCache.get(targetAddr);
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

          // Build callee host imports (recursive — shares ctx)
          const calleeEnv = this.buildHostImports(
            ctx, targetAddr, address, // caller of this sub-call is the current contract
            calleeRegisters, calleeMutations,
            (reg: number) => { calleeReturnReg = reg; },
            (msg: string) => { calleeTrapped = true; trapMessage = msg; },
          );

          const calleeInstance = new WebAssembly.Instance(cachedModule, { env: calleeEnv });
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

      trigger_manage: (actionReg: number, dataReg: number) => {
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

      gas_left: (): number => gas,
    };

    // Instantiate
    let instance: WebAssembly.Instance;
    let memory: WebAssembly.Memory;
    try {
      instance = await WebAssembly.instantiate(module, { env });
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

    // Execute with timeout
    try {
      await Promise.race([
        Promise.resolve().then(() => (fn as Function)()),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Execution timeout (gas exhausted)")), CALL_TIMEOUT_MS),
        ),
      ]);

      if (trapped) {
        ctx.callStack.pop();
        // Rollback this contract's mutations on trap
        mutations.clear();
        return { ok: false, logs: [], error: `Contract trapped: ${trapMessage}` };
      }
    } catch (e: any) {
      ctx.callStack.pop();
      mutations.clear();
      return { ok: false, logs: [], error: e.message };
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
  ): { env: Record<string, Function> } {
    let memory: WebAssembly.Memory | null = null;

    const env: Record<string, Function> = {
      storage_read: (keyReg: number): number => {
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
        if (ctx.readOnly) return;
        const keyBytes = registers.get(keyReg);
        const valBytes = registers.get(valReg);
        if (!keyBytes || !valBytes) return;
        mutations.set(bytesToHex(keyBytes), new Uint8Array(valBytes));
      },

      storage_remove: (keyReg: number): number => {
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

      register_len: (regId: number): number => registers.get(regId)?.length ?? 0,

      read_register: (regId: number, ptr: number) => {
        const data = registers.get(regId);
        if (!data || !memory) return;
        new Uint8Array(memory.buffer).set(data, ptr);
      },

      write_register: (regId: number, ptr: number, len: number) => {
        if (!memory) return;
        registers.set(regId, new Uint8Array(new Uint8Array(memory.buffer).slice(ptr, ptr + len)));
      },

      caller: (regId: number) => {
        registers.set(regId, new TextEncoder().encode(callerAddr));
      },

      origin: (regId: number) => {
        registers.set(regId, new TextEncoder().encode(ctx.rootCaller));
      },

      self_address: (regId: number) => {
        registers.set(regId, new TextEncoder().encode(address));
      },

      log: (ptr: number, len: number) => {
        if (!memory) return;
        const msg = new TextDecoder().decode(new Uint8Array(memory.buffer).slice(ptr, ptr + len));
        ctx.logs.push(`[${address.slice(0, 8)}] ${msg}`);
      },

      set_return: (regId: number) => onSetReturn(regId),

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
          const cachedModule = this.moduleCache.get(targetAddr);
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

      trigger_manage: (actionReg: number, dataReg: number) => {
        if (ctx.readOnly) return;
        const actionBytes = registers.get(actionReg);
        const dataBytes = registers.get(dataReg);
        if (!actionBytes || !dataBytes) return;
        try {
          const data = JSON.parse(new TextDecoder().decode(dataBytes));
          ctx.triggerRequests.push({ action: new TextDecoder().decode(actionBytes) as "create" | "remove", ...data, contract: address });
        } catch { }
      },

      gas_left: (): number => 0,
    };

    return { env };
  }

  // ─── Pre-cache modules for cross-contract calls ──────────────────────

  async ensureModuleCached(address: string): Promise<boolean> {
    if (this.moduleCache.has(address)) return true;
    return (await this.getModule(address)) !== null;
  }

  // ─── Module Cache ─────────────────────────────────────────────────────

  private async getModule(address: string): Promise<WebAssembly.Module | null> {
    if (this.moduleCache.has(address)) return this.moduleCache.get(address)!;
    const rows = [...this.sql.exec("SELECT wasm_bytes FROM contracts WHERE address = ?", address)];
    if (rows.length === 0) return null;
    const module = await WebAssembly.compile(rows[0].wasm_bytes as Uint8Array);
    this.moduleCache.set(address, module);
    return module;
  }

  // ─── Flush All Mutations (atomic commit across all contracts in chain) ──

  private flushAllMutations(ctx: ExecutionContext) {
    for (const [contractAddr, mutations] of ctx.mutations) {
      for (const [keyHex, value] of mutations) {
        const keyBytes = hexToBytes(keyHex);
        if (value === null) {
          this.sql.exec(
            "DELETE FROM contract_state WHERE contract_address = ? AND key = ?",
            contractAddr, keyBytes,
          );
        } else {
          this.sql.exec(
            `INSERT INTO contract_state (contract_address, key, value) VALUES (?, ?, ?)
             ON CONFLICT(contract_address, key) DO UPDATE SET value = ?`,
            contractAddr, keyBytes, value, value,
          );
        }
      }
    }
  }

  // ─── Info ─────────────────────────────────────────────────────────────

  getContractInfo(address: string): ContractInfo | null {
    const rows = [...this.sql.exec(
      "SELECT address, deployer, wasm_hash, created_at, deploy_seq FROM contracts WHERE address = ?",
      address,
    )];
    if (rows.length === 0) return null;
    const r = rows[0] as any;
    return { address: r.address, deployer: r.deployer, wasm_hash: r.wasm_hash, created_at: r.created_at, deploy_seq: r.deploy_seq };
  }
}
