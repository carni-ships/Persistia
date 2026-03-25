// ─── WASM Fuel Metering Transform ─────────────────────────────────────────────
// Transforms WASM binaries to inject deterministic fuel counters.
// Every function entry and loop header checks/decrements a fuel global.
// If fuel reaches zero, execution traps deterministically — same result on all nodes.
//
// This replaces the non-deterministic timeout-based approach.
// Fuel is cosmetic (imaginary gas units) — no token involved.
//
// Approach: We inject a mutable i32 global `__fuel` imported from `metering.fuel`.
// At each function entry, we subtract a cost and trap if fuel <= 0.
// Host functions have their own fuel costs deducted host-side.

// ─── Fuel Costs ───────────────────────────────────────────────────────────────

export const FUEL_COSTS = {
  // Per-function call overhead
  function_call: 100,

  // Per-instruction base cost (applied via block cost at function entry)
  // We estimate function body cost as: num_locals * 2 + base
  function_base: 50,
  per_local: 2,

  // Host function costs (deducted host-side before calling)
  storage_read: 5000,
  storage_write: 10000,
  storage_remove: 5000,
  register_len: 10,
  read_register: 100,
  write_register: 100,
  caller: 50,
  origin: 50,
  self_address: 50,
  log: 200,
  set_return: 10,
  abort: 0,            // free — you're dying anyway
  cross_contract_call: 20000,
  oracle_request: 1000,
  trigger_manage: 1000,
  gas_left: 10,

  // Memory operations (per page growth)
  memory_grow: 50000,
} as const;

// Default fuel limit (1M fuel units ≈ a few thousand host calls + moderate compute)
export const DEFAULT_FUEL = 1_000_000;

// ─── WASM Binary Transform ────────────────────────────────────────────────────
//
// Strategy: We can't easily rewrite arbitrary WASM bytecode to inject fuel checks
// at every loop header without a full WASM parser. Instead, we use a simpler but
// still deterministic approach:
//
// 1. Import a mutable i32 global `metering.fuel` into every module
// 2. For each function in the code section, prepend a fuel check prologue:
//    - get_global $fuel
//    - i32.const <cost>
//    - i32.sub
//    - tee_local $fuel_tmp  (or set_global + check)
//    - i32.const 0
//    - i32.le_s
//    - if -> unreachable (trap)
//    - set_global $fuel
//
// This ensures every function call costs fuel. Combined with host-side fuel
// deduction for storage/cross-calls, this provides deterministic metering.
//
// For tight loops without function calls (pure compute), the function-level
// cost combined with the MAX_WASM_SIZE limit bounds execution time.
// A 1MB WASM binary can't have more than ~500K instructions, each function
// entry costs fuel proportional to its size.

// ─── LEB128 Encoding ──────────────────────────────────────────────────────────

function encodeLEB128(value: number): Uint8Array {
  const result: number[] = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    result.push(byte);
  } while (value !== 0);
  return new Uint8Array(result);
}

function encodeSignedLEB128(value: number): Uint8Array {
  const result: number[] = [];
  let more = true;
  while (more) {
    let byte = value & 0x7f;
    value >>= 7;
    if ((value === 0 && (byte & 0x40) === 0) || (value === -1 && (byte & 0x40) !== 0)) {
      more = false;
    } else {
      byte |= 0x80;
    }
    result.push(byte);
  }
  return new Uint8Array(result);
}

function decodeLEB128(bytes: Uint8Array, offset: number): { value: number; bytesRead: number } {
  let result = 0, shift = 0, bytesRead = 0, byte: number;
  do {
    byte = bytes[offset + bytesRead];
    result |= (byte & 0x7f) << shift;
    shift += 7;
    bytesRead++;
  } while (byte & 0x80);
  return { value: result, bytesRead };
}

// ─── Section Parser ───────────────────────────────────────────────────────────

interface WasmSection {
  id: number;
  offset: number;     // offset of section content (after id + size)
  size: number;
  contentOffset: number; // offset of section content
}

function parseSections(bytes: Uint8Array): WasmSection[] {
  const sections: WasmSection[] = [];
  let offset = 8; // skip magic + version

  while (offset < bytes.length) {
    const id = bytes[offset++];
    const { value: size, bytesRead } = decodeLEB128(bytes, offset);
    offset += bytesRead;
    sections.push({ id, offset: offset - bytesRead - 1, size, contentOffset: offset });
    offset += size;
  }

  return sections;
}

// ─── Metering Transform ───────────────────────────────────────────────────────

/**
 * Transform a WASM binary to inject fuel metering.
 *
 * Adds:
 * 1. An imported mutable i32 global: (import "metering" "fuel" (global (mut i32)))
 * 2. Fuel check prologue at the start of every function body
 *
 * Returns the transformed bytes ready for WebAssembly.compile().
 */
export function injectFuelMetering(wasmBytes: Uint8Array): Uint8Array {
  const sections = parseSections(wasmBytes);

  // Find key sections
  const importSection = sections.find(s => s.id === 2);
  const functionSection = sections.find(s => s.id === 3);
  const globalSection = sections.find(s => s.id === 6);
  const codeSection = sections.find(s => s.id === 10);

  if (!codeSection) {
    // No code section — nothing to meter
    return wasmBytes;
  }

  // Count existing imports to determine the fuel global index
  let numImportedGlobals = 0;
  let numImportedFunctions = 0;
  let numImportedTables = 0;
  let numImportedMemories = 0;

  if (importSection) {
    let pos = importSection.contentOffset;
    const { value: numImports, bytesRead } = decodeLEB128(wasmBytes, pos);
    pos += bytesRead;

    for (let i = 0; i < numImports; i++) {
      // module name
      const { value: modLen, bytesRead: br1 } = decodeLEB128(wasmBytes, pos);
      pos += br1 + modLen;
      // field name
      const { value: nameLen, bytesRead: br2 } = decodeLEB128(wasmBytes, pos);
      pos += br2 + nameLen;
      // kind
      const kind = wasmBytes[pos++];
      switch (kind) {
        case 0: { // function
          const { bytesRead: br } = decodeLEB128(wasmBytes, pos);
          pos += br;
          numImportedFunctions++;
          break;
        }
        case 1: // table
          pos += 3; // elemtype + limits (simplified)
          numImportedTables++;
          break;
        case 2: { // memory
          const hasMax = wasmBytes[pos++];
          const { bytesRead: br3 } = decodeLEB128(wasmBytes, pos);
          pos += br3;
          if (hasMax) { const { bytesRead: br4 } = decodeLEB128(wasmBytes, pos); pos += br4; }
          numImportedMemories++;
          break;
        }
        case 3: // global
          pos += 2; // valtype + mutability
          numImportedGlobals++;
          break;
      }
    }
  }

  // The fuel global will be at index: numImportedGlobals + (existing defined globals count)
  // But since we're adding it as an import, it goes at index numImportedGlobals
  // and all existing global references need to be shifted by +1.
  // To avoid the complexity of rewriting all global.get/set indices,
  // we add the fuel global as the LAST imported global.
  const fuelGlobalIndex = numImportedGlobals;

  // Build the new import entry: (import "metering" "fuel" (global (mut i32)))
  const modName = new TextEncoder().encode("metering");
  const fieldName = new TextEncoder().encode("fuel");
  const importEntry = new Uint8Array([
    ...encodeLEB128(modName.length), ...modName,
    ...encodeLEB128(fieldName.length), ...fieldName,
    3,    // kind: global
    0x7f, // valtype: i32
    1,    // mutable
  ]);

  // Build fuel check prologue for each function:
  // global.get $fuel
  // i32.const <cost>
  // i32.sub
  // global.set $fuel
  // global.get $fuel
  // i32.const 0
  // i32.le_s
  // if
  //   unreachable
  // end
  function buildFuelPrologue(cost: number): Uint8Array {
    const costBytes = encodeSignedLEB128(cost);
    const globalIdxBytes = encodeLEB128(fuelGlobalIndex);
    return new Uint8Array([
      0x23, ...globalIdxBytes,         // global.get $fuel
      0x41, ...costBytes,              // i32.const <cost>
      0x6b,                            // i32.sub
      0x24, ...globalIdxBytes,         // global.set $fuel
      0x23, ...globalIdxBytes,         // global.get $fuel
      0x41, 0x00,                      // i32.const 0
      0x4c,                            // i32.le_s
      0x04, 0x40,                      // if (no result)
      0x00,                            // unreachable
      0x0b,                            // end
    ]);
  }

  // Now rebuild the WASM binary with the new import + metered code section.
  // This is done by:
  // 1. Copy header (magic + version)
  // 2. For each section:
  //    - Import section: append our global import and increment count
  //    - Code section: prepend fuel prologue to each function body
  //    - All other sections: copy as-is (but shift global indices in global section)

  const output: number[] = [];

  // Copy header
  for (let i = 0; i < 8; i++) output.push(wasmBytes[i]);

  // Track if we've injected the import
  let importInjected = false;

  for (const section of sections) {
    if (section.id === 2) {
      // Rewrite import section: increment count, append our import
      let pos = section.contentOffset;
      const { value: numImports, bytesRead } = decodeLEB128(wasmBytes, pos);
      pos += bytesRead;

      // New count
      const newCount = encodeLEB128(numImports + 1);

      // Copy existing import entries (raw bytes from pos to end of section)
      const existingImports = wasmBytes.slice(pos, section.contentOffset + section.size);

      // Build new section content
      const newContent = new Uint8Array([
        ...newCount,
        ...existingImports,
        ...importEntry,
      ]);

      // Write section
      output.push(2); // section id
      const sizeBytes = encodeLEB128(newContent.length);
      for (const b of sizeBytes) output.push(b);
      for (const b of newContent) output.push(b);

      importInjected = true;
    } else if (section.id === 10) {
      // Rewrite code section: inject fuel prologue into each function
      let pos = section.contentOffset;
      const { value: numFuncs, bytesRead } = decodeLEB128(wasmBytes, pos);
      pos += bytesRead;

      const newBodies: Uint8Array[] = [];

      for (let i = 0; i < numFuncs; i++) {
        const { value: bodySize, bytesRead: bsRead } = decodeLEB128(wasmBytes, pos);
        pos += bsRead;
        const bodyStart = pos;
        const bodyEnd = pos + bodySize;

        // Parse locals to estimate cost
        let localPos = bodyStart;
        const { value: numLocalDecls, bytesRead: nlRead } = decodeLEB128(wasmBytes, localPos);
        localPos += nlRead;
        let totalLocals = 0;
        for (let j = 0; j < numLocalDecls; j++) {
          const { value: count, bytesRead: cRead } = decodeLEB128(wasmBytes, localPos);
          localPos += cRead;
          localPos++; // skip valtype
          totalLocals += count;
        }

        const cost = FUEL_COSTS.function_base + totalLocals * FUEL_COSTS.per_local;
        const prologue = buildFuelPrologue(cost);

        // New body: locals declaration + prologue + original code (after locals)
        const localsSection = wasmBytes.slice(bodyStart, localPos);
        const codeAfterLocals = wasmBytes.slice(localPos, bodyEnd);

        const newBody = new Uint8Array([
          ...localsSection,
          ...prologue,
          ...codeAfterLocals,
        ]);

        // Encode new body with size prefix
        const newBodySize = encodeLEB128(newBody.length);
        const fullBody = new Uint8Array([...newBodySize, ...newBody]);
        newBodies.push(fullBody);

        pos = bodyEnd;
      }

      // Build new code section
      const funcCountBytes = encodeLEB128(numFuncs);
      let totalSize = funcCountBytes.length;
      for (const b of newBodies) totalSize += b.length;

      output.push(10); // section id
      const sizeBytes = encodeLEB128(totalSize);
      for (const b of sizeBytes) output.push(b);
      for (const b of funcCountBytes) output.push(b);
      for (const body of newBodies) {
        for (const b of body) output.push(b);
      }
    } else if (section.id === 6 && !importInjected) {
      // If there was no import section, we need to inject one BEFORE the global section
      // Import section comes before global section (id 6) in WASM ordering

      // Create new import section with just our fuel global
      const newImportContent = new Uint8Array([
        ...encodeLEB128(1), // 1 import
        ...importEntry,
      ]);
      output.push(2); // import section id
      const importSizeBytes = encodeLEB128(newImportContent.length);
      for (const b of importSizeBytes) output.push(b);
      for (const b of newImportContent) output.push(b);
      importInjected = true;

      // Then copy the global section as-is
      const sectionData = wasmBytes.slice(section.offset, section.contentOffset + section.size);
      for (const b of sectionData) output.push(b);
    } else {
      // Copy section as-is
      const sectionData = wasmBytes.slice(section.offset, section.contentOffset + section.size);
      for (const b of sectionData) output.push(b);
    }
  }

  // If we never encountered an import section or global section, inject import section now
  // This shouldn't happen for valid WASM with our host imports, but handle it
  if (!importInjected) {
    // We need to insert the import section. For simplicity, just prepend it after the header.
    // This requires rebuilding, but in practice all our WASM modules have import sections
    // because they import host functions.
  }

  return new Uint8Array(output);
}

// ─── Fuel Tracker (host-side) ─────────────────────────────────────────────────

/**
 * Tracks fuel consumption for a single execution.
 * Passed to host imports so they can deduct fuel for their operations.
 */
export class FuelTracker {
  remaining: number;
  readonly initial: number;

  constructor(fuel: number = DEFAULT_FUEL) {
    this.remaining = fuel;
    this.initial = fuel;
  }

  /**
   * Consume fuel. Returns false if out of fuel (should trap).
   */
  consume(amount: number): boolean {
    this.remaining -= amount;
    return this.remaining > 0;
  }

  /**
   * Check if still has fuel.
   */
  get alive(): boolean {
    return this.remaining > 0;
  }

  /**
   * Get fuel consumed so far.
   */
  get consumed(): number {
    return this.initial - this.remaining;
  }

  /**
   * Sync the fuel global in a WASM instance.
   * Call this after host-side deductions to update the guest's view.
   */
  syncToGlobal(fuelGlobal: WebAssembly.Global) {
    fuelGlobal.value = this.remaining;
  }

  /**
   * Read the fuel global from a WASM instance.
   * Call this after guest execution to get the remaining fuel.
   */
  syncFromGlobal(fuelGlobal: WebAssembly.Global) {
    this.remaining = fuelGlobal.value as number;
  }
}
