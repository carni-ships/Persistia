// ─── Oracle: Trustless External Data Fetching ────────────────────────────────
// Fetches data from Web2 APIs with multi-node consensus verification.
// Inspired by Chainlink CRE's capability model.

import { sha256 } from "./consensus";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OracleRequest {
  id: string;              // deterministic: SHA256(contract + callback + url + timestamp)
  contract: string;        // contract address requesting data
  callback_method: string; // method to call with result
  url: string;             // URL to fetch
  json_path?: string;      // optional JSONPath-like selector (e.g., "data.price")
  aggregation: AggregationStrategy;
  created_at: number;
  status: "pending" | "fetching" | "aggregating" | "delivered" | "failed";
}

export type AggregationStrategy = "identical" | "median" | "majority";

export interface OracleResponse {
  request_id: string;
  value: string;           // JSON-encoded result
  sources: number;         // how many nodes contributed
  consensus_met: boolean;
}

export interface NodeFetchResult {
  node_pubkey: string;
  request_id: string;
  value: string;           // raw fetched value (JSON string)
  fetched_at: number;
}

// ─── Aggregation Functions ────────────────────────────────────────────────────

/**
 * Aggregate results from multiple nodes using the specified strategy.
 * Returns null if consensus cannot be reached.
 */
export function aggregate(
  results: NodeFetchResult[],
  strategy: AggregationStrategy,
  quorum: number,
): { value: string; sources: number } | null {
  if (results.length < quorum) return null;

  switch (strategy) {
    case "identical":
      return aggregateIdentical(results, quorum);
    case "median":
      return aggregateMedian(results, quorum);
    case "majority":
      return aggregateMajority(results, quorum);
    default:
      return null;
  }
}

/**
 * All nodes must return the same value. Strict — any divergence fails.
 */
function aggregateIdentical(
  results: NodeFetchResult[],
  quorum: number,
): { value: string; sources: number } | null {
  const values = results.map(r => r.value);
  const first = values[0];
  const matching = values.filter(v => v === first).length;
  if (matching >= quorum) {
    return { value: first, sources: matching };
  }
  return null;
}

/**
 * Parse all values as numbers, take the median. Good for price feeds.
 * Requires at least `quorum` valid numeric values.
 */
function aggregateMedian(
  results: NodeFetchResult[],
  quorum: number,
): { value: string; sources: number } | null {
  const numbers: number[] = [];
  for (const r of results) {
    const n = parseFloat(r.value);
    if (!isNaN(n) && isFinite(n)) numbers.push(n);
  }
  if (numbers.length < quorum) return null;

  numbers.sort((a, b) => a - b);
  const mid = Math.floor(numbers.length / 2);
  const median = numbers.length % 2 === 0
    ? (numbers[mid - 1] + numbers[mid]) / 2
    : numbers[mid];

  return { value: String(median), sources: numbers.length };
}

/**
 * Most common value wins if it appears in >= quorum nodes.
 * Good for string/enum data where small differences are unlikely.
 */
function aggregateMajority(
  results: NodeFetchResult[],
  quorum: number,
): { value: string; sources: number } | null {
  const counts = new Map<string, number>();
  for (const r of results) {
    counts.set(r.value, (counts.get(r.value) || 0) + 1);
  }

  let bestValue = "";
  let bestCount = 0;
  for (const [value, count] of counts) {
    if (count > bestCount) {
      bestValue = value;
      bestCount = count;
    }
  }

  if (bestCount >= quorum) {
    return { value: bestValue, sources: bestCount };
  }
  return null;
}

// ─── JSON Path Extraction ─────────────────────────────────────────────────────

/**
 * Simple dot-notation path extractor. Supports "data.price", "items.0.name".
 * Not a full JSONPath implementation — just enough for common oracle use cases.
 */
export function extractJsonPath(json: string, path?: string): string {
  if (!path) return json;

  try {
    let obj = JSON.parse(json);
    const parts = path.split(".");
    for (const part of parts) {
      if (obj === null || obj === undefined) return "null";
      // Array index
      const idx = parseInt(part);
      if (!isNaN(idx) && Array.isArray(obj)) {
        obj = obj[idx];
      } else {
        obj = obj[part];
      }
    }
    return typeof obj === "object" ? JSON.stringify(obj) : String(obj ?? "null");
  } catch {
    return json;
  }
}

// ─── Fetch with Timeout ───────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 10_000;

/**
 * Fetch a URL with timeout. Returns the response body as string.
 * Used by individual nodes to fetch oracle data independently.
 */
export async function fetchWithTimeout(url: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Persistia-Oracle/0.1" },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.text();
  } finally {
    clearTimeout(timeout);
  }
}

// ─── Request ID Generation ────────────────────────────────────────────────────

export async function computeRequestId(
  contract: string,
  callbackMethod: string,
  url: string,
  nonce: number,
): Promise<string> {
  return sha256(`oracle:${contract}:${callbackMethod}:${url}:${nonce}`);
}
