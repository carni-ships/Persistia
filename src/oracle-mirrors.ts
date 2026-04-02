// ─── Oracle Mirror Adapters ──────────────────────────────────────────────────
// Stateless adapters for fetching price data from external oracle networks.
// Each adapter normalizes results to { value, decimals, source_ts }.

import { fetchWithTimeout, extractJsonPath } from "./oracle";
import type { MirrorResult, FeedSource } from "./types";

const MIRROR_TIMEOUT_MS = 8_000;
const EVM_MAX_RETRIES = 3;
const EVM_BASE_DELAY_MS = 200;

// ─── Chainlink ──────────────────────────────────────────────────────────────

/**
 * Call a read-only function on an EVM contract via eth_call.
 * Shared helper for Chainlink, RedStone Bolt, and any AggregatorV3-compatible feed.
 * Retries up to 3 times with exponential backoff + jitter on 429/5xx/network errors.
 */
async function evmCall(
  rpcUrl: string,
  to: string,
  data: string,
): Promise<string | null> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_call",
    params: [{ to, data }, "latest"],
  });

  for (let attempt = 0; attempt < EVM_MAX_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), MIRROR_TIMEOUT_MS);
      let response: Response;
      try {
        response = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }

      // Retry on rate limit or server error
      if (response.status === 429 || response.status >= 500) {
        if (attempt < EVM_MAX_RETRIES - 1) {
          const delay = EVM_BASE_DELAY_MS * Math.pow(2, attempt) + Math.random() * 100;
          await new Promise(r => setTimeout(r, delay));
          continue;
        }
        return null;
      }

      if (!response.ok) return null;

      const json = await response.json() as any;
      if (!json.result || json.result === "0x") return null;
      return json.result;
    } catch {
      // Network error / timeout — retry with backoff
      if (attempt < EVM_MAX_RETRIES - 1) {
        const delay = EVM_BASE_DELAY_MS * Math.pow(2, attempt) + Math.random() * 100;
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      return null;
    }
  }
  return null;
}

/**
 * Batch multiple eth_call requests into a single JSON-RPC batch request.
 * Sends one HTTP POST with an array of calls, returns results by index.
 * Falls back to individual calls on batch failure.
 */
export async function evmCallBatch(
  rpcUrl: string,
  calls: { to: string; data: string }[],
): Promise<(string | null)[]> {
  if (calls.length === 0) return [];
  if (calls.length === 1) {
    const result = await evmCall(rpcUrl, calls[0].to, calls[0].data);
    return [result];
  }

  const batchBody = JSON.stringify(
    calls.map((call, i) => ({
      jsonrpc: "2.0",
      id: i + 1,
      method: "eth_call",
      params: [{ to: call.to, data: call.data }, "latest"],
    })),
  );

  for (let attempt = 0; attempt < EVM_MAX_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), MIRROR_TIMEOUT_MS);
      let response: Response;
      try {
        response = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: batchBody,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }

      if (response.status === 429 || response.status >= 500) {
        if (attempt < EVM_MAX_RETRIES - 1) {
          const delay = EVM_BASE_DELAY_MS * Math.pow(2, attempt) + Math.random() * 100;
          await new Promise(r => setTimeout(r, delay));
          continue;
        }
        return calls.map(() => null);
      }

      if (!response.ok) return calls.map(() => null);

      const json = await response.json() as any;
      if (!Array.isArray(json)) return calls.map(() => null);

      // Map results by id back to original order
      const resultMap = new Map<number, string | null>();
      for (const entry of json) {
        const id = entry.id;
        const result = entry.result && entry.result !== "0x" ? entry.result : null;
        resultMap.set(id, result);
      }

      return calls.map((_, i) => resultMap.get(i + 1) || null);
    } catch {
      if (attempt < EVM_MAX_RETRIES - 1) {
        const delay = EVM_BASE_DELAY_MS * Math.pow(2, attempt) + Math.random() * 100;
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      return calls.map(() => null);
    }
  }
  return calls.map(() => null);
}

/**
 * Batch-fetch multiple RedStone Bolt (or Chainlink) feeds from a single RPC.
 * Groups all aggregator addresses targeting the same RPC into one batch call.
 * Returns a map of aggregatorAddress → MirrorResult.
 */
export async function fetchRedstoneBoltBatch(
  aggregators: { address: string; decimals?: number }[],
  rpcUrl: string = MEGAETH_RPC,
): Promise<Map<string, MirrorResult>> {
  const results = new Map<string, MirrorResult>();
  if (aggregators.length === 0) return results;

  // Batch latestRoundData() + decimals() for all aggregators
  const calls: { to: string; data: string }[] = [];
  const callIndex: { address: string; type: "round" | "decimals" }[] = [];

  for (const agg of aggregators) {
    calls.push({ to: agg.address, data: "0xfeaf968c" }); // latestRoundData()
    callIndex.push({ address: agg.address, type: "round" });
    calls.push({ to: agg.address, data: "0x313ce567" }); // decimals()
    callIndex.push({ address: agg.address, type: "decimals" });
  }

  const batchResults = await evmCallBatch(rpcUrl, calls);

  // Pair up results: each aggregator has 2 calls (roundData, decimals)
  for (let i = 0; i < aggregators.length; i++) {
    const roundResult = batchResults[i * 2];
    const decimalsResult = batchResults[i * 2 + 1];

    if (!roundResult) continue;

    let dec = aggregators[i].decimals ?? 8;
    if (decimalsResult) {
      const hexDec = decimalsResult.startsWith("0x") ? decimalsResult.slice(2) : decimalsResult;
      const parsed = Number(BigInt("0x" + hexDec));
      if (!isNaN(parsed) && parsed >= 0 && parsed <= 18) dec = parsed;
    }

    const decoded = decodeLatestRoundData(roundResult, dec);
    if (decoded) results.set(aggregators[i].address, decoded);
  }

  return results;
}

/**
 * Batch-fetch multiple Chainlink feeds from a single RPC.
 * Same as Bolt batch but defaults to Ethereum RPC.
 */
export async function fetchChainlinkBatch(
  aggregators: { address: string }[],
  rpcUrl: string = "https://ethereum-rpc.publicnode.com",
): Promise<Map<string, MirrorResult>> {
  const results = new Map<string, MirrorResult>();
  if (aggregators.length === 0) return results;

  const calls = aggregators.map(agg => ({ to: agg.address, data: "0xfeaf968c" }));
  const batchResults = await evmCallBatch(rpcUrl, calls);

  for (let i = 0; i < aggregators.length; i++) {
    if (!batchResults[i]) continue;
    const decoded = decodeLatestRoundData(batchResults[i]!, 8);
    if (decoded) results.set(aggregators[i].address, decoded);
  }

  return results;
}

/**
 * Decode a standard AggregatorV3 latestRoundData() response.
 * Returns (roundId, answer, startedAt, updatedAt, answeredInRound) — we use answer + updatedAt.
 * Works for Chainlink on-chain feeds AND RedStone Bolt (both use the same interface).
 */
function decodeLatestRoundData(
  hexResult: string,
  decimals: number = 8,
): MirrorResult | null {
  try {
    const hex = hexResult.startsWith("0x") ? hexResult.slice(2) : hexResult;
    if (hex.length < 320) return null; // need at least 5 × 32 bytes

    // answer is at offset 32 bytes (slot 1)
    const answerHex = hex.slice(64, 128);
    const answer = BigInt("0x" + answerHex);
    // updatedAt is at offset 96 bytes (slot 3)
    const updatedAtHex = hex.slice(192, 256);
    const updatedAt = Number(BigInt("0x" + updatedAtHex));

    const value = Number(answer) / Math.pow(10, decimals);

    return { value, decimals, source_ts: updatedAt * 1000 };
  } catch {
    return null;
  }
}

/**
 * Fetch latest answer from a Chainlink aggregator contract via eth_call.
 * Calls latestRoundData() on the AggregatorV3 interface.
 */
export async function fetchChainlink(
  aggregatorAddress: string,
  rpcUrl: string,
): Promise<MirrorResult | null> {
  // latestRoundData() selector = 0xfeaf968c
  const result = await evmCall(rpcUrl, aggregatorAddress, "0xfeaf968c");
  if (!result) return null;
  return decodeLatestRoundData(result, 8);
}

// ─── RedStone Bolt (via MegaETH) ───────────────────────────────────────────

const MEGAETH_RPC = "https://mainnet.megaeth.com/rpc";

/**
 * Fetch latest price from a RedStone Bolt feed on MegaETH.
 * Bolt uses the standard Chainlink AggregatorV3 interface (latestRoundData),
 * so the on-chain read is identical — the difference is that Bolt updates
 * every 2.4ms instead of every ~1 hour.
 *
 * endpoint: the Bolt aggregator contract address on MegaETH (0x...)
 * rpcUrl: defaults to MegaETH mainnet RPC
 */
export async function fetchRedstoneBolt(
  aggregatorAddress: string,
  rpcUrl: string = MEGAETH_RPC,
): Promise<MirrorResult | null> {
  // Same ABI as Chainlink — latestRoundData() selector = 0xfeaf968c
  const result = await evmCall(rpcUrl, aggregatorAddress, "0xfeaf968c");
  if (!result) return null;
  // RedStone Bolt uses 8 decimals by default; call decimals() to be precise
  const decimalsResult = await evmCall(rpcUrl, aggregatorAddress, "0x313ce567");
  let dec = 8;
  if (decimalsResult) {
    const hexDec = decimalsResult.startsWith("0x") ? decimalsResult.slice(2) : decimalsResult;
    dec = Number(BigInt("0x" + hexDec));
    if (isNaN(dec) || dec < 0 || dec > 18) dec = 8;
  }
  return decodeLatestRoundData(result, dec);
}

// ─── Pyth Network ───────────────────────────────────────────────────────────

const PYTH_HERMES_URL = "https://hermes.pyth.network";

/**
 * Fetch latest price from Pyth via the Hermes REST API.
 * priceId is the hex price feed ID (e.g., "0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43" for BTC/USD).
 */
export async function fetchPyth(
  priceId: string,
  hermesUrl: string = PYTH_HERMES_URL,
): Promise<MirrorResult | null> {
  try {
    const url = `${hermesUrl}/v2/updates/price/latest?ids[]=${priceId}&parsed=true`;
    const raw = await fetchWithTimeout(url);
    const json = JSON.parse(raw);

    const parsed = json?.parsed?.[0];
    if (!parsed?.price) return null;

    const price = parsed.price;
    const expo = price.expo; // negative exponent (e.g., -8)
    const value = Number(price.price) * Math.pow(10, expo);
    const decimals = Math.abs(expo);
    const source_ts = Number(price.publish_time) * 1000;

    return { value, decimals, source_ts };
  } catch {
    return null;
  }
}

// ─── RedStone ───────────────────────────────────────────────────────────────

const REDSTONE_API_URL = "https://api.redstone.finance";

/**
 * Fetch latest price from RedStone's public API.
 * dataFeedId is the symbol (e.g., "BTC", "ETH").
 */
export async function fetchRedStone(
  dataFeedId: string,
  apiUrl: string = REDSTONE_API_URL,
): Promise<MirrorResult | null> {
  try {
    const url = `${apiUrl}/prices?symbol=${dataFeedId}&provider=redstone&limit=1`;
    const raw = await fetchWithTimeout(url);
    const json = JSON.parse(raw);

    if (!Array.isArray(json) || json.length === 0) return null;
    const entry = json[0];

    return {
      value: entry.value,
      decimals: 8,
      source_ts: entry.timestamp,
    };
  } catch {
    return null;
  }
}

// ─── CoinGecko ──────────────────────────────────────────────────────────────

/**
 * Fetch price from CoinGecko's free API.
 * coinId is the CoinGecko ID (e.g., "bitcoin", "ethereum").
 * vsCurrency is the quote currency (e.g., "usd").
 */
export async function fetchCoinGecko(
  coinId: string,
  vsCurrency: string = "usd",
): Promise<MirrorResult | null> {
  try {
    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${coinId}&vs_currencies=${vsCurrency}&include_last_updated_at=true`;
    const raw = await fetchWithTimeout(url);
    const json = JSON.parse(raw);

    const data = json[coinId];
    if (!data) return null;

    return {
      value: data[vsCurrency],
      decimals: 8,
      source_ts: (data.last_updated_at || Math.floor(Date.now() / 1000)) * 1000,
    };
  } catch {
    return null;
  }
}

/**
 * Batch-fetch multiple coins from CoinGecko in a single API call.
 * Returns a map of coinId → MirrorResult.
 * E.g., fetchCoinGeckoBatch(["bitcoin", "ethereum", "solana"], "usd")
 * uses ?ids=bitcoin,ethereum,solana — one HTTP request for all.
 */
export async function fetchCoinGeckoBatch(
  coinIds: string[],
  vsCurrency: string = "usd",
): Promise<Map<string, MirrorResult>> {
  const results = new Map<string, MirrorResult>();
  if (coinIds.length === 0) return results;

  try {
    const ids = [...new Set(coinIds)].join(",");
    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=${vsCurrency}&include_last_updated_at=true`;
    const raw = await fetchWithTimeout(url);
    const json = JSON.parse(raw);

    for (const coinId of coinIds) {
      const data = json[coinId];
      if (data && data[vsCurrency] !== undefined) {
        results.set(coinId, {
          value: data[vsCurrency],
          decimals: 8,
          source_ts: (data.last_updated_at || Math.floor(Date.now() / 1000)) * 1000,
        });
      }
    }
  } catch { /* return whatever we got */ }
  return results;
}

// ─── Binance ────────────────────────────────────────────────────────────────

/**
 * Fetch price from Binance's public ticker API.
 * symbol is the trading pair (e.g., "BTCUSDT", "ETHUSDT").
 */
export async function fetchBinance(
  symbol: string,
): Promise<MirrorResult | null> {
  try {
    const url = `https://api.binance.com/api/v3/ticker/price?symbol=${symbol}`;
    const raw = await fetchWithTimeout(url);
    const json = JSON.parse(raw);

    if (!json.price) return null;

    return {
      value: parseFloat(json.price),
      decimals: 8,
      source_ts: Date.now(),
    };
  } catch {
    return null;
  }
}

/**
 * Batch-fetch multiple symbols from Binance in a single API call.
 * Uses the ticker/price endpoint with no symbol param (returns all tickers),
 * then filters to requested symbols.
 * Returns a map of symbol → MirrorResult.
 */
export async function fetchBinanceBatch(
  symbols: string[],
): Promise<Map<string, MirrorResult>> {
  const results = new Map<string, MirrorResult>();
  if (symbols.length === 0) return results;

  try {
    // Binance: when symbols ≤ 5, use individual param; otherwise fetch the batch endpoint
    // The symbols[] param format works for multiple symbols in one call
    const symbolSet = new Set(symbols);
    const encoded = JSON.stringify([...symbolSet]);
    const url = `https://api.binance.com/api/v3/ticker/price?symbols=${encodeURIComponent(encoded)}`;
    const raw = await fetchWithTimeout(url);
    const json = JSON.parse(raw);

    const now = Date.now();
    if (Array.isArray(json)) {
      for (const entry of json) {
        if (entry.symbol && entry.price && symbolSet.has(entry.symbol)) {
          results.set(entry.symbol, {
            value: parseFloat(entry.price),
            decimals: 8,
            source_ts: now,
          });
        }
      }
    }
  } catch { /* return whatever we got */ }
  return results;
}

// ─── Generic HTTP ───────────────────────────────────────────────────────────

/**
 * Fetch a numeric value from any HTTP JSON endpoint with optional JSON path extraction.
 */
export async function fetchHttp(
  url: string,
  jsonPath?: string,
): Promise<MirrorResult | null> {
  try {
    const raw = await fetchWithTimeout(url);
    const extracted = extractJsonPath(raw, jsonPath);
    const value = parseFloat(extracted);
    if (isNaN(value) || !isFinite(value)) return null;

    return { value, decimals: 8, source_ts: Date.now() };
  } catch {
    return null;
  }
}

// ─── Unified Source Fetcher ─────────────────────────────────────────────────

/**
 * Fetch a value from any configured source. Returns null on failure.
 */
export async function fetchSource(source: FeedSource): Promise<MirrorResult | null> {
  switch (source.type) {
    case "chainlink":
      return fetchChainlink(source.endpoint, source.rpc_url || "https://ethereum-rpc.publicnode.com");
    case "pyth":
      return fetchPyth(source.endpoint, source.rpc_url);
    case "redstone":
      return fetchRedStone(source.endpoint, source.rpc_url);
    case "redstone_bolt":
      return fetchRedstoneBolt(source.endpoint, source.rpc_url || MEGAETH_RPC);
    case "coingecko": {
      const [coinId, vsCurrency] = source.endpoint.split(":");
      return fetchCoinGecko(coinId, vsCurrency || "usd");
    }
    case "binance":
      return fetchBinance(source.endpoint);
    case "http":
      return fetchHttp(source.endpoint, source.json_path);
    default:
      return null;
  }
}

/**
 * Fetch from all sources concurrently, return successful results with weights.
 */
export async function fetchAllSources(
  sources: FeedSource[],
): Promise<{ value: number; weight: number; source_ts: number }[]> {
  const results = await fetchAllSourcesWithStats(sources);
  return results.filter(r => r.success).map(r => ({
    value: r.value!,
    weight: r.weight,
    source_ts: r.source_ts!,
  }));
}

/**
 * Fetch from all sources with detailed stats for source scoring.
 */
export interface SourceFetchResult {
  source_index: number;
  source_type: string;
  success: boolean;
  value?: number;
  weight: number;
  source_ts?: number;
  latency_ms: number;
  freshness_ms: number;
}

export async function fetchAllSourcesWithStats(
  sources: FeedSource[],
): Promise<SourceFetchResult[]> {
  const now = Date.now();
  const results = await Promise.allSettled(
    sources.map(async (src, index) => {
      const start = Date.now();
      try {
        const result = await fetchSource(src);
        const latency = Date.now() - start;
        if (!result) {
          return {
            source_index: index, source_type: src.type, success: false,
            weight: src.weight, latency_ms: latency, freshness_ms: 0,
          } as SourceFetchResult;
        }
        const freshness = now - result.source_ts;
        return {
          source_index: index, source_type: src.type, success: true,
          value: result.value, weight: src.weight, source_ts: result.source_ts,
          latency_ms: latency, freshness_ms: Math.max(0, freshness),
        } as SourceFetchResult;
      } catch {
        return {
          source_index: index, source_type: src.type, success: false,
          weight: src.weight, latency_ms: Date.now() - start, freshness_ms: 0,
        } as SourceFetchResult;
      }
    }),
  );

  const out: SourceFetchResult[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") out.push(r.value);
  }
  return out;
}
