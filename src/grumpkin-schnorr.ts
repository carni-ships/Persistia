// ─── Grumpkin Schnorr Signatures ──────────────────────────────────────────────
// Pure TypeScript implementation of Schnorr signatures on the Grumpkin curve,
// compatible with Barretenberg/Noir's schnorr::verify_signature.
//
// Uses @noble/curves (weierstrass) + @noble/hashes (blake2s) which are pure JS
// and work in Cloudflare Workers, Node.js, and browsers.
//
// The Grumpkin curve is BN254's embedded curve: y² = x³ - 17 over BN254's Fr.
// Schnorr challenge: e = Blake2s(PedersenHash([R.x, P.x, P.y]) || message)

import { weierstrass } from "@noble/curves/abstract/weierstrass";
import { Field } from "@noble/curves/abstract/modular";
import { blake2s } from "@noble/hashes/blake2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

// ─── Grumpkin Curve ──────────────────────────────────────────────────────────

// BN254 scalar field (= Grumpkin base field)
const GRUMPKIN_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// BN254 base field (= Grumpkin scalar field / group order)
const GRUMPKIN_N =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const Fp = Field(GRUMPKIN_P);

function getRandomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

export const grumpkin = weierstrass({
  a: 0n,
  b: Fp.neg(17n),
  Fp,
  n: GRUMPKIN_N,
  Gx: 1n,
  Gy: BigInt(
    "0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c",
  ),
  h: 1n,
  hash: sha256,
  hmac: (key: Uint8Array, ...msgs: Uint8Array[]) =>
    hmac(sha256, key, concatBytes(...msgs)),
  randomBytes: getRandomBytes,
});

type ProjectivePoint = ReturnType<typeof grumpkin.ProjectivePoint.fromAffine>;

// ─── Pedersen Hash (Barretenberg-compatible) ─────────────────────────────────
// pedersen_hash(inputs) = x_coord(len * H_len + sum(inputs[i] * G_i))
// These generators are deterministically derived by Barretenberg from
// the domain separator "DEFAULT_DOMAIN_SEPARATOR" (G_i) and
// "pedersen_hash_length" (H_len).

const PEDERSEN_G0 = grumpkin.ProjectivePoint.fromAffine({
  x: BigInt(
    "0x083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a",
  ),
  y: BigInt(
    "0x1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d",
  ),
});
const PEDERSEN_G1 = grumpkin.ProjectivePoint.fromAffine({
  x: BigInt(
    "0x054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402",
  ),
  y: BigInt(
    "0x209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126",
  ),
});
const PEDERSEN_G2 = grumpkin.ProjectivePoint.fromAffine({
  x: BigInt(
    "0x1c44f2a5207c81c28a8321a5815ce8b1311024bbed131819bbdaf5a2ada84748",
  ),
  y: BigInt(
    "0x03aaee36e6422a1d0191632ac6599ae9eba5ac2c17a8c920aa3caf8b89c5f8a8",
  ),
});

// H_len generator: derive y from x via curve equation y² = x³ - 17
const H_LEN_X = BigInt(
  "0x2df8b940e5890e4e1377e05373fae69a1d754f6935e6a780b666947431f2cdcd",
);
const H_LEN_Y2 = Fp.add(
  Fp.mul(Fp.mul(H_LEN_X, H_LEN_X), H_LEN_X),
  Fp.neg(17n),
);
const PEDERSEN_H_LEN = grumpkin.ProjectivePoint.fromAffine({
  x: H_LEN_X,
  y: Fp.sqrt(H_LEN_Y2)!,
});

const PEDERSEN_GENERATORS = [PEDERSEN_G0, PEDERSEN_G1, PEDERSEN_G2];

function pedersenHash(inputs: bigint[]): bigint {
  let result: ProjectivePoint = PEDERSEN_H_LEN.multiply(BigInt(inputs.length));
  for (let i = 0; i < inputs.length; i++) {
    if (inputs[i] !== 0n) {
      result = result.add(PEDERSEN_GENERATORS[i].multiply(inputs[i]));
    }
  }
  return result.toAffine().x;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Serialize a field element to 32 bytes big-endian. */
export function fieldToBytes(f: bigint): Uint8Array {
  const hex = f.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Deserialize 32 bytes big-endian to a field element. */
export function bytesToField(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** Hex string to field. */
export function hexToField(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : "0x" + hex);
}

// ─── Key Generation ──────────────────────────────────────────────────────────

export interface GrumpkinKeyPair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: { x: bigint; y: bigint };
}

/** Generate a random Grumpkin keypair. */
export function generateGrumpkinKeyPair(): GrumpkinKeyPair {
  const privBytes = getRandomBytes(32);
  // Reduce mod n to ensure valid scalar
  let privKey = bytesToField(privBytes) % GRUMPKIN_N;
  if (privKey === 0n) privKey = 1n;
  const P = grumpkin.ProjectivePoint.BASE.multiply(privKey).toAffine();
  return {
    privateKey: fieldToBytes(privKey),
    publicKey: { x: P.x, y: P.y },
  };
}

/** Derive public key from private key bytes. */
export function getPublicKey(privateKey: Uint8Array): { x: bigint; y: bigint } {
  const scalar = bytesToField(privateKey) % GRUMPKIN_N;
  return grumpkin.ProjectivePoint.BASE.multiply(scalar).toAffine();
}

// ─── Schnorr Signing ─────────────────────────────────────────────────────────

export interface SchnorrSignature {
  s: Uint8Array; // 32 bytes
  e: Uint8Array; // 32 bytes (raw Blake2s hash)
}

/**
 * Sign a message using Schnorr on Grumpkin.
 * Compatible with Barretenberg/Noir's schnorr::verify_signature.
 */
export function schnorrSign(
  privateKey: Uint8Array,
  message: Uint8Array,
): SchnorrSignature {
  const privKey = bytesToField(privateKey) % GRUMPKIN_N;
  const G = grumpkin.ProjectivePoint.BASE;
  const P = G.multiply(privKey).toAffine();

  // Random nonce k
  const kBytes = getRandomBytes(32);
  let k = bytesToField(kBytes) % GRUMPKIN_N;
  if (k === 0n) k = 1n;

  const R = G.multiply(k).toAffine();

  // Challenge: e = Blake2s(PedersenHash([R.x, P.x, P.y]) || message)
  const compressed = pedersenHash([R.x, P.x, P.y]);
  const eInput = concatBytes(fieldToBytes(compressed), message);
  const eBytes = blake2s(eInput);

  // e as scalar
  let e = bytesToField(eBytes) % GRUMPKIN_N;

  // s = k - privKey * e (mod n)
  let s = (k - privKey * e) % GRUMPKIN_N;
  if (s < 0n) s += GRUMPKIN_N;

  return { s: fieldToBytes(s), e: eBytes };
}

// ─── Schnorr Verification ────────────────────────────────────────────────────

/**
 * Verify a Schnorr signature on Grumpkin.
 * Compatible with Barretenberg/Noir's schnorr::verify_signature.
 */
export function schnorrVerify(
  publicKey: { x: bigint; y: bigint },
  signature: SchnorrSignature,
  message: Uint8Array,
): boolean {
  try {
    const G = grumpkin.ProjectivePoint.BASE;
    const P = grumpkin.ProjectivePoint.fromAffine(publicKey);

    const e = bytesToField(signature.e) % GRUMPKIN_N;
    const s = bytesToField(signature.s) % GRUMPKIN_N;

    if (s === 0n || e === 0n) return false;

    // Reconstruct R = s*G + e*P
    const R = G.multiply(s).add(P.multiply(e)).toAffine();

    // Recompute challenge
    const compressed = pedersenHash([R.x, publicKey.x, publicKey.y]);
    const eInput = concatBytes(fieldToBytes(compressed), message);
    const targetE = blake2s(eInput);

    // Byte-level comparison (matches Barretenberg)
    for (let i = 0; i < 32; i++) {
      if (signature.e[i] !== targetE[i]) return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ─── Serialization Helpers (for circuit witness format) ──────────────────────

/** Format signature for the Noir circuit witness. */
export function signatureToWitness(
  publicKey: { x: bigint; y: bigint },
  signature: SchnorrSignature,
  message: Uint8Array,
): {
  pubkey_x: string;
  pubkey_y: string;
  signature: number[];
  msg: number[];
} {
  return {
    pubkey_x:
      "0x" + publicKey.x.toString(16).padStart(64, "0"),
    pubkey_y:
      "0x" + publicKey.y.toString(16).padStart(64, "0"),
    signature: [...Array.from(signature.s), ...Array.from(signature.e)],
    msg: Array.from(message),
  };
}
