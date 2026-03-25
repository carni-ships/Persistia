// ─── Cross-Shard Communication ────────────────────────────────────────────────
// Message passing between shards (Durable Object instances).
// Each shard is a PersistiaWorld DO identified by name.
//
// Messages are routed through the Worker entry point which can access
// any DO by name. Cross-shard messages include a proof of the source
// state so the receiving shard can verify without trusting the sender.

import { sha256 } from "./consensus";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CrossShardMessage {
  id: string;               // unique message ID
  source_shard: string;     // shard name of sender
  target_shard: string;     // shard name of receiver
  type: string;             // message type (e.g., "token.transfer", "contract.call")
  payload: any;             // message data
  source_state_root: string; // state commitment of source shard at time of send
  proof?: any;              // optional Merkle proof of relevant state
  timestamp: number;
  sender_pubkey: string;    // who initiated the cross-shard action
}

export interface CrossShardReceipt {
  message_id: string;
  status: "delivered" | "failed";
  result?: any;
  error?: string;
  target_state_root: string;
  timestamp: number;
}

// ─── Message Construction ─────────────────────────────────────────────────────

export async function createCrossShardMessage(
  sourceShard: string,
  targetShard: string,
  type: string,
  payload: any,
  sourceStateRoot: string,
  senderPubkey: string,
): Promise<CrossShardMessage> {
  const id = await sha256(`xshard:${sourceShard}:${targetShard}:${Date.now()}:${Math.random()}`);
  return {
    id,
    source_shard: sourceShard,
    target_shard: targetShard,
    type,
    payload,
    source_state_root: sourceStateRoot,
    timestamp: Date.now(),
    sender_pubkey: senderPubkey,
  };
}

// ─── Message Validation ───────────────────────────────────────────────────────

export function validateMessage(msg: CrossShardMessage): { ok: boolean; error?: string } {
  if (!msg.id) return { ok: false, error: "missing id" };
  if (!msg.source_shard) return { ok: false, error: "missing source_shard" };
  if (!msg.target_shard) return { ok: false, error: "missing target_shard" };
  if (!msg.type) return { ok: false, error: "missing type" };
  if (!msg.sender_pubkey) return { ok: false, error: "missing sender_pubkey" };
  if (msg.source_shard === msg.target_shard) return { ok: false, error: "cannot send to same shard" };
  return { ok: true };
}

// ─── Note-Based Cross-Shard Transfers (Miden-inspired) ───────────────────────
// Notes are richer than raw messages: they carry assets, have consumption scripts,
// and track nullifiers to prevent double-spend across shards.

export interface CrossShardNote {
  id: string;
  source_shard: string;
  target_shard: string;
  creator: string;
  recipient?: string;           // if set, only this address can consume
  asset_type: string;
  amount: string;
  script: string;               // consumption script (conditions for redemption)
  nullifier_seed: string;       // used to derive nullifier on consumption
  source_state_root: string;
  created_round: number;
  timestamp: number;
}

export async function createCrossShardNote(
  sourceShard: string,
  targetShard: string,
  creator: string,
  assetType: string,
  amount: string,
  recipient?: string,
  script?: string,
  sourceStateRoot?: string,
  createdRound?: number,
): Promise<CrossShardNote> {
  const nullifierSeed = await sha256(`nullifier_seed:${creator}:${assetType}:${amount}:${Date.now()}:${Math.random()}`);
  const id = await sha256(`xnote:${sourceShard}:${targetShard}:${nullifierSeed}`);
  return {
    id,
    source_shard: sourceShard,
    target_shard: targetShard,
    creator,
    recipient,
    asset_type: assetType,
    amount,
    script: script || "",
    nullifier_seed: nullifierSeed,
    source_state_root: sourceStateRoot || "",
    created_round: createdRound || 0,
    timestamp: Date.now(),
  };
}

export async function computeNullifier(noteId: string, consumer: string): Promise<string> {
  return sha256(`nullifier:${noteId}:${consumer}`);
}

export function validateNote(note: CrossShardNote): { ok: boolean; error?: string } {
  if (!note.id) return { ok: false, error: "missing id" };
  if (!note.source_shard || !note.target_shard) return { ok: false, error: "missing shard info" };
  if (!note.creator) return { ok: false, error: "missing creator" };
  if (!note.asset_type || !note.amount) return { ok: false, error: "missing asset info" };
  if (note.source_shard === note.target_shard) return { ok: false, error: "cannot send to same shard" };
  return { ok: true };
}
