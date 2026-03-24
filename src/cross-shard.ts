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
