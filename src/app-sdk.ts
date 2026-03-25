// ─── Persistia App SDK ────────────────────────────────────────────────────────
// Served at /app/sdk.js — provides a client-side library for on-chain apps
// to interact with their backing smart contract.

export const APP_SDK_JS = `
/**
 * Persistia App SDK v0.1
 * Include via: <script src="/app/sdk.js"></script>
 *
 * Usage:
 *   const app = new PersistiaApp({ contract: "abc123...", node: "https://..." });
 *   const result = await app.query("get_count");
 *   await app.call("increment", new Uint8Array(), keypair);
 */
(function(global) {
  'use strict';

  class PersistiaApp {
    constructor(opts = {}) {
      this.contract = opts.contract || null;
      this.node = opts.node || location.origin;
      this.shard = opts.shard || new URLSearchParams(location.search).get('shard') || 'global-world';
      this._ws = null;
      this._listeners = new Map();
    }

    // ─── Queries (read-only, no signature needed) ─────────────────────
    async query(method, argsBytes) {
      const params = new URLSearchParams({
        address: this.contract,
        method,
        shard: this.shard,
      });
      if (argsBytes && argsBytes.length > 0) {
        params.set('args', btoa(String.fromCharCode(...argsBytes)));
      }
      const res = await fetch(this.node + '/contract/query?' + params);
      const data = await res.json();
      if (data.return_data) {
        data.return_bytes = Uint8Array.from(atob(data.return_data), c => c.charCodeAt(0));
      }
      return data;
    }

    // ─── Calls (state-mutating, requires signed event) ────────────────
    async call(method, argsBytes, keypair) {
      const payload = {
        contract: this.contract,
        method,
      };
      if (argsBytes && argsBytes.length > 0) {
        payload.args_b64 = btoa(String.fromCharCode(...argsBytes));
      }
      const event = {
        type: 'contract.call',
        payload,
        pubkey: keypair.pubkey,
        timestamp: Date.now(),
      };
      // Sign if keypair has sign method
      if (keypair.sign) {
        const msg = JSON.stringify({ type: event.type, payload: event.payload, timestamp: event.timestamp });
        event.signature = await keypair.sign(msg);
      }
      const res = await fetch(this.node + '/contract/call?shard=' + this.shard, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
      });
      return res.json();
    }

    // ─── Contract info ────────────────────────────────────────────────
    async info() {
      const res = await fetch(this.node + '/contract/info?address=' + this.contract + '&shard=' + this.shard);
      return res.json();
    }

    // ─── WebSocket subscriptions ──────────────────────────────────────
    connect() {
      if (this._ws) return;
      const wsUrl = this.node.replace(/^http/, 'ws') + '/?shard=' + this.shard;
      this._ws = new WebSocket(wsUrl);
      this._ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          // Emit to type-specific listeners
          const handlers = this._listeners.get(msg.type) || [];
          handlers.forEach(fn => fn(msg));
          // Emit to wildcard listeners
          const all = this._listeners.get('*') || [];
          all.forEach(fn => fn(msg));
        } catch {}
      };
      this._ws.onclose = () => { this._ws = null; };
    }

    on(eventType, handler) {
      if (!this._listeners.has(eventType)) this._listeners.set(eventType, []);
      this._listeners.get(eventType).push(handler);
      return this;
    }

    disconnect() {
      if (this._ws) { this._ws.close(); this._ws = null; }
    }

    // ─── Wallet helpers ───────────────────────────────────────────────
    async getBalance(address, denom) {
      const params = new URLSearchParams({ address, shard: this.shard });
      if (denom) params.set('denom', denom);
      const res = await fetch(this.node + '/wallet/balance?' + params);
      return res.json();
    }

    async faucet(pubkey, amount) {
      const res = await fetch(this.node + '/wallet/faucet?shard=' + this.shard, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pubkey, amount }),
      });
      return res.json();
    }

    // ─── App file listing ─────────────────────────────────────────────
    async listFiles() {
      const res = await fetch(this.node + '/app/' + this.contract + '/_manifest?shard=' + this.shard);
      return res.json();
    }
  }

  // ─── Ed25519 Key Helper (uses SubtleCrypto) ──────────────────────
  PersistiaApp.generateKeypair = async function() {
    const key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const pubRaw = await crypto.subtle.exportKey('raw', key.publicKey);
    const pubkey = btoa(String.fromCharCode(...new Uint8Array(pubRaw)));
    return {
      pubkey,
      publicKey: key.publicKey,
      privateKey: key.privateKey,
      sign: async (msg) => {
        const data = new TextEncoder().encode(msg);
        const sig = await crypto.subtle.sign('Ed25519', key.privateKey, data);
        return btoa(String.fromCharCode(...new Uint8Array(sig)));
      },
    };
  };

  global.PersistiaApp = PersistiaApp;
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
`;
