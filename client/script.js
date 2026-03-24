// ─── Persistia Client v0.2 ────────────────────────────────────────────────────

class PersistiaClient {
  constructor(workerUrl) {
    this.url = workerUrl;
    this.ws = null;
    this.keyPair = null;
    this.pubkeyB64 = "";

    // World state
    this.blocks = new Map(); // "x,z" → blockType
    this.inventory = {};
    this.ledgerSeq = 0;

    // Player
    this.playerX = 0;
    this.playerZ = 0;
    this.selectedBlock = 1;

    // Cursor (grid coords under mouse)
    this.cursorX = 0;
    this.cursorZ = 0;

    // Canvas
    this.canvas = document.getElementById("c");
    this.ctx = this.canvas.getContext("2d");
    this.cellSize = 24;

    // Consensus state
    this.consensusRound = 0;
    this.activeNodes = 0;
  }

  // ─── Init ──────────────────────────────────────────────────────────────

  async init() {
    this.setupCanvas();
    this.setupControls();
    this.renderLoop();

    try {
      await this.loadOrCreateKeys();
      this.connect();
    } catch (e) {
      console.error("Crypto init failed (need secure context — use localhost, not file://):", e);
      document.getElementById("status").textContent = "Crypto unavailable (use localhost)";
      document.getElementById("status").className = "hud-red";
    }
  }

  // ─── Ed25519 Key Management ────────────────────────────────────────────

  async loadOrCreateKeys() {
    const stored = localStorage.getItem("persistia_keys");
    if (stored) {
      try {
        const { pub, priv } = JSON.parse(stored);
        const pubBytes = this.b64ToBytes(pub);
        const privBytes = this.b64ToBytes(priv);
        this.keyPair = {
          publicKey: await crypto.subtle.importKey("raw", pubBytes, "Ed25519", true, ["verify"]),
          privateKey: await crypto.subtle.importKey("pkcs8", privBytes, "Ed25519", true, ["sign"]),
        };
        this.pubkeyB64 = pub;
      } catch (e) {
        console.warn("Stored keys invalid, regenerating:", e);
        localStorage.removeItem("persistia_keys");
        return this.loadOrCreateKeys();
      }
    } else {
      this.keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
      const pubRaw = await crypto.subtle.exportKey("raw", this.keyPair.publicKey);
      const privPkcs8 = await crypto.subtle.exportKey("pkcs8", this.keyPair.privateKey);
      this.pubkeyB64 = this.bytesToB64(new Uint8Array(pubRaw));
      localStorage.setItem("persistia_keys", JSON.stringify({
        pub: this.pubkeyB64,
        priv: this.bytesToB64(new Uint8Array(privPkcs8)),
      }));
    }
    document.getElementById("pubkey").textContent = this.pubkeyB64.slice(0, 16) + "...";
  }

  async sign(data) {
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const sig = await crypto.subtle.sign("Ed25519", this.keyPair.privateKey, encoded);
    return this.bytesToB64(new Uint8Array(sig));
  }

  // ─── Actions (signed + submitted) ─────────────────────────────────────

  async submitAction(type, payload) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    const timestamp = Date.now();
    const dataToSign = { type, payload, timestamp };
    const signature = await this.sign(dataToSign);

    this.ws.send(JSON.stringify({
      type: "submit",
      event: {
        type,
        payload,
        pubkey: this.pubkeyB64,
        signature,
        timestamp,
      },
    }));
  }

  async submitCraft(recipe) {
    await this.submitAction("craft", { recipe });
  }

  // ─── WebSocket ────────────────────────────────────────────────────────

  connect() {
    const wsUrl = this.url.replace(/^http/, "ws");
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      document.getElementById("status").textContent = "Connected";
      document.getElementById("status").className = "hud-green";
      this.ws.send(JSON.stringify({ type: "join", pubkey: this.pubkeyB64 }));
    };

    this.ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        this.handleMessage(msg);
      } catch (err) {
        console.error("Bad message:", err);
      }
    };

    this.ws.onclose = () => {
      document.getElementById("status").textContent = "Disconnected — reconnecting...";
      document.getElementById("status").className = "hud-yellow";
      setTimeout(() => this.connect(), 2000);
    };

    this.ws.onerror = () => {
      document.getElementById("status").textContent = "Error";
      document.getElementById("status").className = "hud-red";
    };
  }

  handleMessage(msg) {
    switch (msg.type) {
      case "state":
        // Full state sync on join
        this.blocks.clear();
        for (const b of msg.blocks) {
          this.blocks.set(`${b.x},${b.z}`, b.block_type);
        }
        this.inventory = msg.inventory || {};
        this.ledgerSeq = msg.seq || 0;
        if (msg.consensus) {
          this.consensusRound = msg.consensus.round || 0;
          this.activeNodes = msg.consensus.active_nodes || 0;
        }
        this.updateUI();
        break;

      case "event":
        // Legacy direct-apply event
        this.applyEvent(msg.event);
        break;

      case "pending":
        // Optimistic: event accepted into pending pool, not yet finalized
        this.applyEvent(msg.event);
        break;

      case "finalized":
        // Consensus-confirmed event
        this.ledgerSeq = msg.event.consensus_seq || this.ledgerSeq;
        // Event may already be applied optimistically — just update seq
        this.updateUI();
        break;

      case "commit":
        // A round was committed
        this.ledgerSeq = msg.finalized_seq || this.ledgerSeq;
        this.consensusRound = msg.round || this.consensusRound;
        this.updateUI();
        break;

      case "result":
        if (!msg.ok) {
          console.warn("Action rejected:", msg.error);
        }
        break;

      case "error":
        console.error("Server:", msg.message);
        break;
    }
  }

  applyEvent(event) {
    this.ledgerSeq = event.seq || this.ledgerSeq;

    switch (event.type) {
      case "place":
        this.blocks.set(`${event.payload.x},${event.payload.z}`, event.payload.block);
        if (event.pubkey === this.pubkeyB64) {
          const item = this.blockName(event.payload.block);
          this.inventory[item] = (this.inventory[item] || 0) - 1;
          if (this.inventory[item] <= 0) delete this.inventory[item];
        }
        break;

      case "break": {
        const key = `${event.payload.x},${event.payload.z}`;
        const blockType = this.blocks.get(key);
        this.blocks.delete(key);
        if (event.pubkey === this.pubkeyB64 && blockType !== undefined) {
          const item = this.blockName(blockType);
          this.inventory[item] = (this.inventory[item] || 0) + 1;
        }
        break;
      }

      case "craft":
        // Re-fetch inventory for accuracy after craft
        if (event.pubkey === this.pubkeyB64) {
          this.fetchInventory();
        }
        break;
    }

    this.updateUI();
  }

  async fetchInventory() {
    try {
      const res = await fetch(`${this.url}/inventory?pubkey=${encodeURIComponent(this.pubkeyB64)}`);
      const data = await res.json();
      this.inventory = data.inventory || {};
      this.updateUI();
    } catch { /* offline */ }
  }

  // ─── UI Updates ───────────────────────────────────────────────────────

  updateUI() {
    // Inventory
    const items = Object.entries(this.inventory)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `${k}: ${v}`)
      .join("   ");
    document.getElementById("inv").textContent = items || "(empty)";

    // Seq + consensus info
    const seqText = this.activeNodes > 0
      ? `${this.ledgerSeq} (R${this.consensusRound}, ${this.activeNodes} nodes)`
      : `${this.ledgerSeq}`;
    document.getElementById("seq").textContent = seqText;
  }

  // ─── Rendering ────────────────────────────────────────────────────────

  setupCanvas() {
    const resize = () => {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);
  }

  renderLoop() {
    this.render();
    requestAnimationFrame(() => this.renderLoop());
  }

  render() {
    const ctx = this.ctx;
    const cs = this.cellSize;
    const w = this.canvas.width;
    const h = this.canvas.height;

    // Clear
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, w, h);

    // Camera: center on player
    const camX = Math.floor(w / 2) - this.playerX * cs - cs / 2;
    const camZ = Math.floor(h / 2) - this.playerZ * cs - cs / 2;

    // Visible range
    const startX = Math.floor(-camX / cs) - 1;
    const startZ = Math.floor(-camZ / cs) - 1;
    const endX = startX + Math.ceil(w / cs) + 2;
    const endZ = startZ + Math.ceil(h / cs) + 2;

    // Grid lines
    ctx.strokeStyle = "#161b22";
    ctx.lineWidth = 0.5;
    for (let x = startX; x <= endX; x++) {
      const sx = x * cs + camX;
      ctx.beginPath();
      ctx.moveTo(sx, 0);
      ctx.lineTo(sx, h);
      ctx.stroke();
    }
    for (let z = startZ; z <= endZ; z++) {
      const sz = z * cs + camZ;
      ctx.beginPath();
      ctx.moveTo(0, sz);
      ctx.lineTo(w, sz);
      ctx.stroke();
    }

    // Blocks
    for (const [key, blockType] of this.blocks) {
      const [bx, bz] = key.split(",").map(Number);
      if (bx < startX - 1 || bx > endX + 1 || bz < startZ - 1 || bz > endZ + 1) continue;
      ctx.fillStyle = this.blockColor(blockType);
      ctx.fillRect(bx * cs + camX + 1, bz * cs + camZ + 1, cs - 2, cs - 2);
    }

    // Player
    ctx.fillStyle = "#00ff88";
    ctx.shadowColor = "#00ff88";
    ctx.shadowBlur = 8;
    ctx.fillRect(
      this.playerX * cs + camX + 3,
      this.playerZ * cs + camZ + 3,
      cs - 6, cs - 6
    );
    ctx.shadowBlur = 0;

    // Cursor highlight
    const cx = this.cursorX * cs + camX;
    const cz = this.cursorZ * cs + camZ;
    ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
    ctx.lineWidth = 2;
    ctx.strokeRect(cx, cz, cs, cs);

    // Show selected block preview at cursor
    ctx.fillStyle = this.blockColor(this.selectedBlock);
    ctx.globalAlpha = 0.25;
    ctx.fillRect(cx + 1, cz + 1, cs - 2, cs - 2);
    ctx.globalAlpha = 1;

    // Origin marker
    ctx.fillStyle = "rgba(255,255,255,0.08)";
    ctx.fillRect(camX - 1, camZ - 1, cs + 2, cs + 2);
  }

  blockColor(type) {
    return {
      1: "#8B6914", // dirt
      2: "#808080", // stone
      3: "#654321", // wood
      4: "#228B22", // grass
    }[type] || "#ff00ff";
  }

  blockName(type) {
    return { 1: "dirt", 2: "stone", 3: "wood", 4: "grass" }[type] || "unknown";
  }

  // ─── Controls ─────────────────────────────────────────────────────────

  setupControls() {
    document.addEventListener("keydown", (e) => {
      // Don't capture when typing in inputs
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;

      switch (e.key.toLowerCase()) {
        case "w": this.playerZ--; break;
        case "s": this.playerZ++; break;
        case "a": this.playerX--; break;
        case "d": this.playerX++; break;
        case "1": this.setSelectedBlock(1); break;
        case "2": this.setSelectedBlock(2); break;
        case "3": this.setSelectedBlock(3); break;
        case "4": this.setSelectedBlock(4); break;
      }
    });

    this.canvas.addEventListener("mousemove", (e) => {
      const cs = this.cellSize;
      const camX = Math.floor(this.canvas.width / 2) - this.playerX * cs - cs / 2;
      const camZ = Math.floor(this.canvas.height / 2) - this.playerZ * cs - cs / 2;
      this.cursorX = Math.floor((e.clientX - camX) / cs);
      this.cursorZ = Math.floor((e.clientY - camZ) / cs);
    });

    this.canvas.addEventListener("click", () => {
      this.submitAction("place", { x: this.cursorX, z: this.cursorZ, block: this.selectedBlock });
    });

    this.canvas.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      this.submitAction("break", { x: this.cursorX, z: this.cursorZ });
    });
  }

  setSelectedBlock(n) {
    this.selectedBlock = n;
    document.querySelectorAll(".block-btn").forEach((btn) => {
      btn.classList.toggle("active", parseInt(btn.dataset.block) === n);
    });
    document.getElementById("selected-block").textContent = this.blockName(n);
  }

  // ─── Helpers ──────────────────────────────────────────────────────────

  bytesToB64(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }

  b64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
}

// ─── Global functions (called from HTML) ─────────────────────────────────────

let client;

function setUrl() {
  const current = localStorage.getItem("persistia_url") || "http://localhost:8787";
  const url = prompt("Enter Persistia node URL:", current);
  if (url && url !== current) {
    localStorage.setItem("persistia_url", url);
    location.reload();
  }
}

function selectBlock(n) {
  if (client) client.setSelectedBlock(n);
}

function doCraft(recipe) {
  if (client) client.submitCraft(recipe);
}

// ─── Boot ────────────────────────────────────────────────────────────────────

const WORLD_URL = localStorage.getItem("persistia_url") || "http://localhost:8787";
client = new PersistiaClient(WORLD_URL);
client.init().catch(console.error);
