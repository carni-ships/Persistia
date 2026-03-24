// npm install arweave
import Arweave from "arweave";

const arweave = Arweave.init({ host: "arweave.net" });
// In real version: fetch latest Merkle root from DO logs and post to Arweave
console.log("Run this after deploy to anchor Merkle root");