//! Persistia Token Standard (PTS-20 / PTS-721)
//!
//! A single contract that supports both fungible tokens (ERC-20 style)
//! and non-fungible tokens (ERC-721 style). Each token is identified by
//! a `token_id`. Fungible tokens have `is_nft = false` and track balances.
//! NFTs have `is_nft = true` and track individual ownership.
//!
//! Storage layout (all keys prefixed with token_id):
//!   meta:{token_id}        → JSON { name, symbol, decimals, is_nft, total_supply, creator }
//!   bal:{token_id}:{owner} → u64 (fungible balance)
//!   allow:{token_id}:{owner}:{spender} → u64 (fungible allowance)
//!   nft:{token_id}:{nft_id} → owner pubkey (NFT owner)
//!   nft_meta:{token_id}:{nft_id} → JSON metadata (NFT metadata)
//!   nft_count:{token_id}   → u64 (total NFTs minted)
//!
//! All methods take JSON input via register 0.
//! Cross-contract callable: other contracts can call these methods directly.

#![no_std]

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use persistia_sdk::*;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn key(parts: &[&str]) -> Vec<u8> {
    let joined = parts.join(":");
    Vec::from(joined.as_bytes())
}

fn read_u64_key(k: &[u8]) -> u64 {
    storage_get(k)
        .map(|v| {
            let mut buf = [0u8; 8];
            let len = v.len().min(8);
            buf[..len].copy_from_slice(&v[..len]);
            u64::from_le_bytes(buf)
        })
        .unwrap_or(0)
}

fn write_u64_key(k: &[u8], val: u64) {
    storage_set(k, &val.to_le_bytes());
}

fn read_string_key(k: &[u8]) -> Option<String> {
    storage_get(k).map(|v| String::from_utf8(v).unwrap_or_default())
}

/// Simple JSON string extractor. Finds `"key":"value"` in a JSON string.
fn json_str(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", field);
    if let Some(start) = json.find(&pattern) {
        let val_start = start + pattern.len();
        if let Some(end) = json[val_start..].find('"') {
            return Some(String::from(&json[val_start..val_start + end]));
        }
    }
    None
}

/// Extract u64 from JSON: `"key":123`
fn json_u64(json: &str, field: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern) {
        let val_start = start + pattern.len();
        let rest = &json[val_start..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().ok()
    } else {
        None
    }
}

/// Extract bool from JSON: `"key":true`
fn json_bool(json: &str, field: &str) -> Option<bool> {
    let pattern = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern) {
        let val_start = start + pattern.len();
        let rest = &json[val_start..];
        if rest.starts_with("true") { return Some(true); }
        if rest.starts_with("false") { return Some(false); }
    }
    None
}

fn return_json(json: &str) {
    set_return_data(json.as_bytes());
}

fn return_error(msg: &str) {
    let json = format!(r#"{{"error":"{}"}}"#, msg);
    set_return_data(json.as_bytes());
}

fn return_ok(msg: &str) {
    let json = format!(r#"{{"ok":true,"result":"{}"}}"#, msg);
    set_return_data(json.as_bytes());
}

// ─── Token Creation ───────────────────────────────────────────────────────────

/// Create a new fungible token.
/// Input: {"token_id":"...", "name":"...", "symbol":"...", "decimals":18, "initial_supply":1000000}
#[no_mangle]
pub extern "C" fn create_token() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let name = json_str(json, "name").unwrap_or_else(|| String::from("Unnamed"));
    let symbol = json_str(json, "symbol").unwrap_or_else(|| String::from("???"));
    let decimals = json_u64(json, "decimals").unwrap_or(18);
    let initial_supply = json_u64(json, "initial_supply").unwrap_or(0);
    let caller = get_caller();

    // Check if already exists
    let meta_key = key(&["meta", &token_id]);
    if storage_get(&meta_key).is_some() {
        return_error("token already exists");
        return;
    }

    // Store metadata
    let meta = format!(
        r#"{{"name":"{}","symbol":"{}","decimals":{},"is_nft":false,"total_supply":{},"creator":"{}"}}"#,
        name, symbol, decimals, initial_supply, caller,
    );
    storage_set(&meta_key, meta.as_bytes());

    // Mint initial supply to creator
    if initial_supply > 0 {
        let bal_key = key(&["bal", &token_id, &caller]);
        write_u64_key(&bal_key, initial_supply);
    }

    log_msg(&format!("created token {} ({}) supply={}", token_id, symbol, initial_supply));
    return_ok(&token_id);
}

/// Create a new NFT collection.
/// Input: {"token_id":"...", "name":"...", "symbol":"..."}
#[no_mangle]
pub extern "C" fn create_nft_collection() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let name = json_str(json, "name").unwrap_or_else(|| String::from("Unnamed"));
    let symbol = json_str(json, "symbol").unwrap_or_else(|| String::from("???"));
    let caller = get_caller();

    let meta_key = key(&["meta", &token_id]);
    if storage_get(&meta_key).is_some() {
        return_error("collection already exists");
        return;
    }

    let meta = format!(
        r#"{{"name":"{}","symbol":"{}","decimals":0,"is_nft":true,"total_supply":0,"creator":"{}"}}"#,
        name, symbol, caller,
    );
    storage_set(&meta_key, meta.as_bytes());

    let count_key = key(&["nft_count", &token_id]);
    write_u64_key(&count_key, 0);

    log_msg(&format!("created NFT collection {} ({})", token_id, symbol));
    return_ok(&token_id);
}

// ─── Fungible Token Operations ────────────────────────────────────────────────

/// Transfer fungible tokens.
/// Input: {"token_id":"...", "to":"...", "amount":100}
#[no_mangle]
pub extern "C" fn transfer() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let to = match json_str(json, "to") {
        Some(t) => t,
        None => { return_error("missing to"); return; }
    };
    let amount = match json_u64(json, "amount") {
        Some(a) => a,
        None => { return_error("missing amount"); return; }
    };

    let caller = get_caller();
    let from_key = key(&["bal", &token_id, &caller]);
    let to_key = key(&["bal", &token_id, &to]);

    let from_bal = read_u64_key(&from_key);
    if from_bal < amount {
        return_error("insufficient balance");
        return;
    }

    write_u64_key(&from_key, from_bal - amount);
    write_u64_key(&to_key, read_u64_key(&to_key) + amount);

    return_ok("transferred");
}

/// Approve a spender to transfer tokens on your behalf.
/// Input: {"token_id":"...", "spender":"...", "amount":100}
#[no_mangle]
pub extern "C" fn approve() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let spender = match json_str(json, "spender") {
        Some(s) => s,
        None => { return_error("missing spender"); return; }
    };
    let amount = match json_u64(json, "amount") {
        Some(a) => a,
        None => { return_error("missing amount"); return; }
    };

    let caller = get_caller();
    let allow_key = key(&["allow", &token_id, &caller, &spender]);
    write_u64_key(&allow_key, amount);

    return_ok("approved");
}

/// Transfer tokens using allowance (transferFrom pattern).
/// Input: {"token_id":"...", "from":"...", "to":"...", "amount":100}
#[no_mangle]
pub extern "C" fn transfer_from() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let from = match json_str(json, "from") {
        Some(f) => f,
        None => { return_error("missing from"); return; }
    };
    let to = match json_str(json, "to") {
        Some(t) => t,
        None => { return_error("missing to"); return; }
    };
    let amount = match json_u64(json, "amount") {
        Some(a) => a,
        None => { return_error("missing amount"); return; }
    };

    let caller = get_caller();
    let allow_key = key(&["allow", &token_id, &from, &caller]);
    let allowance = read_u64_key(&allow_key);
    if allowance < amount {
        return_error("insufficient allowance");
        return;
    }

    let from_key = key(&["bal", &token_id, &from]);
    let from_bal = read_u64_key(&from_key);
    if from_bal < amount {
        return_error("insufficient balance");
        return;
    }

    write_u64_key(&allow_key, allowance - amount);
    write_u64_key(&from_key, from_bal - amount);
    let to_key = key(&["bal", &token_id, &to]);
    write_u64_key(&to_key, read_u64_key(&to_key) + amount);

    return_ok("transferred");
}

/// Mint new fungible tokens (creator only).
/// Input: {"token_id":"...", "to":"...", "amount":100}
#[no_mangle]
pub extern "C" fn mint() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let to = match json_str(json, "to") {
        Some(t) => t,
        None => { return_error("missing to"); return; }
    };
    let amount = match json_u64(json, "amount") {
        Some(a) => a,
        None => { return_error("missing amount"); return; }
    };

    // Check creator
    let meta_key = key(&["meta", &token_id]);
    let meta = match read_string_key(&meta_key) {
        Some(m) => m,
        None => { return_error("token not found"); return; }
    };
    let creator = json_str(&meta, "creator").unwrap_or_default();
    let caller = get_caller();
    if caller != creator {
        return_error("only creator can mint");
        return;
    }

    let to_key = key(&["bal", &token_id, &to]);
    write_u64_key(&to_key, read_u64_key(&to_key) + amount);

    // Update total supply in metadata
    let old_supply = json_u64(&meta, "total_supply").unwrap_or(0);
    let new_meta = meta.replace(
        &format!("\"total_supply\":{}", old_supply),
        &format!("\"total_supply\":{}", old_supply + amount),
    );
    storage_set(&meta_key, new_meta.as_bytes());

    return_ok("minted");
}

// ─── NFT Operations ───────────────────────────────────────────────────────────

/// Mint a new NFT in a collection (creator only).
/// Input: {"token_id":"...", "to":"...", "metadata":"..."}
/// Returns the NFT ID (sequential).
#[no_mangle]
pub extern "C" fn mint_nft() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let to = match json_str(json, "to") {
        Some(t) => t,
        None => { return_error("missing to"); return; }
    };
    let metadata = json_str(json, "metadata").unwrap_or_default();

    // Check creator
    let meta_key = key(&["meta", &token_id]);
    let meta = match read_string_key(&meta_key) {
        Some(m) => m,
        None => { return_error("collection not found"); return; }
    };
    if json_bool(&meta, "is_nft") != Some(true) {
        return_error("not an NFT collection");
        return;
    }
    let creator = json_str(&meta, "creator").unwrap_or_default();
    let caller = get_caller();
    if caller != creator {
        return_error("only creator can mint NFTs");
        return;
    }

    // Get next NFT ID
    let count_key = key(&["nft_count", &token_id]);
    let nft_id = read_u64_key(&count_key);
    let nft_id_str = format!("{}", nft_id);

    // Store owner
    let owner_key = key(&["nft", &token_id, &nft_id_str]);
    storage_set(&owner_key, to.as_bytes());

    // Store metadata
    if !metadata.is_empty() {
        let meta_nft_key = key(&["nft_meta", &token_id, &nft_id_str]);
        storage_set(&meta_nft_key, metadata.as_bytes());
    }

    // Increment count + total supply
    write_u64_key(&count_key, nft_id + 1);
    let old_supply = json_u64(&meta, "total_supply").unwrap_or(0);
    let new_meta = meta.replace(
        &format!("\"total_supply\":{}", old_supply),
        &format!("\"total_supply\":{}", old_supply + 1),
    );
    storage_set(&meta_key, new_meta.as_bytes());

    return_ok(&nft_id_str);
}

/// Transfer an NFT.
/// Input: {"token_id":"...", "nft_id":"...", "to":"..."}
#[no_mangle]
pub extern "C" fn transfer_nft() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let nft_id = match json_str(json, "nft_id") {
        Some(id) => id,
        None => { return_error("missing nft_id"); return; }
    };
    let to = match json_str(json, "to") {
        Some(t) => t,
        None => { return_error("missing to"); return; }
    };

    let owner_key = key(&["nft", &token_id, &nft_id]);
    let current_owner = match read_string_key(&owner_key) {
        Some(o) => o,
        None => { return_error("NFT not found"); return; }
    };

    let caller = get_caller();
    if caller != current_owner {
        return_error("not the owner");
        return;
    }

    storage_set(&owner_key, to.as_bytes());
    return_ok("transferred");
}

// ─── Queries ──────────────────────────────────────────────────────────────────

/// Get token metadata.
/// Input: {"token_id":"..."}
#[no_mangle]
pub extern "C" fn get_token_info() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let meta_key = key(&["meta", &token_id]);
    match read_string_key(&meta_key) {
        Some(meta) => return_json(&meta),
        None => return_error("token not found"),
    }
}

/// Get fungible balance.
/// Input: {"token_id":"...", "owner":"..."}
#[no_mangle]
pub extern "C" fn balance_of() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let owner = match json_str(json, "owner") {
        Some(o) => o,
        None => { return_error("missing owner"); return; }
    };
    let bal_key = key(&["bal", &token_id, &owner]);
    let balance = read_u64_key(&bal_key);
    let result = format!(r#"{{"balance":{}}}"#, balance);
    return_json(&result);
}

/// Get NFT owner.
/// Input: {"token_id":"...", "nft_id":"..."}
#[no_mangle]
pub extern "C" fn owner_of() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let nft_id = match json_str(json, "nft_id") {
        Some(id) => id,
        None => { return_error("missing nft_id"); return; }
    };
    let owner_key = key(&["nft", &token_id, &nft_id]);
    match read_string_key(&owner_key) {
        Some(owner) => {
            let result = format!(r#"{{"owner":"{}"}}"#, owner);
            return_json(&result);
        },
        None => return_error("NFT not found"),
    }
}

/// Get allowance.
/// Input: {"token_id":"...", "owner":"...", "spender":"..."}
#[no_mangle]
pub extern "C" fn allowance() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let token_id = match json_str(json, "token_id") {
        Some(id) => id,
        None => { return_error("missing token_id"); return; }
    };
    let owner = match json_str(json, "owner") {
        Some(o) => o,
        None => { return_error("missing owner"); return; }
    };
    let spender = match json_str(json, "spender") {
        Some(s) => s,
        None => { return_error("missing spender"); return; }
    };
    let allow_key = key(&["allow", &token_id, &owner, &spender]);
    let amount = read_u64_key(&allow_key);
    let result = format!(r#"{{"allowance":{}}}"#, amount);
    return_json(&result);
}
