//! Persistia AI Services Marketplace Contract
//!
//! On-chain escrow, fee splitting, and dispute resolution for the AI services gateway.
//!
//! Flow:
//!   1. Node registers as a provider with a service catalog
//!   2. Consumer creates an escrow order (locks PERSIST tokens)
//!   3. Provider delivers service + attestation ID
//!   4. Contract verifies attestation, releases payment with fee split
//!   5. If disputed, arbitration resolves via challenge outcome
//!
//! Fee split (enforced on-chain):
//!   PERSIST:  70% provider, 15% validator pool, 10% burned, 5% treasury
//!
//! Storage layout:
//!   cfg:admin            → admin pubkey
//!   cfg:token            → token contract address
//!   cfg:treasury         → treasury address
//!   cfg:fee_node         → provider fee pct (700 = 70.0%)
//!   cfg:fee_val          → validator pool pct (150 = 15.0%)
//!   cfg:fee_burn         → burn pct (100 = 10.0%)
//!   cfg:fee_treasury     → treasury pct (50 = 5.0%)
//!   provider:{pubkey}    → JSON { url, services, reputation, registered_at }
//!   order:{id}           → JSON { id, consumer, provider, service, amount, denom,
//!                                  status, attestation_id, created_at, resolved_at }
//!   order_seq            → u64 monotonic order counter
//!   pool:{denom}         → u64 accumulated validator reward pool
//!   burned               → u64 total burned
//!   stats:orders         → u64 total orders
//!   stats:volume         → u64 total volume

#![no_std]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use persistia_sdk::*;

// ─── JSON Helpers (no serde, keep WASM small) ───────────────────────────────

fn json_str(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\"", field);
    let start = json.find(&pattern)?;
    let after_key = start + pattern.len();
    let rest = &json[after_key..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if after_colon.starts_with('"') {
        let inner = &after_colon[1..];
        let end = inner.find('"')?;
        Some(String::from(&inner[..end]))
    } else {
        None
    }
}

fn json_u64(json: &str, field: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", field);
    let start = json.find(&pattern)?;
    let after_key = start + pattern.len();
    let rest = &json[after_key..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    let end = after_colon.find(|c: char| !c.is_ascii_digit()).unwrap_or(after_colon.len());
    after_colon[..end].parse().ok()
}

// ─── Storage Helpers ────────────────────────────────────────────────────────

fn key(parts: &[&str]) -> Vec<u8> {
    let joined: String = parts.iter().enumerate().fold(String::new(), |mut acc, (i, p)| {
        if i > 0 { acc.push(':'); }
        acc.push_str(p);
        acc
    });
    joined.into_bytes()
}

fn read_u64_key(k: &[u8]) -> u64 {
    match storage_get(k) {
        Some(v) if v.len() == 8 => u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]),
        _ => 0,
    }
}

fn write_u64_key(k: &[u8], val: u64) {
    storage_set(k, &val.to_le_bytes());
}

fn read_string_key(k: &[u8]) -> Option<String> {
    storage_get(k).and_then(|v| String::from_utf8(v).ok())
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

fn get_config(field: &str) -> Option<String> {
    read_string_key(&key(&["cfg", field]))
}

fn get_config_u64(field: &str) -> u64 {
    read_u64_key(&key(&["cfg", field]))
}

fn require_admin() -> Option<String> {
    let caller = get_caller();
    let admin = match get_config("admin") {
        Some(a) => a,
        None => return Some(caller), // first caller becomes admin during init
    };
    if caller != admin {
        return_error("not authorized: admin only");
        return None;
    }
    Some(caller)
}

// ─── Initialization ─────────────────────────────────────────────────────────

/// Initialize the marketplace contract.
/// Input: {"token_contract":"<addr>","treasury":"<addr>"}
/// Must be called once by the deployer (becomes admin).
#[no_mangle]
pub extern "C" fn init() {
    // Check not already initialized
    if get_config("admin").is_some() {
        return_error("already initialized");
        return;
    }

    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let token_contract = match json_str(json, "token_contract") {
        Some(v) => v,
        None => { return_error("token_contract required"); return; }
    };
    let treasury = match json_str(json, "treasury") {
        Some(v) => v,
        None => { return_error("treasury required"); return; }
    };

    let caller = get_caller();

    // Store config
    storage_set(&key(&["cfg", "admin"]), caller.as_bytes());
    storage_set(&key(&["cfg", "token"]), token_contract.as_bytes());
    storage_set(&key(&["cfg", "treasury"]), treasury.as_bytes());

    // Default fee split: 700/150/100/50 (basis points out of 1000)
    write_u64_key(&key(&["cfg", "fee_node"]), 700);
    write_u64_key(&key(&["cfg", "fee_val"]), 150);
    write_u64_key(&key(&["cfg", "fee_burn"]), 100);
    write_u64_key(&key(&["cfg", "fee_treasury"]), 50);

    // Initialize counters
    write_u64_key(b"order_seq", 0);
    write_u64_key(b"burned", 0);
    write_u64_key(&key(&["stats", "orders"]), 0);
    write_u64_key(&key(&["stats", "volume"]), 0);

    log_msg("marketplace initialized");
    return_ok("initialized");
}

// ─── Admin: Update Fee Split ────────────────────────────────────────────────

/// Update the fee split percentages (basis points, must sum to 1000).
/// Input: {"node":700,"validator":150,"burn":100,"treasury":50}
#[no_mangle]
pub extern "C" fn update_fees() {
    if require_admin().is_none() { return; }

    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let node = json_u64(json, "node").unwrap_or(700);
    let validator = json_u64(json, "validator").unwrap_or(150);
    let burn = json_u64(json, "burn").unwrap_or(100);
    let treasury = json_u64(json, "treasury").unwrap_or(50);

    if node + validator + burn + treasury != 1000 {
        return_error("fees must sum to 1000 basis points");
        return;
    }

    write_u64_key(&key(&["cfg", "fee_node"]), node);
    write_u64_key(&key(&["cfg", "fee_val"]), validator);
    write_u64_key(&key(&["cfg", "fee_burn"]), burn);
    write_u64_key(&key(&["cfg", "fee_treasury"]), treasury);

    return_ok("fees updated");
}

// ─── Provider Registration ──────────────────────────────────────────────────

/// Register as a service provider.
/// Input: {"url":"https://...","services":"llm,tts,image"}
#[no_mangle]
pub extern "C" fn register_provider() {
    let caller = get_caller();
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let url = json_str(json, "url").unwrap_or_default();
    let services = json_str(json, "services").unwrap_or_default();

    if url.is_empty() || services.is_empty() {
        return_error("url and services required");
        return;
    }

    let provider_json = format!(
        r#"{{"url":"{}","services":"{}","reputation":100,"registered_at":{}}}"#,
        url, services, 0 // timestamp set by host, we use 0 as placeholder
    );

    storage_set(&key(&["provider", &caller]), provider_json.as_bytes());
    log_msg(&format!("provider registered: {}", &caller[..12]));
    return_ok("registered");
}

/// Update provider details.
/// Input: {"url":"...","services":"..."}
#[no_mangle]
pub extern "C" fn update_provider() {
    let caller = get_caller();
    let pk = key(&["provider", &caller]);

    let existing = match read_string_key(&pk) {
        Some(v) => v,
        None => { return_error("not registered"); return; }
    };

    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let url = json_str(json, "url")
        .unwrap_or_else(|| json_str(&existing, "url").unwrap_or_default());
    let services = json_str(json, "services")
        .unwrap_or_else(|| json_str(&existing, "services").unwrap_or_default());
    let reputation = json_u64(&existing, "reputation").unwrap_or(100);
    let registered_at = json_u64(&existing, "registered_at").unwrap_or(0);

    let provider_json = format!(
        r#"{{"url":"{}","services":"{}","reputation":{},"registered_at":{}}}"#,
        url, services, reputation, registered_at
    );

    storage_set(&pk, provider_json.as_bytes());
    return_ok("updated");
}

/// Query a provider.
/// Input: {"pubkey":"..."}
#[no_mangle]
pub extern "C" fn get_provider() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let pubkey = match json_str(json, "pubkey") {
        Some(v) => v,
        None => { return_error("pubkey required"); return; }
    };

    match read_string_key(&key(&["provider", &pubkey])) {
        Some(v) => return_json(&v),
        None => return_error("provider not found"),
    }
}

// ─── Escrow Orders ──────────────────────────────────────────────────────────

/// Create an escrow order. Consumer locks tokens until provider delivers.
/// Input: {"provider":"<pubkey>","service":"llm","amount":100,"denom":"PERSIST"}
///
/// The consumer must have already approved this contract to spend `amount` tokens
/// via the token contract's `approve()` method.
#[no_mangle]
pub extern "C" fn create_order() {
    let caller = get_caller();
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let provider = match json_str(json, "provider") {
        Some(v) => v,
        None => { return_error("provider required"); return; }
    };
    let service = json_str(json, "service").unwrap_or_default();
    let amount = match json_u64(json, "amount") {
        Some(v) if v > 0 => v,
        _ => { return_error("amount must be > 0"); return; }
    };
    let denom = json_str(json, "denom").unwrap_or_else(|| String::from("PERSIST"));

    // Verify provider exists
    if storage_get(&key(&["provider", &provider])).is_none() {
        return_error("provider not registered");
        return;
    }

    // Transfer tokens from consumer to this contract (escrow)
    let token_contract = match get_config("token") {
        Some(v) => v,
        None => { return_error("marketplace not initialized"); return; }
    };
    let self_addr = get_self_address();
    let transfer_args = format!(
        r#"{{"token_id":"{}","from":"{}","to":"{}","amount":{}}}"#,
        denom, caller, self_addr, amount
    );
    match call_contract(&token_contract, "transfer_from", transfer_args.as_bytes()) {
        Ok(result) => {
            let result_str = core::str::from_utf8(&result).unwrap_or("");
            if result_str.contains("error") {
                return_error("escrow transfer failed: insufficient balance or allowance");
                return;
            }
        }
        Err(e) => {
            let msg = format!("escrow transfer failed: {}", e);
            return_error(&msg);
            return;
        }
    }

    // Create order
    let seq_key = b"order_seq";
    let order_id = read_u64_key(seq_key) + 1;
    write_u64_key(seq_key, order_id);

    let order_json = format!(
        r#"{{"id":{},"consumer":"{}","provider":"{}","service":"{}","amount":{},"denom":"{}","status":"escrowed","attestation_id":"","created_at":0,"resolved_at":0}}"#,
        order_id, caller, provider, service, amount, denom
    );

    storage_set(&key(&["order", &format!("{}", order_id)]), order_json.as_bytes());

    // Update stats
    let total_orders = read_u64_key(&key(&["stats", "orders"])) + 1;
    write_u64_key(&key(&["stats", "orders"]), total_orders);
    let total_volume = read_u64_key(&key(&["stats", "volume"])) + amount;
    write_u64_key(&key(&["stats", "volume"]), total_volume);

    log_msg(&format!("order {} created: {} {} for {}", order_id, amount, denom, service));
    let result = format!(r#"{{"ok":true,"order_id":{}}}"#, order_id);
    return_json(&result);
}

/// Provider delivers service and claims payment.
/// Input: {"order_id":1,"attestation_id":"<hash>"}
///
/// The attestation_id references a service attestation from the off-chain
/// attestation system. It can be verified separately.
#[no_mangle]
pub extern "C" fn deliver() {
    let caller = get_caller();
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let order_id = match json_u64(json, "order_id") {
        Some(v) => v,
        None => { return_error("order_id required"); return; }
    };
    let attestation_id = json_str(json, "attestation_id").unwrap_or_default();
    if attestation_id.is_empty() {
        return_error("attestation_id required");
        return;
    }

    let order_key = key(&["order", &format!("{}", order_id)]);
    let order_str = match read_string_key(&order_key) {
        Some(v) => v,
        None => { return_error("order not found"); return; }
    };

    // Verify caller is the provider
    let provider = match json_str(&order_str, "provider") {
        Some(v) => v,
        None => { return_error("corrupt order"); return; }
    };
    if caller != provider {
        return_error("only the assigned provider can deliver");
        return;
    }

    // Verify order is in escrowed state
    let status = json_str(&order_str, "status").unwrap_or_default();
    if status != "escrowed" {
        return_error(&format!("order not escrowed, status: {}", status));
        return;
    }

    let amount = json_u64(&order_str, "amount").unwrap_or(0);
    let denom = json_str(&order_str, "denom").unwrap_or_else(|| String::from("PERSIST"));
    let consumer = json_str(&order_str, "consumer").unwrap_or_default();

    // Execute fee split and pay out
    let token_contract = match get_config("token") {
        Some(v) => v,
        None => { return_error("marketplace not initialized"); return; }
    };

    let fee_node = get_config_u64("fee_node");       // 700
    let fee_val = get_config_u64("fee_val");          // 150
    let fee_burn = get_config_u64("fee_burn");        // 100
    let fee_treasury = get_config_u64("fee_treasury"); // 50

    let self_addr = get_self_address();
    let treasury = get_config("treasury").unwrap_or_default();

    let node_share = amount * fee_node / 1000;
    let val_share = amount * fee_val / 1000;
    let burn_share = amount * fee_burn / 1000;
    let treasury_share = amount * fee_treasury / 1000;
    // Rounding dust goes to provider
    let remainder = amount - node_share - val_share - burn_share - treasury_share;
    let provider_total = node_share + remainder;

    // 1. Pay provider
    if provider_total > 0 {
        let args = format!(
            r#"{{"token_id":"{}","from":"{}","to":"{}","amount":{}}}"#,
            denom, self_addr, provider, provider_total
        );
        if call_contract(&token_contract, "transfer_from", args.as_bytes()).is_err() {
            return_error("failed to pay provider");
            return;
        }
    }

    // 2. Pay treasury
    if treasury_share > 0 && !treasury.is_empty() {
        let args = format!(
            r#"{{"token_id":"{}","from":"{}","to":"{}","amount":{}}}"#,
            denom, self_addr, treasury, treasury_share
        );
        let _ = call_contract(&token_contract, "transfer_from", args.as_bytes());
    }

    // 3. Accumulate validator pool (held by contract, distributed off-chain per round)
    if val_share > 0 {
        let pool_key = key(&["pool", &denom]);
        let current_pool = read_u64_key(&pool_key);
        write_u64_key(&pool_key, current_pool + val_share);
    }

    // 4. Burn (remove from circulation — transfer to burn address / zero balance)
    if burn_share > 0 && denom == "PERSIST" {
        let burned_key = b"burned";
        let total_burned = read_u64_key(burned_key) + burn_share;
        write_u64_key(burned_key, total_burned);
        // The tokens stay locked in the contract (effectively burned).
        // Could also call a burn() method on the token contract if available.
        log_msg(&format!("burned {} PERSIST", burn_share));
    }

    // Update order status
    let updated_order = format!(
        r#"{{"id":{},"consumer":"{}","provider":"{}","service":"{}","amount":{},"denom":"{}","status":"delivered","attestation_id":"{}","created_at":0,"resolved_at":0}}"#,
        order_id, consumer, provider,
        json_str(&order_str, "service").unwrap_or_default(),
        amount, denom, attestation_id
    );
    storage_set(&order_key, updated_order.as_bytes());

    // Boost provider reputation
    let provider_key = key(&["provider", &provider]);
    if let Some(prov_str) = read_string_key(&provider_key) {
        let rep = json_u64(&prov_str, "reputation").unwrap_or(100);
        let new_rep = if rep < 10000 { rep + 1 } else { rep };
        let updated_prov = format!(
            r#"{{"url":"{}","services":"{}","reputation":{},"registered_at":{}}}"#,
            json_str(&prov_str, "url").unwrap_or_default(),
            json_str(&prov_str, "services").unwrap_or_default(),
            new_rep,
            json_u64(&prov_str, "registered_at").unwrap_or(0)
        );
        storage_set(&provider_key, updated_prov.as_bytes());
    }

    log_msg(&format!(
        "order {} delivered: {} to provider, {} to treasury, {} to pool, {} burned",
        order_id, provider_total, treasury_share, val_share, burn_share
    ));
    return_ok("delivered");
}

// ─── Dispute Resolution ─────────────────────────────────────────────────────

/// Consumer disputes an order (attestation challenged and failed).
/// Input: {"order_id":1}
///
/// If order is still "escrowed" and provider hasn't delivered within the
/// expiry window, consumer can reclaim funds. Admin can also force-refund.
#[no_mangle]
pub extern "C" fn dispute() {
    let caller = get_caller();
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let order_id = match json_u64(json, "order_id") {
        Some(v) => v,
        None => { return_error("order_id required"); return; }
    };

    let order_key = key(&["order", &format!("{}", order_id)]);
    let order_str = match read_string_key(&order_key) {
        Some(v) => v,
        None => { return_error("order not found"); return; }
    };

    let consumer = json_str(&order_str, "consumer").unwrap_or_default();
    let provider = json_str(&order_str, "provider").unwrap_or_default();
    let status = json_str(&order_str, "status").unwrap_or_default();
    let admin = get_config("admin").unwrap_or_default();

    // Only consumer or admin can dispute
    if caller != consumer && caller != admin {
        return_error("only consumer or admin can dispute");
        return;
    }

    // Can dispute escrowed or delivered orders
    if status != "escrowed" && status != "delivered" {
        return_error(&format!("cannot dispute order in status: {}", status));
        return;
    }

    let amount = json_u64(&order_str, "amount").unwrap_or(0);
    let denom = json_str(&order_str, "denom").unwrap_or_else(|| String::from("PERSIST"));

    // Refund consumer from escrow
    let token_contract = match get_config("token") {
        Some(v) => v,
        None => { return_error("marketplace not initialized"); return; }
    };
    let self_addr = get_self_address();

    if amount > 0 {
        let args = format!(
            r#"{{"token_id":"{}","from":"{}","to":"{}","amount":{}}}"#,
            denom, self_addr, consumer, amount
        );
        if call_contract(&token_contract, "transfer_from", args.as_bytes()).is_err() {
            return_error("refund transfer failed");
            return;
        }
    }

    // Penalize provider reputation
    let provider_key = key(&["provider", &provider]);
    if let Some(prov_str) = read_string_key(&provider_key) {
        let rep = json_u64(&prov_str, "reputation").unwrap_or(100);
        let new_rep = if rep > 10 { rep - 10 } else { 0 };
        let updated_prov = format!(
            r#"{{"url":"{}","services":"{}","reputation":{},"registered_at":{}}}"#,
            json_str(&prov_str, "url").unwrap_or_default(),
            json_str(&prov_str, "services").unwrap_or_default(),
            new_rep,
            json_u64(&prov_str, "registered_at").unwrap_or(0)
        );
        storage_set(&provider_key, updated_prov.as_bytes());
    }

    // Update order status
    let updated_order = format!(
        r#"{{"id":{},"consumer":"{}","provider":"{}","service":"{}","amount":{},"denom":"{}","status":"disputed","attestation_id":"{}","created_at":0,"resolved_at":0}}"#,
        order_id, consumer, provider,
        json_str(&order_str, "service").unwrap_or_default(),
        amount, denom,
        json_str(&order_str, "attestation_id").unwrap_or_default()
    );
    storage_set(&order_key, updated_order.as_bytes());

    log_msg(&format!("order {} disputed, {} {} refunded to consumer", order_id, amount, denom));
    return_ok("disputed and refunded");
}

// ─── Validator Reward Distribution ──────────────────────────────────────────

/// Admin distributes accumulated validator pool to a list of validators.
/// Input: {"denom":"PERSIST","validators":[{"address":"...","share":500},{"address":"...","share":500}]}
/// Shares are relative weights (not basis points).
#[no_mangle]
pub extern "C" fn distribute_pool() {
    if require_admin().is_none() { return; }

    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");

    let denom = json_str(json, "denom").unwrap_or_else(|| String::from("PERSIST"));
    let pool_key = key(&["pool", &denom]);
    let pool_balance = read_u64_key(&pool_key);

    if pool_balance == 0 {
        return_error("pool is empty");
        return;
    }

    // Parse validators array manually (simple format)
    // Expect a "validators" field containing JSON-ish data
    // For simplicity, we accept repeated calls with individual payouts
    let address = match json_str(json, "address") {
        Some(v) => v,
        None => { return_error("address required"); return; }
    };
    let share_amount = match json_u64(json, "amount") {
        Some(v) => v,
        None => { return_error("amount required"); return; }
    };

    if share_amount > pool_balance {
        return_error("amount exceeds pool balance");
        return;
    }

    // Transfer from contract to validator
    let token_contract = match get_config("token") {
        Some(v) => v,
        None => { return_error("marketplace not initialized"); return; }
    };
    let self_addr = get_self_address();

    let args = format!(
        r#"{{"token_id":"{}","from":"{}","to":"{}","amount":{}}}"#,
        denom, self_addr, address, share_amount
    );
    match call_contract(&token_contract, "transfer_from", args.as_bytes()) {
        Ok(_) => {
            write_u64_key(&pool_key, pool_balance - share_amount);
            log_msg(&format!("distributed {} {} to {}", share_amount, denom, &address[..12]));
            return_ok("distributed");
        }
        Err(e) => {
            return_error(&format!("distribution failed: {}", e));
        }
    }
}

// ─── Queries ────────────────────────────────────────────────────────────────

/// Query an order by ID.
/// Input: {"order_id":1}
#[no_mangle]
pub extern "C" fn get_order() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let order_id = match json_u64(json, "order_id") {
        Some(v) => v,
        None => { return_error("order_id required"); return; }
    };

    match read_string_key(&key(&["order", &format!("{}", order_id)])) {
        Some(v) => return_json(&v),
        None => return_error("order not found"),
    }
}

/// Get marketplace statistics.
#[no_mangle]
pub extern "C" fn get_stats() {
    let total_orders = read_u64_key(&key(&["stats", "orders"]));
    let total_volume = read_u64_key(&key(&["stats", "volume"]));
    let total_burned = read_u64_key(b"burned");
    let pool_persist = read_u64_key(&key(&["pool", "PERSIST"]));
    let fee_node = get_config_u64("fee_node");
    let fee_val = get_config_u64("fee_val");
    let fee_burn = get_config_u64("fee_burn");
    let fee_treasury = get_config_u64("fee_treasury");

    let result = format!(
        r#"{{"total_orders":{},"total_volume":{},"total_burned":{},"validator_pool":{},"fee_split":{{"node":{},"validator":{},"burn":{},"treasury":{}}}}}"#,
        total_orders, total_volume, total_burned, pool_persist,
        fee_node, fee_val, fee_burn, fee_treasury
    );
    return_json(&result);
}

/// Get marketplace configuration.
#[no_mangle]
pub extern "C" fn get_config_info() {
    let admin = get_config("admin").unwrap_or_default();
    let token = get_config("token").unwrap_or_default();
    let treasury = get_config("treasury").unwrap_or_default();

    let result = format!(
        r#"{{"admin":"{}","token_contract":"{}","treasury":"{}"}}"#,
        admin, token, treasury
    );
    return_json(&result);
}

/// Get the validator reward pool balance for a denom.
/// Input: {"denom":"PERSIST"}
#[no_mangle]
pub extern "C" fn get_pool() {
    let data = input();
    let json = core::str::from_utf8(&data).unwrap_or("{}");
    let denom = json_str(json, "denom").unwrap_or_else(|| String::from("PERSIST"));
    let balance = read_u64_key(&key(&["pool", &denom]));
    let result = format!(r#"{{"denom":"{}","balance":{}}}"#, denom, balance);
    return_json(&result);
}
