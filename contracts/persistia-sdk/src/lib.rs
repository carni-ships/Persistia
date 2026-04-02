//! Persistia Smart Contract SDK
//!
//! Provides safe wrappers around the host-imported functions for writing
//! Persistia smart contracts. Uses a NEAR-style register-based ABI.

#![no_std]

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// ─── Host Imports ────────────────────────────────────────────────────────────

extern "C" {
    fn storage_read(key_reg: u32) -> u32;
    fn storage_write(key_reg: u32, val_reg: u32);
    fn storage_remove(key_reg: u32) -> u32;
    fn register_len(reg_id: u32) -> u64;
    fn read_register(reg_id: u32, ptr: *mut u8);
    fn write_register(reg_id: u32, ptr: *const u8, len: u32);
    fn caller(reg_id: u32);
    fn log(ptr: *const u8, len: u32);
    fn set_return(reg_id: u32);
    fn abort(msg_ptr: *const u8, msg_len: u32, line: u32, col: u32);
    fn gas_left() -> u64;
    // Cross-contract call (synchronous, within same execution context)
    fn cross_contract_call(target_reg: u32, method_reg: u32, args_reg: u32) -> u32;
    // Get the original external caller (tx signer), not the immediate caller
    fn origin(reg_id: u32);
    // Get this contract's own address
    fn self_address(reg_id: u32);
    // Oracle: request external data (async two-phase, legacy)
    fn oracle_request(url_reg: u32, callback_reg: u32, aggregation_reg: u32, json_path_reg: u32);
    // Oracle Network: read latest feed value (synchronous pull)
    fn oracle_read_feed(feed_id_reg: u32, result_reg: u32) -> u32;
    // Oracle Network: subscribe to feed updates (push)
    fn oracle_subscribe(feed_id_reg: u32, callback_reg: u32, deviation_reg: u32, interval_reg: u32);
    // Oracle Network: unsubscribe from feed updates
    fn oracle_unsubscribe(sub_id_reg: u32);
    // Oracle Network: request verifiable random number
    fn oracle_request_random(seed_reg: u32, callback_reg: u32);
    // Trigger: manage cron-like scheduled calls
    fn trigger_manage(action_reg: u32, data_reg: u32);
    // Deploy: programmatically deploy a new contract from WASM bytes
    fn deploy_contract(wasm_reg: u32) -> u32;
    // Lock: permanently prevent future upgrades to this contract
    fn lock_contract();
}

// ─── Register Helpers ────────────────────────────────────────────────────────

const REG_INPUT: u32 = 0;
const REG_SCRATCH_1: u32 = 1;
const REG_SCRATCH_2: u32 = 2;
const REG_RETURN: u32 = 3;
const REG_SCRATCH_3: u32 = 4;
const REG_SCRATCH_4: u32 = 5;

fn read_reg(reg_id: u32) -> Vec<u8> {
    let len = unsafe { register_len(reg_id) } as usize;
    if len == 0 {
        return vec![];
    }
    let mut buf = vec![0u8; len];
    unsafe { read_register(reg_id, buf.as_mut_ptr()) };
    buf
}

fn write_reg(reg_id: u32, data: &[u8]) {
    unsafe { write_register(reg_id, data.as_ptr(), data.len() as u32) };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Read the input arguments (register 0, set by the host before calling the method).
pub fn input() -> Vec<u8> {
    read_reg(REG_INPUT)
}

/// Read a value from contract storage. Returns `None` if key doesn't exist.
pub fn storage_get(key: &[u8]) -> Option<Vec<u8>> {
    write_reg(REG_SCRATCH_1, key);
    let found = unsafe { storage_read(REG_SCRATCH_1) };
    if found == 0 {
        return None;
    }
    Some(read_reg(REG_INPUT)) // storage_read writes result to register 0
}

/// Write a value to contract storage.
pub fn storage_set(key: &[u8], value: &[u8]) {
    write_reg(REG_SCRATCH_1, key);
    write_reg(REG_SCRATCH_2, value);
    unsafe { storage_write(REG_SCRATCH_1, REG_SCRATCH_2) };
}

/// Remove a key from contract storage. Returns true if the key existed.
pub fn storage_del(key: &[u8]) -> bool {
    write_reg(REG_SCRATCH_1, key);
    let result = unsafe { storage_remove(REG_SCRATCH_1) };
    result == 1
}

/// Get the public key of the caller (the user who submitted the transaction).
pub fn get_caller() -> String {
    unsafe { caller(REG_SCRATCH_1) };
    let bytes = read_reg(REG_SCRATCH_1);
    String::from_utf8(bytes).unwrap_or_default()
}

/// Log a message (visible in call results but not stored on-chain).
pub fn log_msg(msg: &str) {
    unsafe { log(msg.as_ptr(), msg.len() as u32) };
}

/// Set the return value for this contract call.
pub fn set_return_data(data: &[u8]) {
    write_reg(REG_RETURN, data);
    unsafe { set_return(REG_RETURN) };
}

/// Panic with a message. Aborts execution and rolls back all state changes.
pub fn panic_msg(msg: &str) -> ! {
    unsafe { abort(msg.as_ptr(), msg.len() as u32, 0, 0) };
    unreachable!()
}

/// Get remaining gas for this execution.
pub fn remaining_gas() -> u64 {
    unsafe { gas_left() }
}

// ─── Cross-Contract Calls ────────────────────────────────────────────────────

/// Call a method on another contract. Returns `Ok(return_data)` on success,
/// `Err(error_message)` on failure. The callee executes in the same atomic
/// context — all mutations across the call chain commit or rollback together.
///
/// Max call depth: 10. Reentrancy (calling back into a contract already on
/// the call stack) is not allowed.
pub fn call_contract(target_address: &str, method: &str, args: &[u8]) -> Result<Vec<u8>, String> {
    write_reg(REG_SCRATCH_1, target_address.as_bytes());
    write_reg(REG_SCRATCH_2, method.as_bytes());
    write_reg(REG_SCRATCH_3, args);
    let ok = unsafe { cross_contract_call(REG_SCRATCH_1, REG_SCRATCH_2, REG_SCRATCH_3) };
    let result = read_reg(REG_INPUT); // result/error in register 0
    if ok == 1 {
        Ok(result)
    } else {
        Err(String::from_utf8(result).unwrap_or_default())
    }
}

/// Get the original transaction signer's pubkey (not the immediate caller).
/// When contract A calls contract B, `get_caller()` in B returns A's address,
/// but `get_origin()` returns the user who signed the original transaction.
pub fn get_origin() -> String {
    unsafe { origin(REG_SCRATCH_1) };
    let bytes = read_reg(REG_SCRATCH_1);
    String::from_utf8(bytes).unwrap_or_default()
}

/// Get this contract's own address.
pub fn get_self_address() -> String {
    unsafe { self_address(REG_SCRATCH_1) };
    let bytes = read_reg(REG_SCRATCH_1);
    String::from_utf8(bytes).unwrap_or_default()
}

// ─── Oracle API ──────────────────────────────────────────────────────────────

/// Request external data from a URL. The result will be delivered asynchronously
/// to the specified callback method. The callback receives JSON-encoded result
/// as its input (register 0).
///
/// Aggregation strategies:
/// - "identical" — all nodes must return the same value
/// - "median" — take median of numeric values (good for price feeds)
/// - "majority" — most common value wins
pub fn request_oracle(url: &str, callback_method: &str, aggregation: &str, json_path: Option<&str>) {
    write_reg(REG_SCRATCH_1, url.as_bytes());
    write_reg(REG_SCRATCH_2, callback_method.as_bytes());
    write_reg(REG_SCRATCH_3, aggregation.as_bytes());
    match json_path {
        Some(path) => write_reg(REG_SCRATCH_4, path.as_bytes()),
        None => write_reg(REG_SCRATCH_4, &[]),
    }
    unsafe { oracle_request(REG_SCRATCH_1, REG_SCRATCH_2, REG_SCRATCH_3, REG_SCRATCH_4) };
}

// ─── Oracle Network (PON) API ────────────────────────────────────────────────

/// Read the latest value for a price feed. Returns the JSON-encoded feed data
/// or None if the feed doesn't exist.
///
/// The returned JSON has this structure:
/// ```json
/// {"feed_id":"BTC/USD","value":"42000.50","value_num":42000.5,
///  "round":123,"observers":5,"committed_at":1711500000000,"stale":false}
/// ```
///
/// Available feeds: BTC/USD, ETH/USD, SOL/USD, BERA/USD, AVAX/USD, LINK/USD, etc.
pub fn read_feed(feed_id: &str) -> Option<Vec<u8>> {
    write_reg(REG_SCRATCH_1, feed_id.as_bytes());
    let found = unsafe { oracle_read_feed(REG_SCRATCH_1, REG_SCRATCH_2) };
    if found == 0 {
        return None;
    }
    let data = read_reg(REG_SCRATCH_2);
    if data == b"null" {
        return None;
    }
    Some(data)
}

/// Subscribe to a feed for push updates. When the feed value changes beyond
/// the specified deviation threshold, the callback method is called with
/// the new value as JSON input.
///
/// - `feed_id`: e.g., "BTC/USD"
/// - `callback`: method name to call with updates
/// - `deviation_bps`: minimum deviation in basis points to trigger callback (0 = every update)
/// - `min_interval_ms`: minimum interval between callbacks in milliseconds (0 = no throttle)
pub fn subscribe_feed(feed_id: &str, callback: &str, deviation_bps: u32, min_interval_ms: u64) {
    use alloc::format;
    write_reg(REG_SCRATCH_1, feed_id.as_bytes());
    write_reg(REG_SCRATCH_2, callback.as_bytes());
    let dev_str = format!("{}", deviation_bps);
    write_reg(REG_SCRATCH_3, dev_str.as_bytes());
    let interval_str = format!("{}", min_interval_ms);
    write_reg(REG_SCRATCH_4, interval_str.as_bytes());
    unsafe { oracle_subscribe(REG_SCRATCH_1, REG_SCRATCH_2, REG_SCRATCH_3, REG_SCRATCH_4) };
}

/// Unsubscribe from a feed subscription by ID.
pub fn unsubscribe_feed(sub_id: &str) {
    write_reg(REG_SCRATCH_1, sub_id.as_bytes());
    unsafe { oracle_unsubscribe(REG_SCRATCH_1) };
}

/// Request a verifiable random number. The result is delivered asynchronously
/// to the callback method. The VRF uses quorum-combined Schnorr signatures
/// to produce an unpredictable, verifiable random value.
///
/// The callback receives JSON: `{"request_id":"...","random":"hex...","round":N}`
pub fn request_random(seed: &[u8], callback: &str) {
    write_reg(REG_SCRATCH_1, seed);
    write_reg(REG_SCRATCH_2, callback.as_bytes());
    unsafe { oracle_request_random(REG_SCRATCH_1, REG_SCRATCH_2) };
}

// ─── Trigger API ─────────────────────────────────────────────────────────────

/// Schedule a recurring call to a method on this contract.
/// Returns after emitting the request — the system processes it asynchronously.
///
/// - `method`: the exported WASM method to call on each fire
/// - `interval_ms`: milliseconds between fires (min 10_000, max 86_400_000)
/// - `max_fires`: 0 = unlimited, N = stop after N fires
pub fn create_trigger(method: &str, interval_ms: u64, max_fires: u64) {
    use alloc::format;
    write_reg(REG_SCRATCH_1, b"create");
    let json = format!(
        r#"{{"method":"{}","interval_ms":{},"max_fires":{}}}"#,
        method, interval_ms, max_fires,
    );
    write_reg(REG_SCRATCH_2, json.as_bytes());
    unsafe { trigger_manage(REG_SCRATCH_1, REG_SCRATCH_2) };
}

/// Remove a trigger by its ID. Only the trigger's creator can remove it.
pub fn remove_trigger(trigger_id: &str) {
    use alloc::format;
    write_reg(REG_SCRATCH_1, b"remove");
    let json = format!(r#"{{"trigger_id":"{}"}}"#, trigger_id);
    write_reg(REG_SCRATCH_2, json.as_bytes());
    unsafe { trigger_manage(REG_SCRATCH_1, REG_SCRATCH_2) };
}

// ─── Deploy API ─────────────────────────────────────────────────────────────

/// Deploy a new contract from raw WASM bytes. Returns `Ok(address)` with the
/// deterministic address of the newly deployed contract, or `Err(error)` if
/// validation failed.
///
/// The deploy is queued and executed after the current call succeeds — the child
/// contract is immediately callable in subsequent transactions.
///
/// Use case: factory contracts, LLM-generated contracts, agent swarms.
pub fn deploy_child_contract(wasm_bytes: &[u8]) -> Result<String, String> {
    write_reg(REG_SCRATCH_1, wasm_bytes);
    let ok = unsafe { deploy_contract(REG_SCRATCH_1) };
    let result = read_reg(REG_INPUT); // address or error in register 0
    if ok == 1 {
        Ok(String::from_utf8(result).unwrap_or_default())
    } else {
        Err(String::from_utf8(result).unwrap_or_default())
    }
}

// ─── Upgrade Lock ───────────────────────────────────────────────────────────

/// Permanently lock this contract, preventing any future code upgrades.
/// This is irreversible — once called, even the original deployer cannot
/// replace the WASM binary. Use this to make a contract trustlessly immutable.
pub fn lock_upgrades() {
    unsafe { lock_contract() };
}

// ─── Global Allocator ────────────────────────────────────────────────────────

use core::alloc::{GlobalAlloc, Layout};

struct BumpAllocator;

static mut HEAP_POS: usize = 0;

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Use exported __heap_base if available, otherwise start at 1MB
        extern "C" {
            static __heap_base: u8;
        }
        if HEAP_POS == 0 {
            HEAP_POS = unsafe { &__heap_base as *const u8 as usize };
        }
        let align = layout.align();
        let pos = (HEAP_POS + align - 1) & !(align - 1);
        HEAP_POS = pos + layout.size();
        pos as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator never frees — fine for short-lived contract calls
    }
}

#[global_allocator]
static ALLOC: BumpAllocator = BumpAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort(core::ptr::null(), 0, 0, 0) };
    loop {}
}
