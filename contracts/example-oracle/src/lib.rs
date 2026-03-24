//! Example oracle contract for Persistia.
//!
//! Demonstrates:
//! - Requesting external API data (oracle)
//! - Receiving oracle callbacks with aggregated results
//! - Setting up cron triggers for periodic price updates

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use persistia_sdk::*;

const KEY_PRICE: &[u8] = b"btc_price";
const KEY_LAST_UPDATE: &[u8] = b"last_update";
const KEY_UPDATE_COUNT: &[u8] = b"update_count";

/// Request a BTC price fetch from the CoinGecko API.
/// The result will be delivered to `on_price_update`.
#[no_mangle]
pub extern "C" fn fetch_price() {
    request_oracle(
        "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd",
        "on_price_update",
        "median",
        Some("bitcoin.usd"),
    );
    log_msg("price fetch requested");
}

/// Callback: receives the oracle result with the BTC price.
/// Input is JSON: {"request_id":"...","value":"42000.50","sources":3}
#[no_mangle]
pub extern "C" fn on_price_update() {
    let data = input();
    // Store the raw result
    storage_set(KEY_PRICE, &data);

    // Increment update counter
    let count = storage_get(KEY_UPDATE_COUNT)
        .map(|v| {
            let mut buf = [0u8; 8];
            buf[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
            u64::from_le_bytes(buf)
        })
        .unwrap_or(0);
    storage_set(KEY_UPDATE_COUNT, &(count + 1).to_le_bytes());

    // Store timestamp (from input, but we just use the counter as proxy)
    storage_set(KEY_LAST_UPDATE, &(count + 1).to_le_bytes());

    log_msg("price updated from oracle");
    set_return_data(&data);
}

/// Query the last stored price.
#[no_mangle]
pub extern "C" fn get_price() {
    let price = storage_get(KEY_PRICE).unwrap_or_else(|| Vec::from(b"no data" as &[u8]));
    set_return_data(&price);
}

/// Set up a cron trigger to fetch price every 60 seconds.
#[no_mangle]
pub extern "C" fn start_auto_update() {
    create_trigger("fetch_price", 60_000, 0); // every 60s, unlimited fires
    log_msg("auto-update trigger created");
}

/// Get the update count.
#[no_mangle]
pub extern "C" fn get_update_count() {
    let count = storage_get(KEY_UPDATE_COUNT)
        .map(|v| {
            let mut buf = [0u8; 8];
            buf[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
            u64::from_le_bytes(buf)
        })
        .unwrap_or(0);
    set_return_data(&count.to_le_bytes());
}
