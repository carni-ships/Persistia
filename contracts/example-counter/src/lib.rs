//! Example counter contract for Persistia.
//! Demonstrates basic storage read/write with the SDK.

#![no_std]

extern crate alloc;
use persistia_sdk::*;

const KEY_COUNT: &[u8] = b"count";

#[no_mangle]
pub extern "C" fn increment() {
    let current = read_count();
    let new_val = current + 1;
    storage_set(KEY_COUNT, &new_val.to_le_bytes());
    log_msg("incremented");
    set_return_data(&new_val.to_le_bytes());
}

#[no_mangle]
pub extern "C" fn decrement() {
    let current = read_count();
    if current == 0 {
        panic_msg("counter is already zero");
    }
    let new_val = current - 1;
    storage_set(KEY_COUNT, &new_val.to_le_bytes());
    set_return_data(&new_val.to_le_bytes());
}

#[no_mangle]
pub extern "C" fn get_count() {
    let val = read_count();
    set_return_data(&val.to_le_bytes());
}

#[no_mangle]
pub extern "C" fn reset() {
    storage_set(KEY_COUNT, &0u64.to_le_bytes());
    set_return_data(&0u64.to_le_bytes());
}

fn read_count() -> u64 {
    storage_get(KEY_COUNT)
        .map(|v| {
            let mut buf = [0u8; 8];
            buf[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
            u64::from_le_bytes(buf)
        })
        .unwrap_or(0)
}
