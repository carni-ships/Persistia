//! # CosmWasm Compatibility Shim for Persistia
//!
//! This crate provides CosmWasm-compatible types and traits that route through
//! the Persistia SDK internally. It allows CosmWasm contracts (e.g. cw20-base,
//! cw721-base) to compile for Persistia with minimal source changes.
//!
//! ## Quick Start
//!
//! Replace `use cosmwasm_std::*` with `use cosmwasm_compat::*` and use the
//! `cosmwasm_entry!` macro to generate Persistia-native entry points.
//!
//! ```ignore
//! use cosmwasm_compat::*;
//!
//! fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg)
//!     -> StdResult<Response> { ... }
//! fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg)
//!     -> StdResult<Response> { ... }
//! fn query(deps: Deps, env: Env, msg: QueryMsg)
//!     -> StdResult<Binary> { ... }
//!
//! cosmwasm_entry!(instantiate, execute, query);
//! ```

#![no_std]

extern crate alloc;

pub mod storage;
pub mod types;

// Re-export everything at the crate root for a drop-in `use cosmwasm_compat::*`.
pub use types::*;
pub use storage::{Item, Map, IndexedMap, PrimaryKey};


// ─── Response dispatch ──────────────────────────────────────────────────────

/// Process a `Response` by executing any sub-messages through Persistia's
/// cross-contract call API and setting the return data.
fn dispatch_response(resp: &Response) {
    // Log attributes as key=value pairs
    for attr in &resp.attributes {
        let msg = alloc::format!("{}={}", attr.key, attr.value);
        persistia_sdk::log_msg(&msg);
    }

    // Log events
    for event in &resp.events {
        persistia_sdk::log_msg(&alloc::format!("event:{}", event.ty));
        for attr in &event.attributes {
            let msg = alloc::format!("  {}={}", attr.key, attr.value);
            persistia_sdk::log_msg(&msg);
        }
    }

    // Execute sub-messages
    for sub in &resp.messages {
        match &sub.msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr,
                msg,
                funds: _,
            }) => {
                let result =
                    persistia_sdk::call_contract(contract_addr, "execute", msg.as_slice());
                match (&sub.reply_on, result) {
                    (ReplyOn::Never, _) | (ReplyOn::Success, Ok(_)) | (ReplyOn::Error, Err(_)) => {
                        // handled or ignored
                    }
                    (ReplyOn::Always, _) => {
                        // In a full implementation we'd invoke a reply handler
                    }
                    (_, Err(e)) => {
                        persistia_sdk::panic_msg(&alloc::format!(
                            "submsg {} failed: {}",
                            sub.id, e
                        ));
                    }
                    _ => {}
                }
            }
            CosmosMsg::Custom(PersistiaMsg {
                target,
                method,
                args,
            }) => {
                let result = persistia_sdk::call_contract(target, method, args.as_slice());
                if let Err(e) = result {
                    persistia_sdk::panic_msg(&alloc::format!("custom msg failed: {}", e));
                }
            }
            CosmosMsg::Bank(BankMsg::Send { to_address, amount: _ }) => {
                // Persistia doesn't have native bank sends; log a warning.
                persistia_sdk::log_msg(&alloc::format!(
                    "WARN: BankMsg::Send to {} ignored (not supported on Persistia)",
                    to_address
                ));
            }
            _ => {
                persistia_sdk::log_msg("WARN: unsupported CosmosMsg variant ignored");
            }
        }
    }

    // Set return data
    if let Some(ref data) = resp.data {
        persistia_sdk::set_return_data(data.as_slice());
    }
}

/// Handle an `execute` or `instantiate` result: either dispatch the response
/// or abort with the error.
pub fn handle_result(result: StdResult<Response>) {
    match result {
        Ok(resp) => dispatch_response(&resp),
        Err(e) => {
            let msg = alloc::format!("{}", e);
            persistia_sdk::panic_msg(&msg);
        }
    }
}

/// Handle a `query` result: set return data or abort.
pub fn handle_query_result(result: StdResult<Binary>) {
    match result {
        Ok(bin) => persistia_sdk::set_return_data(bin.as_slice()),
        Err(e) => {
            let msg = alloc::format!("{}", e);
            persistia_sdk::panic_msg(&msg);
        }
    }
}

// ─── Entry-point macro ──────────────────────────────────────────────────────

/// Generate Persistia `#[no_mangle] pub extern "C"` entry points from
/// standard CosmWasm handler functions.
///
/// Usage:
/// ```ignore
/// cosmwasm_entry!(instantiate, execute, query);
/// ```
///
/// This expands to three WASM exports (`instantiate`, `execute`, `query`)
/// that:
/// 1. Read the JSON input from register 0
/// 2. Build `Deps`/`DepsMut`, `Env`, and `MessageInfo` from the Persistia runtime
/// 3. Deserialize the input into the message type
/// 4. Call your handler function
/// 5. Dispatch the `Response` (execute sub-messages, set return data)
///
/// Your handler functions must have these exact signatures:
/// - `fn instantiate(DepsMut, Env, MessageInfo, InstantiateMsg) -> StdResult<Response>`
/// - `fn execute(DepsMut, Env, MessageInfo, ExecuteMsg) -> StdResult<Response>`
/// - `fn query(Deps, Env, QueryMsg) -> StdResult<Binary>`
///
/// The message types (`InstantiateMsg`, `ExecuteMsg`, `QueryMsg`) are inferred
/// from the handler function signatures; they just need to implement
/// `serde::Deserialize`.
#[macro_export]
macro_rules! cosmwasm_entry {
    ($instantiate_fn:ident, $execute_fn:ident, $query_fn:ident) => {
        // We generate a dispatcher that reads the method name from the exported
        // function name. Persistia calls the WASM export by name.

        #[no_mangle]
        pub extern "C" fn instantiate() {
            let input = persistia_sdk::input();
            let mut storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let info = $crate::MessageInfo::from_runtime();
            let deps = $crate::DepsMut {
                storage: &mut storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse InstantiateMsg: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $instantiate_fn(deps, env, info, msg);
            $crate::handle_result(result);
        }

        #[no_mangle]
        pub extern "C" fn execute() {
            let input = persistia_sdk::input();
            let mut storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let info = $crate::MessageInfo::from_runtime();
            let deps = $crate::DepsMut {
                storage: &mut storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse ExecuteMsg: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $execute_fn(deps, env, info, msg);
            $crate::handle_result(result);
        }

        #[no_mangle]
        pub extern "C" fn query() {
            let input = persistia_sdk::input();
            let storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let deps = $crate::Deps {
                storage: &storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse QueryMsg: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $query_fn(deps, env, msg);
            $crate::handle_query_result(result);
        }
    };

    // Two-function variant: just execute + query (no separate instantiate)
    ($execute_fn:ident, $query_fn:ident) => {
        #[no_mangle]
        pub extern "C" fn execute() {
            let input = persistia_sdk::input();
            let mut storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let info = $crate::MessageInfo::from_runtime();
            let deps = $crate::DepsMut {
                storage: &mut storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse ExecuteMsg: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $execute_fn(deps, env, info, msg);
            $crate::handle_result(result);
        }

        #[no_mangle]
        pub extern "C" fn query() {
            let input = persistia_sdk::input();
            let storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let deps = $crate::Deps {
                storage: &storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse QueryMsg: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $query_fn(deps, env, msg);
            $crate::handle_query_result(result);
        }
    };
}

/// Macro to generate a single entry point. Useful when you only want to expose
/// one function (e.g. a migrate handler).
///
/// ```ignore
/// cosmwasm_entry_point!(migrate, MigrateMsg, execute_style);
/// ```
#[macro_export]
macro_rules! cosmwasm_entry_point {
    // Execute-style: (DepsMut, Env, MessageInfo, Msg) -> StdResult<Response>
    ($fn_name:ident, $msg_type:ty, execute_style) => {
        #[no_mangle]
        pub extern "C" fn $fn_name() {
            let input = persistia_sdk::input();
            let mut storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let info = $crate::MessageInfo::from_runtime();
            let deps = $crate::DepsMut {
                storage: &mut storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg: $msg_type = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse message: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $fn_name(deps, env, info, msg);
            $crate::handle_result(result);
        }
    };

    // Query-style: (Deps, Env, Msg) -> StdResult<Binary>
    ($fn_name:ident, $msg_type:ty, query_style) => {
        #[no_mangle]
        pub extern "C" fn $fn_name() {
            let input = persistia_sdk::input();
            let storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let deps = $crate::Deps {
                storage: &storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg: $msg_type = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse message: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $fn_name(deps, env, msg);
            $crate::handle_query_result(result);
        }
    };

    // Migrate-style: (DepsMut, Env, Msg) -> StdResult<Response>
    ($fn_name:ident, $msg_type:ty, migrate_style) => {
        #[no_mangle]
        pub extern "C" fn $fn_name() {
            let input = persistia_sdk::input();
            let mut storage = $crate::PersistiaStorage;
            let env = $crate::Env::from_runtime();
            let deps = $crate::DepsMut {
                storage: &mut storage,
                api: $crate::Api,
                querier: $crate::QuerierWrapper,
            };
            let msg: $msg_type = match $crate::from_json(&input) {
                Ok(m) => m,
                Err(e) => {
                    let err_msg = alloc::format!("Failed to parse message: {}", e);
                    persistia_sdk::panic_msg(&err_msg);
                }
            };
            let result = $fn_name(deps, env, msg);
            $crate::handle_result(result);
        }
    };
}
