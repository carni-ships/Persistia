//! Core CosmWasm-compatible types backed by the Persistia runtime.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use core::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum StdError {
    GenericErr { msg: String },
    InvalidBase64 { msg: String },
    InvalidUtf8 { msg: String },
    NotFound { kind: String },
    ParseErr { target_type: String, msg: String },
    SerializeErr { source_type: String, msg: String },
    Overflow { source: String },
    Unauthorized {},
}

impl fmt::Display for StdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StdError::GenericErr { msg } => write!(f, "Generic error: {}", msg),
            StdError::InvalidBase64 { msg } => write!(f, "Invalid base64: {}", msg),
            StdError::InvalidUtf8 { msg } => write!(f, "Invalid UTF-8: {}", msg),
            StdError::NotFound { kind } => write!(f, "Not found: {}", kind),
            StdError::ParseErr { target_type, msg } => {
                write!(f, "Error parsing into {}: {}", target_type, msg)
            }
            StdError::SerializeErr { source_type, msg } => {
                write!(f, "Error serializing {}: {}", source_type, msg)
            }
            StdError::Overflow { source } => write!(f, "Overflow: {}", source),
            StdError::Unauthorized {} => write!(f, "Unauthorized"),
        }
    }
}

impl StdError {
    pub fn generic_err(msg: impl Into<String>) -> Self {
        StdError::GenericErr { msg: msg.into() }
    }

    pub fn not_found(kind: impl Into<String>) -> Self {
        StdError::NotFound { kind: kind.into() }
    }

    pub fn parse_err(target_type: impl Into<String>, msg: impl Into<String>) -> Self {
        StdError::ParseErr {
            target_type: target_type.into(),
            msg: msg.into(),
        }
    }

    pub fn serialize_err(source_type: impl Into<String>, msg: impl Into<String>) -> Self {
        StdError::SerializeErr {
            source_type: source_type.into(),
            msg: msg.into(),
        }
    }

    pub fn overflow(source: impl Into<String>) -> Self {
        StdError::Overflow {
            source: source.into(),
        }
    }
}

pub type StdResult<T> = Result<T, StdError>;

// ─── Addr ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Addr(String);

impl Addr {
    pub fn unchecked(s: impl Into<String>) -> Self {
        Addr(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Addr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Addr> for String {
    fn from(addr: Addr) -> Self {
        addr.0
    }
}

// ─── Binary ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Binary(Vec<u8>);

impl Binary {
    pub fn from_base64(encoded: &str) -> StdResult<Self> {
        // Simple base64 decode (no padding required, standard alphabet)
        base64_decode(encoded)
            .map(Binary)
            .map_err(|e| StdError::InvalidBase64 { msg: e })
    }

    pub fn to_base64(&self) -> String {
        base64_encode(&self.0)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Binary {
    fn from(v: Vec<u8>) -> Self {
        Binary(v)
    }
}

impl From<&[u8]> for Binary {
    fn from(s: &[u8]) -> Self {
        Binary(s.to_vec())
    }
}

impl From<Binary> for Vec<u8> {
    fn from(b: Binary) -> Self {
        b.0
    }
}

impl AsRef<[u8]> for Binary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Binary {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Binary {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Binary::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

// ─── Uint128 / Uint64 ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Uint128(u128);

impl Uint128 {
    pub const fn new(v: u128) -> Self {
        Uint128(v)
    }

    pub const fn zero() -> Self {
        Uint128(0)
    }

    pub const fn one() -> Self {
        Uint128(1)
    }

    pub fn u128(self) -> u128 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn checked_add(self, other: Self) -> StdResult<Self> {
        self.0
            .checked_add(other.0)
            .map(Uint128)
            .ok_or_else(|| StdError::overflow("addition overflow"))
    }

    pub fn checked_sub(self, other: Self) -> StdResult<Self> {
        self.0
            .checked_sub(other.0)
            .map(Uint128)
            .ok_or_else(|| StdError::overflow("subtraction overflow"))
    }

    pub fn checked_mul(self, other: Self) -> StdResult<Self> {
        self.0
            .checked_mul(other.0)
            .map(Uint128)
            .ok_or_else(|| StdError::overflow("multiplication overflow"))
    }

    pub fn checked_div(self, other: Self) -> StdResult<Self> {
        self.0
            .checked_div(other.0)
            .map(Uint128)
            .ok_or_else(|| StdError::overflow("division by zero"))
    }
}

impl From<u128> for Uint128 {
    fn from(v: u128) -> Self {
        Uint128(v)
    }
}

impl From<u64> for Uint128 {
    fn from(v: u64) -> Self {
        Uint128(v as u128)
    }
}

impl fmt::Display for Uint128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Uint128 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // CosmWasm serializes Uint128 as a string
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Uint128 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<u128>()
            .map(Uint128)
            .map_err(serde::de::Error::custom)
    }
}

impl core::ops::Add for Uint128 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Uint128(self.0 + rhs.0)
    }
}

impl core::ops::Sub for Uint128 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Uint128(self.0 - rhs.0)
    }
}

impl core::ops::Mul for Uint128 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Uint128(self.0 * rhs.0)
    }
}

impl core::ops::AddAssign for Uint128 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl core::ops::SubAssign for Uint128 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Uint64(u64);

impl Uint64 {
    pub const fn new(v: u64) -> Self {
        Uint64(v)
    }

    pub const fn zero() -> Self {
        Uint64(0)
    }

    pub fn u64(self) -> u64 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for Uint64 {
    fn from(v: u64) -> Self {
        Uint64(v)
    }
}

impl fmt::Display for Uint64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Uint64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Uint64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<u64>()
            .map(Uint64)
            .map_err(serde::de::Error::custom)
    }
}

// ─── Coin ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    pub denom: String,
    pub amount: Uint128,
}

impl Coin {
    pub fn new(amount: u128, denom: impl Into<String>) -> Self {
        Coin {
            denom: denom.into(),
            amount: Uint128::new(amount),
        }
    }
}

impl fmt::Display for Coin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.amount, self.denom)
    }
}

// ─── Env / MessageInfo / BlockInfo ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub height: u64,
    pub time: Timestamp,
    pub chain_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Timestamp(u64); // nanoseconds since epoch

impl Timestamp {
    pub fn from_nanos(nanos: u64) -> Self {
        Timestamp(nanos)
    }

    pub fn from_seconds(seconds: u64) -> Self {
        Timestamp(seconds * 1_000_000_000)
    }

    pub fn nanos(&self) -> u64 {
        self.0
    }

    pub fn seconds(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    pub fn plus_seconds(&self, seconds: u64) -> Self {
        Timestamp(self.0 + seconds * 1_000_000_000)
    }

    pub fn minus_seconds(&self, seconds: u64) -> Self {
        Timestamp(self.0 - seconds * 1_000_000_000)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    pub address: Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Env {
    pub block: BlockInfo,
    pub contract: ContractInfo,
    pub transaction: Option<TransactionInfo>,
}

impl Env {
    /// Build an Env from the live Persistia runtime.
    pub fn from_runtime() -> Self {
        let self_addr = persistia_sdk::get_self_address();
        Env {
            block: BlockInfo {
                height: 0, // Persistia doesn't expose block height yet
                time: Timestamp::from_seconds(0), // Stubbed
                chain_id: String::from("persistia-1"),
            },
            contract: ContractInfo {
                address: Addr::unchecked(self_addr),
            },
            transaction: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageInfo {
    pub sender: Addr,
    pub funds: Vec<Coin>,
}

impl MessageInfo {
    /// Build a MessageInfo from the live Persistia runtime.
    pub fn from_runtime() -> Self {
        let caller = persistia_sdk::get_caller();
        MessageInfo {
            sender: Addr::unchecked(caller),
            funds: Vec::new(), // Persistia doesn't have native coin transfers in calls yet
        }
    }
}

// ─── Attribute / Event ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub key: String,
    pub value: String,
}

impl Attribute {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Attribute {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Shorthand for creating an Attribute.
pub fn attr(key: impl Into<String>, value: impl Into<String>) -> Attribute {
    Attribute::new(key, value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub ty: String,
    pub attributes: Vec<Attribute>,
}

impl Event {
    pub fn new(ty: impl Into<String>) -> Self {
        Event {
            ty: ty.into(),
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push(Attribute::new(key, value));
        self
    }

    pub fn add_attributes(mut self, attrs: impl IntoIterator<Item = Attribute>) -> Self {
        self.attributes.extend(attrs);
        self
    }
}

// ─── Messages (CosmosMsg, WasmMsg, BankMsg, SubMsg) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WasmMsg {
    Execute {
        contract_addr: String,
        msg: Binary,
        funds: Vec<Coin>,
    },
    Instantiate {
        admin: Option<String>,
        code_id: u64,
        msg: Binary,
        funds: Vec<Coin>,
        label: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BankMsg {
    Send {
        to_address: String,
        amount: Vec<Coin>,
    },
    Burn {
        amount: Vec<Coin>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CosmosMsg {
    Wasm(WasmMsg),
    Bank(BankMsg),
    /// Persistia-specific: raw cross-contract call
    Custom(PersistiaMsg),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistiaMsg {
    pub target: String,
    pub method: String,
    pub args: Binary,
}

/// Reply handling mode for SubMsg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplyOn {
    Always,
    Success,
    Error,
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubMsg {
    pub id: u64,
    pub msg: CosmosMsg,
    pub reply_on: ReplyOn,
}

impl SubMsg {
    pub fn new(msg: impl Into<CosmosMsg>) -> Self {
        SubMsg {
            id: 0,
            msg: msg.into(),
            reply_on: ReplyOn::Never,
        }
    }

    pub fn reply_on_success(msg: impl Into<CosmosMsg>, id: u64) -> Self {
        SubMsg {
            id,
            msg: msg.into(),
            reply_on: ReplyOn::Success,
        }
    }

    pub fn reply_always(msg: impl Into<CosmosMsg>, id: u64) -> Self {
        SubMsg {
            id,
            msg: msg.into(),
            reply_on: ReplyOn::Always,
        }
    }

    pub fn reply_on_error(msg: impl Into<CosmosMsg>, id: u64) -> Self {
        SubMsg {
            id,
            msg: msg.into(),
            reply_on: ReplyOn::Error,
        }
    }
}

impl From<WasmMsg> for CosmosMsg {
    fn from(msg: WasmMsg) -> Self {
        CosmosMsg::Wasm(msg)
    }
}

impl From<BankMsg> for CosmosMsg {
    fn from(msg: BankMsg) -> Self {
        CosmosMsg::Bank(msg)
    }
}

// ─── Response ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub messages: Vec<SubMsg>,
    pub attributes: Vec<Attribute>,
    pub events: Vec<Event>,
    pub data: Option<Binary>,
}

impl Response {
    pub fn new() -> Self {
        Response::default()
    }

    pub fn add_message(mut self, msg: impl Into<CosmosMsg>) -> Self {
        self.messages.push(SubMsg::new(msg));
        self
    }

    pub fn add_submessage(mut self, msg: SubMsg) -> Self {
        self.messages.push(msg);
        self
    }

    pub fn add_submessages(mut self, msgs: impl IntoIterator<Item = SubMsg>) -> Self {
        self.messages.extend(msgs);
        self
    }

    pub fn add_messages(mut self, msgs: impl IntoIterator<Item = impl Into<CosmosMsg>>) -> Self {
        for m in msgs {
            self.messages.push(SubMsg::new(m));
        }
        self
    }

    pub fn add_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push(Attribute::new(key, value));
        self
    }

    pub fn add_attributes(mut self, attrs: impl IntoIterator<Item = Attribute>) -> Self {
        self.attributes.extend(attrs);
        self
    }

    pub fn add_event(mut self, event: Event) -> Self {
        self.events.push(event);
        self
    }

    pub fn add_events(mut self, events: impl IntoIterator<Item = Event>) -> Self {
        self.events.extend(events);
        self
    }

    pub fn set_data(mut self, data: impl Into<Binary>) -> Self {
        self.data = Some(data.into());
        self
    }
}

// ─── Deps / DepsMut ──────────────────────────────────────────────────────────

/// Read-only contract dependencies (for queries).
pub struct Deps<'a> {
    pub storage: &'a dyn Storage,
    pub api: Api,
    pub querier: QuerierWrapper,
}

/// Mutable contract dependencies (for execute/instantiate).
pub struct DepsMut<'a> {
    pub storage: &'a mut dyn Storage,
    pub api: Api,
    pub querier: QuerierWrapper,
}

impl<'a> DepsMut<'a> {
    /// Reborrow as a read-only Deps.
    pub fn as_ref(&self) -> Deps<'_> {
        Deps {
            storage: self.storage,
            api: Api,
            querier: QuerierWrapper,
        }
    }
}

// ─── Storage trait ───────────────────────────────────────────────────────────

pub trait Storage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &[u8]);
    fn remove(&mut self, key: &[u8]);
}

/// Concrete storage implementation backed by the Persistia host.
pub struct PersistiaStorage;

impl Storage for PersistiaStorage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        persistia_sdk::storage_get(key)
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        persistia_sdk::storage_set(key, value);
    }

    fn remove(&mut self, key: &[u8]) {
        persistia_sdk::storage_del(key);
    }
}

// ─── Api (address validation) ────────────────────────────────────────────────

/// Minimal Api — address validation is a no-op on Persistia (addresses are pubkeys).
pub struct Api;

impl Api {
    pub fn addr_validate(&self, input: &str) -> StdResult<Addr> {
        if input.is_empty() {
            return Err(StdError::generic_err("Empty address"));
        }
        Ok(Addr::unchecked(input))
    }

    pub fn addr_canonicalize(&self, input: &str) -> StdResult<Vec<u8>> {
        Ok(input.as_bytes().to_vec())
    }

    pub fn addr_humanize(&self, canonical: &[u8]) -> StdResult<Addr> {
        let s = core::str::from_utf8(canonical)
            .map_err(|e| StdError::InvalidUtf8 {
                msg: format!("{}", e),
            })?;
        Ok(Addr::unchecked(s))
    }
}

// ─── QuerierWrapper (stub) ───────────────────────────────────────────────────

/// Stub querier. Persistia uses synchronous cross-contract calls rather than
/// the Cosmos query model. Use `call_contract` from the SDK for querying
/// other contracts.
pub struct QuerierWrapper;

impl QuerierWrapper {
    /// Query another contract by calling its "query" method synchronously.
    pub fn query_wasm_smart<T: DeserializeOwned>(
        &self,
        contract_addr: impl AsRef<str>,
        msg: &impl Serialize,
    ) -> StdResult<T> {
        let msg_bytes = to_json_vec(msg)?;
        let result = persistia_sdk::call_contract(contract_addr.as_ref(), "query", &msg_bytes)
            .map_err(|e| StdError::generic_err(e))?;
        from_json(&result)
    }

    /// Query raw storage of another contract — not supported on Persistia.
    pub fn query_wasm_raw(
        &self,
        _contract_addr: impl AsRef<str>,
        _key: impl AsRef<[u8]>,
    ) -> StdResult<Option<Vec<u8>>> {
        Err(StdError::generic_err(
            "query_wasm_raw not supported on Persistia; use query_wasm_smart",
        ))
    }
}

// ─── JSON helpers ────────────────────────────────────────────────────────────

/// Serialize a value to a JSON Binary.
pub fn to_json_binary<T: Serialize>(val: &T) -> StdResult<Binary> {
    to_json_vec(val).map(Binary::from)
}

/// Serialize a value to JSON bytes.
pub fn to_json_vec<T: Serialize>(val: &T) -> StdResult<Vec<u8>> {
    serde_json::to_vec(val).map_err(|e| StdError::serialize_err(core::any::type_name::<T>(), format!("{}", e)))
}

/// Deserialize from JSON bytes.
pub fn from_json<T: DeserializeOwned>(data: &[u8]) -> StdResult<T> {
    serde_json::from_slice(data).map_err(|e| StdError::parse_err(core::any::type_name::<T>(), format!("{}", e)))
}

// ─── Base64 (minimal, no_std) ────────────────────────────────────────────────

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_CHARS[((triple >> 18) & 0x3F) as usize]);
        out.push(B64_CHARS[((triple >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((triple >> 6) & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(triple & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }
    }
    // SAFETY: we only push valid ASCII bytes
    unsafe { String::from_utf8_unchecked(out) }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() % 4 != 0 {
        return Err(String::from("Invalid base64 length"));
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.chunks(4) {
        let mut vals = [0u32; 4];
        for (i, &byte) in chunk.iter().enumerate() {
            vals[i] = match byte {
                b'A'..=b'Z' => (byte - b'A') as u32,
                b'a'..=b'z' => (byte - b'a' + 26) as u32,
                b'0'..=b'9' => (byte - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err(format!("Invalid base64 character: {}", byte as char)),
            };
        }
        let triple = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((triple >> 16) as u8);
        if chunk[2] != b'=' {
            out.push((triple >> 8) as u8);
        }
        if chunk[3] != b'=' {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

// ─── Empty type (used as a placeholder for unused generics) ──────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Empty {}
