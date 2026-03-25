//! Storage helpers modeled after cw-storage-plus.
//!
//! `Item<T>` stores a single typed value under a fixed key.
//! `Map<K, V>` stores typed values under a namespaced composite key.
//!
//! All values are JSON-serialized, matching CosmWasm convention.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{de::DeserializeOwned, Serialize};

use crate::types::{from_json, to_json_vec, Addr, StdError, StdResult, Storage};

// ─── Item<T> ─────────────────────────────────────────────────────────────────

/// A typed single-value store, analogous to `cw_storage_plus::Item`.
///
/// ```ignore
/// const OWNER: Item<Addr> = Item::new("owner");
/// OWNER.save(storage, &Addr::unchecked("alice"))?;
/// let owner = OWNER.load(storage)?;
/// ```
pub struct Item<T> {
    key: &'static str,
    _phantom: core::marker::PhantomData<T>,
}

impl<T> Item<T> {
    pub const fn new(key: &'static str) -> Self {
        Item {
            key,
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn key(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

impl<T: Serialize + DeserializeOwned> Item<T> {
    /// Save a value to storage.
    pub fn save(&self, storage: &mut dyn Storage, value: &T) -> StdResult<()> {
        let bytes = to_json_vec(value)?;
        storage.set(self.key.as_bytes(), &bytes);
        Ok(())
    }

    /// Load the value from storage. Returns `StdError::NotFound` if missing.
    pub fn load(&self, storage: &dyn Storage) -> StdResult<T> {
        match storage.get(self.key.as_bytes()) {
            Some(data) => from_json(&data),
            None => Err(StdError::not_found(self.key)),
        }
    }

    /// Load the value if it exists, or return `None`.
    pub fn may_load(&self, storage: &dyn Storage) -> StdResult<Option<T>> {
        match storage.get(self.key.as_bytes()) {
            Some(data) => from_json(&data).map(Some),
            None => Ok(None),
        }
    }

    /// Remove the value from storage.
    pub fn remove(&self, storage: &mut dyn Storage) {
        storage.remove(self.key.as_bytes());
    }

    /// Update the value in storage using a closure. If the value doesn't exist
    /// yet, the closure receives `None`.
    pub fn update<F>(&self, storage: &mut dyn Storage, action: F) -> StdResult<T>
    where
        F: FnOnce(Option<T>) -> StdResult<T>,
    {
        let old = self.may_load(storage)?;
        let new_val = action(old)?;
        self.save(storage, &new_val)?;
        Ok(new_val)
    }

    /// Check if the key exists in storage.
    pub fn exists(&self, storage: &dyn Storage) -> bool {
        storage.get(self.key.as_bytes()).is_some()
    }
}

// ─── Map key traits ──────────────────────────────────────────────────────────

/// Trait for types that can be used as Map keys. Converts to/from a byte suffix
/// that gets appended to the namespace prefix.
pub trait PrimaryKey {
    fn raw_key(&self) -> Vec<u8>;
}

impl PrimaryKey for &str {
    fn raw_key(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl PrimaryKey for String {
    fn raw_key(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl PrimaryKey for &String {
    fn raw_key(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl PrimaryKey for Addr {
    fn raw_key(&self) -> Vec<u8> {
        self.as_str().as_bytes().to_vec()
    }
}

impl PrimaryKey for &Addr {
    fn raw_key(&self) -> Vec<u8> {
        self.as_str().as_bytes().to_vec()
    }
}

impl PrimaryKey for u8 {
    fn raw_key(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl PrimaryKey for u16 {
    fn raw_key(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl PrimaryKey for u32 {
    fn raw_key(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl PrimaryKey for u64 {
    fn raw_key(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl PrimaryKey for u128 {
    fn raw_key(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl PrimaryKey for &[u8] {
    fn raw_key(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl PrimaryKey for Vec<u8> {
    fn raw_key(&self) -> Vec<u8> {
        self.clone()
    }
}

/// Composite key support: tuples of two keys produce a compound prefix.
impl<A: PrimaryKey, B: PrimaryKey> PrimaryKey for (A, B) {
    fn raw_key(&self) -> Vec<u8> {
        let a = self.0.raw_key();
        let b = self.1.raw_key();
        // Use length-prefixed encoding: [2-byte len of A][A bytes][B bytes]
        let a_len = (a.len() as u16).to_be_bytes();
        let mut out = Vec::with_capacity(2 + a.len() + b.len());
        out.extend_from_slice(&a_len);
        out.extend_from_slice(&a);
        out.extend_from_slice(&b);
        out
    }
}

/// Triple compound key.
impl<A: PrimaryKey, B: PrimaryKey, C: PrimaryKey> PrimaryKey for (A, B, C) {
    fn raw_key(&self) -> Vec<u8> {
        let a = self.0.raw_key();
        let b = self.1.raw_key();
        let c = self.2.raw_key();
        let a_len = (a.len() as u16).to_be_bytes();
        let b_len = (b.len() as u16).to_be_bytes();
        let mut out = Vec::with_capacity(4 + a.len() + b.len() + c.len());
        out.extend_from_slice(&a_len);
        out.extend_from_slice(&a);
        out.extend_from_slice(&b_len);
        out.extend_from_slice(&b);
        out.extend_from_slice(&c);
        out
    }
}

// ─── Map<K, V> ───────────────────────────────────────────────────────────────

/// A typed key-value map with automatic namespace prefixing, analogous to
/// `cw_storage_plus::Map`.
///
/// ```ignore
/// const BALANCES: Map<&Addr, Uint128> = Map::new("balances");
/// BALANCES.save(storage, &addr, &Uint128::new(1000))?;
/// let bal = BALANCES.load(storage, &addr)?;
/// ```
pub struct Map<K, V> {
    namespace: &'static str,
    _phantom_k: core::marker::PhantomData<K>,
    _phantom_v: core::marker::PhantomData<V>,
}

impl<K, V> Map<K, V> {
    pub const fn new(namespace: &'static str) -> Self {
        Map {
            namespace,
            _phantom_k: core::marker::PhantomData,
            _phantom_v: core::marker::PhantomData,
        }
    }

    /// Build the full storage key: namespace + 0x00 separator + key bytes.
    fn full_key(&self, key: &impl PrimaryKey) -> Vec<u8> {
        let ns = self.namespace.as_bytes();
        let raw = key.raw_key();
        let mut full = Vec::with_capacity(ns.len() + 1 + raw.len());
        full.extend_from_slice(ns);
        full.push(0x00); // separator matching cw-storage-plus convention
        full.extend_from_slice(&raw);
        full
    }
}

impl<K: PrimaryKey, V: Serialize + DeserializeOwned> Map<K, V> {
    /// Save a value under the given key.
    pub fn save(&self, storage: &mut dyn Storage, key: impl PrimaryKey, value: &V) -> StdResult<()> {
        let fk = self.full_key(&key);
        let bytes = to_json_vec(value)?;
        storage.set(&fk, &bytes);
        Ok(())
    }

    /// Load the value at the given key. Returns `StdError::NotFound` if missing.
    pub fn load(&self, storage: &dyn Storage, key: impl PrimaryKey) -> StdResult<V> {
        let fk = self.full_key(&key);
        match storage.get(&fk) {
            Some(data) => from_json(&data),
            None => Err(StdError::not_found(self.namespace)),
        }
    }

    /// Load if exists, or return `None`.
    pub fn may_load(&self, storage: &dyn Storage, key: impl PrimaryKey) -> StdResult<Option<V>> {
        let fk = self.full_key(&key);
        match storage.get(&fk) {
            Some(data) => from_json(&data).map(Some),
            None => Ok(None),
        }
    }

    /// Remove the entry at the given key.
    pub fn remove(&self, storage: &mut dyn Storage, key: impl PrimaryKey) {
        let fk = self.full_key(&key);
        storage.remove(&fk);
    }

    /// Check if a key exists.
    pub fn has(&self, storage: &dyn Storage, key: impl PrimaryKey) -> bool {
        let fk = self.full_key(&key);
        storage.get(&fk).is_some()
    }

    /// Update the value at the given key. The closure receives `Some(old)` if
    /// the key existed, or `None` if it didn't.
    pub fn update<F>(&self, storage: &mut dyn Storage, key: impl PrimaryKey + Clone, action: F) -> StdResult<V>
    where
        F: FnOnce(Option<V>) -> StdResult<V>,
    {
        let old = self.may_load(storage, key.clone())?;
        let new_val = action(old)?;
        self.save(storage, key, &new_val)?;
        Ok(new_val)
    }
}

// ─── IndexedMap (simplified stub for compatibility) ──────────────────────────
// Full IndexedMap support requires iteration which Persistia's KV store
// doesn't support natively. We provide the type alias so code that references
// it can compile, but without secondary index queries.

/// Simplified IndexedMap — behaves identically to Map. Secondary indexes are
/// not supported on Persistia's register-based storage.
/// Simplified IndexedMap — behaves identically to Map. Secondary indexes are
/// not supported on Persistia's register-based storage. The index type `I`
/// is accepted but ignored.
pub struct IndexedMap<K, V, I> {
    inner: Map<K, V>,
    _index: core::marker::PhantomData<I>,
}

impl<K, V, I> IndexedMap<K, V, I> {
    pub fn new(namespace: &'static str, _indexes: I) -> Self {
        IndexedMap {
            inner: Map::new(namespace),
            _index: core::marker::PhantomData,
        }
    }
}

impl<K: PrimaryKey, V: Serialize + DeserializeOwned, I> IndexedMap<K, V, I> {
    pub fn save(&self, storage: &mut dyn Storage, key: impl PrimaryKey, value: &V) -> StdResult<()> {
        self.inner.save(storage, key, value)
    }

    pub fn load(&self, storage: &dyn Storage, key: impl PrimaryKey) -> StdResult<V> {
        self.inner.load(storage, key)
    }

    pub fn may_load(&self, storage: &dyn Storage, key: impl PrimaryKey) -> StdResult<Option<V>> {
        self.inner.may_load(storage, key)
    }

    pub fn remove(&self, storage: &mut dyn Storage, key: impl PrimaryKey) {
        self.inner.remove(storage, key)
    }

    pub fn has(&self, storage: &dyn Storage, key: impl PrimaryKey) -> bool {
        self.inner.has(storage, key)
    }

    pub fn update<F>(&self, storage: &mut dyn Storage, key: impl PrimaryKey + Clone, action: F) -> StdResult<V>
    where
        F: FnOnce(Option<V>) -> StdResult<V>,
    {
        self.inner.update(storage, key, action)
    }
}
