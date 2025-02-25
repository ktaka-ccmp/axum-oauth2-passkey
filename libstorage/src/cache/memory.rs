use async_trait::async_trait;
use std::collections::HashMap;

use super::traits::CacheStore;
use super::types::InMemoryCacheStore;

use crate::errors::StorageError;
use crate::types::CacheData;

const CACHE_PREFIX: &str = "cache";

impl InMemoryCacheStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory generic cache store");
        Self {
            entry: HashMap::new(),
        }
    }

    fn make_key(prefix: &str, key: &str) -> String {
        format!("{}:{}:{}", CACHE_PREFIX, prefix, key)
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(key, value);
        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        _ttl: usize,
    ) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(key, value);
        Ok(())
    }

    async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError> {
        let key = Self::make_key(prefix, key);
        Ok(self.entry.get(&key).cloned())
    }

    async fn gets(&self, prefix: &str, key: &str) -> Result<Vec<CacheData>, StorageError> {
        let prefix_key = Self::make_key(prefix, key);
        let matching_entries = self
            .entry
            .iter()
            .filter_map(|(k, v)| {
                if k.starts_with(&prefix_key) {
                    Some(v.clone())
                } else {
                    None
                }
            })
            .collect();
        Ok(matching_entries)
    }

    async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.remove(&key);
        Ok(())
    }
}
