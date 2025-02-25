use async_trait::async_trait;

use crate::errors::StorageError;
use crate::types::CacheData;

use super::types::{InMemoryCacheStore, RedisCacheStore};

use super::config::{GENERIC_CACHE_TYPE, GENERIC_CACHE_URL};
use super::types::CacheStoreType;

impl CacheStoreType {
    pub fn from_env() -> Result<Self, StorageError> {
        dotenv::dotenv().ok();

        let store_type = GENERIC_CACHE_TYPE.as_str();

        match store_type {
            "memory" => Ok(CacheStoreType::Memory),
            "redis" => {
                let url = GENERIC_CACHE_URL.to_string();
                Ok(CacheStoreType::Redis { url })
            }
            _ => Err(StorageError::Storage(format!(
                "Unknown cache store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn CacheStore>, StorageError> {
        let store: Box<dyn CacheStore> = match self {
            CacheStoreType::Memory => Box::new(InMemoryCacheStore::new()),
            CacheStoreType::Redis { url } => Box::new(RedisCacheStore::connect(url).await?),
        };
        store.init().await?;
        Ok(store)
    }
}

#[async_trait]
pub trait CacheStore: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), StorageError>;

    /// Put a token into the store.
    async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError>;

    /// Put a token into the store with a TTL.
    async fn put_with_ttl(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        ttl: usize,
    ) -> Result<(), StorageError>;

    /// Get a token from the store.
    async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError>;

    /// Gets multiple tokens from the store.
    async fn gets(&self, prefix: &str, key: &str) -> Result<Vec<CacheData>, StorageError>;

    /// Remove a token from the store.
    async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError>;
}
