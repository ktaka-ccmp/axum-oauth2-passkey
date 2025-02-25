use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use crate::cache::{CacheStore, CacheStoreType, InMemoryCacheStore};
use crate::errors::StorageError;

pub(crate) static GENERIC_CACHE_TYPE: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_CACHE_STORAGE_TYPE").unwrap_or_else(|_| "memory".to_string())
});

pub(crate) static GENERIC_CACHE_URL: LazyLock<String> =
    LazyLock::new(|| env::var("GENERIC_CACHE_STORAGE_URL").expect("Failed to get CACHE_URL"));

pub static GENERIC_CACHE_STORE: LazyLock<Mutex<SingletonCacheStore>> = LazyLock::new(|| {
    Mutex::new(SingletonCacheStore::new(
        Box::new(InMemoryCacheStore::new()),
    ))
});

pub async fn init_cache_store() -> Result<(), StorageError> {
    let store_type = CacheStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize token store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        CacheStoreType::Memory
    });

    tracing::info!("Initializing cache store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    GENERIC_CACHE_STORE.lock().await.set_store(store)?;
    tracing::info!("Cache store initialized successfully");
    Ok(())
}

pub struct SingletonCacheStore {
    store: Box<dyn CacheStore>,
    initialized: bool,
}

impl SingletonCacheStore {
    fn new(store: Box<dyn CacheStore>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    fn set_store(&mut self, new_store: Box<dyn CacheStore>) -> Result<(), StorageError> {
        if self.initialized {
            return Err(StorageError::Storage(
                "Cache store has already been initialized".to_string(),
            ));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    pub fn get_store(&self) -> &dyn CacheStore {
        &*self.store
    }

    pub fn get_store_mut(&mut self) -> &mut Box<dyn CacheStore> {
        &mut self.store
    }
}
