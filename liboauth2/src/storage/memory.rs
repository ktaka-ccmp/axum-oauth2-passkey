use async_trait::async_trait;
use std::collections::HashMap;

use crate::errors::AppError;
use crate::storage::traits::CacheStoreToken;
use crate::types::StoredToken;

pub(crate) struct InMemoryTokenStore {
    entry: HashMap<String, StoredToken>,
}

impl InMemoryTokenStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory token store");
        Self {
            entry: HashMap::new(),
        }
    }
}

#[async_trait]
impl CacheStoreToken for InMemoryTokenStore {
    async fn init(&self) -> Result<(), AppError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(&mut self, key: &str, value: StoredToken) -> Result<(), AppError> {
        self.entry.insert(key.to_owned(), value);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<StoredToken>, AppError> {
        Ok(self.entry.get(key).cloned())
    }

    async fn remove(&mut self, key: &str) -> Result<(), AppError> {
        self.entry.remove(key);
        Ok(())
    }
}
