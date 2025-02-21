use crate::errors::AppError;
use crate::storage::traits::CacheStoreSession;
use crate::types::StoredSession;
use async_trait::async_trait;
use std::collections::HashMap;

pub(crate) struct InMemorySessionStore {
    entry: HashMap<String, StoredSession>,
}

impl InMemorySessionStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory session store");
        Self {
            entry: HashMap::new(),
        }
    }
}

#[async_trait]
impl CacheStoreSession for InMemorySessionStore {
    async fn init(&self) -> Result<(), AppError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(&mut self, key: &str, value: StoredSession) -> Result<(), AppError> {
        self.entry.insert(key.to_owned(), value);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<StoredSession>, AppError> {
        Ok(self.entry.get(key).cloned())
    }

    async fn remove(&mut self, key: &str) -> Result<(), AppError> {
        self.entry.remove(key);
        Ok(())
    }
}
