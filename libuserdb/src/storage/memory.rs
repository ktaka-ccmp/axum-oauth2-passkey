use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{errors::AppError, storage::UserStore, types::User};

pub(crate) struct MemoryStore {
    entry: Arc<RwLock<HashMap<String, User>>>,
}

impl MemoryStore {
    pub(crate) fn new() -> Self {
        Self {
            entry: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserStore for MemoryStore {
    async fn init(&self) -> Result<(), AppError> {
        Ok(())
    }

    async fn put(&mut self, key: &str, value: User) -> Result<(), AppError> {
        self.entry.write().await.insert(key.to_owned(), value);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<User>, AppError> {
        Ok(self.entry.read().await.get(key).cloned())
    }

    async fn remove(&mut self, key: &str) -> Result<(), AppError> {
        self.entry.write().await.remove(key);
        Ok(())
    }

    async fn get_by_subject(&self, subject: &str) -> Result<Vec<User>, AppError> {
        let users = self.get_all().await?;
        Ok(users
            .into_iter()
            .filter(|u| u.provider_user_id == subject)
            .collect())
    }

    async fn get_all(&self) -> Result<Vec<User>, AppError> {
        Ok(self.entry.read().await.values().cloned().collect())
    }
}
