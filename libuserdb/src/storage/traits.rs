use async_trait::async_trait;
use std::env;

use crate::storage::{MemoryStore, RedisStore};
use crate::{
    errors::AppError,
    types::{User, UserStoreType},
};

impl UserStoreType {
    pub fn from_env() -> Result<Self, AppError> {
        dotenv::dotenv().ok();

        let store_type = env::var("USER_DB_STORE")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase();

        match store_type.as_str() {
            "memory" => Ok(UserStoreType::Memory),
            "sqlite" => {
                let url = env::var("USER_DB_SQLITE_URL")
                    .map_err(|_| AppError::Storage("USER_DB_SQLITE_URL not set".to_string()))?;
                Ok(UserStoreType::Sqlite { url })
            }
            "postgres" => {
                let url = env::var("USER_DB_POSTGRES_URL")
                    .map_err(|_| AppError::Storage("USER_DB_POSTGRES_URL not set".to_string()))?;
                Ok(UserStoreType::Postgres { url })
            }
            "redis" => {
                let url = env::var("USER_DB_REDIS_URL")
                    .map_err(|_| AppError::Storage("USER_DB_REDIS_URL not set".to_string()))?;
                Ok(UserStoreType::Redis { url })
            }
            _ => Err(AppError::Storage(format!(
                "Unknown user store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn UserStore>, AppError> {
        let store: Box<dyn UserStore> = match self {
            UserStoreType::Memory => Box::new(MemoryStore::new()),
            UserStoreType::Sqlite { url: _url } => {
                unimplemented!("SQLite support is not yet implemented")
            }
            UserStoreType::Postgres { url: _url } => {
                unimplemented!("PostgreSQL support is not yet implemented")
            }
            UserStoreType::Redis { url } => Box::new(RedisStore::connect(url).await?),
        };
        store.init().await?;
        Ok(store)
    }
}

#[async_trait]
pub(crate) trait UserStore: Send + Sync + 'static {
    async fn init(&self) -> Result<(), AppError>;

    async fn put(&mut self, key: &str, value: User) -> Result<(), AppError>;
    async fn get(&self, key: &str) -> Result<Option<User>, AppError>;
    async fn remove(&mut self, key: &str) -> Result<(), AppError>;

    async fn get_by_subject(&self, subject: &str) -> Result<Vec<User>, AppError>;

    async fn get_all(&self) -> Result<Vec<User>, AppError>;
}
