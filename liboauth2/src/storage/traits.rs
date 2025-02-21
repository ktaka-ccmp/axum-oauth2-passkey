use async_trait::async_trait;
use std::env;

use crate::errors::AppError;
use crate::types::StoredToken;

use crate::storage::{memory::InMemoryTokenStore, redis::RedisTokenStore};
use crate::types::TokenStoreType;

impl TokenStoreType {
    pub fn from_env() -> Result<Self, AppError> {
        dotenv::dotenv().ok();

        let store_type = env::var("OAUTH2_TOKEN_STORE")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase();

        match store_type.as_str() {
            "memory" => Ok(TokenStoreType::Memory),
            "sqlite" => {
                let url = env::var("OAUTH2_TOKEN_SQLITE_URL")
                    .map_err(|_| anyhow::anyhow!("OAUTH2_TOKEN_SQLITE_URL not set"))?;
                Ok(TokenStoreType::Sqlite { url })
            }
            "postgres" => {
                let url = env::var("OAUTH2_TOKEN_POSTGRES_URL")
                    .map_err(|_| anyhow::anyhow!("OAUTH2_TOKEN_POSTGRES_URL not set"))?;
                Ok(TokenStoreType::Postgres { url })
            }
            "redis" => {
                let url = env::var("OAUTH2_TOKEN_REDIS_URL")?;
                Ok(TokenStoreType::Redis { url })
            }
            _ => Err(AppError::from(anyhow::anyhow!(
                "Unknown token store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn CacheStoreToken>, AppError> {
        let store: Box<dyn CacheStoreToken> = match self {
            TokenStoreType::Memory => Box::new(InMemoryTokenStore::new()),
            TokenStoreType::Sqlite { url: _url } => {
                // TODO: Implement SqliteTokenStore
                unimplemented!("SQLite support is not yet implemented")
            }
            TokenStoreType::Postgres { url: _url } => {
                // TODO: Implement PostgresTokenStore
                unimplemented!("PostgreSQL support is not yet implemented")
            }
            TokenStoreType::Redis { url } => Box::new(RedisTokenStore::connect(url).await?),
        };
        store.init().await?;
        Ok(store)
    }
}

#[async_trait]
pub(crate) trait CacheStoreToken: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), AppError>;
    /// Put a token into the store.
    async fn put(&mut self, key: &str, value: StoredToken) -> Result<(), AppError>;

    /// Get a token from the store.
    async fn get(&self, key: &str) -> Result<Option<StoredToken>, AppError>;

    /// Remove a token from the store.
    async fn remove(&mut self, key: &str) -> Result<(), AppError>;
}
