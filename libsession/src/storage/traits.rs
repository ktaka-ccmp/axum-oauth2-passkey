use crate::errors::AppError;
use crate::types::StoredSession;
use async_trait::async_trait;
use std::env;

use crate::storage::{memory::InMemorySessionStore, redis::RedisSessionStore};
use crate::types::SessionStoreType;

impl SessionStoreType {
    pub fn from_env() -> Result<Self, AppError> {
        dotenv::dotenv().ok();

        let store_type = env::var("OAUTH2_SESSION_STORE")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase();

        match store_type.as_str() {
            "memory" => Ok(SessionStoreType::Memory),
            "sqlite" => {
                let url = env::var("OAUTH2_SESSION_SQLITE_URL")
                    .map_err(|_| anyhow::anyhow!("OAUTH2_SESSION_SQLITE_URL not set"))?;
                Ok(SessionStoreType::Sqlite { url })
            }
            "postgres" => {
                let url = env::var("OAUTH2_SESSION_POSTGRES_URL")
                    .map_err(|_| anyhow::anyhow!("OAUTH2_SESSION_POSTGRES_URL not set"))?;
                Ok(SessionStoreType::Postgres { url })
            }
            "redis" => {
                let url = env::var("OAUTH2_SESSION_REDIS_URL")?;
                Ok(SessionStoreType::Redis { url })
            }
            _ => Err(AppError::from(anyhow::anyhow!(
                "Unknown session store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn CacheStoreSession>, AppError> {
        let store: Box<dyn CacheStoreSession> = match self {
            SessionStoreType::Memory => Box::new(InMemorySessionStore::new()),
            SessionStoreType::Sqlite { url: _url } => {
                // TODO: Implement SqliteSessionStore
                unimplemented!("SQLite support is not yet implemented")
            }
            SessionStoreType::Postgres { url: _url } => {
                // TODO: Implement PostgresSessionStore
                unimplemented!("PostgreSQL support is not yet implemented")
            }
            SessionStoreType::Redis { url } => Box::new(RedisSessionStore::connect(url).await?),
        };
        store.init().await?;
        Ok(store)
    }
}

#[async_trait]
pub(crate) trait CacheStoreSession: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), AppError>;
    async fn put(&mut self, key: &str, value: StoredSession) -> Result<(), AppError>;

    async fn get(&self, key: &str) -> Result<Option<StoredSession>, AppError>;

    async fn remove(&mut self, key: &str) -> Result<(), AppError>;
}
