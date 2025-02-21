use redis::{self, AsyncCommands};

use crate::errors::AppError;
use crate::storage::traits::CacheStoreSession;
use crate::types::StoredSession;

use async_trait::async_trait;

const SESSION_PREFIX: &str = "session_";

pub(crate) struct RedisSessionStore {
    client: redis::Client,
}

impl RedisSessionStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, AppError> {
        println!("Connecting to Redis at {} for sessions", url);
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CacheStoreSession for RedisSessionStore {
    async fn init(&self) -> Result<(), AppError> {
        // Verify the connection works
        let _conn = self.client.get_multiplexed_async_connection().await?;
        Ok(())
    }

    async fn put(&mut self, key: &str, value: StoredSession) -> Result<(), AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", SESSION_PREFIX, key);
        let ttl = value.ttl;
        let value = serde_json::to_string(&value)?;

        let _: () = conn.set_ex(&key, value, ttl).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<StoredSession>, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", SESSION_PREFIX, key);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn remove(&mut self, key: &str) -> Result<(), AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", SESSION_PREFIX, key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }
}
