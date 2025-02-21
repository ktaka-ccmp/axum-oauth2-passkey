use async_trait::async_trait;
use redis::AsyncCommands;

use crate::{errors::AppError, storage::UserStore, types::User};

const USER_PREFIX: &str = "user_";

pub(crate) struct RedisStore {
    client: redis::Client,
}

impl RedisStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, AppError> {
        let client = redis::Client::open(url)
            .map_err(|e| AppError::Storage(format!("Failed to connect to Redis: {}", e)))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl UserStore for RedisStore {
    async fn init(&self) -> Result<(), AppError> {
        // Verify the connection works
        let _conn = self.client.get_multiplexed_async_connection().await?;
        Ok(())
    }

    async fn put(&mut self, key: &str, value: User) -> Result<(), AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", USER_PREFIX, key);
        let value = serde_json::to_string(&value)?;

        let _: () = conn.set(&key, value).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<User>, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", USER_PREFIX, key);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn remove(&mut self, key: &str) -> Result<(), AppError> {
        let key = format!("{}{}", USER_PREFIX, key);
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.del(&key).await?;
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
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let pattern = format!("{}*", USER_PREFIX);
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let mut users = Vec::new();
        for key in keys {
            let value: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| AppError::Storage(e.to_string()))?;

            if let Some(v) = value {
                let user: User =
                    serde_json::from_str(&v).map_err(|e| AppError::Storage(e.to_string()))?;
                users.push(user);
            }
        }

        Ok(users)
    }
}
