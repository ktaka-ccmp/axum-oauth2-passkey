use async_trait::async_trait;
use redis::{self, AsyncCommands};

use super::traits::{CacheStore, ChallengeStore, CredentialStore};
use super::types::{RedisCacheStore, RedisChallengeStore, RedisCredentialStore};

use crate::errors::PasskeyError;
use crate::types::{CacheData, StoredChallenge, StoredCredential};

const CHALLENGE_PREFIX: &str = "challenge:";
const CREDENTIAL_PREFIX: &str = "credential:";

impl RedisChallengeStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, PasskeyError> {
        println!("Connecting to Redis at {} for challenges", url);
        let client = redis::Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        // Verify the connection works
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(format!("Redis connection error: {}", e)))?;
        Ok(())
    }

    async fn store_challenge(
        &mut self,
        challenge_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let value =
            serde_json::to_string(&challenge).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, value, challenge.ttl)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<StoredChallenge>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match value {
            Some(v) => Ok(Some(
                serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn remove_challenge(&mut self, challenge_id: &str) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }
}

impl RedisCredentialStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, PasskeyError> {
        println!("Connecting to Redis at {} for credentials", url);
        let client = redis::Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CredentialStore for RedisCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        // Verify the connection works
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CREDENTIAL_PREFIX, credential_id);
        let value =
            serde_json::to_string(&credential).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set(&key, value)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CREDENTIAL_PREFIX, credential_id);
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match value {
            Some(v) => Ok(Some(
                serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CREDENTIAL_PREFIX, credential_id);

        // Get the existing credential
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut credential: StoredCredential = match value {
            Some(v) => {
                serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?
            }
            None => return Err(PasskeyError::Storage("Credential not found".to_string())),
        };

        // Update the counter
        credential.counter = new_counter;

        // Save back to Redis
        let value =
            serde_json::to_string(&credential).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        let _: () = conn
            .set(&key, value)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        let all_credentials = self.get_all_credentials().await?;
        Ok(all_credentials
            .into_iter()
            .filter(|credential| credential.user.name == username)
            .collect())
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let pattern = format!("{}*", CREDENTIAL_PREFIX);
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut credentials = Vec::new();
        for key in keys {
            let value: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| PasskeyError::Storage(e.to_string()))?;

            if let Some(v) = value {
                let credential: StoredCredential =
                    serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?;
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }
}

const CACHE_PREFIX: &str = "cache:";

impl RedisCacheStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, PasskeyError> {
        println!("Connecting to Redis at {} for tokens", url);
        let client = redis::Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        // Verify the connection works
        let _conn = self.client.get_multiplexed_async_connection().await?;
        Ok(())
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), PasskeyError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        // let ttl = 600; // 10 minute for testing
        // let _: () = conn.expire(&key, ttl).await?;
        // let _: () = conn.set_ex(&key, value, ttl).await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, PasskeyError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, PasskeyError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let keys: Vec<String> = conn.keys(&key).await?;

        let mut results = Vec::new();
        for key in keys {
            let value: Option<String> = conn.get(&key).await?;

            if let Some(v) = value {
                let data: CacheData = serde_json::from_str(&v)?;
                results.push(data);
            }
        }
        Ok(results)
    }

    async fn remove(&mut self, key: &str) -> Result<(), PasskeyError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }
}
