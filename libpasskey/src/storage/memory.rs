use async_trait::async_trait;
use std::collections::HashMap;

use super::traits::{CacheStore, ChallengeStore, CredentialStore};
use super::types::{InMemoryCacheStore, InMemoryChallengeStore, InMemoryCredentialStore};

use crate::errors::PasskeyError;
use crate::types::{CacheData, StoredChallenge, StoredCredential};

impl InMemoryChallengeStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory challenge store");
        Self {
            challenges: HashMap::new(),
        }
    }
}

impl InMemoryCredentialStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory credential store");
        Self {
            credentials: HashMap::new(),
        }
    }
}

impl InMemoryCacheStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory cache store");
        Self {
            entry: HashMap::new(),
        }
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn store_challenge(
        &mut self,
        challenge_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError> {
        self.challenges.insert(challenge_id, challenge);
        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<StoredChallenge>, PasskeyError> {
        Ok(self.challenges.get(challenge_id).cloned())
    }

    async fn remove_challenge(&mut self, challenge_id: &str) -> Result<(), PasskeyError> {
        self.challenges.remove(challenge_id);
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        self.credentials.insert(credential_id, credential);
        Ok(())
    }

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        Ok(self.credentials.get(credential_id).cloned())
    }

    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        Ok(self
            .credentials
            .values()
            .filter(|credential| credential.user.name == username)
            .cloned()
            .collect())
    }

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        if let Some(credential) = self.credentials.get_mut(credential_id) {
            credential.counter = new_counter;
            Ok(())
        } else {
            Err(PasskeyError::NotFound("Credential not found".to_string()))
        }
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        Ok(self.credentials.values().cloned().collect())
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), PasskeyError> {
        self.entry.insert(key.to_owned(), value);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, PasskeyError> {
        Ok(self.entry.get(key).cloned())
    }

    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, PasskeyError> {
        let matching_entries = self
            .entry
            .iter()
            .filter_map(|(k, v)| if k == key { Some(v.clone()) } else { None })
            .collect();
        Ok(matching_entries)
    }

    async fn remove(&mut self, key: &str) -> Result<(), PasskeyError> {
        self.entry.remove(key);
        Ok(())
    }
}
