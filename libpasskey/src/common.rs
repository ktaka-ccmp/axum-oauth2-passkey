use base64::engine::{
    Engine,
    general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use ring::rand::SecureRandom;

use libstorage::GENERIC_CACHE_STORE;

use crate::errors::PasskeyError;
use crate::storage::PasskeyStore;
use crate::types::{CredentialSearchField, SessionInfo, StoredOptions, UserIdCredentialIdStr};

pub async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *super::config::PASSKEY_RP_ID;

    libstorage::init()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    PasskeyStore::init().await?;

    Ok(())
}

pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, PasskeyError> {
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    let decoded = URL_SAFE
        .decode(padded)
        .map_err(|_| PasskeyError::Format("Failed to decode base64url".to_string()))?;
    Ok(decoded)
}

pub(crate) fn generate_challenge() -> Result<Vec<u8>, PasskeyError> {
    let rng = ring::rand::SystemRandom::new();
    let mut challenge = vec![0u8; 32];
    rng.fill(&mut challenge)
        .map_err(|_| PasskeyError::Crypto("Failed to generate random challenge".to_string()))?;
    Ok(challenge)
}

pub fn gen_random_string(len: usize) -> Result<String, PasskeyError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| PasskeyError::Crypto("Failed to generate random string".to_string()))?;
    Ok(URL_SAFE.encode(session_id))
}

pub(crate) async fn get_credential_id_strs_by(
    field: CredentialSearchField,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    let stored_credentials = PasskeyStore::get_credentials_by(field).await?;

    let credential_id_strs = stored_credentials
        .into_iter()
        .map(|cred| UserIdCredentialIdStr {
            user_id: cred.user_id,
            credential_id_str: URL_SAFE_NO_PAD.encode(&cred.credential_id),
            credential_id: cred.credential_id,
        })
        .collect();

    Ok(credential_id_strs)
}

pub(crate) async fn name2cid_str_vec(
    name: &str,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    get_credential_id_strs_by(CredentialSearchField::UserName(name.to_string())).await
}

/// Helper functions for cache store operations to improve code reuse and maintainability
impl From<SessionInfo> for libstorage::CacheData {
    fn from(data: SessionInfo) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize SessionInfo"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for SessionInfo {
    type Error = PasskeyError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}

impl From<StoredOptions> for libstorage::CacheData {
    fn from(data: StoredOptions) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize StoredOptions"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for StoredOptions {
    type Error = PasskeyError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}

/// Helper function to store data in the cache
pub(crate) async fn store_in_cache<T>(
    category: &str,
    key: &str,
    data: T,
) -> Result<(), PasskeyError>
where
    T: Into<libstorage::CacheData>,
{
    GENERIC_CACHE_STORE
        .lock()
        .await
        .put(category, key, data.into())
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Helper function to retrieve data from the cache
pub(crate) async fn get_from_cache<T>(category: &str, key: &str) -> Result<Option<T>, PasskeyError>
where
    T: TryFrom<libstorage::CacheData, Error = PasskeyError>,
{
    let data = GENERIC_CACHE_STORE
        .lock()
        .await
        .get(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    match data {
        Some(value) => Ok(Some(value.try_into()?)),
        None => Ok(None),
    }
}

/// Helper function to remove data from the cache
pub(crate) async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}
