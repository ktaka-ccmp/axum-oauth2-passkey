use base64::engine::{Engine, general_purpose::URL_SAFE};
use ring::rand::SecureRandom;

use libstorage::GENERIC_CACHE_STORE;

use crate::errors::PasskeyError;
use crate::storage::PasskeyStore;
use crate::types::{EmailUserId, SessionInfo, StoredChallenge, UserIdCredentialIdStr};

pub async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *super::config::PASSKEY_RP_ID;

    // Initialize libstorage's cache store first
    libstorage::init_cache_store()
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

pub(crate) fn gen_random_string(len: usize) -> Result<String, PasskeyError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| PasskeyError::Crypto("Failed to generate random string".to_string()))?;
    Ok(URL_SAFE.encode(session_id))
}

pub async fn email_to_user_id(username: String) -> Result<String, PasskeyError> {
    let email_user_id: EmailUserId = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get("email", &username)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?
        .ok_or_else(|| PasskeyError::NotFound("User not found".to_string()))?
        .try_into()?;

    Ok(email_user_id.user_id)
}

pub(crate) async fn uid2cid_str_vec(
    user_id: String,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    let credential_id_strs: Vec<UserIdCredentialIdStr> = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .gets("uid2cid_str", &user_id)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?
        .into_iter()
        .filter_map(|data| {
            if let Ok(id_str) = UserIdCredentialIdStr::try_from(data) {
                Some(id_str)
            } else {
                None
            }
        })
        .collect();
    Ok(credential_id_strs)
}

// libpasskey/src/types.rs
impl From<EmailUserId> for libstorage::CacheData {
    fn from(data: EmailUserId) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize EmailUserId"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for EmailUserId {
    type Error = PasskeyError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}

impl From<UserIdCredentialIdStr> for libstorage::CacheData {
    fn from(data: UserIdCredentialIdStr) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize UserIdCredentialIdStr"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for UserIdCredentialIdStr {
    type Error = PasskeyError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}

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

impl From<StoredChallenge> for libstorage::CacheData {
    fn from(data: StoredChallenge) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize StoredChallenge"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for StoredChallenge {
    type Error = PasskeyError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}
