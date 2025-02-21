use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::rand::SecureRandom;

use crate::config::PASSKEY_CACHE_STORE;
use crate::errors::PasskeyError;
use crate::types::CacheData;

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
    let user_id = PASSKEY_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get(&username)
        .await?
        .ok_or(PasskeyError::Storage("User not found".into()))?;
    let user_id = match user_id {
        CacheData::EmailUserId(id) => Ok(id.user_id),
        _ => Err(PasskeyError::Format("Invalid user type".to_string())),
    };
    let user_id = user_id?;
    Ok(user_id)
}
