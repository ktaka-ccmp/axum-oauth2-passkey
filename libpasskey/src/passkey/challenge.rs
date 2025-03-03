use std::time::SystemTime;

use libstorage::GENERIC_CACHE_STORE;

use crate::config::PASSKEY_CHALLENGE_TIMEOUT;
use crate::errors::PasskeyError;
use crate::types::StoredChallenge;

/// Retrieves and validates a stored challenge from the cache
///
/// This function:
/// 1. Retrieves the challenge from the cache using the provided challenge type and ID
/// 2. Validates the challenge TTL (Time-To-Live)
/// 3. Returns the validated StoredChallenge if successful
pub async fn get_and_validate_challenge(
    challenge_type: &str,
    id: &str,
) -> Result<StoredChallenge, PasskeyError> {
    let stored_challenge: StoredChallenge = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get(challenge_type, id)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?
        .ok_or_else(|| PasskeyError::NotFound("Challenge not found".to_string()))?
        .try_into()?;

    // Validate challenge TTL
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now - stored_challenge.timestamp;
    let timeout = stored_challenge.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);
    if age > timeout {
        tracing::warn!(
            "Challenge expired after {} seconds (timeout: {})",
            age,
            timeout
        );
        return Err(PasskeyError::Authentication(
            "Challenge has expired. For more details, run with RUST_LOG=debug".into(),
        ));
    }

    tracing::debug!("Found stored challenge: {:?}", stored_challenge);

    Ok(stored_challenge)
}

/// Removes a challenge from the cache store after it has been used
///
/// This function is called after a successful registration or authentication
/// to clean up the challenge data from the cache.
pub async fn remove_challenge(challenge_type: &str, id: &str) -> Result<(), PasskeyError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove(challenge_type, id)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    tracing::debug!("Removed {} challenge for ID: {}", challenge_type, id);

    Ok(())
}
