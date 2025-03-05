use std::time::SystemTime;

use crate::common::{get_from_cache, remove_from_cache};
use crate::config::PASSKEY_CHALLENGE_TIMEOUT;
use crate::errors::PasskeyError;
use crate::types::StoredOptions;

/// Retrieves and validates a stored challenge from the cache
///
/// This function:
/// 1. Retrieves the challenge from the cache using the provided challenge type and ID
/// 2. Validates the challenge TTL (Time-To-Live)
/// 3. Returns the validated StoredOptions if successful
pub async fn get_and_validate_options(
    challenge_type: &str,
    id: &str,
) -> Result<StoredOptions, PasskeyError> {
    let stored_options: StoredOptions = get_from_cache(challenge_type, id)
        .await?
        .ok_or(PasskeyError::NotFound("Challenge not found".to_string()))?;

    // Validate challenge TTL
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now - stored_options.timestamp;
    let timeout = stored_options.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);
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

    tracing::debug!("Found stored challenge: {:?}", stored_options);

    Ok(stored_options)
}

/// Removes a challenge from the cache store after it has been used
///
/// This function is called after a successful registration or authentication
/// to clean up the challenge data from the cache.
pub async fn remove_options(challenge_type: &str, id: &str) -> Result<(), PasskeyError> {
    remove_from_cache(challenge_type, id).await?;
    tracing::debug!("Removed {} options for ID: {}", challenge_type, id);

    Ok(())
}
