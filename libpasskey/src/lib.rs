// mod axum;
mod common;
mod config;
mod errors;
mod passkey;
mod storage;
mod types;

// pub(crate) use storage::{
//     ChallengeStore, ChallengeStoreType, CredentialStore, CredentialStoreType,
// };
// pub(crate) use errors::PasskeyError;

// pub use types::AppState;

// pub use axum::router;
pub use config::PASSKEY_ROUTE_PREFIX; // Required for route configuration

pub use passkey::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    finish_registration, finish_registration_with_auth_user, start_authentication,
    start_registration, start_registration_with_auth_user, verify_authentication,
};

pub use common::email_to_user_id;

use errors::PasskeyError;
use storage::PasskeyStore;

pub async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *config::PASSKEY_RP_ID;

    // Initialize libstorage's cache store first
    libstorage::init_cache_store()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    // Initialize passkey's stores
    // config::init_challenge_store().await?;
    // config::init_credential_store().await?;
    // config::init_cache_store().await?;

    // Initialize the passkey store
    PasskeyStore::init().await?;

    Ok(())
}
