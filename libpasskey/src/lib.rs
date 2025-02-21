mod axum;
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

pub use axum::router;
pub use config::PASSKEY_ROUTE_PREFIX; // Required for route configuration

pub use passkey::{
    finish_registration, finish_registration_with_auth_user, start_authentication,
    start_registration, start_registration_with_auth_user, verify_authentication,
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use common::email_to_user_id;

pub async fn init() -> Result<(), errors::PasskeyError> {
    // Validate required environment variables early
    let _ = *config::PASSKEY_RP_ID;

    config::init_challenge_store().await?;
    config::init_credential_store().await?;
    config::init_cache_store().await?;
    Ok(())
}
