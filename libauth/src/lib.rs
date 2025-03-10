//! libauth - Authentication coordination library for axum-oauth2-passkey
//!
//! This crate provides coordination between different authentication mechanisms
//! including OAuth2, Passkey, and user database operations.

mod errors;
mod oauth2_coordinator;
mod passkey_coordinator;

// Re-export the main coordination components
pub use errors::AuthError;
pub use oauth2_coordinator::OAuth2Coordinator;
pub use passkey_coordinator::PasskeyCoordinator;

pub use libpasskey::{
    AuthenticationOptions, AuthenticatorResponse, PublicKeyCredentialUserEntity,
    RegisterCredential, RegistrationOptions, finish_authentication, finish_registration,
    finish_registration_with_auth_user, gen_random_string, start_authentication,
    start_registration,
};

/// Initialize the authentication coordination layer
pub async fn init() -> Result<(), AuthError> {
    // Initialize the underlying stores
    libuserdb::init().await.map_err(AuthError::User)?;
    liboauth2::init().await.map_err(AuthError::OAuth2)?;
    libpasskey::init().await.map_err(AuthError::Passkey)?;

    Ok(())
}
