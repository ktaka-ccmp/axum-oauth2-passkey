mod config;
mod errors;
mod main;
mod storage;
mod types;

pub(super) use types::{StateParams, StoredToken};

pub use config::{OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME};

pub use errors::OAuth2Error;
pub use main::{
    csrf_checks, decode_state, delete_session_and_misc_token_from_store, get_idinfo_userinfo,
    get_uid_from_stored_session_by_state_param, prepare_oauth2_auth_request, validate_origin,
};
pub use storage::OAuth2Store;
pub use types::{AccountSearchField, AuthResponse, OAuth2Account};

pub async fn init() -> Result<(), errors::OAuth2Error> {
    // Validate required environment variables early
    let _ = *config::OAUTH2_REDIRECT_URI; // This will validate ORIGIN
    let _ = *config::OAUTH2_GOOGLE_CLIENT_ID;
    let _ = *config::OAUTH2_GOOGLE_CLIENT_SECRET;

    // Initialize the storage layer
    crate::storage::init()
        .await
        .map_err(|e| errors::OAuth2Error::Storage(e.to_string()))?;

    // Initialize the OAuth2 database tables
    OAuth2Store::init().await?;

    Ok(())
}
