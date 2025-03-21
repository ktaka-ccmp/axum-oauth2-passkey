//! oauth2_passkey - Authentication coordination library for axum-oauth2-passkey
//!
//! This crate provides coordination between different authentication mechanisms
//! including OAuth2, Passkey, and user database operations.

mod config;
mod coordination;
mod oauth2;
mod passkey;
mod session;
mod storage;
mod userdb;
mod utils;

// Re-export the main coordination components
// pub use coordinate::AuthError;
pub use coordination::{
    CoordinationError, RegistrationStartRequest, delete_passkey_credential_core,
    handle_finish_authentication_core, handle_finish_registration_core,
    handle_start_authentication_core, handle_start_registration_core, list_credentials_core,
};
// pub use coordinate::{
//     USER_CONTEXT_TOKEN_COOKIE, extract_context_token_from_cookies, generate_user_context_token,
//     obfuscate_user_id, verify_context_token_and_page, verify_user_context_token,
// };

pub use coordination::{
    delete_oauth2_account_core, delete_user_account, get_authorized_core, list_accounts_core,
    post_authorized_core, update_user_account,
};

// Re-export the route prefixes
pub use config::{O2P_ROUTE_PREFIX, OAUTH2_SUB_ROUTE, PASSKEY_SUB_ROUTE, SUMMARY_SUB_ROUTE};

pub use oauth2::{AuthResponse, OAuth2Account, OAuth2Error, prepare_oauth2_auth_request};

pub use passkey::{
    AuthenticationOptions, AuthenticatorResponse, PasskeyCredential, RegisterCredential,
    RegistrationOptions, get_related_origin_json,
};

pub use session::{
    SESSION_COOKIE_NAME, SessionError, User as SessionUser, get_user_from_session,
    is_authenticated_basic, is_authenticated_strict, obfuscate_user_id, prepare_logout_response,
    verify_context_token_and_page,
};

/// Initialize the authentication coordination layer
pub async fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the underlying stores
    userdb::init().await?;
    oauth2::init().await?;
    passkey::init().await?;
    Ok(())
}
