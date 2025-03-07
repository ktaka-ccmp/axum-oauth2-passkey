//! Error types for the libauth crate

use thiserror::Error;

/// Errors that can occur during authentication coordination
#[derive(Error, Debug)]
pub enum AuthError {
    /// Error from the user database operations
    #[error("User error: {0}")]
    User(#[from] libuserdb::UserError),

    /// Error from OAuth2 operations
    #[error("OAuth2 error: {0}")]
    OAuth2(#[from] liboauth2::OAuth2Error),

    /// Error from Passkey operations
    #[error("Passkey error: {0}")]
    Passkey(#[from] libpasskey::PasskeyError),

    /// General coordination error
    #[error("Coordination error: {0}")]
    Coordination(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),
}
