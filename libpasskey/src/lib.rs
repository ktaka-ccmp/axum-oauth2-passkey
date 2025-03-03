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
    finish_authentication, finish_registration, finish_registration_with_auth_user,
    start_authentication, start_registration, start_registration_with_auth_user,
};

pub use common::{email_to_user_id, init};
