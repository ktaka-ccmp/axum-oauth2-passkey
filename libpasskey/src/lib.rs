mod common;
mod config;
mod errors;
mod passkey;
mod storage;
mod types;
pub use common::{gen_random_string, init};
pub use config::PASSKEY_ROUTE_PREFIX; // Required for route configuration
pub use errors::PasskeyError;

pub use passkey::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    finish_authentication, finish_registration, finish_registration_with_auth_user,
    start_authentication, start_registration, start_registration_with_auth_user,
};

pub use storage::PasskeyStore;
pub use types::{CredentialSearchField, PublicKeyCredentialUserEntity, StoredCredential};
