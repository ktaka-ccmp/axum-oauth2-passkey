mod attestation;
mod auth;
mod register;
mod types;

pub use types::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use auth::{start_authentication, verify_authentication};
pub use register::{
    finish_registration, finish_registration_with_auth_user, start_registration,
    start_registration_with_auth_user,
};
