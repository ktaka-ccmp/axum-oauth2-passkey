// mod common;
mod config;
mod errors;
mod main;
mod types;

pub use config::SESSION_COOKIE_NAME; // Required for cookie configuration
pub use errors::SessionError;
pub use types::User; // Required for session data

pub use main::{
    get_user_from_session, is_authenticated_basic, is_authenticated_strict, obfuscate_user_id,
    prepare_logout_response, verify_context_token_and_page,
};

pub(crate) use main::{
    delete_session_from_store_by_session_id, get_session_id_from_headers, renew_session_header,
};
