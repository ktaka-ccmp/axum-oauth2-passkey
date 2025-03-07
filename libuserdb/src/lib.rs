mod errors;
mod types;
mod user;

pub use errors::UserError;
pub use types::{OAuth2Account, User};
pub use user::UserStore;

pub async fn init() -> Result<(), UserError> {
    UserStore::init().await
}
