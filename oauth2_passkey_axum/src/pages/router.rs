use axum::{
    Router,
    routing::{delete, get, put},
};

/// Create a router for the user summary endpoints
pub fn router() -> Router<()> {
    Router::new()
        .route("/login", get(super::login::login))
        .route("/summary", get(super::user::user_summary))
        .route("/info", get(super::user::user_info))
        .route("/delete", delete(super::user::delete_user_account_handler))
        .route("/update", put(super::user::update_user_account_handler))
}
