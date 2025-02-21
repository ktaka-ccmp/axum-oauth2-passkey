use axum::routing::{get, post, Router};

use super::handlers::{
    handle_finish_authentication, handle_finish_registration, handle_start_authentication,
    handle_start_registration, index,
};

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .nest("/auth", router_auth())
        .nest("/register", router_register())
}

pub fn router_register() -> Router {
    Router::new()
        .route("/start", post(handle_start_registration))
        .route("/finish", post(handle_finish_registration))
}

pub fn router_auth() -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
}
