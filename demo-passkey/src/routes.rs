use axum::{extract::Json, http::StatusCode, routing::post, Router};
use libpasskey::{
    finish_registration, start_authentication, start_registration, verify_authentication,
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

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

async fn handle_start_registration(Json(username): Json<String>) -> Json<RegistrationOptions> {
    Json(
        start_registration(username)
            .await
            .expect("Failed to start registration"),
    )
}

async fn handle_finish_registration(
    Json(reg_data): Json<RegisterCredential>,
) -> Result<String, (StatusCode, String)> {
    finish_registration(&reg_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

async fn handle_start_authentication(
    username: Result<Json<String>, axum::extract::rejection::JsonRejection>,
) -> Json<AuthenticationOptions> {
    let username = match username {
        Ok(Json(username)) => Some(username),
        Err(_) => None,
    };

    Json(
        start_authentication(username)
            .await
            .expect("Failed to start authentication"),
    )
}

async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    verify_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
