use askama::Template;
use axum::{extract::Json, http::StatusCode, response::Html};
use axum_core::response::IntoResponse;

use crate::passkey::{
    finish_registration, start_authentication, start_registration, verify_authentication,
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

use crate::config::PASSKEY_ROUTE_PREFIX;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    passkey_route_prefix: &'static str,
}

pub(crate) async fn index() -> impl IntoResponse {
    let template = IndexTemplate {
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

pub(crate) async fn handle_start_registration(
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    Json(
        start_registration(username)
            .await
            .expect("Failed to start registration"),
    )
}

pub(crate) async fn handle_finish_registration(
    Json(reg_data): Json<RegisterCredential>,
) -> Result<String, (StatusCode, String)> {
    finish_registration(&reg_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

pub(crate) async fn handle_start_authentication(
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

pub(crate) async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    verify_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
