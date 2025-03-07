use askama::Template;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
};
use serde_json::Value;

use libpasskey::{
    AuthenticationOptions, AuthenticatorResponse, PublicKeyCredentialUserEntity,
    RegisterCredential, RegistrationOptions, finish_authentication, finish_registration,
    finish_registration_with_auth_user, gen_random_string, start_authentication,
    start_registration, start_registration_with_auth_user,
};

use liboauth2::OAuth2Store;
use libpasskey::PASSKEY_ROUTE_PREFIX;
use libsession::{User as SessionUser, create_session_with_uid};

use crate::session::AuthUser;

pub(crate) async fn handle_start_registration_get(
    user: Option<AuthUser>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    match user {
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
        Some(u) => {
            tracing::debug!("User: {:#?}", u);

            let session_user: SessionUser = (*u).clone();

            let oauth2_accounts = OAuth2Store::get_oauth2_accounts(&session_user.id)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
                .first()
                .cloned()
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "No OAuth2 accounts found".to_string(),
                    )
                })?;

            let user_info = PublicKeyCredentialUserEntity {
                user_handle: gen_random_string(16)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
                name: oauth2_accounts.email.clone(),
                display_name: oauth2_accounts.name.clone(),
            };

            let options = start_registration_with_auth_user(session_user, user_info)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(Json(options))
        }
    }
}

pub(crate) async fn handle_start_registration(
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    Json(
        start_registration(username)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
            .expect("Failed to start registration"),
    )
}

pub(crate) async fn handle_finish_registration(
    user: Option<AuthUser>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<String, (StatusCode, String)> {
    tracing::debug!("Registration data: {:#?}", reg_data);

    match user {
        None => finish_registration(&reg_data)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string())),
        Some(u) => {
            tracing::debug!("User: {:#?}", u);

            finish_registration_with_auth_user((*u).clone(), reg_data)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

pub(crate) async fn handle_start_authentication(
    Json(username): Json<Value>,
) -> Result<Json<AuthenticationOptions>, (StatusCode, String)> {
    let username = if username.is_object() {
        username
            .get("username")
            .and_then(|v| v.as_str())
            .map(String::from)
    } else if username.is_string() {
        Some(username.as_str().unwrap().to_string()) // Directly use the string
    } else {
        None
    };

    match start_authentication(username).await {
        Ok(auth_options) => Ok(Json(auth_options)),
        Err(e) => {
            tracing::debug!("Error: {:#?}", e);
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

pub(crate) async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    let (uid, name) = finish_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    tracing::debug!("User ID: {:#?}", uid);

    let headers = create_session_with_uid(&uid)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok((headers, name))
}

pub(crate) async fn serve_passkey_js() -> Response {
    let js_content = include_str!("../../static/passkey.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

#[derive(Template)]
#[template(path = "conditional_ui.j2")]
struct ConditionalUiTemplate {
    passkey_route_prefix: &'static str,
}

pub(crate) async fn conditional_ui() -> impl IntoResponse {
    let template = ConditionalUiTemplate {
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

pub(crate) async fn serve_conditional_ui_js() -> Response {
    let js_content = include_str!("../../static/conditional_ui.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}
