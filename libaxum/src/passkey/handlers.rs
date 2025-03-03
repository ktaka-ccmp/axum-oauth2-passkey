use askama::Template;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
};

use libpasskey::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    email_to_user_id, finish_authentication, finish_registration,
    finish_registration_with_auth_user, start_authentication, start_registration,
    start_registration_with_auth_user,
};

use libpasskey::PASSKEY_ROUTE_PREFIX;
use libsession::{User as SessionUser, create_session_with_uid};
use serde_json::Value;

use crate::session::AuthUser;

pub(crate) async fn handle_start_registration_get(
    user: Option<AuthUser>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    match user {
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
        Some(u) => {
            #[cfg(debug_assertions)]
            println!("User: {:#?}", u);

            let session_user: SessionUser = (*u).clone();
            let options = start_registration_with_auth_user(session_user)
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
    #[cfg(debug_assertions)]
    println!("Registration data: {:#?}", reg_data);

    match user {
        None => finish_registration(&reg_data)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string())),
        Some(u) => {
            #[cfg(debug_assertions)]
            println!("User: {:#?}", u);

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
            #[cfg(debug_assertions)]
            println!("Error: {:#?}", e);
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

pub(crate) async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    #[cfg(debug_assertions)]
    println!("Auth response: {:#?}", auth_response);

    let name = finish_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let uid = email_to_user_id(name.clone())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

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
