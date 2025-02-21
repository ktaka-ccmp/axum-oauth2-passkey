use askama::Template;
use axum::{
    extract::{Form, Query},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
    routing::get,
    Router,
};
use axum_extra::{headers, TypedHeader};
use chrono::{Duration, Utc};

// Helper trait for converting errors to a standard response error format
trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

use crate::common::header_set_cookie;
use crate::config::{OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_ROUTE_PREFIX};
use crate::oauth2::{
    csrf_checks, get_idinfo_userinfo, prepare_oauth2_auth_request, validate_origin,
};
use crate::types::AuthResponse;

use libsession::{
    delete_session_from_store, prepare_logout_response, User as SessionUser, SESSION_COOKIE_NAME,
};

pub fn router() -> Router {
    Router::new()
        .route("/google", get(google_auth))
        .route("/oauth2.js", get(oauth2_js))
        .route("/authorized", get(get_authorized).post(post_authorized))
        .route("/popup_close", get(popup_close))
        .route("/logout", get(logout))
}

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate;

#[derive(Template)]
#[template(path = "oauth2_js.j2")]
struct OAuth2JsTemplate<'a> {
    auth_route_prefix: &'a str,
}

pub(crate) async fn popup_close() -> Result<Html<String>, (StatusCode, String)> {
    let template = PopupCloseTemplate;
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub(crate) async fn oauth2_js() -> Result<(HeaderMap, String), (StatusCode, String)> {
    let template = OAuth2JsTemplate {
        auth_route_prefix: OAUTH2_ROUTE_PREFIX.as_str(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        "application/javascript".parse().unwrap(),
    );

    Ok((headers, template.render().into_response_error()?))
}

pub(crate) async fn google_auth(
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (auth_url, headers) = prepare_oauth2_auth_request(headers)
        .await
        .into_response_error()?;

    Ok((headers, Redirect::to(&auth_url)))
}

pub async fn logout(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let headers = prepare_logout_response(cookies)
        .await
        .into_response_error()?;
    Ok((headers, Redirect::to("/")))
}

pub async fn post_authorized(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
    Form(form): Form<AuthResponse>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    #[cfg(debug_assertions)]
    println!(
        "Cookies: {:#?}",
        cookies.get(OAUTH2_CSRF_COOKIE_NAME.as_str())
    );

    validate_origin(&headers, OAUTH2_AUTH_URL.as_str())
        .await
        .into_response_error()?;

    if form.state.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing state parameter".to_string(),
        ));
    }

    authorized(&form).await
}

pub async fn get_authorized(
    Query(query): Query<AuthResponse>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    validate_origin(&headers, OAUTH2_AUTH_URL.as_str())
        .await
        .into_response_error()?;
    csrf_checks(cookies.clone(), &query, headers)
        .await
        .into_response_error()?;

    delete_session_from_store(cookies, SESSION_COOKIE_NAME.to_string())
        .await
        .into_response_error()?;

    authorized(&query).await
}

async fn authorized(
    auth_response: &AuthResponse,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (idinfo, userinfo) = get_idinfo_userinfo(auth_response)
        .await
        .into_response_error()?;

    // Convert GoogleUserInfo to DbUser and store it
    static OAUTH2_GOOGLE_USER: &str = "idinfo";

    let user_data = match OAUTH2_GOOGLE_USER {
        "idinfo" => SessionUser::from(idinfo),
        "userinfo" => SessionUser::from(userinfo),
        _ => SessionUser::from(idinfo), // Default case
    };

    let mut headers = libsession::create_session_with_user(user_data)
        .await
        .into_response_error()?;

    let _ = header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )
    .into_response_error()?;

    Ok((
        headers,
        Redirect::to(&format!("{}/popup_close", OAUTH2_ROUTE_PREFIX.as_str())),
    ))
}
