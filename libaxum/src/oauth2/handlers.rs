use askama::Template;
use axum::{
    Router,
    extract::{Form, Query},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, Redirect, Response},
    routing::get,
};
use axum_extra::{TypedHeader, headers};
use chrono::{Duration, Utc};
// use axum_core::response::Response;

// Helper trait for converting errors to a standard response error format
trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

use libuserdb::{User, UserStore};

use liboauth2::{
    AuthResponse, OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_ROUTE_PREFIX, OAuth2Account,
    OAuth2Store, csrf_checks, get_idinfo_userinfo, header_set_cookie, prepare_oauth2_auth_request,
    validate_origin,
};

use libsession::{
    SESSION_COOKIE_NAME, create_session_with_uid, delete_session_from_store,
    prepare_logout_response,
};

pub fn router() -> Router {
    Router::new()
        .route("/oauth2.js", get(serve_oauth2_js))
        .route("/google", get(google_auth))
        .route("/authorized", get(get_authorized).post(post_authorized))
        .route("/popup_close", get(popup_close))
        .route("/logout", get(logout))
}

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate;

pub(crate) async fn popup_close() -> Result<Html<String>, (StatusCode, String)> {
    let template = PopupCloseTemplate;
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub(crate) async fn serve_oauth2_js() -> Result<Response, (StatusCode, String)> {
    let js_content = include_str!("../../static/oauth2.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .into_response_error()
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
    tracing::debug!(
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

    let mut oauth2_account = match OAUTH2_GOOGLE_USER {
        "idinfo" => OAuth2Account::from(idinfo),
        "userinfo" => OAuth2Account::from(userinfo),
        _ => OAuth2Account::from(idinfo), // Default case
    };

    // Upsert oauth2_account and user
    // 1. Check if sub of idinfo/userinfo has a corresponding entry in oauth2_account table
    // 2. If not, create a new entry in users table
    // 3. Create a new entry in oauth2_account table

    // Create session with user_id
    // 4. Create a new entry in session store
    // 5. Create a header for the session cookie

    // Upsert oauth2_account and user
    // 1. Check if the OAuth2 account exists

    let existing_account = OAuth2Store::get_oauth2_account_by_provider(
        &oauth2_account.provider,
        &oauth2_account.provider_user_id,
    )
    .await
    .into_response_error()?;

    // 2. Process the account
    let user_id = match existing_account {
        // If account exists, use its user_id
        Some(account) => account.user_id,
        // If not, create a new user and link it
        None => {
            // Create a new user
            let new_user = User {
                id: uuid::Uuid::new_v4().to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            // Store the user
            let stored_user = UserStore::upsert_user(new_user)
                .await
                .into_response_error()?;

            // Set the user_id in the OAuth2 account
            oauth2_account.user_id = stored_user.id.clone();

            // Store the OAuth2 account
            OAuth2Store::upsert_oauth2_account(oauth2_account)
                .await
                .into_response_error()?;

            stored_user.id
        }
    };

    // Create session with the user_id
    let mut headers = create_session_with_uid(&user_id)
        .await
        .into_response_error()?;

    // let mut headers = create_session_with_user(user_data)
    //     .await
    //     .into_response_error()?;

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
