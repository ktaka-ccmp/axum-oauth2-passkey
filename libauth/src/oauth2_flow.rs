use chrono::{Duration, Utc};
use http::{HeaderMap, StatusCode};

use liboauth2::{
    AuthResponse, OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAuth2Account, OAuth2Store,
    csrf_checks, decode_state, delete_session_and_misc_token_from_store, get_idinfo_userinfo,
    get_uid_from_stored_session_by_state_param, header_set_cookie, validate_origin,
};
use libsession::{User as SessionUser, create_session_with_uid};
use libuserdb::{User as DbUser, UserStore};

use crate::errors::AuthError;

trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

pub async fn get_authorized_core(
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    validate_origin(headers, OAUTH2_AUTH_URL.as_str())
        .await
        .into_response_error()?;

    csrf_checks(cookies.clone(), auth_response, headers.clone())
        .await
        .into_response_error()?;

    process_oauth2_authorization(auth_response).await
}

pub async fn post_authorized_core(
    auth_response: &AuthResponse,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    validate_origin(headers, OAUTH2_AUTH_URL.as_str())
        .await
        .into_response_error()?;

    if auth_response.state.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing state parameter".to_string(),
        ));
    }

    process_oauth2_authorization(auth_response).await
}

pub async fn list_accounts_core(
    user: Option<&SessionUser>,
) -> Result<Vec<OAuth2Account>, (StatusCode, String)> {
    match user {
        Some(user) => {
            tracing::debug!("User: {:#?}", user);
            OAuth2Store::get_oauth2_accounts(&user.id)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
        }
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
    }
}

pub async fn process_oauth2_authorization(
    auth_response: &AuthResponse,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
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
    // 1. Decode the state from the auth response
    // 2. Extract user_id from the stored session if available
    // 3. Check if the OAuth2 account exists

    // Handle user and account linking
    // 4. If user is logged in and account exists, ensure they match
    // 5. If user is logged in but account doesn't exist, link account to user
    // 6. If user is not logged in but account exists, create session for account
    // 7. If neither user is logged in nor account exists, create new user and account

    // Create session with user_id
    // 8. Create a new entry in session store
    // 9. Create a header for the session cookie

    // Decode the state from the auth response
    let state_in_response =
        decode_state(&auth_response.state).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Extract user_id from the stored session if available
    let state_user = get_uid_from_stored_session_by_state_param(&state_in_response)
        .await
        .into_response_error()?;

    let (state_user_id, state_user_name) = match &state_user {
        Some(user) => (Some(user.id.clone()), Some(user.account.clone())),
        None => (None, None),
    };

    // Check if the OAuth2 account exists
    let stored_oauth2_account = OAuth2Store::get_oauth2_account_by_provider(
        &oauth2_account.provider,
        &oauth2_account.provider_user_id,
    )
    .await
    .into_response_error()?;

    // Match on the combination of auth_user and existing_account
    let (user_id, message) = match (state_user_id, stored_oauth2_account) {
        // Case 1: User is logged in and account exists
        (Some(state_user_id), Some(stored_oauth2_account)) => {
            let message = if state_user_id == stored_oauth2_account.user_id {
                let msg = format!(
                    "Already linked to current user {}",
                    state_user_name.unwrap()
                );
                tracing::debug!("{}", msg);
                // Nothing to do, account is already properly linked
                msg
            } else {
                let msg = "Already linked to a different user".to_string();
                tracing::debug!("{}", msg);
                // return Err((StatusCode::BAD_REQUEST, "This OAuth2 account is already linked to a different user".to_string()));
                msg
            };
            delete_session_and_misc_token_from_store(&state_in_response)
                .await
                .into_response_error()?;
            (state_user_id.to_string(), message)
        }
        // Case 2: User is logged in but account doesn't exist
        (Some(state_user_id), None) => {
            let message = format!("Successfully linked to {}", state_user_name.unwrap());
            tracing::debug!("{}", message);
            oauth2_account.user_id = state_user_id.clone();
            OAuth2Store::upsert_oauth2_account(oauth2_account)
                .await
                .into_response_error()?;
            delete_session_and_misc_token_from_store(&state_in_response)
                .await
                .into_response_error()?;
            (state_user_id.to_string(), message)
        }
        // Case 3: User is not logged in but account exists
        (None, Some(stored_oauth2_account)) => {
            let message = format!("Signing in as {}", stored_oauth2_account.name);
            tracing::debug!("{}", message);
            (stored_oauth2_account.user_id, message)
        }
        // Case 4: User is not logged in and account doesn't exist
        (None, None) => {
            let name = oauth2_account.name.clone();
            #[allow(clippy::let_and_return)]
            let user_id = create_user_and_oauth2account(oauth2_account)
                .await
                .into_response_error()?;
            let message = format!("Created {}", name);
            tracing::debug!("{}", message);
            (user_id, message)
        }
    };

    let mut headers = renew_session_header(user_id).await?;

    let _ = header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )
    .into_response_error()?;

    Ok((headers, message))
}

async fn renew_session_header(user_id: String) -> Result<HeaderMap, (StatusCode, String)> {
    let headers = create_session_with_uid(&user_id)
        .await
        .into_response_error()?;
    Ok(headers)
}

// When creating a new user, map fields according to configuration or defaults
// We also assign the user_id to the oauth2_account.
async fn create_user_and_oauth2account(
    mut oauth2_account: OAuth2Account,
) -> Result<String, AuthError> {
    // Get field mappings from environment or use defaults
    let account_field = std::env::var("OAUTH2_USER_ACCOUNT_FIELD").unwrap_or_else(|_| "email".to_string());
    let label_field = std::env::var("OAUTH2_USER_LABEL_FIELD").unwrap_or_else(|_| "name".to_string());
    
    // Map fields based on configuration
    let account = match account_field.as_str() {
        "email" => oauth2_account.email.clone(),
        "name" => oauth2_account.name.clone(),
        _ => oauth2_account.email.clone(), // Default to email if invalid mapping
    };
    
    let label = match label_field.as_str() {
        "email" => oauth2_account.email.clone(),
        "name" => oauth2_account.name.clone(),
        _ => oauth2_account.name.clone(), // Default to name if invalid mapping
    };
    
    let new_user = DbUser {
        id: uuid::Uuid::new_v4().to_string(),
        account,
        label,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let stored_user = UserStore::upsert_user(new_user).await?;
    oauth2_account.user_id = stored_user.id.clone();
    OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
    Ok(stored_user.id)
}

/// Get all OAuth2 accounts for a user
pub async fn get_oauth2_accounts(user_id: &str) -> Result<Vec<OAuth2Account>, AuthError> {
    OAuth2Store::get_oauth2_accounts(user_id)
        .await
        .map_err(AuthError::OAuth2)
}
