use chrono::{Duration, Utc};
use headers::Cookie;
use http::header::{COOKIE, HeaderMap};

use super::context_token::add_context_token_to_header;

use crate::session::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
use crate::session::errors::SessionError;
use crate::session::types::{SessionInfo, StoredSession, User as SessionUser};
use crate::utils::{gen_random_string, header_set_cookie};

use crate::storage::GENERIC_CACHE_STORE;
use crate::userdb::UserStore;

/// Get user information from libuserdb for a given session
pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, SessionError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;
    delete_session_from_store(cookies, SESSION_COOKIE_NAME.to_string()).await?;
    Ok(headers)
}

async fn create_new_session(session_info: SessionInfo) -> Result<HeaderMap, SessionError> {
    let mut headers = HeaderMap::new();
    let expires_at = session_info.expires_at;

    let session_id = create_and_store_session(session_info).await?;
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        session_id,
        expires_at,
        *SESSION_COOKIE_MAX_AGE as i64,
    )?;

    tracing::debug!("Headers: {:#?}", headers);
    Ok(headers)
}

async fn create_and_store_session(session_info: SessionInfo) -> Result<String, SessionError> {
    let session_id = gen_random_string(32)?;
    let stored_session = StoredSession {
        info: session_info,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(
            "session",
            &session_id,
            stored_session.into(),
            *SESSION_COOKIE_MAX_AGE as usize,
        )
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(session_id)
}

pub async fn delete_session_from_store(
    cookies: Cookie,
    cookie_name: String,
) -> Result<(), SessionError> {
    if let Some(cookie) = cookies.get(&cookie_name) {
        GENERIC_CACHE_STORE
            .lock()
            .await
            .remove("session", cookie)
            .await
            .map_err(|e| SessionError::Storage(e.to_string()))?;
    };
    Ok(())
}

pub async fn delete_session_from_store_by_session_id(session_id: &str) -> Result<(), SessionError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(())
}

pub async fn create_session_with_uid(user_id: &str) -> Result<HeaderMap, SessionError> {
    // Create minimal session info
    let session_info = SessionInfo {
        user_id: user_id.to_string(),
        expires_at: Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64),
    };

    create_new_session(session_info).await
}

pub async fn get_user_from_session(session_cookie: &str) -> Result<SessionUser, SessionError> {
    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_cookie)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    let user = UserStore::get_user(&stored_session.info.user_id)
        .await
        .map_err(|_| SessionError::SessionError)?
        .ok_or(SessionError::SessionError)?;

    Ok(SessionUser::from(user))
}

pub fn get_session_id_from_headers(headers: &HeaderMap) -> Result<Option<&str>, SessionError> {
    let Some(cookie_header) = headers.get(COOKIE) else {
        tracing::debug!("No cookie header found");
        return Ok(None);
    };

    let cookie_str = cookie_header.to_str().map_err(|e| {
        tracing::error!("Invalid cookie header: {}", e);
        SessionError::HeaderError("Invalid cookie header".to_string())
    })?;

    let cookie_name = SESSION_COOKIE_NAME.as_str();
    tracing::debug!("Looking for cookie: {}", cookie_name);

    let session_id = cookie_str.split(';').map(|s| s.trim()).find_map(|s| {
        let mut parts = s.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(k), Some(v)) if k == cookie_name => Some(v),
            _ => None,
        }
    });

    if session_id.is_none() {
        tracing::debug!("No session cookie '{}' found in cookies", cookie_name);
    }

    Ok(session_id)
}

/// Check if the request is authenticated by examining the session headers
///
/// This function checks if valid session credentials exist in the request headers
/// without fully loading the user data, making it a lightweight authentication check.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request
/// * `verify_user_exists` - If true, also checks that the user exists in the database (default: false)
///
/// # Returns
/// * `Result<bool, SessionError>` - True if authenticated, false if not authenticated, or an error
pub async fn is_authenticated(
    headers: &HeaderMap,
    verify_user_exists: bool,
) -> Result<bool, SessionError> {
    // Get session ID from headers
    let Some(session_id) = get_session_id_from_headers(headers)? else {
        return Ok(false);
    };

    // Check if the session exists in the store
    let session_result = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    // let _sessions = GENERIC_CACHE_STORE
    //     .lock()
    //     .await
    //     .gets("session", session_id)
    //     .await
    //     .map_err(|e| SessionError::Storage(e.to_string()))?;

    // If no session found, return false
    let Some(cached_session) = session_result else {
        return Ok(false);
    };

    // Convert to StoredSession and check expiration
    let stored_session: StoredSession = match cached_session.try_into() {
        Ok(session) => session,
        Err(_) => return Ok(false),
    };

    // Check if session has expired
    if stored_session.info.expires_at < Utc::now() {
        tracing::debug!("Session expired at {}", stored_session.info.expires_at);
        return Ok(false);
    }

    // Optionally check if the user exists in the database
    if verify_user_exists {
        let user_exists = UserStore::get_user(&stored_session.info.user_id)
            .await
            .map_err(|e| {
                tracing::error!("Error checking user existence: {}", e);
                SessionError::from(e)
            })?
            .is_some();

        Ok(user_exists)
    } else {
        // If we don't need to verify user existence, the session is valid at this point
        Ok(true)
    }
}

pub async fn is_authenticated_basic(headers: &HeaderMap) -> Result<bool, SessionError> {
    is_authenticated(headers, false).await
}

pub async fn is_authenticated_strict(headers: &HeaderMap) -> Result<bool, SessionError> {
    is_authenticated(headers, true).await
}

#[tracing::instrument]
pub(crate) async fn renew_session_header(user_id: String) -> Result<HeaderMap, SessionError> {
    // Create session cookie for authentication
    let mut headers = create_session_with_uid(&user_id).await?;

    add_context_token_to_header(&user_id, &mut headers)?;

    tracing::debug!("Created session and context token cookies: {headers:?}");

    Ok(headers)
}
