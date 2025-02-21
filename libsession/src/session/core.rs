use chrono::{Duration, Utc};
use headers::Cookie;
use http::header::HeaderMap;

use libuserdb::{get_user, upsert_user, User as DbUser};

use crate::common::{gen_random_string, header_set_cookie};
use crate::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME, SESSION_STORE};
use crate::errors::{AppError, SessionError};
use crate::types::{SessionInfo, StoredSession, User as SessionUser};

/// Get user information from libuserdb for a given session
pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, AppError> {
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

async fn create_new_session(session_info: SessionInfo) -> Result<HeaderMap, AppError> {
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
    #[cfg(debug_assertions)]
    println!("Headers: {:#?}", headers);
    Ok(headers)
}

async fn create_and_store_session(session_info: SessionInfo) -> Result<String, AppError> {
    let session_id = gen_random_string(32)?;
    let stored_session = StoredSession {
        info: session_info,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    let mut store_guard = SESSION_STORE.lock().await;
    store_guard
        .get_store_mut()
        .put(&session_id, stored_session)
        .await?;

    Ok(session_id)
}

pub async fn delete_session_from_store(
    cookies: Cookie,
    cookie_name: String,
) -> Result<(), AppError> {
    let mut store_guard = SESSION_STORE.lock().await;

    if let Some(cookie) = cookies.get(&cookie_name) {
        store_guard
            .get_store_mut()
            .remove(cookie)
            .await
            .map_err(|e| {
                println!("Error removing session: {}", e);
                e
            })?;
    };
    Ok(())
}

pub async fn create_session_with_user(user_data: SessionUser) -> Result<HeaderMap, AppError> {
    let db_user: DbUser = user_data.into_db_user();

    // Store the user in the database
    let user: SessionUser = upsert_user(db_user)
        .await
        .map_err(|e| AppError(anyhow::Error::from(e)))?
        .into();

    create_session_with_uid(&user.id).await
}

pub async fn create_session_with_uid(user_id: &str) -> Result<HeaderMap, AppError> {
    // Create minimal session info
    let session_info = SessionInfo {
        user_id: user_id.to_string(),
        expires_at: Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64),
    };

    create_new_session(session_info).await
}

pub async fn get_user_from_session(session_cookie: &str) -> Result<SessionUser, SessionError> {
    let store_guard = SESSION_STORE.lock().await;
    let session = store_guard
        .get_store()
        .get(session_cookie)
        .await
        .map_err(|_| SessionError::SessionError)?;
    let stored_session = session.ok_or(SessionError::SessionError)?;
    let user = get_user(&stored_session.info.user_id)
        .await
        .map_err(|_| SessionError::SessionError)?
        .ok_or(SessionError::SessionError)?;

    Ok(SessionUser::from(user))
}
