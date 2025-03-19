//! User context token functionality for session/page synchronization
//!
//! This module provides stateless token generation and verification for
//! ensuring that the user interacting with a page is the same as the
//! user in the session, preventing session/page desynchronization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use http::{HeaderMap, header::SET_COOKIE};
use sha2::Sha256;
use std::{env, sync::LazyLock};

use headers::{Cookie, HeaderMapExt};

/// Name of the cookie where the user context token will be stored
pub const USER_CONTEXT_TOKEN_COOKIE: &str = "auth_context_token";

use super::errors::AuthError;

type HmacSha256 = Hmac<Sha256>;

// We're using a simple string representation for tokens instead of a struct
// to minimize dependencies and complexity

static AUTH_SERVER_SECRET: LazyLock<Vec<u8>> = LazyLock::new(|| {
    env::var("AUTH_SERVER_SECRET")
        .ok()
        .unwrap_or("default_secret_key_change_in_production".to_string())
        .into_bytes()
});

static USE_CONTEXT_TOKEN_COOKIE: LazyLock<bool> =
    LazyLock::new(|| env::var("USE_CONTEXT_TOKEN_COOKIE").is_ok());

/// Generate a signed context token for a user
///
/// This token contains the user ID and an expiration timestamp, signed with HMAC-SHA256
/// to prevent tampering. The token can be used to verify that the user viewing a page
/// is the same as the user in the session.
pub fn generate_user_context_token(user_id: &str) -> String {
    let expires_at = Utc::now() + Duration::days(1);
    let expiry_str = expires_at.timestamp().to_string();

    // Create the data string
    let data = format!("{}:{}", user_id, expiry_str);

    // Sign the data
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_base64 = URL_SAFE_NO_PAD.encode(signature);

    // Format as data:signature
    format!("{}:{}", data, signature_base64)
}

/// Verify a user context token against the session user ID
///
/// This function validates that:
/// 1. The token format is valid
/// 2. The signature is correct (no tampering)
/// 3. The token has not expired
/// 4. The user ID in the token matches the session user ID
pub fn verify_user_context_token(token: &str, session_user_id: &str) -> Result<(), AuthError> {
    // Parse token parts
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return Err(AuthError::Authentication(
            "Invalid token format".to_string(),
        ));
    }

    let token_user_id = parts[0];
    let expiry_str = parts[1];
    let signature_base64 = parts[2];

    // Check expiration
    let expiry = expiry_str
        .parse::<i64>()
        .map_err(|_| AuthError::Authentication("Invalid expiration format in token".to_string()))?;

    let now = Utc::now().timestamp();
    if now > expiry {
        return Err(AuthError::Authentication("Token has expired".to_string()));
    }

    // Verify signature
    let data = format!("{}:{}", token_user_id, expiry_str);
    let mut mac = HmacSha256::new_from_slice(&AUTH_SERVER_SECRET)
        .map_err(|_| AuthError::Authentication("Failed to create HMAC".to_string()))?;
    mac.update(data.as_bytes());

    let signature = URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|_| AuthError::Authentication("Invalid signature encoding".to_string()))?;

    mac.verify_slice(&signature)
        .map_err(|_| AuthError::Authentication("Invalid token signature".to_string()))?;

    // Check user ID matches session
    if token_user_id != session_user_id {
        tracing::debug!(
            "Session desynchronization detected: token user_id '{}' does not match session user_id '{}'",
            token_user_id,
            session_user_id
        );
        return Err(AuthError::SessionMismatch(
            "Your session has changed since this page was loaded".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn add_context_token_to_header(user_id: &str, headers: &mut HeaderMap) {
    if *USE_CONTEXT_TOKEN_COOKIE {
        let context_headers = create_context_token_cookie(user_id);
        for (key, value) in context_headers.iter() {
            headers.append(key, value.clone());
        }
    }
}

fn create_context_token_cookie(user_id: &str) -> HeaderMap {
    let token = generate_user_context_token(user_id);
    let mut headers = HeaderMap::new();

    // Create cookie with the token that expires in 1 day
    let cookie = format!(
        "{USER_CONTEXT_TOKEN_COOKIE}={}; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict",
        token
    );
    if let Ok(cookie_value) = cookie.parse() {
        headers.insert(SET_COOKIE, cookie_value);
    }

    headers
}

/// Extract context token from request headers
///
/// This function extracts the context token from the Cookie header
/// of an incoming request.
pub fn extract_context_token_from_cookies(headers: &HeaderMap) -> Option<String> {
    // Try to extract Cookie header

    let token = headers.typed_get::<Cookie>().and_then(|cookie| {
        // Look for our specific context token cookie
        cookie.get(USER_CONTEXT_TOKEN_COOKIE).map(|s| s.to_string())
    });

    token
}

/// Verifies both context token and page context match the user ID
///
/// This function combines both verification steps:
/// 1. Extracts and verifies the context token from cookies
/// 2. Verifies that any page context (if provided) matches the user ID
///
/// Returns AuthError if verification fails.
pub fn verify_context_token_and_page(
    headers: &HeaderMap,
    page_context: Option<&String>,
    user_id: &str,
) -> Result<(), super::errors::AuthError> {
    use super::errors::AuthError;

    if *USE_CONTEXT_TOKEN_COOKIE {
        // Extract token
        let context_token = extract_context_token_from_cookies(headers)
            .ok_or_else(|| AuthError::Authentication("Context token missing".to_string()))?;

        // Verify token belongs to user
        verify_user_context_token(&context_token, user_id)?;
    }

    // Verify page context matches user (if provided)
    if let Some(context) = page_context {
        if !context.is_empty() && context != user_id {
            return Err(AuthError::SessionMismatch(
                "Page context does not match session user".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let user_id = "test-user-123";
        let token = generate_user_context_token(user_id);

        // Verification should succeed with matching user ID
        assert!(verify_user_context_token(&token, user_id).is_ok());

        // Verification should fail with different user ID
        assert!(verify_user_context_token(&token, "different-user").is_err());
    }

    #[test]
    fn test_cookie_creation_and_extraction() {
        let user_id = "test-user-456";
        let headers = create_context_token_cookie(user_id);

        // Check that cookie header was set
        assert!(headers.contains_key(SET_COOKIE));

        // We can't easily test extraction here since it requires parsing
        // the Set-Cookie header into a Cookie header, which is complex in testing
    }
}
