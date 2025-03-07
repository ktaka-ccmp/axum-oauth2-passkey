use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;

use super::errors::OAuth2Error;
use super::oauth2::IdInfo as GoogleIdInfo;

/// Represents an OAuth2 account linked to a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuth2Account {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub name: String,
    pub email: String,
    pub picture: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for OAuth2Account {
    fn default() -> Self {
        Self {
            id: String::new(),
            user_id: String::new(),
            provider: String::new(),
            provider_user_id: String::new(),
            name: String::new(),
            email: String::new(),
            picture: None,
            metadata: Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

// The user data we'll get back from Google
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    pub(crate) id: String,
    pub(crate) family_name: String,
    pub name: String,
    pub picture: Option<String>,
    pub(crate) email: String,
    pub(crate) given_name: String,
    pub(crate) hd: Option<String>,
    pub(crate) verified_email: bool,
}

// Add these implementations
impl From<GoogleUserInfo> for OAuth2Account {
    fn from(google_user: GoogleUserInfo) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: String::new(), // Will be set during upsert process
            name: google_user.name,
            email: google_user.email,
            picture: google_user.picture,
            provider: "google".to_string(),
            provider_user_id: format!("google_{}", google_user.id),
            metadata: json!({
                "family_name": google_user.family_name,
                "given_name": google_user.given_name,
                "hd": google_user.hd,
                "verified_email": google_user.verified_email,
            }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl From<GoogleIdInfo> for OAuth2Account {
    fn from(idinfo: GoogleIdInfo) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: String::new(), // Will be set during upsert process
            name: idinfo.name,
            email: idinfo.email,
            picture: idinfo.picture,
            provider: "google".to_string(),
            provider_user_id: format!("google_{}", idinfo.sub),
            metadata: json!({
                "family_name": idinfo.family_name,
                "given_name": idinfo.given_name,
                "hd": idinfo.hd,
                "verified_email": idinfo.email_verified,
            }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct StateParams {
    pub(crate) csrf_token: String,
    pub(crate) nonce_id: String,
    pub(crate) pkce_id: String,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub(crate) struct StoredToken {
    pub(crate) token: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) user_agent: Option<String>,
    pub(crate) ttl: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub(crate) code: String,
    pub state: String,
    _id_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OidcTokenResponse {
    pub(crate) access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
    pub(crate) id_token: Option<String>,
}

impl From<StoredToken> for libstorage::CacheData {
    fn from(data: StoredToken) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize StoredToken"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for StoredToken {
    type Error = OAuth2Error;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| OAuth2Error::Storage(e.to_string()))
    }
}
