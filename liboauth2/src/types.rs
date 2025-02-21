use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::oauth2::IdInfo as GoogleIdInfo;
use libsession::User as SessionUser;

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

impl From<GoogleUserInfo> for SessionUser {
    fn from(google_user: GoogleUserInfo) -> Self {
        Self {
            id: "_undefined".to_string(),
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

impl From<GoogleIdInfo> for SessionUser {
    fn from(idinfo: GoogleIdInfo) -> Self {
        Self {
            id: "_undefined".to_string(),
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

#[derive(Clone, Debug)]
pub enum TokenStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}
