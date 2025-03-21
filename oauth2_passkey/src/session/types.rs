use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::session::errors::SessionError;
use crate::storage::CacheData;

// Minimal session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub user_id: String,
    // pub provider: String,
    pub expires_at: DateTime<Utc>,
}

// User information from libuserdb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub account: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

use crate::userdb::User as DbUser;

impl User {
    pub fn into_db_user(self) -> DbUser {
        DbUser {
            id: self.id,
            account: self.account,
            label: self.label,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
            account: db_user.account,
            label: db_user.label,
            created_at: db_user.created_at,
            updated_at: db_user.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredSession {
    pub(crate) info: SessionInfo,
    pub(crate) ttl: u64,
}

impl From<StoredSession> for CacheData {
    fn from(data: StoredSession) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize StoredSession"),
        }
    }
}

impl TryFrom<CacheData> for StoredSession {
    type Error = SessionError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| SessionError::Storage(e.to_string()))
    }
}
