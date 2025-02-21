use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub provider: String,
    pub provider_user_id: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

use libuserdb::User as DbUser;

impl User {
    pub fn into_db_user(self) -> DbUser {
        DbUser {
            id: self.id,
            email: self.email,
            name: self.name,
            picture: self.picture,
            provider: self.provider,
            provider_user_id: self.provider_user_id,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
            name: db_user.name,
            email: db_user.email,
            picture: db_user.picture,
            provider: db_user.provider,
            provider_user_id: db_user.provider_user_id,
            metadata: db_user.metadata,
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

#[derive(Clone, Debug)]
pub(crate) enum SessionStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}
