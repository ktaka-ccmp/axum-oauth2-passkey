use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

use libuserdb::User as DbUser;

impl User {
    pub fn into_db_user(self) -> DbUser {
        DbUser {
            id: self.id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
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
