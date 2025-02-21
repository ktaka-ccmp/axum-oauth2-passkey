use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents a user in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub picture: Option<String>,
    pub provider: String,
    pub provider_user_id: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // pub credentials: Vec<Credential>,
}

/// Type of user store to use
#[derive(Clone, Debug)]
pub(crate) enum UserStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

impl Default for User {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            email: String::new(),
            picture: None,
            provider: String::new(),
            provider_user_id: String::new(),
            metadata: Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
