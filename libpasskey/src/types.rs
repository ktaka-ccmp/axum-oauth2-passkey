use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct PublicKeyCredentialUserEntity {
    pub user_handle: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredOptions {
    pub(super) challenge: Vec<u8>,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) timestamp: u64,
    pub(super) ttl: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Stored credential information for a passkey
pub struct StoredCredential {
    /// Raw credential ID bytes
    pub credential_id: Vec<u8>,
    /// User ID associated with this credential (database ID)
    pub user_id: String,
    /// Public key bytes for the credential
    pub public_key: Vec<u8>,
    /// Counter value for the credential (used to prevent replay attacks)
    pub counter: u32,
    /// User entity information
    pub user: PublicKeyCredentialUserEntity,
    /// When the credential was created
    pub created_at: DateTime<Utc>,
    /// When the credential was last updated
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) enum CacheData {
    SessionInfo(SessionInfo),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct UserIdCredentialIdStr {
    pub(super) user_id: String,
    pub(super) credential_id_str: String,
    pub(super) credential_id: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct SessionInfo {
    pub(super) user: libsession::User,
}

/// Search field options for credential lookup
#[allow(dead_code)]
#[derive(Debug)]
pub enum CredentialSearchField {
    /// Search by credential ID
    CredentialId(String),
    /// Search by user ID (database ID)
    UserId(String),
    /// Search by user handle (WebAuthn user handle)
    UserHandle(String),
    /// Search by username
    UserName(String),
}
