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
pub struct StoredCredential {
    pub(super) credential_id: Vec<u8>,
    pub(super) user_id: String,
    pub(super) public_key: Vec<u8>,
    pub(super) counter: u32,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) created_at: DateTime<Utc>,
    pub(super) updated_at: DateTime<Utc>,
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

#[allow(dead_code)]
#[derive(Debug)]
pub enum CredentialSearchField {
    CredentialId(String),
    UserId(String),
    UserHandle(String),
    UserName(String),
}
