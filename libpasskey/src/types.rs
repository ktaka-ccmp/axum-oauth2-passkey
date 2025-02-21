use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub(super) struct PublicKeyCredentialUserEntity {
    pub(super) id_handle: String,
    pub(super) name: String,
    #[serde(rename = "displayName")]
    pub(super) display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredChallenge {
    pub(super) challenge: Vec<u8>,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) timestamp: u64,
    pub(super) ttl: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredCredential {
    pub(super) credential_id: Vec<u8>,
    pub(super) public_key: Vec<u8>,
    pub(super) counter: u32,
    pub(super) user: PublicKeyCredentialUserEntity,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) enum CacheData {
    SessionInfo(SessionInfo),
    EmailUserId(EmailUserId),
    UserIdCredentialIdStr(UserIdCredentialIdStr),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct EmailCredId {
    // pub(super) credential_id: Vec<u8>, // stored_credential.credential_id will suffice
    // pub(super) usr_id: String, // user.id will suffice
    // pub(super) email: String, // user.email will suffice
    // pub(super) user_handle: String, // stored_credential.user.id is the user_handle
    pub(super) stored_credential: StoredCredential,
    pub(super) user: libsession::User,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct EmailUserId {
    pub(super) email: String,
    pub(super) user_id: String,
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
