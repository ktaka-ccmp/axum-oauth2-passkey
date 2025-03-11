use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};

use crate::types::PublicKeyCredentialUserEntity;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    pub(super) challenge: String,
    pub(super) timeout: u32,
    pub(super) rp_id: String,
    pub(super) allow_credentials: Vec<AllowCredential>,
    pub(super) user_verification: String,
    pub(super) auth_id: String,
}

#[derive(Serialize, Debug)]
pub(super) struct AllowCredential {
    pub(super) type_: String,
    pub(super) id: Vec<u8>,
}

#[derive(Serialize, Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    pub(crate) authenticator_attachment: String,
    pub(crate) resident_key: String,
    pub(crate) user_verification: String,
    pub(crate) require_resident_key: bool,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct AuthenticatorResponse {
    pub(super) id: String,
    raw_id: String,
    pub(super) response: AuthenticatorAssertionResponse,
    authenticator_attachment: Option<String>,
    pub(super) auth_id: String,
}

#[derive(Deserialize, Debug)]
pub(super) struct AuthenticatorAssertionResponse {
    pub(super) client_data_json: String,
    pub(super) authenticator_data: String,
    pub(super) signature: String,
    pub(super) user_handle: Option<String>,
}

#[derive(Serialize, Debug)]
pub(super) struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) alg: i32,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOptions {
    pub(super) challenge: String,
    pub(super) rp_id: String,
    pub(super) rp: RelyingParty,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) pub_key_cred_params: Vec<PubKeyCredParam>,
    pub(super) authenticator_selection: AuthenticatorSelection,
    pub(super) timeout: u32,
    pub(super) attestation: String,
}

#[derive(Serialize, Debug)]
pub(super) struct RelyingParty {
    pub(super) name: String,
    pub(super) id: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct RegisterCredential {
    pub(super) id: String,
    pub(super) raw_id: String,
    pub(super) response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) user_handle: Option<String>,
}

impl RegisterCredential {
    /// Attempts to retrieve the stored user entity for this registration
    /// If the stored options are no longer available, falls back to a default value
    pub async fn get_user_name(&self) -> String {
        // Try to get the stored options if user_handle exists
        if let Some(handle) = &self.user_handle {
            match super::challenge::get_and_validate_options("regi_challenge", handle).await {
                Ok(stored_options) => stored_options.user.name,
                Err(e) => {
                    tracing::warn!("Failed to get stored user: {}", e);
                    "Passkey User".to_string()
                }
            }
        } else {
            // Fall back to default if user_handle is None
            "Passkey User".to_string()
        }
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct AuthenticatorAttestationResponse {
    pub(super) client_data_json: String,
    pub(super) attestation_object: String,
}

#[derive(Debug)]
pub(super) struct AttestationObject {
    pub(super) fmt: String,
    pub(super) auth_data: Vec<u8>,
    pub(super) att_stmt: Vec<(CborValue, CborValue)>,
}

#[derive(Debug)]
pub(super) struct ParsedClientData {
    pub(super) challenge: Vec<u8>,
    pub(super) origin: String,
    pub(super) type_: String,
    pub(super) raw_data: Vec<u8>,
}

/// AuthenticatorData structure as defined in WebAuthn spec Level 2
/// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
#[derive(Debug)]
pub(super) struct AuthenticatorData {
    /// SHA-256 hash of the RP ID (32 bytes)
    pub(super) rp_id_hash: Vec<u8>,

    /// Flags (1 byte) indicating various attributes:
    /// - Bit 0: User Present (UP)
    /// - Bit 2: User Verified (UV)
    /// - Bit 3: Backup Eligibility (BE) - Indicates if credential is discoverable
    /// - Bit 4: Backup State (BS)
    /// - Bit 6: Attested Credential Data Present (AT)
    /// - Bit 7: Extension Data Present (ED)
    pub(super) flags: u8,

    /// Signature counter (4 bytes), 32-bit unsigned big-endian integer
    pub(super) counter: u32,

    /// Raw authenticator data for verification
    pub(super) raw_data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct WebAuthnClientData {
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) challenge: String, // base64url encoded
    pub(super) origin: String,
}
