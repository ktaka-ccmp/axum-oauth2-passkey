use base64::engine::{Engine, general_purpose::URL_SAFE};
use ring::{digest, signature::UnparsedPublicKey};
use std::time::SystemTime;

use libstorage::GENERIC_CACHE_STORE;

use super::types::{
    AllowCredential, AuthenticationOptions, AuthenticatorData, AuthenticatorResponse,
    ParsedClientData,
};

use crate::common::{base64url_decode, email_to_user_id, generate_challenge, uid2cid_str_vec};
use crate::config::{
    ORIGIN, PASSKEY_CHALLENGE_TIMEOUT, PASSKEY_RP_ID, PASSKEY_TIMEOUT, PASSKEY_USER_VERIFICATION,
};
use crate::errors::PasskeyError;
use crate::storage::PasskeyStore;
use crate::types::{PublicKeyCredentialUserEntity, StoredChallenge, StoredCredential};

pub async fn start_authentication(
    username: Option<String>,
) -> Result<AuthenticationOptions, PasskeyError> {
    let mut allow_credentials = Vec::new();
    match username.clone() {
        Some(username) => {
            let user_id = email_to_user_id(username).await?;

            let credential_id_strs = uid2cid_str_vec(user_id).await?;

            for credential in credential_id_strs {
                allow_credentials.push(AllowCredential {
                    type_: "public-key".to_string(),
                    id: credential.credential_id,
                });
            }
        }
        None => {
            // allow_credentials = vec![];
        }
    }

    let challenge = generate_challenge();
    let auth_id = crate::common::gen_random_string(16)?;

    let stored_challenge = StoredChallenge {
        challenge: challenge.clone().unwrap_or_default(),
        user: PublicKeyCredentialUserEntity {
            user_handle: "temp".to_string(),
            name: "temp".to_string(),
            display_name: "temp".to_string(),
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl: *PASSKEY_CHALLENGE_TIMEOUT as u64,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .put("auth_challenge", &auth_id, stored_challenge.into())
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    let auth_option = AuthenticationOptions {
        challenge: URL_SAFE.encode(challenge.unwrap_or_default()),
        timeout: (*PASSKEY_TIMEOUT) * 1000, // Convert seconds to milliseconds
        rp_id: PASSKEY_RP_ID.to_string(),
        allow_credentials,
        user_verification: PASSKEY_USER_VERIFICATION.to_string(),
        auth_id,
    };

    #[cfg(debug_assertions)]
    println!("Auth options: {:?}", auth_option);
    Ok(auth_option)
}

pub async fn verify_authentication(
    auth_response: AuthenticatorResponse,
) -> Result<String, PasskeyError> {
    #[cfg(debug_assertions)]
    println!(
        "Starting authentication verification for response: {:?}",
        auth_response
    );

    // Get stored challenge and verify auth
    let stored_challenge: StoredChallenge = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get("auth_challenge", &auth_response.auth_id)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?
        .ok_or_else(|| PasskeyError::NotFound("Challenge not found".to_string()))?
        .try_into()?;

    // Validate challenge TTL
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now - stored_challenge.timestamp;
    let timeout = stored_challenge.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);
    if age > timeout {
        println!(
            "Challenge expired after {} seconds (timeout: {})",
            age, timeout
        );
        return Err(PasskeyError::Authentication(
            "Challenge has expired. For more details, run with RUST_LOG=debug".into(),
        ));
    }

    #[cfg(debug_assertions)]
    println!("Found stored challenge: {:?}", stored_challenge);

    // Parse and verify client data
    #[cfg(debug_assertions)]
    println!(
        "Parsing client data: {}",
        &auth_response.response.client_data_json
    );

    let client_data = ParsedClientData::from_base64(&auth_response.response.client_data_json)?;

    #[cfg(debug_assertions)]
    println!("Parsed client data: {:?}", client_data);

    client_data.verify(&stored_challenge.challenge)?;

    // Parse and verify authenticator data
    #[cfg(debug_assertions)]
    println!(
        "Parsing authenticator data: {}",
        &auth_response.response.authenticator_data
    );

    let auth_data = AuthenticatorData::from_base64(&auth_response.response.authenticator_data)?;

    #[cfg(debug_assertions)]
    println!("Parsed authenticator data: {:?}", auth_data);

    auth_data.verify()?;

    // Get credential then public key
    let stored_credential = PasskeyStore::get_credential(&auth_response.id)
        .await?
        .ok_or_else(|| PasskeyError::NotFound("Credential not found".into()))?;

    #[cfg(debug_assertions)]
    println!("Found credential: {:?}", stored_credential);

    // Verify user handle based on credential type
    let user_handle = auth_response
        .response
        .user_handle
        .as_ref()
        .map(|handle| {
            base64url_decode(handle)
                .ok()
                .and_then(|decoded| String::from_utf8(decoded).ok())
        })
        .flatten();

    // Check if credential is discoverable
    let is_discoverable = auth_data.is_discoverable();

    #[cfg(debug_assertions)]
    println!(
        "Credential properties:\n\
         - Type: {}\n\
         - User present: {}\n\
         - User verified: {}\n\
         - Backed up: {}",
        if is_discoverable {
            "discoverable"
        } else {
            "server-side"
        },
        auth_data.is_user_present(),
        auth_data.is_user_verified(),
        auth_data.is_backed_up(),
    );

    match (
        user_handle,
        &stored_credential.user.user_handle,
        is_discoverable,
    ) {
        (Some(handle), stored_handle, _) if handle != *stored_handle => {
            return Err(PasskeyError::Authentication(
                "User handle mismatch. For more details, run with RUST_LOG=debug".into(),
            ));
        }
        (None, _, true) => {
            // Discoverable credentials MUST provide a user handle
            return Err(PasskeyError::Authentication(
                "Missing required user handle for discoverable credential. For more details, run with RUST_LOG=debug".into(),
            ));
        }
        (None, _, false) => {
            // Non-discoverable credentials may omit the user handle
            #[cfg(debug_assertions)]
            println!("No user handle provided for non-discoverable credential");
        }
        _ => {
            #[cfg(debug_assertions)]
            println!("User handle verified successfully");
        }
    }

    // Verify the authenticator data counter
    let auth_counter = auth_data.counter;
    tracing::debug!(
        "Counter verification - stored: {}, received: {}",
        stored_credential.counter,
        auth_counter
    );

    if auth_counter == 0 {
        // Counter value of 0 means the authenticator doesn't support counters
        tracing::info!("Authenticator does not support counters (received counter=0)");
    } else if auth_counter <= stored_credential.counter {
        // Counter value decreased or didn't change - possible cloning attack
        tracing::warn!(
            "Counter verification failed - stored: {}, received: {}",
            stored_credential.counter,
            auth_counter
        );
        return Err(PasskeyError::Authentication(
            "Counter value decreased - possible credential cloning detected. For more details, run with RUST_LOG=debug".into(),
        ));
    } else {
        // Counter increased as expected
        tracing::debug!(
            "Counter verification successful - stored: {}, received: {}",
            stored_credential.counter,
            auth_counter
        );
    }

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &stored_credential.public_key);

    // Signature
    let signature = base64url_decode(&auth_response.response.signature)
        .map_err(|e| PasskeyError::Format(format!("Invalid signature: {}", e)))?;

    #[cfg(debug_assertions)]
    println!("Decoded signature length: {}", signature.len());

    // Prepare signed data
    let client_data_hash = digest::digest(&digest::SHA256, &client_data.raw_data);
    let mut signed_data = Vec::new();

    signed_data.extend_from_slice(&auth_data.raw_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    #[cfg(debug_assertions)]
    println!("Signed data length: {}", signed_data.len());

    // Verify signature using public key
    match public_key.verify(&signed_data, &signature) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!("Signature verification successful");

            // Update the counter
            PasskeyStore::update_credential_counter(
                &auth_response.id,
                stored_credential.counter + 1,
            )
            .await?;

            // Cleanup and return success
            GENERIC_CACHE_STORE
                .lock()
                .await
                .get_store_mut()
                .remove("auth_challenge", &auth_response.auth_id)
                .await
                .map_err(|e| PasskeyError::Storage(e.to_string()))?;

            Ok(stored_credential.user.name)
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            println!("Signature verification failed: {:?}", e);

            Err(PasskeyError::Verification(
                "Signature verification failed. For more details, run with RUST_LOG=debug".into(),
            ))
        }
    }
}

pub async fn get_credential(credential_id: &str) -> Result<Option<StoredCredential>, PasskeyError> {
    let credential = PasskeyStore::get_credential(credential_id).await?;
    Ok(credential)
}

impl ParsedClientData {
    fn from_base64(client_data_json: &str) -> Result<Self, PasskeyError> {
        let raw_data = base64url_decode(client_data_json)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

        let data_str = String::from_utf8(raw_data.clone())
            .map_err(|e| PasskeyError::Format(format!("Invalid UTF-8: {}", e)))?;

        let data: serde_json::Value = serde_json::from_str(&data_str)
            .map_err(|e| PasskeyError::Format(format!("Invalid JSON: {}", e)))?;

        let challenge = base64url_decode(
            data["challenge"]
                .as_str()
                .ok_or_else(|| PasskeyError::ClientData("Missing challenge".into()))?,
        )
        .map_err(|e| PasskeyError::Format(format!("Invalid challenge: {}", e)))?;

        Ok(Self {
            challenge,
            origin: data["origin"]
                .as_str()
                .ok_or_else(|| PasskeyError::ClientData("Missing origin".into()))?
                .to_string(),
            type_: data["type"]
                .as_str()
                .ok_or_else(|| PasskeyError::ClientData("Missing type".into()))?
                .to_string(),
            raw_data,
        })
    }

    fn verify(&self, stored_challenge: &[u8]) -> Result<(), PasskeyError> {
        // Verify challenge
        if self.challenge != stored_challenge {
            return Err(PasskeyError::Challenge(
                "Challenge mismatch. For more details, run with RUST_LOG=debug".into(),
            ));
        }

        // Verify origin
        if self.origin != *ORIGIN {
            return Err(PasskeyError::ClientData(format!(
                "Invalid origin. Expected: {}, Got: {}",
                *ORIGIN, self.origin
            )));
        }

        // Verify type for authentication
        if self.type_ != "webauthn.get" {
            return Err(PasskeyError::ClientData(format!(
                "Invalid type. Expected 'webauthn.get', Got: {}",
                self.type_
            )));
        }

        Ok(())
    }
}

/// Flags for AuthenticatorData as defined in WebAuthn spec Level 2
mod auth_data_flags {
    /// User Present (UP) - Bit 0
    pub(super) const UP: u8 = 1 << 0;
    /// User Verified (UV) - Bit 2
    pub(super) const UV: u8 = 1 << 2;
    /// Backup Eligibility (BE) - Bit 3 - Indicates if credential is discoverable
    pub(super) const BE: u8 = 1 << 3;
    /// Backup State (BS) - Bit 4
    pub(super) const BS: u8 = 1 << 4;
    /// Attested Credential Data Present - Bit 6
    pub(super) const AT: u8 = 1 << 6;
    /// Extension Data Present - Bit 7
    pub(super) const ED: u8 = 1 << 7;
}

impl AuthenticatorData {
    /// Parse base64url-encoded authenticator data
    /// Format (minimum 37 bytes):
    /// - RP ID Hash (32 bytes)
    /// - Flags (1 byte)
    /// - Counter (4 bytes)
    /// - Optional: Attested Credential Data
    /// - Optional: Extensions
    fn from_base64(auth_data: &str) -> Result<Self, PasskeyError> {
        let data = base64url_decode(auth_data)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

        if data.len() < 37 {
            return Err(PasskeyError::AuthenticatorData(
                "Authenticator data too short. For more details, run with RUST_LOG=debug".into(),
            ));
        }

        Ok(Self {
            rp_id_hash: data[..32].to_vec(),
            flags: data[32],
            counter: u32::from_be_bytes([data[33], data[34], data[35], data[36]]),
            raw_data: data,
        })
    }

    /// Check if user was present during the authentication
    fn is_user_present(&self) -> bool {
        (self.flags & auth_data_flags::UP) != 0
    }

    /// Check if user was verified by the authenticator
    fn is_user_verified(&self) -> bool {
        (self.flags & auth_data_flags::UV) != 0
    }

    /// Check if this is a discoverable credential (previously known as resident key)
    fn is_discoverable(&self) -> bool {
        (self.flags & auth_data_flags::BE) != 0
    }

    /// Check if this credential is backed up
    fn is_backed_up(&self) -> bool {
        (self.flags & auth_data_flags::BS) != 0
    }

    /// Check if attested credential data is present
    fn has_attested_credential_data(&self) -> bool {
        (self.flags & auth_data_flags::AT) != 0
    }

    /// Check if extension data is present
    fn has_extension_data(&self) -> bool {
        (self.flags & auth_data_flags::ED) != 0
    }

    /// Verify the authenticator data
    fn verify(&self) -> Result<(), PasskeyError> {
        // Verify rpIdHash matches SHA-256 hash of rpId
        let expected_hash = digest::digest(&digest::SHA256, PASSKEY_RP_ID.as_bytes());
        if self.rp_id_hash != expected_hash.as_ref() {
            return Err(PasskeyError::AuthenticatorData(format!(
                "Invalid RP ID hash. Expected: {:?}, Got: {:?}",
                expected_hash.as_ref(),
                self.rp_id_hash
            )));
        }

        // Verify user present flag
        if !self.is_user_present() {
            return Err(PasskeyError::Authentication(
                "User not present. For more details, run with RUST_LOG=debug".into(),
            ));
        }

        // Verify user verification if required
        if *PASSKEY_USER_VERIFICATION == "required" && !self.is_user_verified() {
            return Err(PasskeyError::AuthenticatorData(format!(
                "User verification required but flag not set. Flags: {:02x}",
                self.flags
            )));
        }

        Ok(())
    }
}
