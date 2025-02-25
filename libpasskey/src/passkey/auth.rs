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
    ORIGIN, PASSKEY_CHALLENGE_TIMEOUT, PASSKEY_CREDENTIAL_STORE,
    PASSKEY_RP_ID, PASSKEY_TIMEOUT, PASSKEY_USER_VERIFICATION,
};
use crate::errors::PasskeyError;
use crate::types::{PublicKeyCredentialUserEntity, StoredChallenge};

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
    let credential_store = PASSKEY_CREDENTIAL_STORE.lock().await;

    // let mut store = state.store.lock().await;
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
        return Err(PasskeyError::Authentication("Challenge has expired".into()));
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
    let credential = credential_store
        .get_store()
        .get_credential(&auth_response.id)
        .await?
        .ok_or(PasskeyError::Authentication("Unknown credential".into()))?;

    #[cfg(debug_assertions)]
    println!("Found credential: {:?}", credential);

    let user_handle = auth_response
        .response
        .user_handle
        .as_ref()
        .and_then(|handle| {
            base64url_decode(handle)
                .ok()
                .and_then(|decoded| String::from_utf8(decoded).ok())
        })
        .unwrap_or("default".to_string());

    #[cfg(debug_assertions)]
    println!("user_info stored in credential: {:?}", &credential.user);
    #[cfg(debug_assertions)]
    println!("user_handle received from client: {:?}", &user_handle);
    #[cfg(debug_assertions)]
    println!(
        "user_handle before decoding: {:?}",
        auth_response.response.user_handle
    );

    // let display_name = credential.user.display_name.as_str().to_owned();
    let name = credential.user.name.as_str().to_owned();

    if credential.user.user_handle != user_handle {
        return Err(PasskeyError::Authentication("User handle mismatch".into()));
    }

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);

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

            // Cleanup and return success
            GENERIC_CACHE_STORE
                .lock()
                .await
                .get_store_mut()
                .remove("auth_challenge", &auth_response.auth_id)
                .await
                .map_err(|e| PasskeyError::Storage(e.to_string()))?;

            Ok(name)
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            println!("Signature verification failed: {:?}", e);

            Err(PasskeyError::Verification(
                "Signature verification failed".into(),
            ))
        }
    }
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
            return Err(PasskeyError::Challenge("Challenge mismatch".into()));
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

impl AuthenticatorData {
    fn from_base64(auth_data: &str) -> Result<Self, PasskeyError> {
        let data = base64url_decode(auth_data)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

        if data.len() < 37 {
            return Err(PasskeyError::AuthenticatorData(
                "Authenticator data too short".into(),
            ));
        }

        Ok(Self {
            rp_id_hash: data[..32].to_vec(),
            flags: data[32],
            raw_data: data,
        })
    }

    fn verify(&self) -> Result<(), PasskeyError> {
        // Verify RP ID hash
        let expected_hash = digest::digest(&digest::SHA256, PASSKEY_RP_ID.as_bytes());
        if self.rp_id_hash != expected_hash.as_ref() {
            return Err(PasskeyError::AuthenticatorData(format!(
                "Invalid RP ID hash. Expected: {:?}, Got: {:?}",
                expected_hash.as_ref(),
                self.rp_id_hash
            )));
        }

        // Check user presence flag
        if self.flags & 0x01 == 0 {
            return Err(PasskeyError::AuthenticatorData(
                "User presence flag not set".into(),
            ));
        }

        // Check user verification flag if required
        if PASSKEY_USER_VERIFICATION.to_string().to_lowercase() == "required"
            && self.flags & 0x04 == 0
        {
            return Err(PasskeyError::AuthenticatorData(format!(
                "User verification required but flag not set. Flags: {:02x}",
                self.flags
            )));
        }

        Ok(())
    }
}
