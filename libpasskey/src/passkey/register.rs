use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::{Integer, Value as CborValue};
use std::time::SystemTime;

use libsession::User as SessionUser;

use super::types::{
    AttestationObject, AuthenticatorSelection, PubKeyCredParam, RegisterCredential,
    RegistrationOptions, RelyingParty,
};
use crate::common::{base64url_decode, generate_challenge};
use crate::config::{
    ORIGIN, PASSKEY_AUTHENTICATOR_ATTACHMENT, PASSKEY_CACHE_STORE, PASSKEY_CHALLENGE_STORE,
    PASSKEY_CHALLENGE_TIMEOUT, PASSKEY_CREDENTIAL_STORE, PASSKEY_REQUIRE_RESIDENT_KEY,
    PASSKEY_RESIDENT_KEY, PASSKEY_RP_ID, PASSKEY_RP_NAME, PASSKEY_TIMEOUT,
    PASSKEY_USER_VERIFICATION,
};
use crate::errors::PasskeyError;
use crate::types::{
    CacheData, EmailUserId, PublicKeyCredentialUserEntity, SessionInfo, StoredChallenge,
    StoredCredential, UserIdCredentialIdStr,
};

pub async fn start_registration(username: String) -> Result<RegistrationOptions, PasskeyError> {
    println!("start_registration user: {}", username);

    let user_info = PublicKeyCredentialUserEntity {
        id_handle: crate::common::gen_random_string(16)?,
        name: username.clone(),
        display_name: username.clone(),
    };

    let options = create_registration_options(user_info).await?;

    Ok(options)
}

pub async fn start_registration_with_auth_user(
    user: SessionUser,
) -> Result<RegistrationOptions, PasskeyError> {
    let user_info = PublicKeyCredentialUserEntity {
        id_handle: crate::common::gen_random_string(16)?,
        name: user.email.clone(),
        display_name: user.name.clone(),
    };

    // Wrap user info in session info to match the cache store data type
    let session_info = CacheData::SessionInfo(SessionInfo { user });

    PASSKEY_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .put(&user_info.id_handle, session_info)
        .await?;

    #[cfg(debug_assertions)]
    println!("User info: {:#?}", user_info);

    let options = create_registration_options(user_info).await?;

    Ok(options)
}

pub async fn create_registration_options(
    user_info: PublicKeyCredentialUserEntity,
) -> Result<RegistrationOptions, PasskeyError> {
    let challenge = generate_challenge();
    let stored_challenge = StoredChallenge {
        challenge: challenge.clone().unwrap_or_default(),
        user: user_info.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl: *PASSKEY_CHALLENGE_TIMEOUT as u64,
    };

    PASSKEY_CHALLENGE_STORE
        .lock()
        .await
        .get_store_mut()
        .store_challenge(user_info.id_handle.clone(), stored_challenge)
        .await?;

    let authenticator_selection = AuthenticatorSelection {
        authenticator_attachment: PASSKEY_AUTHENTICATOR_ATTACHMENT.to_string(),
        resident_key: PASSKEY_RESIDENT_KEY.to_string(),
        require_resident_key: *PASSKEY_REQUIRE_RESIDENT_KEY,
        user_verification: PASSKEY_USER_VERIFICATION.to_string(),
    };

    let options = RegistrationOptions {
        challenge: URL_SAFE.encode(challenge.unwrap_or_default()),
        rp_id: PASSKEY_RP_ID.to_string(),
        rp: RelyingParty {
            name: PASSKEY_RP_NAME.to_string(),
            id: PASSKEY_RP_ID.to_string(),
        },
        user: user_info,
        pub_key_cred_params: vec![
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -7,
            },
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -257,
            },
        ],
        authenticator_selection,
        timeout: (*PASSKEY_TIMEOUT) * 1000, // Convert seconds to milliseconds
        attestation: "direct".to_string(),
    };

    #[cfg(debug_assertions)]
    println!("Registration options: {:?}", options);

    Ok(options)
}

pub async fn finish_registration_with_auth_user(
    user: SessionUser,
    reg_data: RegisterCredential,
) -> Result<String, PasskeyError> {
    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let session_info = match PASSKEY_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .get(user_handle)
        .await?
    {
        Some(CacheData::SessionInfo(info)) => Ok(info),
        _ => Err(PasskeyError::Format("Invalid session type".to_string())),
    }?;

    // Delete the session info from the store
    PASSKEY_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove(user_handle)
        .await?;

    // Verify the user is the same as the one in the cache store i.e. used to start the registration
    if user.id != session_info.user.id {
        return Err(PasskeyError::Format("User ID mismatch".to_string()));
    }

    finish_registration(&reg_data).await?;

    // Store email vs credential ID etc. in CacheStore
    PASSKEY_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .put(
            &user.email.clone(),
            CacheData::EmailUserId(EmailUserId {
                email: user.email,
                user_id: user.id.clone(),
            }),
        )
        .await?;

    let credential_id = base64url_decode(&reg_data.raw_id)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode credential ID: {}", e)))?;

    PASSKEY_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .put(
            &user.id.clone(),
            CacheData::UserIdCredentialIdStr(UserIdCredentialIdStr {
                user_id: user.id,
                credential_id_str: reg_data.raw_id,
                credential_id,
            }),
        )
        .await?;

    Ok("Registration successful".to_string())
}

pub async fn finish_registration(reg_data: &RegisterCredential) -> Result<String, PasskeyError> {
    println!("finish_registration user: {:?}", reg_data);

    verify_client_data(reg_data).await?;

    let public_key = extract_credential_public_key(reg_data)?;

    // Decode and store credential
    let credential_id = base64url_decode(&reg_data.raw_id)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode credential ID: {}", e)))?;

    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let stored_challenge = PASSKEY_CHALLENGE_STORE
        .lock()
        .await
        .get_store()
        .get_challenge(user_handle)
        .await?
        .ok_or(PasskeyError::Storage(
            "No challenge found for this user".to_string(),
        ))?;

    let stored_user = stored_challenge.user.clone();

    // Store using base64url encoded credential_id as the key
    let credential_id_str = reg_data.raw_id.clone();

    PASSKEY_CREDENTIAL_STORE
        .lock()
        .await
        .get_store_mut()
        .store_credential(
            credential_id_str,
            StoredCredential {
                credential_id,
                public_key,
                counter: 0,
                user: stored_user,
            },
        )
        .await?;

    // Remove used challenge
    PASSKEY_CHALLENGE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove_challenge(user_handle)
        .await?;

    Ok("Registration successful".to_string())
}

fn extract_credential_public_key(reg_data: &RegisterCredential) -> Result<Vec<u8>, PasskeyError> {
    let decoded_client_data = base64url_decode(&reg_data.response.client_data_json)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode client data: {}", e)))?;

    let decoded_client_data_json = String::from_utf8(decoded_client_data.clone())
        .map_err(|e| PasskeyError::Format(format!("Client data is not valid UTF-8: {}", e)))
        .and_then(|s: String| {
            serde_json::from_str::<serde_json::Value>(&s).map_err(|e| {
                PasskeyError::Format(format!("Failed to parse client data JSON: {}", e))
            })
        })?;

    println!("Client data json: {:?}", decoded_client_data_json);

    let attestation_obj = parse_attestation_object(&reg_data.response.attestation_object)?;

    // Verify attestation based on format
    crate::passkey::attestation::verify_attestation(&attestation_obj, &decoded_client_data)?;

    // Extract public key from authenticator data
    let public_key = extract_public_key_from_auth_data(&attestation_obj.auth_data)?;

    Ok(public_key)
}

fn parse_attestation_object(attestation_base64: &str) -> Result<AttestationObject, PasskeyError> {
    let attestation_bytes = base64url_decode(attestation_base64)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode attestation object: {}", e)))?;

    let attestation_cbor: CborValue = ciborium::de::from_reader(&attestation_bytes[..])
        .map_err(|e| PasskeyError::Format(format!("Invalid CBOR data: {}", e)))?;

    if let CborValue::Map(map) = attestation_cbor {
        let mut fmt = None;
        let mut auth_data = None;
        let mut att_stmt = None;

        for (key, value) in map {
            if let CborValue::Text(k) = key {
                match k.as_str() {
                    "fmt" => {
                        if let CborValue::Text(f) = value {
                            fmt = Some(f);
                        }
                    }
                    "authData" => {
                        if let CborValue::Bytes(data) = value {
                            auth_data = Some(data);
                        }
                    }
                    "attStmt" => {
                        if let CborValue::Map(stmt) = value {
                            att_stmt = Some(stmt);
                        }
                    }
                    _ => {}
                }
            }
        }

        #[cfg(debug_assertions)]
        println!(
            "Attestation format: {:?}, auth data: {:?}, attestation statement: {:?}",
            fmt, auth_data, att_stmt
        );

        match (fmt, auth_data, att_stmt) {
            (Some(f), Some(d), Some(s)) => Ok(AttestationObject {
                fmt: f,
                auth_data: d,
                att_stmt: s,
            }),
            _ => Err(PasskeyError::Format(
                "Missing required attestation data".to_string(),
            )),
        }
    } else {
        Err(PasskeyError::Format(
            "Invalid attestation format".to_string(),
        ))
    }
}

fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    // Check attested credential data flag
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;
    if !has_attested_cred_data {
        return Err(PasskeyError::AuthenticatorData(
            "No attested credential data present".to_string(),
        ));
    }

    // Parse credential data
    let credential_data = parse_credential_data(auth_data)?;

    // Extract public key coordinates
    let (x_coord, y_coord) = extract_key_coordinates(credential_data)?;

    // Concatenate x and y coordinates for public key
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point format
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    Ok(public_key)
}

fn parse_credential_data(auth_data: &[u8]) -> Result<&[u8], PasskeyError> {
    let mut pos = 37; // Skip RP ID hash (32) + flags (1) + counter (4)

    if auth_data.len() < pos + 18 {
        return Err(PasskeyError::Format(
            "Authenticator data too short".to_string(),
        ));
    }

    pos += 16; // Skip AAGUID

    // Get credential ID length
    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2;

    if cred_id_len == 0 || cred_id_len > 1024 {
        return Err(PasskeyError::Format(
            "Invalid credential ID length".to_string(),
        ));
    }

    if auth_data.len() < pos + cred_id_len {
        return Err(PasskeyError::Format(
            "Authenticator data too short for credential ID".to_string(),
        ));
    }

    pos += cred_id_len;

    Ok(&auth_data[pos..])
}

fn extract_key_coordinates(credential_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
    let public_key_cbor: CborValue = ciborium::de::from_reader(credential_data)
        .map_err(|e| PasskeyError::Format(format!("Invalid public key CBOR: {}", e)))?;

    if let CborValue::Map(map) = public_key_cbor {
        let mut x_coord = None;
        let mut y_coord = None;

        for (key, value) in map {
            if let CborValue::Integer(i) = key {
                if i == Integer::from(-2) {
                    if let CborValue::Bytes(x) = value {
                        x_coord = Some(x);
                    }
                } else if i == Integer::from(-3) {
                    if let CborValue::Bytes(y) = value {
                        y_coord = Some(y);
                    }
                }
            }
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => Ok((x, y)),
            _ => Err(PasskeyError::Format(
                "Missing or invalid key coordinates".to_string(),
            )),
        }
    } else {
        Err(PasskeyError::Format(
            "Invalid public key format".to_string(),
        ))
    }
}

async fn verify_client_data(reg_data: &RegisterCredential) -> Result<(), PasskeyError> {
    // Decode and verify client data
    let decoded_client_data = base64url_decode(&reg_data.response.client_data_json)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode client data: {}", e)))?;

    let client_data_str = String::from_utf8(decoded_client_data.clone())
        .map_err(|e| PasskeyError::Format(format!("Client data is not valid UTF-8: {}", e)))
        .and_then(|s: String| {
            serde_json::from_str::<serde_json::Value>(&s).map_err(|e| {
                PasskeyError::Format(format!("Failed to parse client data JSON: {}", e))
            })
        })?;

    let origin = client_data_str["origin"]
        .as_str()
        .ok_or(PasskeyError::ClientData(
            "Missing origin in client data".to_string(),
        ))?;

    if origin != ORIGIN.to_string() {
        return Err(PasskeyError::ClientData("Invalid origin".to_string()));
    }

    let type_ = client_data_str["type"]
        .as_str()
        .ok_or(PasskeyError::ClientData(
            "Missing type in client data".to_string(),
        ))?;

    if type_ != "webauthn.create" {
        return Err(PasskeyError::ClientData("Invalid type".to_string()));
    }

    let challenge = client_data_str["challenge"]
        .as_str()
        .ok_or(PasskeyError::ClientData(
            "Missing challenge in client data".to_string(),
        ))?;

    let decoded_challenge = base64url_decode(challenge)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode challenge: {}", e)))?;

    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let challenge_store = PASSKEY_CHALLENGE_STORE.lock().await;

    let stored_challenge = challenge_store
        .get_store()
        .get_challenge(user_handle)
        .await?
        .ok_or(PasskeyError::Storage(
            "No challenge found for this user".to_string(),
        ))?;

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

    if decoded_challenge != stored_challenge.challenge {
        return Err(PasskeyError::Challenge(
            "Challenge verification failed".to_string(),
        ));
    }

    Ok(())
}
