use ciborium::value::{Integer, Value as CborValue};
use ring::{digest, signature::UnparsedPublicKey};
use std::time::SystemTime;
use webpki::EndEntityCert;
use x509_parser::{certificate::X509Certificate, prelude::*, time::ASN1Time};

use super::types::AttestationObject;
use crate::config::{PASSKEY_RP_ID, PASSKEY_USER_VERIFICATION};
use crate::errors::PasskeyError;

// Constants for FIDO OIDs id-fido-gen-ce-aaguid
const OID_FIDO_GEN_CE_AAGUID: &str = "1.3.6.1.4.1.45724.1.1.4";

const EC2_KEY_TYPE: i64 = 2;
const ES256_ALG: i64 = -7;
const COORD_LENGTH: usize = 32;

pub(super) fn verify_attestation(
    attestation: &AttestationObject,
    client_data: &[u8],
) -> Result<(), PasskeyError> {
    let client_data_hash = digest::digest(&digest::SHA256, client_data);

    match attestation.fmt.as_str() {
        "none" => {
            // for platform authenticators
            #[cfg(debug_assertions)]
            println!("Using 'none' attestation format");
            verify_none_attestation(attestation)
        }
        "packed" => {
            // for security keys
            #[cfg(debug_assertions)]
            println!("Using 'packed' attestation format");
            verify_packed_attestation(
                &attestation.auth_data,
                client_data_hash.as_ref(),
                &attestation.att_stmt,
            )
            .map_err(|e| {
                PasskeyError::Verification(format!("Attestation verification failed: {:?}", e))
            })
        }
        _ => Err(PasskeyError::Format(
            "Unsupported attestation format".to_string(),
        )),
    }
}

fn verify_none_attestation(attestation: &AttestationObject) -> Result<(), PasskeyError> {
    // Verify attStmt is empty
    if !attestation.att_stmt.is_empty() {
        return Err(PasskeyError::Format(
            "attStmt must be empty for none attestation".to_string(),
        ));
    }

    // Verify RP ID hash
    let rp_id_hash = digest::digest(&digest::SHA256, PASSKEY_RP_ID.as_bytes());
    if attestation.auth_data[..32] != rp_id_hash.as_ref()[..] {
        return Err(PasskeyError::Verification("Invalid RP ID hash".to_string()));
    }

    // Check flags
    let flags = attestation.auth_data[32];
    let user_present = (flags & 0x01) != 0;
    let user_verified = (flags & 0x04) != 0;
    let has_attested_cred_data = (flags & 0x40) != 0;

    if !user_present {
        return Err(PasskeyError::AuthenticatorData(
            "User Present flag not set".to_string(),
        ));
    }

    // Check UV flag if requested
    if *PASSKEY_USER_VERIFICATION == "required" && !user_verified {
        return Err(PasskeyError::AuthenticatorData(
            "User Verification required but flag not set".to_string(),
        ));
    }

    if !has_attested_cred_data {
        return Err(PasskeyError::AuthenticatorData(
            "No attested credential data".to_string(),
        ));
    }

    // Extract AAGUID (starts at byte 37, 16 bytes long)
    let aaguid = &attestation.auth_data[37..53];
    #[cfg(debug_assertions)]
    println!("AAGUID: {:?}", aaguid);

    // Verify credential public key format
    let mut pos = 55; // After AAGUID and 2-byte credential ID length
    let cred_id_len =
        ((attestation.auth_data[53] as usize) << 8) | (attestation.auth_data[54] as usize);
    pos += cred_id_len;

    // Verify COSE key format
    let public_key_cbor: CborValue = ciborium::de::from_reader(&attestation.auth_data[pos..])
        .map_err(|e| PasskeyError::Format(format!("Invalid public key CBOR: {}", e)))?;

    extract_public_key_coords(&public_key_cbor).map_err(|e| {
        PasskeyError::Verification(format!("Invalid public key coordinates: {}", e))
    })?;

    Ok(())
}

fn verify_packed_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(), PasskeyError> {
    // 1) Get the alg and sig from the existing helper
    let (alg, sig) = get_sig_from_stmt(att_stmt)?;

    // 2) Build the data that was signed
    let mut signed_data = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed_data.extend_from_slice(auth_data);
    signed_data.extend_from_slice(client_data_hash);

    // 3) Make sure it's an ECDSA P-256 / SHA256 attestation
    if alg != ES256_ALG {
        return Err(PasskeyError::Verification(format!(
            "Unsupported or unrecognized algorithm: {}",
            alg
        )));
    }

    // 4) Extract x5c and verify its presence for packed attestation
    let mut x5c_opt: Option<Vec<Vec<u8>>> = None;
    let mut ecdaa_key_id: Option<Vec<u8>> = None;

    for (k, v) in att_stmt {
        if let (CborValue::Text(key_str), CborValue::Array(certs)) = (k, v) {
            if key_str == "x5c" {
                let mut cert_chain = Vec::new();
                for cert in certs {
                    if let CborValue::Bytes(cert_bytes) = cert {
                        cert_chain.push(cert_bytes.clone());
                    }
                }
                if !cert_chain.is_empty() {
                    x5c_opt = Some(cert_chain);
                }
            }
        } else if let (CborValue::Text(key_str), CborValue::Bytes(id)) = (k, v) {
            if key_str == "ecdaaKeyId" {
                ecdaa_key_id = Some(id.clone());
            }
        }
    }

    // 5) Based on attestation type, verify accordingly
    match (x5c_opt, ecdaa_key_id) {
        (Some(x5c), None) => {
            // Full attestation with certificate chain
            #[cfg(debug_assertions)]
            println!("Full attestation with certificate chain");

            let attestn_cert_bytes = &x5c[0];
            let attestn_cert =
                EndEntityCert::try_from(attestn_cert_bytes.as_ref()).map_err(|e| {
                    PasskeyError::Verification(format!(
                        "Failed to parse attestation certificate: {:?}",
                        e
                    ))
                })?;

            // Parse with x509-parser for additional verifications
            let (_, x509_cert) = X509Certificate::from_der(attestn_cert_bytes).map_err(|e| {
                PasskeyError::Verification(format!("Failed to parse X509 certificate: {}", e))
            })?;

            // Verify certificate attributes according to FIDO standard
            verify_packed_attestation_cert(&x509_cert, auth_data)?;

            // Verify the signature
            attestn_cert
                .verify_signature(&webpki::ECDSA_P256_SHA256, &signed_data, &sig)
                .map_err(|_| {
                    PasskeyError::Verification("Attestation signature invalid".to_string())
                })?;

            // Verify certificate chain if intermediates are present
            if x5c.len() > 1 {
                verify_certificate_chain(&x5c)?;
            }
        }
        (None, Some(_)) => {
            return Err(PasskeyError::Verification(
                "ECDAA attestation not supported".to_string(),
            ));
        }
        (None, None) => {
            #[cfg(debug_assertions)]
            println!("Self attestation");
            verify_self_attestation(auth_data, &signed_data, &sig)?;
        }
        (Some(_), Some(_)) => {
            return Err(PasskeyError::Verification(
                "Invalid attestation: both x5c and ecdaaKeyId present".to_string(),
            ));
        }
    }

    Ok(())
}

fn get_sig_from_stmt(
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(i64, Vec<u8>), PasskeyError> {
    let mut alg = None;
    let mut sig = None;

    for (key, value) in att_stmt {
        match key {
            CborValue::Text(k) if k == "alg" => {
                if let CborValue::Integer(a) = value {
                    if a == &Integer::from(ES256_ALG) {
                        alg = Some(ES256_ALG);
                    }
                }
            }
            CborValue::Text(k) if k == "sig" => {
                if let CborValue::Bytes(s) = value {
                    sig = Some(s.clone());
                }
            }
            _ => {}
        }
    }

    match (alg, sig) {
        (Some(a), Some(s)) => Ok((a, s)),
        _ => Err(PasskeyError::Verification(
            "Missing algorithm or signature in attestation statement".to_string(),
        )),
    }
}

fn verify_packed_attestation_cert(
    cert: &X509Certificate,
    auth_data: &[u8],
) -> Result<(), PasskeyError> {
    // Check that it's not a CA certificate
    if let Some(basic_constraints) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.as_bytes() == oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS.as_bytes())
    {
        if basic_constraints.value.contains(&0x01) {
            return Err(PasskeyError::Verification(
                "Certificate must not be a CA certificate".to_string(),
            ));
        }
    }

    // Verify AAGUID if present
    if let Some(fido_ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_string() == OID_FIDO_GEN_CE_AAGUID)
    {
        let auth_data_aaguid = &auth_data[37..53];
        let cert_aaguid = fido_ext.value;

        // The format of this extension typically includes:
        // 0x04: This byte indicates the ASN.1 tag for an OCTET STRING.
        // 0x10: This byte represents the length of the OCTET STRING in hexadecimal, which is 16 bytes (decimal 16).
        // #[cfg(debug_assertions)]
        // println!("auth_data_aaguid: {:?}, cert_aaguid: {:?}", auth_data_aaguid, &cert_aaguid[2..]);

        if auth_data_aaguid != &cert_aaguid[2..] {
            return Err(PasskeyError::Verification(
                "AAGUID mismatch between certificate and authenticator data".to_string(),
            ));
        }
    }

    Ok(())
}

fn verify_certificate_chain(x5c: &[Vec<u8>]) -> Result<(), PasskeyError> {
    if x5c.is_empty() {
        return Ok(());
    }

    for cert_bytes in x5c {
        let (_, cert) = X509Certificate::from_der(cert_bytes).map_err(|e| {
            PasskeyError::Verification(format!("Failed to parse certificate in chain: {}", e))
        })?;

        // Convert SystemTime to ASN1Time
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| PasskeyError::Verification(format!("System time error: {}", e)))?;

        let timestamp = ASN1Time::from_timestamp(now.as_secs() as i64)
            .map_err(|e| PasskeyError::Verification(format!("Failed to convert time: {}", e)))?;

        if !cert.validity().is_valid_at(timestamp) {
            return Err(PasskeyError::Verification(
                "Certificate in chain is expired or not yet valid".to_string(),
            ));
        }
    }

    Ok(())
}

fn verify_self_attestation(
    auth_data: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), PasskeyError> {
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;

    if !has_attested_cred_data {
        return Err(PasskeyError::Verification(
            "No attested credential data in self attestation".to_string(),
        ));
    }

    let mut pos = 37; // Skip RP ID hash (32) + flags (1) + counter (4)
    pos += 16; // Skip AAGUID

    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2 + cred_id_len;

    let public_key_cbor: CborValue = ciborium::de::from_reader(&auth_data[pos..]).map_err(|e| {
        PasskeyError::Verification(format!(
            "Invalid public key CBOR in self attestation: {}",
            e
        ))
    })?;

    let (x_coord, y_coord) = extract_public_key_coords(&public_key_cbor)?;

    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point format
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &public_key);

    public_key.verify(signed_data, signature).map_err(|_| {
        PasskeyError::Verification("Self attestation signature verification failed".to_string())
    })?;

    Ok(())
}

fn extract_public_key_coords(
    public_key_cbor: &CborValue,
) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
    if let CborValue::Map(map) = public_key_cbor {
        let mut x_coord = None;
        let mut y_coord = None;
        let mut key_type = None;
        let mut algorithm = None;

        for (key, value) in map {
            if let CborValue::Integer(i) = key {
                if i == &Integer::from(1) {
                    // kty
                    if let CborValue::Integer(k) = value {
                        key_type = Some(k);
                    }
                } else if i == &Integer::from(3) {
                    // alg
                    if let CborValue::Integer(a) = value {
                        algorithm = Some(a);
                    }
                } else if i == &Integer::from(-2) {
                    // x coordinate
                    if let CborValue::Bytes(x) = value {
                        x_coord = Some(x.clone());
                    }
                } else if i == &Integer::from(-3) {
                    // y coordinate
                    if let CborValue::Bytes(y) = value {
                        y_coord = Some(y.clone());
                    }
                }
            }
        }

        // Verify key type (2 = EC2) and algorithm (-7 = ES256)
        let key_type_val = Integer::from(EC2_KEY_TYPE);
        let alg_val = Integer::from(ES256_ALG);

        if (key_type != Some(&key_type_val)) || (algorithm != Some(&alg_val)) {
            return Err(PasskeyError::Verification(
                "Invalid key type or algorithm".to_string(),
            ));
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => {
                if x.len() != COORD_LENGTH || y.len() != COORD_LENGTH {
                    return Err(PasskeyError::Verification(
                        "Invalid coordinate length".to_string(),
                    ));
                }
                Ok((x, y))
            }
            _ => Err(PasskeyError::Verification(
                "Missing public key coordinates".to_string(),
            )),
        }
    } else {
        Err(PasskeyError::Verification(
            "Invalid public key format".to_string(),
        ))
    }
}
