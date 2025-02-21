use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey};
use pkcs1::{EncodeRsaPublicKey, LineEnding};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

use dashmap::DashMap;
use moka::future::Cache;
use once_cell::sync::Lazy;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwk {
    kty: String,
    kid: String,
    alg: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    crv: Option<String>,
    k: Option<String>,
}

#[allow(unused)]
#[derive(Debug, Deserialize, Clone)]
pub struct IdInfo {
    pub iss: String,
    pub sub: String,
    pub azp: String,
    pub aud: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub picture: Option<String>,
    pub given_name: String,
    pub family_name: String,
    pub locale: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    pub nonce: Option<String>,
    pub hd: Option<String>,
    pub at_hash: Option<String>,
}

#[derive(Error, Debug)]
pub enum TokenVerificationError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Base64 decoding failed: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("Invalid token signature")]
    InvalidTokenSignature,
    #[error("Invalid token audience, expected: {0}, actual: {1}")]
    InvalidTokenAudience(String, String),
    #[error("Invalid token issuer, expected: {0}, actual: {1}")]
    InvalidTokenIssuer(String, String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Token not yet valid, now: {0}, nbf: {1}")]
    TokenNotYetValidNotBeFore(u64, u64),
    #[error("Token not yet valid, now: {0}, iat: {1}")]
    TokenNotYetValidIssuedAt(u64, u64),
    #[error("No matching key found in JWKS")]
    NoMatchingKey,
    #[error("Missing key component: {0}")]
    MissingKeyComponent(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("PKCS1 error: {0}")]
    Pkcs1Error(#[from] pkcs1::Error),
}

// Define a struct to hold the JWKS and its expiration time
struct CachedJwks {
    jwks: Jwks,
    expiration: Instant,
}

const CACHE_MODE: &str = "moka";
const CACHE_EXPIRATION: Duration = Duration::from_secs(600);

async fn fetch_jwks(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    match CACHE_MODE {
        "nocache" => fetch_jwks_nocache(jwks_url).await,
        "dashmap" => fetch_jwks_dashmap(jwks_url).await,
        "arc_rwlock_hashmap" => fetch_jwks_arh(jwks_url).await,
        "moka" => fetch_jwks_moka(jwks_url).await,
        _ => fetch_jwks_moka(jwks_url).await,
    }
}

// 0. Without caching:
async fn fetch_jwks_nocache(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    let resp = reqwest::get(jwks_url).await?;
    let jwks: Jwks = resp.json().await?;
    Ok(jwks)
}

// 1. DashMap + Lazy + RwLock:
static JWKS_CACHE_DASHMAP: Lazy<DashMap<String, RwLock<CachedJwks>>> = Lazy::new(DashMap::new);

async fn fetch_jwks_dashmap(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    // Check if the JWKS is in the cache and not expired
    if let Some(cached) = JWKS_CACHE_DASHMAP.get(jwks_url) {
        let cached_jwks = cached.value().read().await;
        if cached_jwks.expiration > Instant::now() {
            return Ok(cached_jwks.jwks.clone());
        }
    }

    // If not in cache or expired, fetch from the URL
    let resp = reqwest::get(jwks_url).await?;
    let jwks: Jwks = resp.json().await?;

    // Update the cache
    let cached_jwks = CachedJwks {
        jwks: jwks.clone(),
        expiration: Instant::now() + CACHE_EXPIRATION,
    };
    JWKS_CACHE_DASHMAP.insert(jwks_url.to_string(), RwLock::new(cached_jwks));

    Ok(jwks)
}

// 2. Arc<RwLock<HashMap>> + tokio::time::Instant:
static JWKS_CACHE_ARC_RWLOCK_HASHMAP: Lazy<Arc<RwLock<HashMap<String, CachedJwks>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

async fn fetch_jwks_arh(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    // Try to get from cache first
    {
        let cache = JWKS_CACHE_ARC_RWLOCK_HASHMAP.read().await;
        if let Some(cached) = cache.get(jwks_url) {
            if cached.expiration > Instant::now() {
                return Ok(cached.jwks.clone());
            }
        }
    } // The RwLock read guard is dropped here

    // If not in cache or expired, fetch from the URL
    let resp = reqwest::get(jwks_url).await?;
    let jwks: Jwks = resp.json().await?;

    // Update the cache
    let mut cache = JWKS_CACHE_ARC_RWLOCK_HASHMAP.write().await;
    cache.insert(
        jwks_url.to_string(),
        CachedJwks {
            jwks: jwks.clone(),
            expiration: Instant::now() + CACHE_EXPIRATION,
        },
    );

    Ok(jwks)
}

// 3. moka::future::Cache:
static JWKS_CACHE_MOKA: Lazy<Cache<String, Jwks>> = Lazy::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(3600))
        .build()
});

async fn fetch_jwks_moka(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    if let Some(jwks) = JWKS_CACHE_MOKA.get(jwks_url).await {
        return Ok(jwks);
    }

    let resp = reqwest::get(jwks_url).await?;
    let jwks: Jwks = resp.json().await?;

    JWKS_CACHE_MOKA
        .insert(jwks_url.to_string(), jwks.clone())
        .await;
    Ok(jwks)
}

fn find_jwk<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|key| key.kid == kid)
}

fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, TokenVerificationError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(TokenVerificationError::from)
}

fn convert_jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, TokenVerificationError> {
    match jwk.alg.as_str() {
        "RS256" | "RS384" | "RS512" => {
            let n = decode_base64_url_safe(
                jwk.n
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("n".to_string()))?,
            )?;
            let e = decode_base64_url_safe(
                jwk.e
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("e".to_string()))?,
            )?;
            let rsa_public_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n),
                rsa::BigUint::from_bytes_be(&e),
            )?;
            let pem = rsa_public_key.to_pkcs1_pem(LineEnding::default())?;
            Ok(DecodingKey::from_rsa_pem(pem.as_bytes())?)
        }
        "ES256" | "ES384" | "ES512" => {
            let x = decode_base64_url_safe(
                jwk.x
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("x".to_string()))?,
            )?;
            let x_str = std::str::from_utf8(&x)?;
            let y = decode_base64_url_safe(
                jwk.y
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("y".to_string()))?,
            )?;
            let y_str = std::str::from_utf8(&y)?;
            Ok(DecodingKey::from_ec_components(x_str, y_str)?)
        }
        "HS256" | "HS384" | "HS512" => {
            let k = decode_base64_url_safe(
                jwk.k
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("k".to_string()))?,
            )?;
            Ok(DecodingKey::from_secret(&k))
        }
        alg => Err(TokenVerificationError::UnsupportedAlgorithm(
            alg.to_string(),
        )),
    }
}

fn decode_token(token: &str) -> Result<IdInfo, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }
    let payload = parts[1];
    let decoded_payload = decode_base64_url_safe(payload)?;
    let idinfo: IdInfo = serde_json::from_slice(&decoded_payload)?;
    Ok(idinfo)
}

fn verify_signature(
    token: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<bool, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = decode_base64_url_safe(parts[2])?;
    let signature_str = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);

    match jsonwebtoken::crypto::verify(&signature_str, message.as_bytes(), decoding_key, alg) {
        Ok(valid) => Ok(valid),
        Err(err) => Err(TokenVerificationError::from(err)),
    }
}

pub async fn verify_idtoken(
    token: String,
    audience: String,
) -> Result<IdInfo, TokenVerificationError> {
    let header = jsonwebtoken::decode_header(&token)?;

    let kid = header
        .kid
        .ok_or(TokenVerificationError::MissingKeyComponent(
            "kid".to_string(),
        ))?;
    let alg = header.alg;

    println!("Algorithm from JWT header: {:?}", alg);

    let idinfo: IdInfo = decode_token(&token)?;
    #[cfg(debug_assertions)]
    println!("Decoded id_token payload: {:#?}", idinfo);

    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let jwks = fetch_jwks(jwks_url).await?;
    let jwk = find_jwk(&jwks, &kid).ok_or(TokenVerificationError::NoMatchingKey)?;

    let decoding_key = convert_jwk_to_decoding_key(jwk)?;

    let signature_valid = verify_signature(&token, &decoding_key, alg)?;
    if !signature_valid {
        return Err(TokenVerificationError::InvalidTokenSignature);
    }

    if idinfo.aud != audience {
        return Err(TokenVerificationError::InvalidTokenAudience(
            audience,
            idinfo.aud.to_string(),
        ));
    }

    let supplied_issuer = "https://accounts.google.com";
    if idinfo.iss != supplied_issuer {
        return Err(TokenVerificationError::InvalidTokenIssuer(
            idinfo.iss.to_string(),
            supplied_issuer.to_string(),
        ));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let skew: u64 = 2; // allow 2 seconds of skew

    if let Some(nbf) = idinfo.nbf {
        if now + skew < nbf.try_into().unwrap() {
            // tolerate the system clock to be the skew seconds behind
            return Err(TokenVerificationError::TokenNotYetValidNotBeFore(
                now,
                nbf.try_into().unwrap(),
            ));
        }
    }

    if now + skew < idinfo.iat.try_into().unwrap() {
        // tolerate the system clock to be the skew seconds behind
        return Err(TokenVerificationError::TokenNotYetValidIssuedAt(
            now,
            idinfo.iat.try_into().unwrap(),
        ));
    } else if now > idinfo.exp.try_into().unwrap() {
        return Err(TokenVerificationError::TokenExpired);
    }

    Ok(idinfo)
}
