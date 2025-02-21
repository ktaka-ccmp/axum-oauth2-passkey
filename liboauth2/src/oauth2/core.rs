use anyhow::Context;
use headers::Cookie;
use http::header::HeaderMap;

// use http::HeaderValue;
// use tower_http::cors::CorsLayer;

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use url::Url;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::common::{gen_random_string, header_set_cookie};
use crate::config::{
    OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_MAX_AGE, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_GOOGLE_CLIENT_ID,
    OAUTH2_GOOGLE_CLIENT_SECRET, OAUTH2_QUERY_STRING, OAUTH2_REDIRECT_URI, OAUTH2_TOKEN_URL,
    OAUTH2_USERINFO_URL, TOKEN_STORE,
};
use crate::errors::AppError;
use crate::oauth2::idtoken::{verify_idtoken, IdInfo as GoogleIdInfo};
use crate::types::{AuthResponse, GoogleUserInfo, OidcTokenResponse, StateParams, StoredToken};

pub fn encode_state(csrf_token: String, nonce_id: String, pkce_id: String) -> String {
    let state_params = StateParams {
        csrf_token,
        nonce_id,
        pkce_id,
    };

    let state_json = serde_json::json!(state_params).to_string();
    URL_SAFE.encode(state_json)
}

pub async fn generate_store_token(
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
) -> Result<(String, String), AppError> {
    let token = gen_random_string(32)?;
    let token_id = gen_random_string(32)?;

    let token_data = StoredToken {
        token: token.clone(),
        expires_at,
        user_agent,
        ttl: *OAUTH2_CSRF_COOKIE_MAX_AGE,
    };

    TOKEN_STORE
        .lock()
        .await
        .get_store_mut()
        .put(&token_id, token_data.clone())
        .await?;

    Ok((token, token_id))
}

pub async fn prepare_oauth2_auth_request(
    headers: HeaderMap,
) -> Result<(String, HeaderMap), AppError> {
    let expires_at = Utc::now() + Duration::seconds((*OAUTH2_CSRF_COOKIE_MAX_AGE) as i64);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let (csrf_token, csrf_id) = generate_store_token(expires_at, Some(user_agent)).await?;
    let (nonce_token, nonce_id) = generate_store_token(expires_at, None).await?;
    let (pkce_token, pkce_id) = generate_store_token(expires_at, None).await?;
    #[cfg(debug_assertions)]
    println!("PKCE ID: {:?}, PKCE verifier: {:?}", pkce_id, pkce_token);
    let pkce_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_token.as_bytes()));
    #[cfg(debug_assertions)]
    println!("PKCE Challenge: {:#?}", pkce_challenge);
    let encoded_state = encode_state(csrf_token, nonce_id, pkce_id);
    let auth_url = format!(
        "{}?{}&client_id={}&redirect_uri={}&state={}&nonce={}\
        &code_challenge={}&code_challenge_method={}",
        OAUTH2_AUTH_URL.as_str(),
        OAUTH2_QUERY_STRING.as_str(),
        OAUTH2_GOOGLE_CLIENT_ID.as_str(),
        OAUTH2_REDIRECT_URI.as_str(),
        encoded_state,
        nonce_token,
        pkce_challenge,
        "S256"
    );
    #[cfg(debug_assertions)]
    println!("Auth URL: {:#?}", auth_url);
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        csrf_id,
        expires_at,
        *OAUTH2_CSRF_COOKIE_MAX_AGE as i64,
    )?;
    Ok((auth_url, headers))
}

pub async fn get_idinfo_userinfo(
    auth_response: &AuthResponse,
) -> Result<(GoogleIdInfo, GoogleUserInfo), AppError> {
    let pkce_verifier = get_pkce_verifier(auth_response).await?;
    let (access_token, id_token) =
        exchange_code_for_token(auth_response.code.clone(), pkce_verifier).await?;

    let idinfo = verify_idtoken(id_token, OAUTH2_GOOGLE_CLIENT_ID.to_string()).await?;
    verify_nonce(auth_response, idinfo.clone()).await?;

    let userinfo = fetch_user_data_from_google(access_token).await?;

    if idinfo.sub != userinfo.id {
        println!(
            "Id mismatch in IdInfo and Userinfo: \nIdInfo: {:#?}\nUserInfo: {:#?}",
            idinfo, userinfo
        );
        return Err(anyhow::anyhow!("ID mismatch").into());
    }
    Ok((idinfo, userinfo))
}

async fn get_pkce_verifier(auth_response: &AuthResponse) -> Result<String, AppError> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)?;

    let pkce_session = TOKEN_STORE
        .lock()
        .await
        .get_store()
        .get(&state_in_response.pkce_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("PKCE Session not found"))?;

    TOKEN_STORE
        .lock()
        .await
        .get_store_mut()
        .remove(&state_in_response.pkce_id)
        .await
        .expect("Failed to remove PKCE session");

    let pkce_verifier = pkce_session.token.clone();
    println!("PKCE Verifier: {:#?}", pkce_verifier);
    Ok(pkce_verifier)
}

async fn verify_nonce(auth_response: &AuthResponse, idinfo: GoogleIdInfo) -> Result<(), AppError> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)?;

    let nonce_session = TOKEN_STORE
        .lock()
        .await
        .get_store()
        .get(&state_in_response.nonce_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Nonce Session not found"))?;

    println!("Nonce Data: {:#?}", nonce_session);

    if Utc::now() > nonce_session.expires_at {
        println!("Nonce Expired: {:#?}", nonce_session.expires_at);
        println!("Now: {:#?}", Utc::now());
        return Err(anyhow::anyhow!("Nonce expired").into());
    }
    if idinfo.nonce != Some(nonce_session.token.clone()) {
        println!("Nonce in ID Token: {:#?}", idinfo.nonce);
        println!("Stored Nonce: {:#?}", nonce_session.token);
        return Err(anyhow::anyhow!("Nonce mismatch").into());
    }

    TOKEN_STORE
        .lock()
        .await
        .get_store_mut()
        .remove(&state_in_response.nonce_id)
        .await
        .expect("Failed to remove nonce session");

    Ok(())
}

pub async fn validate_origin(headers: &HeaderMap, auth_url: &str) -> Result<(), AppError> {
    let parsed_url = Url::parse(auth_url).expect("Invalid URL");
    let scheme = parsed_url.scheme();
    let host = parsed_url.host_str().unwrap_or_default();
    let port = parsed_url
        .port()
        .map_or("".to_string(), |p| format!(":{}", p));
    let expected_origin = format!("{}://{}{}", scheme, host, port);

    let origin = headers
        .get("Origin")
        .or_else(|| headers.get("Referer"))
        .and_then(|h| h.to_str().ok());

    match origin {
        Some(origin) if origin.starts_with(&expected_origin) => Ok(()),
        _ => {
            println!("Expected Origin: {:#?}", expected_origin);
            println!("Actual Origin: {:#?}", origin);
            Err(anyhow::anyhow!("Invalid origin").into())
        }
    }
}

pub async fn csrf_checks(
    cookies: Cookie,
    query: &AuthResponse,
    headers: HeaderMap,
) -> Result<(), AppError> {
    let csrf_id = cookies
        .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
        .ok_or_else(|| anyhow::anyhow!("No CSRF session cookie found"))?;
    let csrf_session = TOKEN_STORE
        .lock()
        .await
        .get_store()
        .get(csrf_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("CSRF Session not found in Session Store"))?;

    TOKEN_STORE
        .lock()
        .await
        .get_store_mut()
        .remove(csrf_id)
        .await
        .expect("Failed to remove PKCE session");

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let decoded_state_string = String::from_utf8(
        URL_SAFE
            .decode(&query.state)
            .map_err(|e| anyhow::anyhow!("Failed to decode state: {e}"))?,
    )
    .context("Failed to convert decoded state to string")?;

    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .context("Failed to deserialize state from response")?;

    if state_in_response.csrf_token != csrf_session.token {
        println!(
            "CSRF Token in state param: {:#?}",
            state_in_response.csrf_token
        );
        println!("Stored CSRF Token: {:#?}", csrf_session.token);
        return Err(anyhow::anyhow!("CSRF token mismatch").into());
    }

    if Utc::now() > csrf_session.expires_at {
        println!("Now: {}", Utc::now());
        println!("CSRF Expires At: {:#?}", csrf_session.expires_at);
        return Err(anyhow::anyhow!("CSRF token expired").into());
    }

    if user_agent != csrf_session.user_agent.clone().unwrap_or_default() {
        println!("User Agent: {:#?}", user_agent);
        println!(
            "Stored User Agent: {:#?}",
            csrf_session.user_agent.unwrap_or_default()
        );
        return Err(anyhow::anyhow!("User agent mismatch").into());
    }

    Ok(())
}

async fn fetch_user_data_from_google(access_token: String) -> Result<GoogleUserInfo, AppError> {
    let client = crate::client::get_client();
    let response = client
        .get(OAUTH2_USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .context("failed in sending request to target Url")?;
    let response_body = response
        .text()
        .await
        .context("failed to get response body")?;
    #[cfg(debug_assertions)]
    println!("Response Body: {:#?}", response_body);
    let user_data: GoogleUserInfo = serde_json::from_str(&response_body).context(format!(
        "Failed to deserialize response body: {}",
        response_body
    ))?;
    #[cfg(debug_assertions)]
    println!("User data: {:#?}", user_data);
    Ok(user_data)
}

async fn exchange_code_for_token(
    code: String,
    code_verifier: String,
) -> Result<(String, String), AppError> {
    let client = crate::client::get_client();
    let response = client
        .post(OAUTH2_TOKEN_URL.as_str())
        .form(&[
            ("code", code),
            ("client_id", OAUTH2_GOOGLE_CLIENT_ID.to_string()),
            ("client_secret", OAUTH2_GOOGLE_CLIENT_SECRET.to_string()),
            ("redirect_uri", OAUTH2_REDIRECT_URI.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .context("failed in sending request request to authorization server")?;

    match response.status() {
        reqwest::StatusCode::OK => {
            println!("Debug Token Exchange Response: {:#?}", response);
        }
        status => {
            println!("Token Exchange Response: {:#?}", response);
            return Err(anyhow::anyhow!("Unexpected status code: {:#?}", status).into());
        }
    };

    let response_body = response
        .text()
        .await
        .context("failed to get response body")?;
    let response_json: OidcTokenResponse =
        serde_json::from_str(&response_body).context("failed to deserialize response body")?;
    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.clone().unwrap();
    println!("Response JSON: {:#?}", response_json);
    Ok((access_token, id_token))
}
