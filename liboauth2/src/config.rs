use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::storage::{CacheStoreToken, InMemoryTokenStore};

use crate::types::TokenStoreType;

// static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
// static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) static OAUTH2_USERINFO_URL: &str = "https://www.googleapis.com/userinfo/v2/me";

pub static OAUTH2_AUTH_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_AUTH_URL")
        .ok()
        .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth".to_string())
});
pub(crate) static OAUTH2_TOKEN_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_TOKEN_URL")
        .ok()
        .unwrap_or("https://oauth2.googleapis.com/token".to_string())
});

static OAUTH2_SCOPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string()));

static OAUTH2_RESPONSE_MODE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string()));

static OAUTH2_RESPONSE_TYPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string()));

pub(crate) static OAUTH2_QUERY_STRING: LazyLock<String> = LazyLock::new(|| {
    let mut query_string = "".to_string();
    query_string.push_str(&format!("&response_type={}", *OAUTH2_RESPONSE_TYPE));
    query_string.push_str(&format!("&scope={}", *OAUTH2_SCOPE));
    query_string.push_str(&format!("&response_mode={}", *OAUTH2_RESPONSE_MODE));
    query_string.push_str(&format!("&access_type={}", "online"));
    query_string.push_str(&format!("&prompt={}", "consent"));
    query_string
});

// Supported parameters:
// response_type: code
// scope: openid+email+profile
// response_mode: form_post, query
// access_type: online, offline(for refresh token)
// prompt: none, consent, select_account

// "__Host-" prefix are added to make cookies "host-only".

pub static OAUTH2_CSRF_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-CsrfId".to_string())
});

pub(crate) static OAUTH2_CSRF_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 60 seconds if not set or invalid
});

pub static OAUTH2_ROUTE_PREFIX: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_ROUTE_PREFIX")
        .ok()
        .unwrap_or("/oauth2".to_string())
});

pub(crate) static OAUTH2_REDIRECT_URI: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}{}/authorized",
        env::var("ORIGIN").expect("Missing ORIGIN!"),
        OAUTH2_ROUTE_PREFIX.as_str()
    )
});

pub(crate) static OAUTH2_GOOGLE_CLIENT_ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set")
});

pub(crate) static OAUTH2_GOOGLE_CLIENT_SECRET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_SECRET").expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set")
});

/// A wrapper type that ensures the token store can only be set once
pub(crate) struct SingletonStore {
    store: Box<dyn CacheStoreToken>,
    initialized: bool,
}

impl SingletonStore {
    fn new(store: Box<dyn CacheStoreToken>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    /// Set the store implementation. This can only be done once.
    /// Returns an error if attempting to set the store after it's already been initialized.
    fn set_store(&mut self, new_store: Box<dyn CacheStoreToken>) -> Result<(), AppError> {
        if self.initialized {
            return Err(AppError(anyhow::anyhow!(
                "Token store has already been initialized"
            )));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    /// Get a reference to the underlying store
    pub(crate) fn get_store(&self) -> &dyn CacheStoreToken {
        &*self.store
    }

    /// Get a mutable reference to the underlying store, but only for operations
    /// defined in the CacheStoreToken trait
    pub(crate) fn get_store_mut(&mut self) -> &mut Box<dyn CacheStoreToken> {
        &mut self.store
    }
}

/// Global singleton for token storage. This follows a pattern where:
/// 1. We initialize with a safe default (InMemoryTokenStore) when the library is first loaded
/// 2. The actual implementation (Memory or Redis) is determined at runtime in init_token_store()
/// 3. We use SingletonStore to ensure the implementation can only be set once
///
/// Type structure:
/// ```text
/// static TOKEN_STORE: LazyLock<Mutex<SingletonStore>>
///     |                |      |    |
///     |                |      |    +-- Wrapper that ensures one-time initialization
///     |                |      +------- Thread-safe interior mutability
///     |                +-------------- Lazy initialization
///     +-------------------------------- Static lifetime
/// ```
///
/// Note on mutability:
/// - The store implementation can only be set once through SingletonStore::set_store
/// - Attempts to set the store after initialization will result in an error
/// - The Mutex ensures thread-safe access to store operations
pub(crate) static TOKEN_STORE: LazyLock<Mutex<SingletonStore>> =
    LazyLock::new(|| Mutex::new(SingletonStore::new(Box::new(InMemoryTokenStore::new()))));

/// Initialize the token store based on environment configuration.
/// This will:
/// 1. Check environment variables for store configuration (OAUTH2_TOKEN_STORE, OAUTH2_TOKEN_REDIS_URL)
/// 2. Create the appropriate store implementation (Memory or Redis)
/// 3. Replace the default in-memory store in TOKEN_STORE with the configured implementation
///
/// Initialize the token store based on environment configuration
pub async fn init_token_store() -> Result<(), AppError> {
    let store_type = TokenStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize token store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        TokenStoreType::Memory
    });

    tracing::info!("Initializing token store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    TOKEN_STORE.lock().await.set_store(store)?;
    tracing::info!("Token store initialized successfully");
    Ok(())
}
