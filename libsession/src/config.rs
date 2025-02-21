use std::sync::LazyLock;
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::storage::{CacheStoreSession, InMemorySessionStore};
use crate::types::SessionStoreType;

pub static SESSION_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-SessionId".to_string())
});
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600) // Default to 10 minutes if not set or invalid
});

/// A wrapper type that ensures the session store can only be set once
pub(crate) struct SingletonStore {
    store: Box<dyn CacheStoreSession>,
    initialized: bool,
}

impl SingletonStore {
    fn new(store: Box<dyn CacheStoreSession>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    /// Set the store implementation. This can only be done once.
    /// Returns an error if attempting to set the store after it's already been initialized.
    fn set_store(&mut self, new_store: Box<dyn CacheStoreSession>) -> Result<(), AppError> {
        if self.initialized {
            return Err(AppError(anyhow::anyhow!(
                "Session store has already been initialized"
            )));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    /// Get a reference to the underlying store
    pub(crate) fn get_store(&self) -> &dyn CacheStoreSession {
        &*self.store
    }

    /// Get a mutable reference to the underlying store, but only for operations
    /// defined in the CacheStoreSession trait
    pub(crate) fn get_store_mut(&mut self) -> &mut Box<dyn CacheStoreSession> {
        &mut self.store
    }
}

/// Global singleton for session storage. This follows a pattern where:
/// 1. We initialize with a safe default (InMemorySessionStore) when the library is first loaded
/// 2. The actual implementation (Memory or Redis) is determined at runtime in init_session_store()
/// 3. We use SingletonStore to ensure the implementation can only be set once
///
/// Type structure:
/// ```text
/// static SESSION_STORE: LazyLock<Mutex<SingletonStore>>
///     |                  |      |    |
///     |                  |      |    +-- Wrapper that ensures one-time initialization
///     |                  |      +------- Thread-safe interior mutability
///     |                  +-------------- Lazy initialization
///     +---------------------------------- Static lifetime
/// ```
///
/// Note on mutability:
/// - The store implementation can only be set once through SingletonStore::set_store
/// - Attempts to set the store after initialization will result in an error
/// - The Mutex ensures thread-safe access to store operations
pub(crate) static SESSION_STORE: LazyLock<Mutex<SingletonStore>> =
    LazyLock::new(|| Mutex::new(SingletonStore::new(Box::new(InMemorySessionStore::new()))));

/// Initialize the session store based on environment configuration.
/// This will:
/// 1. Check environment variables for store configuration (OAUTH2_SESSION_STORE, OAUTH2_SESSION_REDIS_URL)
/// 2. Create the appropriate store implementation (Memory or Redis)
/// 3. Replace the default in-memory store in SESSION_STORE with the configured implementation
pub async fn init_session_store() -> Result<(), AppError> {
    let store_type = SessionStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize session store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        SessionStoreType::Memory
    });

    tracing::info!("Initializing session store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    SESSION_STORE.lock().await.set_store(store)?;
    tracing::info!("Session store initialized successfully");
    Ok(())
}
