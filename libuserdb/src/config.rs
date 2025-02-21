use std::sync::LazyLock;
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::storage::{MemoryStore, UserStore};
use crate::types::UserStoreType;

/// Global singleton for user storage. This follows a pattern where:
/// 1. We initialize with a safe default (MemoryStore) when the library is first loaded
/// 2. The actual implementation (Memory, Redis, etc.) is determined at runtime in init_user_store()
pub(crate) static USER_STORE: LazyLock<Mutex<SingletonStore>> =
    LazyLock::new(|| Mutex::new(SingletonStore::new(Box::new(MemoryStore::new()))));

/// A wrapper type that ensures the user store can only be set once.
///
/// This type provides a safe way to manage the global user store by:
/// 1. Ensuring the store can only be initialized once
/// 2. Providing thread-safe access to the store
/// 3. Supporting both read-only and mutable access when needed
pub(crate) struct SingletonStore {
    store: Box<dyn UserStore>,
    initialized: bool,
}

impl SingletonStore {
    /// Create a new SingletonStore with the given store implementation.
    /// The store starts uninitialized.
    fn new(store: Box<dyn UserStore>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    /// Set the store implementation. This can only be done once.
    /// Returns an error if attempting to set the store after it's already been initialized.
    fn set_store(&mut self, new_store: Box<dyn UserStore>) -> Result<(), AppError> {
        if self.initialized {
            return Err(AppError::Storage(
                "User store has already been initialized".to_string(),
            ));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    /// Get a reference to the underlying store for read-only operations.
    pub(crate) fn get_store(&self) -> &dyn UserStore {
        &*self.store
    }

    /// Get a mutable reference to the underlying store for write operations.
    pub(crate) fn get_store_mut(&mut self) -> &mut Box<dyn UserStore> {
        &mut self.store
    }
}

/// Initialize the user store based on environment configuration.
///
/// This function:
/// 1. Reads the store type from environment variables
/// 2. Creates the appropriate store implementation
/// 3. Initializes the store and sets it as the global singleton
///
/// # Environment Variables
/// - `OAUTH2_USER_STORE`: Type of store to use ("memory", "redis", "sqlite", "postgres")
/// - Store-specific connection URLs based on the chosen store type
///
/// # Errors
/// Returns an error if:
/// - Invalid store type is specified
/// - Required connection URL is missing
/// - Store initialization fails
pub(crate) async fn init_user_store() -> Result<(), AppError> {
    let store_type = UserStoreType::from_env()?;
    let store = store_type.create_store().await?;

    let mut singleton = USER_STORE.lock().await;
    singleton.set_store(store)?;

    Ok(())
}
