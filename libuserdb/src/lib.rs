//! User database management for OAuth2 applications.
//!
//! This library provides a simple interface for storing and retrieving user data
//! in an OAuth2 application. It supports multiple storage backends:
//! - In-memory (for development/testing)
//! - Redis
//! - SQLite (planned)
//! - PostgreSQL (planned)
//!
//! # Getting Started
//!
//! ```no_run
//! use libuserdb;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize user store before using the library
//!     libuserdb::init().await?;
//!
//!     // Use the library...
//!     Ok(())
//! }
//! ```
//!
//! # Configuration
//!
//! The library uses environment variables for configuration:
//! - `USER_DB_STORE`: Type of store to use ("memory", "redis", "sqlite", "postgres")
//! - `USER_DB_REDIS_URL`: Redis connection URL (required if using Redis)
//! - `USER_DB_SQLITE_URL`: SQLite database path (required if using SQLite)
//! - `USER_DB_POSTGRES_URL`: PostgreSQL connection URL (required if using PostgreSQL)

mod config;
mod errors;
mod storage;
mod types;
mod user;

// Re-export only what's necessary for the public API
pub use errors::AppError; // Required for error handling
pub use types::User; // Required for user data
pub use user::{get_user, upsert_user}; // User management functions

/// Initialize the user database library.
///
/// This function must be called before using the library. It:
/// 1. Initializes the user store singleton based on environment configuration
/// 2. Sets up the store with either in-memory, Redis, SQLite, or PostgreSQL backend
///    based on `OAUTH2_USER_STORE` environment variable
///
/// # Errors
/// Returns an error if store initialization fails, for example:
/// - Invalid store type in environment variable
/// - Failed Redis connection if Redis backend is configured
/// - Failed database connection if SQLite or PostgreSQL backend is configured
///
/// # Example
/// ```no_run
/// use libuserdb;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Initialize user store before using the library
///     libuserdb::init().await?;
///     Ok(())
/// }
/// ```
pub async fn init() -> Result<(), AppError> {
    config::init_user_store().await
}
