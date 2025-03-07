use crate::{errors::UserError, types::User};
use libstorage::GENERIC_DATA_STORE;
use sqlx::{Pool, Postgres, Sqlite};

pub struct UserStore;

impl UserStore {
    /// Initialize the user database tables
    pub async fn init() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            create_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            create_tables_postgres(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Get a user by their ID
    pub async fn get_user(id: &str) -> Result<Option<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            get_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Create or update a user
    pub async fn upsert_user(user: User) -> Result<User, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            upsert_user_sqlite(pool, user).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_user_postgres(pool, user).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }
}

// SQLite implementations
async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {
    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_user_sqlite(pool: &Pool<Sqlite>, id: &str) -> Result<Option<User>, UserError> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn upsert_user_sqlite(pool: &Pool<Sqlite>, user: User) -> Result<User, UserError> {
    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // Upsert user
    sqlx::query(
        r#"
        INSERT INTO users (id, created_at, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            created_at = excluded.created_at,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&user.id)
    .bind(user.created_at)
    .bind(user.updated_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // Return updated user
    Ok(user)
}

// PostgreSQL implementations
async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {
    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_user_postgres(pool: &Pool<Postgres>, id: &str) -> Result<Option<User>, UserError> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn upsert_user_postgres(pool: &Pool<Postgres>, user: User) -> Result<User, UserError> {
    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // Upsert user
    sqlx::query(
        r#"
        INSERT INTO users (id, created_at, updated_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET
            created_at = EXCLUDED.created_at,
            updated_at = EXCLUDED.updated_at
        RETURNING *
        "#,
    )
    .bind(&user.id)
    .bind(user.created_at)
    .bind(user.updated_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // Return updated user
    Ok(user)
}
