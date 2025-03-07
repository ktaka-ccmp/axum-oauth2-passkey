use crate::{
    errors::UserError,
    types::{OAuth2Account, User},
};
use libstorage::GENERIC_DATA_STORE;
use sqlx::{Pool, Postgres, Sqlite};
use uuid::Uuid;

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

    /// Get all OAuth2 accounts for a user
    pub async fn get_oauth2_accounts(user_id: &str) -> Result<Vec<OAuth2Account>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_oauth2_accounts_sqlite(pool, user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_accounts_postgres(pool, user_id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Get OAuth2 account by provider and provider_user_id
    pub async fn get_oauth2_account_by_provider(
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuth2Account>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_oauth2_account_by_provider_sqlite(pool, provider, provider_user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_account_by_provider_postgres(pool, provider, provider_user_id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Create or update an OAuth2 account and its associated user
    pub async fn upsert_oauth2_account(account: OAuth2Account) -> Result<OAuth2Account, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            upsert_oauth2_account_sqlite(pool, account).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_oauth2_account_postgres(pool, account).await
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

    // Create oauth2_accounts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth2_accounts (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            picture TEXT,
            metadata TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            UNIQUE(provider, provider_user_id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Create index on user_id for faster lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_oauth2_accounts_user_id ON oauth2_accounts(user_id)
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

async fn get_oauth2_accounts_sqlite(
    pool: &Pool<Sqlite>,
    user_id: &str,
) -> Result<Vec<OAuth2Account>, UserError> {
    sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn get_oauth2_account_by_provider_sqlite(
    pool: &Pool<Sqlite>,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<OAuth2Account>, UserError> {
    sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts 
        WHERE provider = ? AND provider_user_id = ?
        "#,
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn upsert_oauth2_account_sqlite(
    pool: &Pool<Sqlite>,
    account: OAuth2Account,
) -> Result<OAuth2Account, UserError> {
    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // If user_id is empty, create new user
    let user_id = if account.user_id.is_empty() {
        let user = User {
            id: Uuid::new_v4().to_string(),
            created_at: account.created_at,
            updated_at: account.updated_at,
        };

        sqlx::query(
            r#"
            INSERT INTO users (id, created_at, updated_at)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

        user.id
    } else {
        account.user_id
    };

    // Upsert OAuth2 account
    let account_id = if account.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        account.id
    };

    sqlx::query(
        r#"
        INSERT INTO oauth2_accounts (
            id, user_id, provider, provider_user_id, name, email, 
            picture, metadata, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (provider, provider_user_id) DO UPDATE SET
            name = excluded.name,
            email = excluded.email,
            picture = excluded.picture,
            metadata = excluded.metadata,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&account_id)
    .bind(&user_id)
    .bind(&account.provider)
    .bind(&account.provider_user_id)
    .bind(&account.name)
    .bind(&account.email)
    .bind(&account.picture)
    .bind(&account.metadata)
    .bind(account.created_at)
    .bind(account.updated_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // Return updated account
    Ok(OAuth2Account {
        id: account_id,
        user_id,
        ..account
    })
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

    // Create oauth2_accounts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth2_accounts (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            picture TEXT,
            metadata JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            UNIQUE(provider, provider_user_id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Create index on user_id for faster lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_oauth2_accounts_user_id ON oauth2_accounts(user_id)
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

async fn get_oauth2_accounts_postgres(
    pool: &Pool<Postgres>,
    user_id: &str,
) -> Result<Vec<OAuth2Account>, UserError> {
    sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn get_oauth2_account_by_provider_postgres(
    pool: &Pool<Postgres>,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<OAuth2Account>, UserError> {
    sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts 
        WHERE provider = $1 AND provider_user_id = $2
        "#,
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn upsert_oauth2_account_postgres(
    pool: &Pool<Postgres>,
    account: OAuth2Account,
) -> Result<OAuth2Account, UserError> {
    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // If user_id is empty, create new user
    let user_id = if account.user_id.is_empty() {
        let user = User {
            id: Uuid::new_v4().to_string(),
            created_at: account.created_at,
            updated_at: account.updated_at,
        };

        sqlx::query(
            r#"
            INSERT INTO users (id, created_at, updated_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(&user.id)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

        user.id
    } else {
        account.user_id
    };

    // Upsert OAuth2 account
    let account_id = if account.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        account.id
    };

    sqlx::query(
        r#"
        INSERT INTO oauth2_accounts (
            id, user_id, provider, provider_user_id, name, email, 
            picture, metadata, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (provider, provider_user_id) DO UPDATE SET
            name = EXCLUDED.name,
            email = EXCLUDED.email,
            picture = EXCLUDED.picture,
            metadata = EXCLUDED.metadata,
            updated_at = EXCLUDED.updated_at
        RETURNING *
        "#,
    )
    .bind(&account_id)
    .bind(&user_id)
    .bind(&account.provider)
    .bind(&account.provider_user_id)
    .bind(&account.name)
    .bind(&account.email)
    .bind(&account.picture)
    .bind(&account.metadata)
    .bind(account.created_at)
    .bind(account.updated_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // Return updated account
    Ok(OAuth2Account {
        id: account_id,
        user_id,
        ..account
    })
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
