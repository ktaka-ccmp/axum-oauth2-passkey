use chrono::{DateTime, Utc};
use libstorage::GENERIC_DATA_STORE;
use sqlx::{Pool, Postgres, Sqlite};

use crate::errors::PasskeyError;
use crate::types::{CredentialSearchField, PublicKeyCredentialUserEntity, StoredCredential};

pub struct PasskeyStore;

impl PasskeyStore {
    pub async fn init() -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        // Create table based on database type
        if let Some(pool) = store.as_sqlite() {
            create_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            create_tables_postgres(pool).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub async fn store_credential(
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            store_credential_sqlite(pool, &credential_id, &credential).await
        } else if let Some(pool) = store.as_postgres() {
            store_credential_postgres(pool, &credential_id, &credential).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub async fn get_credential(
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credential_sqlite(pool, credential_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_credential_postgres(pool, credential_id).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub async fn get_credentials_by(
        field: CredentialSearchField,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credentials_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_credentials_by_field_postgres(pool, &field).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub async fn update_credential_counter(
        credential_id: &str,
        counter: u32,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_counter_sqlite(pool, credential_id, counter).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_counter_postgres(pool, credential_id, counter).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }
}

// SQLite implementations
async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), PasskeyError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS passkey_credentials (
            credential_id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            public_key BLOB NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            user_handle TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_display_name TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_name ON passkey_credentials(user_name);
        CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id);
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn store_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    credential: &StoredCredential,
) -> Result<(), PasskeyError> {
    let counter_i64 = credential.counter as i64;
    let public_key = &credential.public_key;
    let user_id = &credential.user_id;
    let user_handle = &credential.user.user_handle;
    let user_name = &credential.user.name;
    let user_display_name = &credential.user.display_name;
    let created_at = &credential.created_at;
    let updated_at = &credential.updated_at;

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO passkey_credentials 
        (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)
    .bind(counter_i64)
    .bind(user_handle)
    .bind(user_name)
    .bind(user_display_name)
    .bind(created_at)
    .bind(updated_at)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
) -> Result<Option<StoredCredential>, PasskeyError> {
    sqlx::query_as::<_, StoredCredential>(
        r#"SELECT * FROM passkey_credentials WHERE credential_id = ?"#,
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn get_credentials_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &CredentialSearchField,
) -> Result<Vec<StoredCredential>, PasskeyError> {
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            "SELECT * FROM passkey_credentials WHERE credential_id = ?",
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            "SELECT * FROM passkey_credentials WHERE user_id = ?",
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            "SELECT * FROM passkey_credentials WHERE user_handle = ?",
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            "SELECT * FROM passkey_credentials WHERE user_name = ?",
            name.as_str(),
        ),
    };

    sqlx::query_as::<_, StoredCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn update_credential_counter_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    let counter_i64 = counter as i64;
    sqlx::query(
        r#"
        UPDATE passkey_credentials
        SET counter = ?, updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = ?
        "#,
    )
    .bind(counter_i64)
    .bind(credential_id)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

// PostgreSQL implementations
async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), PasskeyError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS passkey_credentials (
            credential_id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            public_key BYTEA NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            user_handle TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_display_name TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_name ON passkey_credentials(user_name);
        CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id);
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn store_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
    credential: &StoredCredential,
) -> Result<(), PasskeyError> {
    let counter_i32 = credential.counter as i32;
    let public_key = &credential.public_key;
    let user_id = &credential.user_id;
    let user_handle = &credential.user.user_handle;
    let user_name = &credential.user.name;
    let user_display_name = &credential.user.display_name;
    let created_at = &credential.created_at;
    let updated_at = &credential.updated_at;

    sqlx::query_as::<_, (i32,)>(
        r#"
        INSERT INTO passkey_credentials 
        (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (credential_id) DO UPDATE
        SET user_id = $2, public_key = $3, counter = $4, user_handle = $5, user_name = $6, user_display_name = $7, updated_at = CURRENT_TIMESTAMP
        RETURNING 1
        "#,
    )
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)
    .bind(counter_i32)
    .bind(user_handle)
    .bind(user_name)
    .bind(user_display_name)
    .bind(created_at)
    .bind(updated_at)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
) -> Result<Option<StoredCredential>, PasskeyError> {
    sqlx::query_as::<_, StoredCredential>(
        r#"SELECT * FROM passkey_credentials WHERE credential_id = $1"#,
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn get_credentials_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &CredentialSearchField,
) -> Result<Vec<StoredCredential>, PasskeyError> {
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            "SELECT * FROM passkey_credentials WHERE credential_id = $1",
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            "SELECT * FROM passkey_credentials WHERE user_id = $1",
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            "SELECT * FROM passkey_credentials WHERE user_handle = $1",
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            "SELECT * FROM passkey_credentials WHERE user_name = $1",
            name.as_str(),
        ),
    };

    sqlx::query_as::<_, StoredCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn update_credential_counter_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    let counter_i32 = counter as i32;

    sqlx::query_as::<_, (i32,)>(
        r#"
        UPDATE passkey_credentials
        SET counter = $1, updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = $2
        RETURNING 1
        "#,
    )
    .bind(counter_i32)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

use sqlx::{FromRow, Row, postgres::PgRow, sqlite::SqliteRow};

// Implement FromRow for StoredCredential to handle the flattened database structure for SQLite
impl<'r> FromRow<'r, SqliteRow> for StoredCredential {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: Vec<u8> = row.try_get("public_key")?;
        let counter: i64 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

        Ok(StoredCredential {
            credential_id: credential_id.as_bytes().to_vec(),
            user_id,
            public_key,
            counter: counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: user_name,
                display_name: user_display_name,
            },
            created_at,
            updated_at,
        })
    }
}

// Implement FromRow for StoredCredential to handle the flattened database structure for PostgreSQL
impl<'r> FromRow<'r, PgRow> for StoredCredential {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: Vec<u8> = row.try_get("public_key")?;
        let counter: i32 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

        Ok(StoredCredential {
            credential_id: credential_id.as_bytes().to_vec(),
            user_id,
            public_key,
            counter: counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: user_name,
                display_name: user_display_name,
            },
            created_at,
            updated_at,
        })
    }
}
