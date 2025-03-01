use libstorage::GENERIC_DATA_STORE;
use sqlx::{Pool, Postgres, Sqlite};

use crate::errors::PasskeyError;
use crate::types::{PublicKeyCredentialUserEntity, StoredCredential};

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

    pub async fn get_credentials_by_user(
        user_id: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credentials_by_user_sqlite(pool, user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_credentials_by_user_postgres(pool, user_id).await
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
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS passkey_credentials (
            credential_id TEXT PRIMARY KEY NOT NULL,
            public_key BLOB NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            user_handle TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_display_name TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
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
    let user_handle = &credential.user.user_handle;
    let user_name = &credential.user.name;
    let user_display_name = &credential.user.display_name;

    sqlx::query!(
        r#"
        INSERT OR REPLACE INTO passkey_credentials 
        (credential_id, public_key, counter, user_handle, user_name, user_display_name, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        "#,
        credential_id,
        public_key,
        counter_i64,
        user_handle,
        user_name,
        user_display_name,
    )
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
) -> Result<Option<StoredCredential>, PasskeyError> {
    let result = sqlx::query!(
        r#"
        SELECT public_key, counter, user_handle, user_name, user_display_name
        FROM passkey_credentials
        WHERE credential_id = ?
        "#,
        credential_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(result.map(|row| StoredCredential {
        credential_id: credential_id.as_bytes().to_vec(),
        public_key: row.public_key,
        counter: row.counter as u32,
        user: PublicKeyCredentialUserEntity {
            user_handle: row.user_handle,
            name: row.user_name,
            display_name: row.user_display_name,
        },
    }))
}

async fn get_credentials_by_user_sqlite(
    pool: &Pool<Sqlite>,
    user_handle: &str,
) -> Result<Vec<StoredCredential>, PasskeyError> {
    let rows = sqlx::query!(
        r#"
        SELECT credential_id, public_key, counter, user_handle, user_name, user_display_name
        FROM passkey_credentials
        WHERE user_handle = ?
        "#,
        user_handle
    )
    .fetch_all(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(|row| StoredCredential {
            credential_id: row.credential_id.as_bytes().to_vec(),
            public_key: row.public_key,
            counter: row.counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle: row.user_handle,
                name: row.user_name,
                display_name: row.user_display_name,
            },
        })
        .collect())
}

async fn update_credential_counter_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    let counter_i64 = counter as i64;

    sqlx::query!(
        r#"
        UPDATE passkey_credentials
        SET counter = ?, updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = ?
        "#,
        counter_i64,
        credential_id
    )
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

// PostgreSQL implementations
async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), PasskeyError> {
    // Create the passkey_credentials table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS passkey_credentials (
            credential_id TEXT PRIMARY KEY NOT NULL,
            public_key BYTEA NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            user_handle TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_display_name TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
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
    let user_handle = &credential.user.user_handle;
    let user_name = &credential.user.name;
    let user_display_name = &credential.user.display_name;

    sqlx::query_as::<_, (i32,)>(
        r#"
        INSERT INTO passkey_credentials 
        (credential_id, public_key, counter, user_handle, user_name, user_display_name, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
        ON CONFLICT (credential_id) DO UPDATE
        SET public_key = $2, counter = $3, user_handle = $4, user_name = $5, user_display_name = $6, updated_at = CURRENT_TIMESTAMP
        RETURNING 1
        "#,
    )
    .bind(credential_id)
    .bind(public_key)
    .bind(counter_i32)
    .bind(user_handle)
    .bind(user_name)
    .bind(user_display_name)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
) -> Result<Option<StoredCredential>, PasskeyError> {
    #[derive(sqlx::FromRow)]
    struct CredentialRow {
        public_key: Vec<u8>,
        counter: i32,
        user_handle: String,
        user_name: String,
        user_display_name: String,
    }

    let result = sqlx::query_as::<_, CredentialRow>(
        r#"
        SELECT public_key, counter, user_handle, user_name, user_display_name
        FROM passkey_credentials
        WHERE credential_id = $1
        "#,
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(result.map(|row| StoredCredential {
        credential_id: credential_id.as_bytes().to_vec(),
        public_key: row.public_key,
        counter: row.counter as u32,
        user: PublicKeyCredentialUserEntity {
            user_handle: row.user_handle,
            name: row.user_name,
            display_name: row.user_display_name,
        },
    }))
}

async fn get_credentials_by_user_postgres(
    pool: &Pool<Postgres>,
    user_handle: &str,
) -> Result<Vec<StoredCredential>, PasskeyError> {
    #[derive(sqlx::FromRow)]
    struct CredentialRow {
        credential_id: String,
        public_key: Vec<u8>,
        counter: i32,
        user_handle: String,
        user_name: String,
        user_display_name: String,
    }

    let rows = sqlx::query_as::<_, CredentialRow>(
        r#"
        SELECT credential_id, public_key, counter, user_handle, user_name, user_display_name
        FROM passkey_credentials
        WHERE user_handle = $1
        "#,
    )
    .bind(user_handle)
    .fetch_all(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(|row| StoredCredential {
            credential_id: row.credential_id.as_bytes().to_vec(),
            public_key: row.public_key,
            counter: row.counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle: row.user_handle,
                name: row.user_name,
                display_name: row.user_display_name,
            },
        })
        .collect())
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
