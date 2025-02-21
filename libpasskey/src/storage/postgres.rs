use async_trait::async_trait;
use sqlx::Row;

use super::traits::{ChallengeStore, CredentialStore};
use super::types::{PostgresChallengeStore, PostgresCredentialStore};

use crate::errors::PasskeyError;
use crate::types::{PublicKeyCredentialUserEntity, StoredChallenge, StoredCredential};

impl PostgresChallengeStore {
    pub(crate) async fn connect(database_url: &str) -> Result<Self, PasskeyError> {
        println!(
            "Connecting to Postgres database at {} for challenges",
            database_url
        );
        let pool = sqlx::PgPool::connect(database_url)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS challenges (
                challenge_id TEXT PRIMARY KEY,
                challenge BYTEA NOT NULL,
                user_name TEXT NOT NULL,
                user_display_name TEXT NOT NULL,
                timestamp BIGINT NOT NULL,
                ttl BIGINT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl ChallengeStore for PostgresChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS challenges (
                challenge_id TEXT PRIMARY KEY,
                challenge BYTEA NOT NULL,
                user_name TEXT NOT NULL,
                user_display_name TEXT NOT NULL,
                timestamp BIGINT NOT NULL,
                ttl BIGINT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn store_challenge(
        &mut self,
        challenge_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError> {
        sqlx::query(
            r#"
            INSERT INTO challenges (
                challenge_id,
                challenge,
                user_name,
                user_display_name,
                timestamp,
                ttl
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (challenge_id) DO UPDATE SET
                challenge = $2,
                user_name = $3,
                user_display_name = $4,
                timestamp = $5,
                ttl = $6
            "#,
        )
        .bind(&challenge_id)
        .bind(&challenge.challenge)
        .bind(&challenge.user.name)
        .bind(&challenge.user.display_name)
        .bind(challenge.timestamp as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<StoredChallenge>, PasskeyError> {
        let row = sqlx::query(
            r#"
            SELECT challenge, user_name, user_display_name, timestamp, ttl
            FROM challenges
            WHERE challenge_id = $1
            "#,
        )
        .bind(challenge_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let challenge = row.map(|r| {
            let user_info = PublicKeyCredentialUserEntity {
                id_handle: challenge_id.to_string(),
                name: r.get("user_name"),
                display_name: r.get("user_display_name"),
            };
            StoredChallenge {
                challenge: r.get("challenge"),
                user: user_info,
                timestamp: r.get::<i64, _>("timestamp") as u64,
                ttl: r.get::<i64, _>("ttl") as u64,
            }
        });

        Ok(challenge)
    }

    async fn remove_challenge(&mut self, challenge_id: &str) -> Result<(), PasskeyError> {
        sqlx::query(
            r#"
            DELETE FROM challenges
            WHERE challenge_id = $1
            "#,
        )
        .bind(challenge_id)
        .execute(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }
}

impl PostgresCredentialStore {
    pub(crate) async fn connect(database_url: &str) -> Result<Self, PasskeyError> {
        println!(
            "Connecting to Postgres database at {} for credentials",
            database_url
        );
        let pool = sqlx::PgPool::connect(database_url)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                credential_id_blob BYTEA NOT NULL,
                public_key BYTEA NOT NULL,
                counter INTEGER NOT NULL,
                user_handle TEXT NOT NULL,
                user_name TEXT NOT NULL,
                user_display_name TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl CredentialStore for PostgresCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                credential_id_blob BYTEA NOT NULL,
                public_key BYTEA NOT NULL,
                counter INTEGER NOT NULL,
                user_handle TEXT NOT NULL,
                user_name TEXT NOT NULL,
                user_display_name TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        #[cfg(debug_assertions)]
        println!(
            "#################\ncredential_id: {:?},\n Storing credential: {:?}",
            credential_id, credential
        );

        sqlx::query(
            r#"
            INSERT INTO credentials (
                credential_id,
                credential_id_blob,
                public_key,
                counter,
                user_handle,
                user_name,
                user_display_name
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&credential_id)
        .bind(&credential.credential_id)
        .bind(&credential.public_key)
        .bind(credential.counter as i32)
        .bind(&credential.user.id_handle)
        .bind(&credential.user.name)
        .bind(&credential.user.display_name)
        .execute(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        #[cfg(debug_assertions)]
        println!(
            "#################\nGetting credential for credential_id: {:?}",
            credential_id
        );

        let row = sqlx::query(
            r#"
            SELECT * FROM credentials WHERE credential_id = $1
            "#,
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let credential = row.map(|r| {
            let user_info = PublicKeyCredentialUserEntity {
                id_handle: r.get("user_handle"),
                name: r.get("user_name"),
                display_name: r.get("user_display_name"),
            };
            StoredCredential {
                credential_id: r.get("credential_id_blob"),
                public_key: r.get("public_key"),
                counter: r.get::<i32, _>("counter") as u32,
                user: user_info,
            }
        });

        Ok(credential)
    }

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        sqlx::query(
            r#"
            UPDATE credentials
            SET counter = $1
            WHERE credential_id = $2
            "#,
        )
        .bind(new_counter as i32)
        .bind(credential_id)
        .execute(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        let rows = sqlx::query(
            r#"
            SELECT credential_id, credential, public_key, counter, user_handle, user_name, user_display_name
            FROM credentials
            WHERE user_name = $1
            "#,
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let credentials = rows
            .into_iter()
            .map(|r| {
                let user_info = PublicKeyCredentialUserEntity {
                    id_handle: r.get("user_handle"),
                    name: r.get("user_name"),
                    display_name: r.get("user_display_name"),
                };
                StoredCredential {
                    credential_id: r.get("credential"),
                    public_key: r.get("public_key"),
                    counter: r.get::<i32, _>("counter") as u32,
                    user: user_info,
                }
            })
            .collect();

        Ok(credentials)
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM credentials
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let credentials = rows
            .into_iter()
            .map(|r| {
                let user_info = PublicKeyCredentialUserEntity {
                    id_handle: r.get("user_handle"),
                    name: r.get("user_name"),
                    display_name: r.get("user_display_name"),
                };
                StoredCredential {
                    credential_id: r.get("credential_id_blob"),
                    public_key: r.get("public_key"),
                    counter: r.get::<i32, _>("counter") as u32,
                    user: user_info,
                }
            })
            .collect();

        Ok(credentials)
    }
}
