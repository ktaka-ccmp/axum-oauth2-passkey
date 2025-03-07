//! Passkey coordination with user accounts

use crate::errors::AuthError;
use chrono::Utc;
use libpasskey::StoredCredential;
use libuserdb::{User, UserStore};

/// Coordinator for Passkey and user operations
pub struct PasskeyCoordinator;

impl PasskeyCoordinator {
    /// Get all passkey credentials for a user
    pub async fn get_credentials_by_user_id(
        user_id: &str,
    ) -> Result<Vec<StoredCredential>, AuthError> {
        // Use the CredentialSearchField::UserId to find credentials
        let search_field = libpasskey::CredentialSearchField::UserId(user_id.to_string());

        // Retrieve credentials using the PasskeyStore
        libpasskey::PasskeyStore::get_credentials_by(search_field)
            .await
            .map_err(AuthError::Passkey)
    }

    /// Register a new passkey credential for a user
    ///
    /// This method coordinates between UserStore and PasskeyStore to ensure
    /// that both the user and passkey credential are properly created or updated.
    pub async fn register_credential_with_user(
        user_id: &str,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<User, AuthError> {
        // Verify the user exists or create it if needed
        let user = match UserStore::get_user(user_id)
            .await
            .map_err(AuthError::User)?
        {
            Some(user) => user,
            None => {
                // User doesn't exist, so we should create one
                let new_user = User {
                    id: user_id.to_string(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };

                UserStore::upsert_user(new_user)
                    .await
                    .map_err(AuthError::User)?
            }
        };

        // Store the credential using the PasskeyStore
        libpasskey::PasskeyStore::store_credential(credential_id, credential)
            .await
            .map_err(AuthError::Passkey)?;

        Ok(user)
    }

    /// Find a user by passkey credential ID
    pub async fn find_user_by_credential_id(
        credential_id: &str,
    ) -> Result<Option<User>, AuthError> {
        // First find the credential by its ID
        let credential = match libpasskey::PasskeyStore::get_credential(credential_id)
            .await
            .map_err(AuthError::Passkey)?
        {
            Some(cred) => cred,
            None => return Ok(None), // Credential not found
        };

        // Get the user associated with the credential
        let user_id = &credential.user_id;
        UserStore::get_user(user_id).await.map_err(AuthError::User)
    }
}
