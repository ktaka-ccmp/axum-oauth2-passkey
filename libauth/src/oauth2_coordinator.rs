//! OAuth2 coordination with user accounts

use crate::errors::AuthError;
use chrono::Utc;
use liboauth2::{OAuth2Account, OAuth2Store};
use libuserdb::{User, UserStore};
use uuid::Uuid;

/// Coordinator for OAuth2 and user operations
pub struct OAuth2Coordinator;

impl OAuth2Coordinator {
    /// Get an OAuth2 account by provider and provider_user_id
    pub async fn get_oauth2_account_by_provider(
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuth2Account>, AuthError> {
        // Delegate to OAuth2Store
        OAuth2Store::get_oauth2_account_by_provider(provider, provider_user_id)
            .await
            .map_err(AuthError::OAuth2)
    }

    /// Get all OAuth2 accounts for a user
    pub async fn get_oauth2_accounts(user_id: &str) -> Result<Vec<OAuth2Account>, AuthError> {
        // Delegate to OAuth2Store
        OAuth2Store::get_oauth2_accounts(user_id)
            .await
            .map_err(AuthError::OAuth2)
    }

    /// Create or update an OAuth2 account and its associated user
    ///
    /// This method coordinates between UserStore and OAuth2Store to ensure
    /// that both the user and OAuth2 account are properly created or updated.
    pub async fn upsert_oauth2_account_with_user(
        account: OAuth2Account,
    ) -> Result<(OAuth2Account, User), AuthError> {
        // If user_id is empty, create a new user
        let user = if account.user_id.is_empty() {
            let new_user = User {
                id: Uuid::new_v4().to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            // Store the user
            UserStore::upsert_user(new_user)
                .await
                .map_err(AuthError::User)?
        } else {
            // Verify the user exists
            match UserStore::get_user(&account.user_id)
                .await
                .map_err(AuthError::User)?
            {
                Some(user) => user,
                None => {
                    return Err(AuthError::Coordination(format!(
                        "User with ID {} not found",
                        account.user_id
                    )));
                }
            }
        };

        // Create or update the OAuth2 account with the user_id
        let mut updated_account = account;
        updated_account.user_id = user.id.clone();

        let stored_account = OAuth2Store::upsert_oauth2_account(updated_account)
            .await
            .map_err(AuthError::OAuth2)?;

        Ok((stored_account, user))
    }

    /// Find a user by OAuth2 provider and provider_user_id
    pub async fn find_user_by_oauth2_provider(
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, AuthError> {
        // First find the OAuth2 account
        let oauth2_account =
            match Self::get_oauth2_account_by_provider(provider, provider_user_id).await? {
                Some(account) => account,
                None => return Ok(None),
            };

        // Then get the associated user
        UserStore::get_user(&oauth2_account.user_id)
            .await
            .map_err(AuthError::User)
    }
}
