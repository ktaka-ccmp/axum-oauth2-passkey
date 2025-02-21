use crate::{config::USER_STORE, errors::AppError, types::User};

/// Get a user by their ID
pub async fn get_user(id: &str) -> Result<Option<User>, AppError> {
    let store = USER_STORE.lock().await;
    store.get_store().get(id).await
}

/// Create or update a user
pub async fn upsert_user(user: User) -> Result<User, AppError> {
    let mut store = USER_STORE.lock().await;
    let users: Vec<User> = store
        .get_store()
        .get_by_subject(&user.provider_user_id)
        .await?;

    if let Some(existing_user) = users.first() {
        Ok(existing_user.clone())
    } else {
        let uid = uuid::Uuid::new_v4().to_string();
        let user = User { id: uid, ..user };
        store.get_store_mut().put(&user.id, user.clone()).await?;
        Ok(user)
    }
}
