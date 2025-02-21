use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
    RequestPartsExt,
};
use axum_extra::{headers, TypedHeader};
use http::request::Parts;
use std::convert::Infallible;

use libuserdb::get_user;

use crate::config::{SESSION_COOKIE_NAME, SESSION_STORE};
use crate::types::User;

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        println!("AuthRedirect called.");
        Redirect::temporary("/").into_response()
    }
}

impl<S> FromRequestParts<S> for User
where
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|_| AuthRedirect)?;

        // Get session from cookie
        let session_cookie = cookies
            .get(SESSION_COOKIE_NAME.as_str())
            .ok_or(AuthRedirect)?;

        let store_guard = SESSION_STORE.lock().await;
        let session = store_guard
            .get_store()
            .get(session_cookie)
            .await
            .map_err(|_| AuthRedirect)?;

        // Get user data from session
        let stored_session = session.ok_or(AuthRedirect)?;

        let user = get_user(&stored_session.info.user_id)
            .await
            .map_err(|_| AuthRedirect)?
            .ok_or(AuthRedirect)?;

        Ok(User::from(user))
    }
}

impl<S> OptionalFromRequestParts<S> for User
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <User as FromRequestParts<S>>::from_request_parts(parts, _state).await {
            Ok(res) => Ok(Some(res)),
            Err(AuthRedirect) => Ok(None),
        }
    }
}
