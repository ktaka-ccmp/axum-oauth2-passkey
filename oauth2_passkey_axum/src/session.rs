use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{TypedHeader, headers};
use http::request::Parts;

use super::config::O2P_REDIRECT_ANON;
use oauth2_passkey::{SESSION_COOKIE_NAME, SessionError, SessionUser, get_user_from_session};

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        println!("AuthRedirect called.");
        Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
    }
}

impl From<SessionError> for AuthRedirect {
    fn from(_: SessionError) -> Self {
        AuthRedirect
    }
}

/// A local wrapper around libsession::User to allow implementing foreign traits
#[derive(Clone, Debug)]
pub struct AuthUser(SessionUser);

impl std::ops::Deref for AuthUser {
    type Target = SessionUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SessionUser> for AuthUser {
    fn from(user: SessionUser) -> Self {
        Self(user)
    }
}

impl<B> FromRequestParts<B> for AuthUser
where
    B: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        let cookies: TypedHeader<headers::Cookie> =
            parts.extract().await.map_err(|_| AuthRedirect)?;

        // Get session from cookie
        let session_cookie = cookies
            .get(SESSION_COOKIE_NAME.as_str())
            .ok_or(AuthRedirect)?
            .to_string();

        // Convert libuserdb::User to libsession::User to AuthUser
        let user: SessionUser = get_user_from_session(&session_cookie)
            .await
            .map_err(AuthRedirect::from)?;
        Ok(AuthUser::from(user))
    }
}

impl<B> OptionalFromRequestParts<B> for AuthUser
where
    B: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &B,
    ) -> Result<Option<Self>, Self::Rejection> {
        let result: Result<Self, Self::Rejection> =
            <AuthUser as FromRequestParts<B>>::from_request_parts(parts, state).await;
        Ok(result.ok())
    }
}
