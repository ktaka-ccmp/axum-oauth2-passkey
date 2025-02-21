// Use anyhow, define error and enable '?'
// For a simplified example of using anyhow in axum check /examples/anyhow-error-response
#[derive(Debug)]
pub struct AppError(pub(crate) anyhow::Error);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self(err)
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        Self(err.into())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self(err.into())
    }
}

impl From<std::env::VarError> for AppError {
    fn from(err: std::env::VarError) -> Self {
        Self(err.into())
    }
}

impl From<ring::error::Unspecified> for AppError {
    fn from(err: ring::error::Unspecified) -> Self {
        Self(anyhow::anyhow!("Ring error: {:?}", err))
    }
}

impl From<std::num::TryFromIntError> for AppError {
    fn from(err: std::num::TryFromIntError) -> Self {
        Self(err.into())
    }
}

impl From<libsession::AppError> for AppError {
    fn from(err: libsession::AppError) -> Self {
        Self(anyhow::anyhow!("Session error: {}", err))
    }
}

impl From<crate::oauth2::TokenVerificationError> for AppError {
    fn from(err: crate::oauth2::TokenVerificationError) -> Self {
        Self(anyhow::anyhow!("Token verification error: {:?}", err))
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
