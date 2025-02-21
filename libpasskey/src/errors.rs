use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum PasskeyError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid challenge: {0}")]
    Challenge(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Registration error: {0}")]
    Registration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Json conversion(Serde) error: {0}")]
    Serde(String),

    #[error("Invalid client data: {0}")]
    ClientData(String),

    #[error("Invalid authenticator data: {0}")]
    AuthenticatorData(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Not found error: {0}")]
    NotFound(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid format: {0}")]
    Format(String),

    #[error("{0}")]
    Other(String),
}

impl From<redis::RedisError> for PasskeyError {
    fn from(err: redis::RedisError) -> Self {
        Self::Storage(err.to_string()) // Adjust this based on how you want to represent the error
    }
}

impl From<serde_json::Error> for PasskeyError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}
