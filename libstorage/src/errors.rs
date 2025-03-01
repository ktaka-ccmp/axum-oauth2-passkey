use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum StorageError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Json conversion(Serde) error: {0}")]
    Serde(String),

    #[error("Invalid client data: {0}")]
    ClientData(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Not found error: {0}")]
    NotFound(String),

    #[error("{0}")]
    Other(String),
}

impl From<redis::RedisError> for StorageError {
    fn from(err: redis::RedisError) -> Self {
        Self::Storage(err.to_string()) // Adjust this based on how you want to represent the error
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}
