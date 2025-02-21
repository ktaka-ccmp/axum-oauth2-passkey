use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("User not found")]
    NotFound,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::InvalidData(err.to_string())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        AppError::Storage(err.to_string())
    }
}
