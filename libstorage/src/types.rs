use serde::{Deserialize, Serialize};

/// Data stored in the cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub value: Vec<u8>,
}
