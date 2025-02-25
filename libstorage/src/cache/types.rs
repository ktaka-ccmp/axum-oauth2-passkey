use crate::types::CacheData;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(crate) enum CacheStoreType {
    Memory,
    Redis { url: String },
}

pub(crate) struct InMemoryCacheStore {
    pub(super) entry: HashMap<String, CacheData>,
}

pub(crate) struct RedisCacheStore {
    pub(super) client: redis::Client,
}
