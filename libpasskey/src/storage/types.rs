use crate::types::{CacheData, StoredChallenge, StoredCredential};
use sqlx::{Pool, Postgres, Sqlite};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(crate) enum ChallengeStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

#[derive(Clone, Debug)]
pub(crate) enum CredentialStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

pub(crate) struct InMemoryChallengeStore {
    pub(super) challenges: HashMap<String, StoredChallenge>,
}

pub(crate) struct InMemoryCredentialStore {
    pub(super) credentials: HashMap<String, StoredCredential>,
}

pub(crate) struct PostgresChallengeStore {
    pub(super) pool: Pool<Postgres>,
}

pub(crate) struct PostgresCredentialStore {
    pub(super) pool: Pool<Postgres>,
}

pub(crate) struct RedisChallengeStore {
    pub(super) client: redis::Client,
}

pub(crate) struct RedisCredentialStore {
    pub(super) client: redis::Client,
}

pub(crate) struct SqliteChallengeStore {
    pub(super) pool: Pool<Sqlite>,
}

pub(crate) struct SqliteCredentialStore {
    pub(super) pool: Pool<Sqlite>,
}

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
