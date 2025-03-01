mod generic_data_store;
mod memory;
mod postgres;
mod redis;
mod sqlite;
mod traits;
mod types;

pub(crate) use traits::{CacheStore, ChallengeStore, CredentialStore};
pub(crate) use types::{
    CacheStoreType, ChallengeStoreType, CredentialStoreType, InMemoryCacheStore,
    InMemoryChallengeStore, InMemoryCredentialStore,
};

// Re-export the new generic data store implementation
// pub use generic_data_store::CredentialStore as GenericCredentialStore;

pub use generic_data_store::PasskeyStore;
