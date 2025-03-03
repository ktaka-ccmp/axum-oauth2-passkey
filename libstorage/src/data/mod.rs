use sqlx::{Pool, Postgres, Sqlite};
use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

// Types
#[derive(Clone, Debug)]
pub(crate) struct SqliteDataStore {
    pub(super) pool: sqlx::SqlitePool,
}

#[derive(Clone, Debug)]
pub(crate) struct PostgresDataStore {
    pub(super) pool: sqlx::PgPool,
}

// Trait
pub trait DataStore: Send + Sync {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>>;
    fn as_postgres(&self) -> Option<&Pool<Postgres>>;
}

// Store implementations
impl DataStore for SqliteDataStore {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        Some(&self.pool)
    }

    fn as_postgres(&self) -> Option<&Pool<Postgres>> {
        None
    }
}

impl DataStore for PostgresDataStore {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        None
    }

    fn as_postgres(&self) -> Option<&Pool<Postgres>> {
        Some(&self.pool)
    }
}

// Configuration
const DEFAULT_SQLITE_STORE_URL: &str = "sqlite:file:memdb1?mode=memory&cache=shared";
const DEFAULT_POSTGRES_STORE_URL: &str = "postgres://postgres:postgres@localhost:5432/postgres";

pub static GENERIC_DATA_STORE_TYPE: LazyLock<String> =
    LazyLock::new(|| env::var("GENERIC_DATA_STORE_TYPE").unwrap_or_else(|_| "sqlite".to_string()));

pub static GENERIC_DATA_STORE_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_DATA_STORE_URL").unwrap_or_else(|_| match GENERIC_DATA_STORE_TYPE.as_str() {
        "postgres" => DEFAULT_POSTGRES_STORE_URL.to_string(),
        _ => DEFAULT_SQLITE_STORE_URL.to_string(),
    })
});

pub static GENERIC_DATA_STORE: LazyLock<Mutex<Box<dyn DataStore>>> = LazyLock::new(|| {
    let store_type = GENERIC_DATA_STORE_TYPE.as_str();
    let store_url = GENERIC_DATA_STORE_URL.as_str();

    tracing::info!(
        "Initializing data store with type: {}, url: {}",
        store_type,
        store_url
    );

    let store = match store_type {
        "sqlite" => Box::new(SqliteDataStore {
            pool: sqlx::SqlitePool::connect_lazy(store_url).expect("Failed to create SQLite pool"),
        }) as Box<dyn DataStore>,
        "postgres" => Box::new(PostgresDataStore {
            pool: sqlx::PgPool::connect_lazy(store_url).expect("Failed to create Postgres pool"),
        }) as Box<dyn DataStore>,
        t => panic!(
            "Unsupported store type: {}. Supported types are 'sqlite' and 'postgres'",
            t
        ),
    };

    #[cfg(debug_assertions)]
    println!(
        "Connected to database: type={}, url={}",
        store_type, store_url
    );

    Mutex::new(store)
});
