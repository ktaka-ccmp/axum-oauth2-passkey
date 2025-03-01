use libstorage::{DataStore, GENERIC_DATA_STORE, GENERIC_DATA_STORE_TYPE, GENERIC_DATA_STORE_URL};
use sqlx::Error as SqlxError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Store type is determined by environment variables:
    // GENERIC_DATA_STORE_TYPE=sqlite|postgres
    // GENERIC_DATA_STORE_URL=<connection string>
    println!("Using store type: {}", *GENERIC_DATA_STORE_TYPE);
    println!("Using store URL: {}", *GENERIC_DATA_STORE_URL);

    // Get access to the store
    let store = GENERIC_DATA_STORE.lock().await;

    // Example: Database-specific migrations
    migrate_if_needed(&store).await?;

    // Example: Generic query that works on both databases
    let count = execute_generic_query(&store).await?;
    println!("Count: {}", count);

    Ok(())
}

async fn migrate_if_needed(store: &Box<dyn DataStore>) -> Result<(), SqlxError> {
    if let Some(sqlite) = store.as_sqlite() {
        // SQLite-specific migration
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(sqlite)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )",
        )
        .execute(sqlite)
        .await?;
    } else if let Some(postgres) = store.as_postgres() {
        // Postgres-specific migration
        sqlx::query("SET synchronous_commit = off")
            .execute(postgres)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL
            )",
        )
        .execute(postgres)
        .await?;
    }

    Ok(())
}

async fn execute_generic_query(store: &Box<dyn DataStore>) -> Result<i64, SqlxError> {
    // This function works with both SQLite and Postgres
    // because it uses common SQL features
    let count = if let Some(sqlite) = store.as_sqlite() {
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(sqlite)
            .await?
    } else if let Some(postgres) = store.as_postgres() {
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(postgres)
            .await?
    } else {
        return Err(SqlxError::Configuration("Unknown database type".into()));
    };

    Ok(count)
}
