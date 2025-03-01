# Data Store Implementation Guide

This document explains the design and implementation of the database abstraction layer in `libstorage`.

## Overview

The data store implementation provides a type-safe, efficient way to work with different database backends (currently SQLite and PostgreSQL) while maintaining a clean and minimal API.

## Core Components

### 1. DataStore Trait

```rust
pub trait DataStore: Send + Sync {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>>;
    fn as_postgres(&self) -> Option<&Pool<Postgres>>;
}
```

This trait is the primary interface for database interactions. It:
- Provides type-safe access to database pools
- Allows database-specific operations when needed
- Maintains thread safety with `Send + Sync`

### 2. Store Types

```rust
pub(crate) struct SqliteDataStore {
    pub(super) pool: sqlx::SqlitePool,
}

pub(crate) struct PostgresDataStore {
    pub(super) pool: sqlx::PgPool,
}
```

Each database type has its own struct that:
- Encapsulates the database-specific pool
- Implements the `DataStore` trait
- Provides type safety at compile time

### 3. Global Store

```rust
pub static GENERIC_DATA_STORE: LazyLock<Mutex<Box<dyn DataStore>>> = ...
```

A global store instance that:
- Initializes lazily on first use
- Provides thread-safe access via `Mutex`
- Configures via environment variables

## Configuration

The store is configured through environment variables:

1. `GENERIC_DATA_STORE_TYPE`: Database type ("sqlite" or "postgres")
   - Default: "sqlite"

2. `GENERIC_DATA_STORE_URL`: Database connection URL
   - Default for SQLite: "sqlite:file:memdb1?mode=memory&cache=shared"
   - Default for Postgres: "postgres://postgres:postgres@localhost:5432/postgres"

## Usage Example

```rust
async fn example(store: &Box<dyn DataStore>) -> Result<(), Error> {
    // Generic operations (work on any database)
    let users = query_users(store).await?;

    // Database-specific operations
    if let Some(sqlite) = store.as_sqlite() {
        // SQLite-specific code
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(sqlite)
            .await?;
    } else if let Some(postgres) = store.as_postgres() {
        // Postgres-specific code
        sqlx::query("SET synchronous_commit = off")
            .execute(postgres)
            .await?;
    }

    Ok(())
}
```

## Design Decisions

1. **Type Safety**
   - Each database has its own type
   - No runtime type casting needed
   - Compile-time guarantees

2. **Minimal API**
   - Single trait for all databases
   - Only necessary methods exposed
   - Implementation details hidden

3. **Efficiency**
   - Lazy initialization
   - No unnecessary abstractions
   - Direct pool access when needed

4. **Thread Safety**
   - Global store protected by `Mutex`
   - All types implement `Send + Sync`
   - Safe concurrent access

## Adding New Database Types

To add support for a new database:

1. Create a new store type:
   ```rust
   pub(crate) struct NewDbStore {
       pub(super) pool: sqlx::NewDbPool,
   }
   ```

2. Implement the `DataStore` trait:
   ```rust
   impl DataStore for NewDbStore {
       fn as_sqlite(&self) -> Option<&Pool<Sqlite>> { None }
       fn as_postgres(&self) -> Option<&Pool<Postgres>> { None }
       // Add new method if needed:
       // fn as_newdb(&self) -> Option<&Pool<NewDb>> { Some(&self.pool) }
   }
   ```

3. Update the store initialization logic in `GENERIC_DATA_STORE`

## Best Practices

1. **Generic Operations**
   - Use the `DataStore` trait for database-agnostic code
   - Handle both database types in generic functions
   - Use common SQL features when possible

2. **Database-Specific Operations**
   - Use `as_sqlite()` or `as_postgres()` for specific features
   - Keep database-specific code isolated
   - Document when specific features are required

3. **Error Handling**
   - Use proper error types and propagation
   - Provide clear error messages
   - Handle both generic and database-specific errors

## Future Considerations

1. **Additional Databases**
   - Design allows easy addition of new databases
   - Trait can be extended with new methods
   - Minimal impact on existing code

2. **Performance**
   - Connection pooling already implemented
   - Lazy initialization reduces startup cost
   - Direct pool access for optimal performance

3. **Maintenance**
   - Clear separation of concerns
   - Type-safe implementations
   - Minimal code to maintain
