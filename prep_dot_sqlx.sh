#!/bin/bash

cat /dev/null > ./test.db
echo "CREATE TABLE IF NOT EXISTS passkey_credentials (
    credential_id TEXT PRIMARY KEY NOT NULL,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    user_handle TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_display_name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)" | sqlite3 test.db
cargo sqlx prepare --database-url sqlite:./test.db --workspace
# DATABASE_URL=sqlite:./test.db cargo sqlx prepare --workspace
echo ".schema" | sqlite3 ./test.db
rm ./test.db

