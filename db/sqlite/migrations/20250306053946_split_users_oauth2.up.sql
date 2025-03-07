-- Create new users table
CREATE TABLE IF NOT EXISTS users_new (
    id TEXT PRIMARY KEY NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create oauth2_accounts table
CREATE TABLE IF NOT EXISTS oauth2_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    picture TEXT,
    metadata TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users_new(id),
    UNIQUE(provider, provider_user_id)
);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_oauth2_accounts_user_id ON oauth2_accounts(user_id);

-- Migrate data from old users table
INSERT INTO users_new (id, created_at, updated_at)
SELECT id, created_at, updated_at FROM users;

-- Insert data into oauth2_accounts
INSERT INTO oauth2_accounts (
    id, user_id, provider, provider_user_id, name, email, 
    picture, metadata, created_at, updated_at
)
SELECT 
    id, id, provider, provider_user_id, name, email,
    picture, metadata, created_at, updated_at
FROM users;

-- Drop old users table
DROP TABLE users;

-- Rename new users table
ALTER TABLE users_new RENAME TO users;

-- Update passkey_credentials to reference users
ALTER TABLE passkey_credentials ADD COLUMN user_id TEXT REFERENCES users(id);
UPDATE passkey_credentials SET user_id = user_handle;
