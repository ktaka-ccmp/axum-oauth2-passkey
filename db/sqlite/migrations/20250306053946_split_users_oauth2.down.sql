-- Create temporary users table with old schema
CREATE TABLE IF NOT EXISTS users_old (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    picture TEXT,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Migrate data back to old format
INSERT INTO users_old (
    id, name, email, picture, provider, provider_user_id,
    metadata, created_at, updated_at
)
SELECT 
    u.id, o.name, o.email, o.picture, o.provider, o.provider_user_id,
    o.metadata, u.created_at, u.updated_at
FROM users u
JOIN oauth2_accounts o ON u.id = o.user_id;

-- Drop new tables
DROP TABLE oauth2_accounts;
DROP TABLE users;

-- Remove user_id column from passkey_credentials
ALTER TABLE passkey_credentials DROP COLUMN user_id;

-- Rename old users table back
ALTER TABLE users_old RENAME TO users;
