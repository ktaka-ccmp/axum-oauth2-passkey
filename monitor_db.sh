#!/bin/bash

# Database connection string
#DB_STRING="psql postgres://passkey:passkey@localhost:5432/passkey"
DB_STRING="sqlite3 /tmp/sqlite.db"

# SQLite formatting options - using separate commands
SQLITE_HEADERS=".headers on"
SQLITE_MODE=".mode column"

# Define queries for each table
QUERY_USERS="select id,account,label,created_at from o2p_users;"
QUERY_PASSKEY_CREDENTIALS="select user_id,user_name,credential_id,public_key,created_at from o2p_passkey_credentials;"
QUERY_OAUTH2_ACCOUNTS="select user_id,email,id,created_at from o2p_oauth2_accounts;"

#QUERY_PASSKEY_CREDENTIALS="select user_id,user_name,user_display_name,credential_id,public_key,created_at from passkey_credentials;"
#QUERY_PASSKEY_CREDENTIALS="select user_id,hex(credential_id),user_handle,user_name,user_display_name,created_at from passkey_credentials;"
#QUERY_OAUTH2_ACCOUNTS="select user_id,id,provider_user_id,email,created_at from oauth2_accounts;"
#QUERY_OAUTH2_ACCOUNTS="select user_id,email,name,created_at from oauth2_accounts;"

# Combine all queries (can be customized by commenting out lines)
ALL_QUERIES=""
ALL_QUERIES+="$QUERY_USERS"
ALL_QUERIES+="$QUERY_PASSKEY_CREDENTIALS"
ALL_QUERIES+="$QUERY_OAUTH2_ACCOUNTS"

# Run the watch command
#watch -n 1 "echo '$ALL_QUERIES' | $DB_STRING"
#watch -n 1 "echo -e '$SQLITE_HEADERS\n$SQLITE_MODE\n$ALL_QUERIES' | $DB_STRING"
#watch -n 1 "echo '$SQLITE_HEADERS$SQLITE_MODE$ALL_QUERIES' | $DB_STRING"

watch -n 1 'echo "'"$SQLITE_HEADERS
$SQLITE_MODE
$ALL_QUERIES"'" | '"$DB_STRING"
