use std::env;

// Default field mappings for OAuth2
const DEFAULT_OAUTH2_ACCOUNT_FIELD: &str = "email";
const DEFAULT_OAUTH2_LABEL_FIELD: &str = "name";

// Default field mappings for Passkey
const DEFAULT_PASSKEY_ACCOUNT_FIELD: &str = "name";
const DEFAULT_PASSKEY_LABEL_FIELD: &str = "display_name";

/// Get the configured OAuth2 field mappings or defaults
pub fn get_oauth2_field_mappings() -> (String, String) {
    let account_field = env::var("OAUTH2_USER_ACCOUNT_FIELD")
        .unwrap_or_else(|_| DEFAULT_OAUTH2_ACCOUNT_FIELD.to_string());
    let label_field = env::var("OAUTH2_USER_LABEL_FIELD")
        .unwrap_or_else(|_| DEFAULT_OAUTH2_LABEL_FIELD.to_string());
    (account_field, label_field)
}

/// Get the configured Passkey field mappings or defaults
pub fn get_passkey_field_mappings() -> (String, String) {
    let account_field = env::var("PASSKEY_USER_ACCOUNT_FIELD")
        .unwrap_or_else(|_| DEFAULT_PASSKEY_ACCOUNT_FIELD.to_string());
    let label_field = env::var("PASSKEY_USER_LABEL_FIELD")
        .unwrap_or_else(|_| DEFAULT_PASSKEY_LABEL_FIELD.to_string());
    (account_field, label_field)
}
