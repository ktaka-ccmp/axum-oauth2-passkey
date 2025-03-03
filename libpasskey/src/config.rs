use std::{env, sync::LazyLock};

pub static PASSKEY_ROUTE_PREFIX: LazyLock<String> = LazyLock::new(|| {
    std::env::var("PASSKEY_ROUTE_PREFIX")
        .ok()
        .unwrap_or("/passkey".to_string())
});

pub(crate) static ORIGIN: LazyLock<String> =
    LazyLock::new(|| std::env::var("ORIGIN").expect("ORIGIN must be set"));

pub(crate) static PASSKEY_RP_ID: LazyLock<String> = LazyLock::new(|| {
    ORIGIN
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .map(|s| s.to_string())
        .expect("Could not extract RP ID from ORIGIN")
});

pub(crate) static PASSKEY_RP_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("PASSKEY_RP_NAME").ok().unwrap_or(ORIGIN.clone()));

pub(crate) static PASSKEY_TIMEOUT: LazyLock<u32> = LazyLock::new(|| {
    env::var("PASSKEY_TIMEOUT")
        .map(|v| v.parse::<u32>().unwrap_or(60))
        .unwrap_or(60)
});

pub(crate) static PASSKEY_CHALLENGE_TIMEOUT: LazyLock<u32> = LazyLock::new(|| {
    env::var("PASSKEY_CHALLENGE_TIMEOUT")
        .map(|v| v.parse::<u32>().unwrap_or(60))
        .unwrap_or(60)
});

pub(crate) static PASSKEY_AUTHENTICATOR_ATTACHMENT: LazyLock<String> = LazyLock::new(|| {
    match env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT").ok() {
        None => "platform".to_string(),
        Some(v) => match v.to_lowercase().as_str() {
            "platform" => "platform".to_string(),
            "cross-platform" => "cross-platform".to_string(),
            "none" => "None".to_string(), // Ensure "None" is capitalized
            invalid => {
                tracing::warn!(
                    "Invalid authenticator attachment: {}. Using default 'platform'",
                    invalid
                );
                "platform".to_string()
            }
        },
    }
});

pub(crate) static PASSKEY_RESIDENT_KEY: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_RESIDENT_KEY").map_or(
        "required".to_string(), // Default to required
        |v| match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => {
                tracing::warn!("Invalid user verification: {}. Using default 'required'", v);
                "required".to_string()
            }
        },
    )
});

pub(crate) static PASSKEY_REQUIRE_RESIDENT_KEY: LazyLock<bool> = LazyLock::new(|| {
    env::var("PASSKEY_REQUIRE_RESIDENT_KEY").map_or(
        true, // Default to true
        |v| match v.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            invalid => {
                tracing::warn!(
                    "Invalid require_resident_key: {}. Using default 'true'",
                    invalid
                );
                true
            }
        },
    )
});

pub(crate) static PASSKEY_USER_VERIFICATION: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_USER_VERIFICATION").map_or(
        "discouraged".to_string(), // Default to discouraged
        |v| match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => {
                tracing::warn!(
                    "Invalid user verification: {}. Using default 'discouraged'",
                    v
                );
                "discouraged".to_string()
            }
        },
    )
});
