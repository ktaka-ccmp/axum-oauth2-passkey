# Axum Google OAuth2/OIDC Library

[![Crates.io](https://img.shields.io/crates/v/axum-liboauth2)](https://crates.io/crates/axum-liboauth2)
[![Docs.rs](https://docs.rs/axum-liboauth2/badge.svg)](https://docs.rs/axum-liboauth2)
[![License](https://img.shields.io/crates/l/axum-liboauth2)](LICENSE)

A robust and easy-to-use library for implementing Google OAuth2/OIDC authentication in Axum web applications. This library provides a clean API for handling OAuth2 authentication flows with built-in session management and token storage.

## Features

- 🔒 Complete Google OAuth2/OIDC authentication flow
- 🚀 Easy integration with Axum applications
- 💾 Built-in token storage with Redis support
- 🔑 Session management
- 🎯 Type-safe user data handling
- 📦 Example applications included

## Quick Start

1. Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
axum-liboauth2 = "0.1"
```

2. Configure OAuth2 credentials:
   - Obtain Client ID and Client Secret from [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   - Add your redirect URI (e.g., `https://localhost:3443/auth/authorized`) to "Authorized redirect URIs"
   - Create a `.env` file with your credentials (see [Configuration](#configuration))

3. Integrate with your Axum application:

```rust
use axum::{routing::get, Router};
use liboauth2::OAUTH2_ROUTE_PREFIX;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the OAuth2 library
    liboauth2::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .nest(OAUTH2_ROUTE_PREFIX.as_str(), liboauth2::router());

    // Start your server...
    Ok(())
}
```

## Configuration

Create a `.env` file with the following settings:

```env
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URL=https://localhost:3443/auth/authorized
REDIS_URL=redis://localhost:6379
```

## Examples

The repository includes two example applications:

- `demo-oauth2`: A complete example showing OAuth2 authentication with protected routes

## Documentation

For more detailed information about using this library, check out:
- [API Documentation](https://docs.rs/axum-liboauth2)
- [Blog Post](https://ktaka.blog.ccmp.jp/2024/12/axum-google-oauth2oidc-implementation.html)

## Inspiration

This library was inspired by the [Discord OAuth example](https://github.com/tokio-rs/axum/blob/main/examples/oauth/src/main.rs) in the Axum repository, but extends the functionality with additional features and Google OAuth2/OIDC support.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```text
CLIENT_ID=$client_id
CLIENT_SECRET=$client_secret
ORIGIN='https://localhost:3443'

#(Optional: Run ngrok by `ngrok http 3000`)
#ORIGIN="https://xxxxx.ngrok-free.app"
```

- Start the application

```text
cargo run
```

## Todo

- Expiration check for session and token
- Clean up expired sessions and tokens from SQL store
- Implement PostgreSQL and SQLite storage
- Error handling by thiserr i.e. remove anyhow dependency in liboauth2 and libsession
- Design and create user Database table
  - Fetch the user info from a user database as a library or through api request in the future.
- Use middleware to distinguish authenticated users [see](https://github.com/ktaka-ccmp/axum-htmx-google-oauth/blob/master/src/main.rs#L90)
- Write unit tests
- Write integration tests
- Write documentation
- Publish on crates.io
- CI/CD

### Additional Configuration Tasks
- Make OAuth2 userinfo endpoint configurable (currently hardcoded to Google's endpoint)
- Add OAuth2 access type configuration (online/offline for refresh tokens)
- Add OAuth2 prompt configuration (none/consent/select_account)
- Make JWKS cache configurable:
  - Cache TTL
  - Cache size
  - Cache invalidation strategy

- ✅ Document storage singleton pattern (see [StorageSingletonPattern.md](docs/StorageSingletonPattern.md))
- ✅ Separate libsession and liboauth2
- ✅ Remove csrf token etc after their use from token store
- ✅ Use STATIC parameters to simplify state management [see](https://github.com/ktaka-ccmp/axum-htmx-google-oauth/blob/master/src/settings.rs)
