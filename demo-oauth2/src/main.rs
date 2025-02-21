use axum::{routing::get, Router};
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use liboauth2::OAUTH2_ROUTE_PREFIX;

mod handlers;
mod server;

use crate::{
    handlers::{index, protected},
    server::{spawn_http_server, spawn_https_server, Ports},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize the OAuth2 library
    liboauth2::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .nest(OAUTH2_ROUTE_PREFIX.as_str(), liboauth2::router());

    let ports = Ports {
        http: 3001,
        https: 3443,
    };

    let http_server = spawn_http_server(ports.http, app.clone());
    let https_server = spawn_https_server(ports.https, app).await;

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
