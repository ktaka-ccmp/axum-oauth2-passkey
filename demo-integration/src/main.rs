use axum::{Router, routing::get};
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use libaxum::{oauth2_router, passkey_router};
use liboauth2::OAUTH2_ROUTE_PREFIX;
use libpasskey::PASSKEY_ROUTE_PREFIX;

mod handlers;
mod server;

use crate::{
    handlers::{index, protected},
    server::{Ports, spawn_http_server, spawn_https_server},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install default CryptoProvider for rustls to prevent:
    // "no process-level CryptoProvider available -- call CryptoProvider::install_default() before this point"
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    dotenv().ok();

    // Set up tracing with environment variable support and different defaults based on build configuration
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // If no environment variable is set, use different defaults based on build configuration
        #[cfg(debug_assertions)]
        {
            // Debug build default - show all log levels
            "libpasskey=trace,libstorage=trace,demo_integration=trace".into()
        }

        #[cfg(not(debug_assertions))]
        {
            // Release build default - only show info and above
            "info".into()
        }
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(debug_assertions)]
    tracing::debug!("Debug mode enabled - showing detailed logs by default");

    tracing::info!("Starting demo-integration application");
    tracing::info!("You can increase verbosity by setting the RUST_LOG environment variable.");
    tracing::info!("Log levels from least to most verbose: error < warn < info < debug < trace");
    tracing::info!("Example: RUST_LOG=debug ./demo-integration");

    // Print the current log level
    #[cfg(debug_assertions)]
    tracing::info!("Current log level: DEBUG build with detailed logging");
    #[cfg(not(debug_assertions))]
    tracing::info!("Current log level: RELEASE build with standard logging");

    // Add a handler for errors that suggests increasing log level
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("ERROR: The application encountered a problem and needs to close.");
        eprintln!(
            "For more detailed error information, run with: RUST_LOG=debug ./your-application"
        );
        eprintln!("Panic details: {}", panic_info);
    }));

    // Initialize the OAuth2 library
    liboauth2::init().await?;
    libpasskey::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .nest(OAUTH2_ROUTE_PREFIX.as_str(), oauth2_router())
        .nest(PASSKEY_ROUTE_PREFIX.as_str(), passkey_router());

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
