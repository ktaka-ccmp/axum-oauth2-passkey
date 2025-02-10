use axum::{routing::get, Router, response::{IntoResponse, Redirect, Response}};
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use liboauth2::oauth2_state_init;
use libsession::session_state_init;

#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

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

    let session_state = session_state_init().await.unwrap_or_else(|e| {
        eprintln!("Failed to initialize SessionState: {e}");
        std::process::exit(1)
    });

    let oauth2_state: OAuth2State = oauth2_state_init(Arc::new(session_state.clone()))
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to initialize OAuth2State: {e}");
            std::process::exit(1);
        });

    let app_state = AppState {
        session_state,
        oauth2_state: oauth2_state.clone(),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .with_state(app_state.clone())
        .nest(
            &oauth2_state.oauth2_params.oauth2_route_prefix,
            liboauth2::router(oauth2_state.clone()),
        )
        .with_state(oauth2_state);

    let ports = Ports {
        http: 3001,
        https: 3443,
    };

    let http_server = spawn_http_server(ports.http, app.clone());
    let https_server = spawn_https_server(ports.https, app);

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}

fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::debug!("HTTP server listening on {}:{}", addr, port);
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

// HTTPS server spawner
fn spawn_https_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let config = RustlsConfig::from_pem_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("self_signed_certs")
                .join("cert.pem"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("self_signed_certs")
                .join("key.pem"),
        )
        .await
        .unwrap();

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::debug!("HTTPS server listening on {}:{}", addr, port);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

use anyhow::Result;
use askama::Template;
use axum::http::request::Parts;
use axum::{
    extract::{FromRequestParts, State},
    http::StatusCode,
    response::Html,
};
use liboauth2::OAuth2State;
use libsession::{SessionState, User};

#[derive(Clone)]
struct AppState {
    session_state: SessionState,
    oauth2_state: OAuth2State,
}

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}

// Extract SessionState from AppState for User extractor
impl FromRequestParts<AppState> for User {
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        User::from_request_parts(parts, &state.session_state)
            .await
            .map_err(|_| AuthRedirect)
    }
}

// Extract SessionState from AppState for Option<User> extractor
impl FromRequestParts<AppState> for Option<User> {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Option::<User>::from_request_parts(parts, &state.session_state)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            })
    }
}

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexTemplateUser<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexTemplateAnon<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate<'a> {
    user: User,
    auth_route_prefix: &'a str,
}

#[axum::debug_handler(state = AppState)]
pub(crate) async fn index(
    State(s): State<AppState>,
    user: Option<User>,
) -> Result<Html<String>, (StatusCode, String)> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.name);
            let template = IndexTemplateUser {
                message: &message,
                auth_route_prefix: &s.oauth2_state.oauth2_params.oauth2_route_prefix,
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
        None => {
            let message = "Click the Login button below.".to_string();
            let template = IndexTemplateAnon {
                message: &message,
                auth_route_prefix: &s.oauth2_state.oauth2_params.oauth2_route_prefix,
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
    }
}

#[axum::debug_handler(state = AppState)]
async fn protected(
    State(s): State<AppState>,
    user: User,
) -> Result<Html<String>, (StatusCode, String)> {
    let template = ProtectedTemplate {
        user,
        auth_route_prefix: &s.oauth2_state.oauth2_params.oauth2_route_prefix,
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}
