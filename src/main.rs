use axum::{
    response::Html,
    routing::{get, post},
    Router,
};
use db::Database;
use mongodb::{options::ClientOptions, Client};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::info;
use tracing_subscriber;
use types::AppState;

pub mod config;
pub mod db;
pub mod password;
pub mod routes;
pub mod types;

async fn handler() -> Html<&'static str> {
    Html("<h1>Auth server online</h1>")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let config = config::load_config();
    let mongo = Client::with_options(ClientOptions::parse(config.mongodb_uri.clone()).await?)?;
    let app = Router::new()
        .route("/", get(handler))
        .route("/userinfo", get(routes::auth::user_info))
        .route("/token", post(routes::auth::token))
        .route("/auth", get(routes::auth::auth))
        .route("/login", post(routes::auth::login))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(Arc::from(AppState {
            database: Database::new(mongo),
            config: config.clone(),
        }));
    info!("Starting server on {}", config.listen_address);
    axum::Server::bind(&config.listen_address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
