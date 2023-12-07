use actix_web::{http::header::ContentType, web, App, HttpResponse, HttpServer, Responder};
use db::Database;
use mongodb::{options::ClientOptions, Client};
use tracing_subscriber;
use types::AppState;

pub mod config;
pub mod db;
pub mod password;
pub mod routes;
pub mod types;

async fn home_status() -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body("<h1>Auth server online</h1>")
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let config = config::load_config();
    let mongo = Client::with_options(ClientOptions::parse(config.mongodb_uri.clone()).await?)?;
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                database: Database::new(mongo.clone()),
                config: config.clone(),
            }))
            .route("/", web::get().to(home_status))
            .route("/admin", web::get().to(routes::admin::panel))
            .route("/auth", web::get().to(routes::auth::auth))
            .route("/login", web::post().to(routes::auth::login))
            .route("/token", web::post().to(routes::auth::token))
            .route("/userinfo", web::get().to(routes::auth::user_info))
            .service(actix_files::Files::new("/static", "static").show_files_listing())
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await?;
    Ok(())
}

