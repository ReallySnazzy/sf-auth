use crate::{
    password,
    types::{self, AdminPanelTemplate, DbApplication, DbUser},
};
use actix_web::{http::header::ContentType, web, HttpResponse};
use askama::Template;
use rand::prelude::*;
use tracing::error;

pub async fn panel(state: web::Data<types::AppState>) -> HttpResponse {
    if !state.config.admin_panel_enabled {
        return HttpResponse::Forbidden().body("Admin panel is not enabled");
    }
    let rendering = match (AdminPanelTemplate {}).render() {
        Ok(p) => p,
        Err(e) => {
            error!("Template rendering failed: {}", e);
            return HttpResponse::InternalServerError().body("Failed to render template");
        }
    };
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(rendering)
}

pub async fn create_user(
    state: web::Data<types::AppState>,
    request: web::Form<types::AdminCreateUserRequest>,
) -> HttpResponse {
    if !state.config.admin_panel_enabled {
        return HttpResponse::Forbidden().body("Admin panel is not enabled");
    }
    let hashed_password = match password::hash_password(&request.password) {
        Some(s) => s,
        None => {
            return HttpResponse::InternalServerError().body("Failed to hash password.");
        }
    };
    let user = DbUser {
        id: None,
        username: request.username.clone(),
        password_hash: hashed_password,
    };
    match state.database.insert_user(&user).await {
        Ok(_) => (),
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Failed to create user: {e}"));
        }
    };
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body("Created user.")
}

pub async fn create_application(
    state: web::Data<types::AppState>,
    request: web::Form<types::AdminCreateApplicationRequest>,
) -> HttpResponse {
    if !state.config.admin_panel_enabled {
        return HttpResponse::Forbidden().body("Admin panel is not enabled");
    }
    let secret = random_string(128);
    let application = DbApplication {
        id: None,
        name: request.app_name.clone(),
        secret,
        redirect_uris: request
            .redirect_uris
            .split(",")
            .map(|url| url.trim().to_owned())
            .collect::<Vec<_>>(),
    };
    let app_id = match state.database.insert_application(&application).await {
        Ok(i) => i,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to create application: {e}"));
        }
    };
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(format!(
            "Created application.<br />Client ID: {}<br />Client secret: {}",
            app_id, application.secret,
        ))
}

fn random_string(len: usize) -> String {
    let mut selection: Vec<char> = vec![];
    selection.extend('a'..='z');
    selection.extend('A'..='Z');
    selection.extend('0'..='9');
    let mut result: Vec<char> = vec![];
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        result.push(*selection.choose(&mut rng).unwrap());
    }
    result.into_iter().collect::<String>()
}

