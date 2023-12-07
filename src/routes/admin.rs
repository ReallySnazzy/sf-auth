use crate::types::{self, AdminPanelTemplate};
use actix_web::{http::header::ContentType, web, HttpResponse};
use askama::Template;
use tracing::error;

pub async fn panel(data: web::Data<types::AppState>) -> HttpResponse {
    if !data.config.admin_panel_enabled {
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

