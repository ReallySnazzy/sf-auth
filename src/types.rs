use askama::Template;
use bson;
use serde::{Deserialize, Serialize};

use crate::db::Database;

#[derive(Serialize, Deserialize)]
pub struct AdminCreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AdminCreateApplicationRequest {
    pub app_name: String,
    pub redirect_uris: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub id_token: String,
    pub expires_in: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub redirect_uri: String,
    pub client_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub redirect_uri: String,
    pub client_id: String,
}

#[derive(Template)]
#[template(path = "auth.html")]
pub struct AuthTemplate {
    pub redirect_uri: String,
    pub client_id: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct AdminPanelTemplate {}

pub struct AppState {
    pub database: Database,
    pub config: Config,
}

#[derive(Serialize, Deserialize)]
pub struct DbUser {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<bson::oid::ObjectId>,
    pub username: String,
    pub password_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct DbApplicationGrant {
    pub client_id: bson::oid::ObjectId,
    pub code: String,
    pub user_id: bson::oid::ObjectId,
}

#[derive(Serialize, Deserialize)]
pub struct DbApplication {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<bson::oid::ObjectId>,
    pub name: String,
    pub secret: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DbSession {
    pub user_id: bson::oid::ObjectId,
    pub client_id: bson::oid::ObjectId,
    pub expires: u64,
    pub session_key: String,
    pub id_token: String,
}

#[derive(Clone)]
pub struct Config {
    pub mongodb_uri: String,
    pub jwt_secret: String,
    pub listen_address: String,
    pub admin_panel_enabled: bool,
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
}

