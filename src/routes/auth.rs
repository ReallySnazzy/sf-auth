use axum::{extract, headers, http, response, TypedHeader};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use rand::Rng;
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tracing::warn;

use crate::{password, types};

pub async fn auth(request: extract::Query<types::AuthRequest>) -> types::AuthTemplate {
    return types::AuthTemplate {
        redirect_uri: request.redirect_uri.clone(),
        client_id: request.client_id.clone(),
    };
}

pub async fn login(
    request: extract::Query<types::LoginRequest>,
    state: extract::State<Arc<types::AppState>>,
) -> response::Redirect {
    // TODO Encode query params
    let invalid_password_uri = format!(
        "/auth?client_id={}&redirect_uri={}&invalid_creds=1",
        request.client_id, request.redirect_uri
    );
    let invalid_config_uri = format!(
        "/auth?client_id={}&redirect_uri={}&invalid_config=1",
        request.client_id, request.redirect_uri
    );
    let user = match state.database.user_by_username(&request.username).await {
        Some(u) => u,
        None => return response::Redirect::temporary(&invalid_password_uri),
    };
    if !password::check_password(&user.password_hash, &request.password) {
        return response::Redirect::temporary(&invalid_password_uri);
    }
    let client_id = match bson::Uuid::parse_str(&request.client_id) {
        Ok(u) => u,
        Err(e) => {
            warn!("Failed to parse client id({}): {}", request.client_id, e);
            return response::Redirect::temporary(&invalid_config_uri);
        }
    };
    let app = match state.database.app_by_client_id(client_id).await {
        Some(a) => a,
        None => {
            warn!(
                "Failed to find application for client id {}",
                client_id.to_string()
            );
            return response::Redirect::temporary(&invalid_config_uri);
        }
    };
    if !app.redirect_uris.contains(&request.redirect_uri) {
        warn!(
            "Failed to find application for client id {}",
            client_id.to_string()
        );
        return response::Redirect::temporary(&invalid_config_uri);
    }
    // TODO: Support state parameter
    // TODO Make application grants expire
    let code = generate_random_code(128);
    let grant = types::DbApplicationGrant {
        client_id,
        code,
        user_id: user.id,
    };
    if let Err(e) = state.database.insert_application_grant(&grant).await {
        warn!("Failed to insert application grant: {}", e);
        return response::Redirect::temporary(&invalid_config_uri);
    }
    response::Redirect::temporary(&format!("{}?code={}", &request.redirect_uri, &grant.code))
}

fn generate_random_code(len: usize) -> String {
    let mut chars = Vec::<char>::new();
    chars.append(&mut ('a'..='z').collect());
    chars.append(&mut ('A'..='Z').collect());
    chars.append(&mut ('0'..='9').collect());
    let mut rng = rand::thread_rng();
    let mut result = Vec::<_>::with_capacity(len);
    for _ in 0..len {
        let next = chars[rng.gen::<usize>() % chars.len()];
        result.push(next);
    }
    result.into_iter().collect::<String>()
}

fn error_hash_map(message: &str) -> HashMap<String, String> {
    let mut result = HashMap::<String, String>::new();
    result.insert("error".to_owned(), message.to_owned());
    return result;
}

pub async fn token(
    request: extract::Query<types::TokenRequest>,
    state: extract::State<Arc<types::AppState>>,
) -> Result<
    response::Json<types::TokenResponse>,
    (http::StatusCode, response::Json<HashMap<String, String>>),
> {
    let grant = match state.database.get_application_grant(&request.code).await {
        Ok(g) => g,
        Err(e) => {
            warn!("Failed to get application grant: {}", e);
            return Err((
                http::StatusCode::INTERNAL_SERVER_ERROR,
                response::Json(error_hash_map("Database error")),
            ));
        }
    };
    let grant = match grant {
        Some(g) => g,
        None => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                response::Json(error_hash_map("Invalid grant")),
            ));
        }
    };
    let jwt_key: Hmac<Sha256> = match Hmac::new_from_slice(state.config.jwt_secret.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to create hmac key: {}", e);
            return Err((
                http::StatusCode::BAD_REQUEST,
                response::Json(error_hash_map("Failed to sign JWT")),
            ));
        }
    };
    let mut claims = BTreeMap::new();
    claims.insert("sub", grant.user_id.to_string());
    claims.insert("iss", "https://auth.snazzyfellas.com".to_owned());
    // claims.insert("aud", "TODO: Provide correct audience claim");
    // claims.insert("exp", "TODO: Provide expire time to JWT");
    // claims.insert("iat", "TODO: Provide issued at time");
    // claims.insert("nbf", "TODO: Provide not before time");
    // claims.insert("jti", "TODO: Unique identifier to prevent JWT replay");
    let id_token = match claims.sign_with_key(&jwt_key) {
        Ok(id) => id,
        Err(e) => {
            warn!("Failed to sign JWT: {}", e);
            return Err((
                http::StatusCode::BAD_REQUEST,
                response::Json(error_hash_map("Failed to sign JWT")),
            ));
        }
    };
    // TODO Make expiration actually do something
    let session = types::DbSession {
        user_id: grant.user_id,
        expires: 60 * 24 * 30, // + current time
        client_id: grant.client_id,
        session_key: generate_random_code(512),
        id_token: id_token.clone(),
    };
    match state.database.insert_session(&session).await {
        Ok(_) => (),
        Err(e) => {
            warn!("Failed to save session: {}", e);
            return Err((
                http::StatusCode::INTERNAL_SERVER_ERROR,
                response::Json(error_hash_map("Failed to save session to database")),
            ));
        }
    };
    return Ok(response::Json(types::TokenResponse {
        token_type: "Bearer".to_owned(),
        expires_in: session.expires, // 1 month
        access_token: session.session_key,
        id_token,
    }));
}

pub async fn user_info(
    auth_header: TypedHeader<headers::Authorization<headers::authorization::Bearer>>,
    state: extract::State<Arc<types::AppState>>,
) -> Result<
    response::Json<types::UserInfoResponse>,
    (http::StatusCode, response::Json<HashMap<String, String>>),
> {
    let bearer = auth_header.token().clone();
    let session = match state.database.session_from_key(bearer).await {
        Some(s) => s,
        None => {
            return Err((
                http::StatusCode::UNAUTHORIZED,
                response::Json(error_hash_map("Invalid session")),
            ));
        }
    };
    return Ok(response::Json(types::UserInfoResponse {
        sub: session.user_id.to_string(),
    }));
}
