use crate::types;

fn load_env_config(key: &str) -> String {
    dotenv::var(key).expect(&format!("Missing {} env var", key))
}

pub fn load_config() -> types::Config {
    dotenv::dotenv().ok();
    types::Config {
        mongodb_uri: load_env_config("MONGODB_URI"),
        jwt_secret: load_env_config("JWT_SECRET"),
        listen_address: load_env_config("LISTEN_ADDR"),
        admin_panel_enabled: load_env_config("ADMIN_PANEL") == "1",
    }
}

