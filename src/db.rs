use crate::types::{self, DbApplicationGrant};
use mongodb::{bson::doc, Client};
use tracing::warn;

pub struct Database {
    mongo: Client,
}

const AUTH_DATABASE_NAME: &str = "sf_auth";
const COLLECTION_NAME_USERS: &str = "users";
const COLLECTION_NAME_APPS: &str = "apps";
const COLLECTION_NAME_APP_GRANTS: &str = "app_grants";
const COLLECTION_NAME_SESSIONS: &str = "sessions";

impl Database {
    pub fn new(client: Client) -> Database {
        Database { mongo: client }
    }

    pub async fn user_by_id(&self, id: bson::Uuid) -> Option<types::DbUser> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbUser>(COLLECTION_NAME_USERS);
        return match collection.find_one(doc! { "_id": id }, None).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to retrieve user document {}", e);
                None
            }
        };
    }

    pub async fn user_by_username(&self, username: &str) -> Option<types::DbUser> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbUser>(COLLECTION_NAME_USERS);
        return match collection.find_one(doc! { username: username }, None).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to retrieve user document {}", e);
                None
            }
        };
    }

    pub async fn app_by_client_id(&self, client_id: bson::Uuid) -> Option<types::DbApplication> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbApplication>(COLLECTION_NAME_APPS);
        return match collection.find_one(doc! { "_id": client_id }, None).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to retrieve application document {}", e);
                None
            }
        };
    }

    pub async fn insert_session(
        &self,
        session: &types::DbSession,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbSession>(COLLECTION_NAME_SESSIONS);
        collection.insert_one(session, None).await?;
        Ok(())
    }

    pub async fn session_from_key(&self, key: &str) -> Option<types::DbSession> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbSession>(COLLECTION_NAME_SESSIONS);
        let session = match collection.find_one(doc! { "key": key }, None).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to load session: {}", e);
                return None;
            }
        };
        return session;
    }

    pub async fn insert_application_grant(
        &self,
        grant: &types::DbApplicationGrant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbApplicationGrant>(COLLECTION_NAME_APP_GRANTS);
        collection.insert_one(grant, None).await?;
        Ok(())
    }

    pub async fn remove_application_grant(
        &self,
        code: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbApplicationGrant>(COLLECTION_NAME_APP_GRANTS);
        collection.delete_many(doc! { "code": code }, None).await?;
        Ok(())
    }

    pub async fn get_application_grant(
        &self,
        code: &str,
    ) -> Result<Option<DbApplicationGrant>, Box<dyn std::error::Error>> {
        let collection = self
            .mongo
            .database(AUTH_DATABASE_NAME)
            .collection::<types::DbApplicationGrant>(COLLECTION_NAME_APP_GRANTS);
        Ok(collection.find_one(doc! { "code": &code}, None).await?)
    }
}
