use actix::{Actor, SyncContext};
pub mod actions;
pub mod models;
pub mod tests;
pub mod user;

use actix_web::{dev::ServiceRequest, http::StatusCode, HttpResponse};
use argonautica::Hasher;
use diesel::{
    r2d2::{ConnectionManager, Pool, PooledConnection},
    PgConnection,
};
use hmac::{digest::KeyInit, Hmac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    database::models::User,
    middleware::{
        get_jwt_claims,
        models::{SessionType, TokenClaims},
    },
};

impl Actor for DbActor {
    type Context = SyncContext<Self>;
}

pub struct DbActor {
    pub pool: Pool<ConnectionManager<PgConnection>>,
    pub config: crate::config::Config,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

pub fn get_auth_failed_resp(
    req: ServiceRequest,
    err: diesel::result::Error,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    let err_resp = HttpResponse::build(StatusCode::from_u16(500).unwrap()).json(ErrorResponse {
        code: "400".to_string(),
        message: err.to_string(),
    });
    Err((err_resp, req))
}

pub fn diesel_err_to_string(err: diesel::result::Error) -> String {
    match err {
        diesel::result::Error::InvalidCString(_) => "Invalid C string".to_string(),
        diesel::result::Error::DatabaseError(_, _) => "Database error".to_string(),
        diesel::result::Error::NotFound => "Not found".to_string(),
        diesel::result::Error::QueryBuilderError(_) => "Query builder error".to_string(),
        diesel::result::Error::DeserializationError(_) => "Deserialization error".to_string(),
        diesel::result::Error::SerializationError(_) => "Serialization error".to_string(),
        diesel::result::Error::RollbackErrorOnCommit {
            rollback_error: _,
            commit_error: _,
        } => "Rollback error on commit".to_string(),
        diesel::result::Error::RollbackTransaction => "Rollback transaction".to_string(),
        diesel::result::Error::AlreadyInTransaction => "Already in transaction".to_string(),
        diesel::result::Error::NotInTransaction => "Not in transaction".to_string(),
        diesel::result::Error::BrokenTransactionManager => "Broken transaction manager".to_string(),
        _ => "Unknown database error".to_string(),
    }
}

pub fn to_hash(secret_key: &String, password: &String) -> std::result::Result<String, String> {
    let mut hasher = Hasher::default();
    let hasher_res = hasher
        .with_password(password)
        .with_secret_key(secret_key)
        .hash();

    match hasher_res {
        Ok(hash_str) => Ok(hash_str),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

pub fn get_user_db(
    username_fr_client: String,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<User, String> {
    use crate::schema::users::dsl::{username, users};
    use diesel::prelude::*;
    let found_user = users
        .filter(username.eq(username_fr_client))
        .get_result::<User>(conn);

    match found_user {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

pub fn get_claims(
    app_data: &DbActor,
    token_str: &str,
    token_type: SessionType,
) -> std::result::Result<TokenClaims, String> {
    let secret = match token_type {
        SessionType::OTP => app_data.config.jwt_secret_otp.as_bytes(),
        SessionType::UserPage => app_data.config.jwt_secret.as_bytes(),
    };
    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(secret).expect("expected jwt secret");
    if let Ok(claims_user) = get_jwt_claims(token_str, jwt_secret) {
        Ok(claims_user)
    } else {
        std::result::Result::Err("Authentication failed".to_string())
    }
}

pub fn get_user_by_id(
    user_id: &uuid::Uuid,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<User, String> {
    use crate::schema::users::dsl::{id, users};
    use diesel::prelude::*;
    let found_user = users.filter(id.eq(user_id)).get_result::<User>(conn);

    match found_user {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
