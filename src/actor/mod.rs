use actix::{Actor, SyncContext};
mod actions;
mod models;
mod tests;
mod user;

use actix_web::{dev::ServiceRequest, http::StatusCode, HttpResponse};
use diesel::{
    r2d2::{ConnectionManager, Pool},
    PgConnection,
};
use serde::{Deserialize, Serialize};

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

pub fn get_message_err(
    req: ServiceRequest,
    err: String,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    let err_resp = HttpResponse::build(StatusCode::from_u16(500).unwrap()).json(ErrorResponse {
        code: "400".to_string(),
        message: err,
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
