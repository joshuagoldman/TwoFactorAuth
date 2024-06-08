use actix::{Actor, SyncContext};
mod actions;
mod models;
mod tests;
mod user;

use actix_web::{dev::ServiceRequest, http::StatusCode, HttpResponse, ResponseError};
use diesel::{
    r2d2::{ConnectionManager, Pool},
    PgConnection, QueryResult,
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
