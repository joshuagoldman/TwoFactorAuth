use std::time::SystemTime;

use actix_web::{dev::ServiceRequest, http::StatusCode, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::*;
use hmac::{digest::KeyInit, Hmac};
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{actor::DbActor, schema};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
};

use super::{
    models::{SessionInfo, SessionType, TokenClaimsWithTime},
    token_has_not_expired,
};
use crate::schema::sessions::dsl::user_id;

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    dotenv().ok();
    let token_str = credentials.token();
    if let Some(app_data) = req.app_data::<DbActor>() {
        let jwt_secret_opt: Hmac<Sha256> =
            Hmac::new_from_slice(app_data.config.jwt_secret_otp.as_bytes())
                .expect("expected jwt otp secret");
        let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(app_data.config.jwt_secret.as_bytes())
            .expect("expected jwt secret");

        let claims;
        let max_duration;
        let session_type;
        if let Ok(claims_otp) = get_jwt_claims_with_time(token_str, jwt_secret_opt) {
            claims = claims_otp;
            max_duration = app_data.config.otp_duration.clone();
            session_type = SessionType::OTP;
        } else if let Ok(claims_user) = get_jwt_claims_with_time(token_str, jwt_secret) {
            claims = claims_user;
            max_duration = app_data.config.session_duration.clone();
            session_type = SessionType::UserPage;
        } else {
            return get_message_err(req, "Autentication failed".to_string());
        }

        let mut conn = app_data.pool.get().expect("unable to get connection");

        let mut session_info: SessionInfo = SessionInfo::new();
        let mut err: diesel::result::Error = diesel::result::Error::NotFound;
        if !get_session(&claims, &mut conn, &mut session_info, &mut err) {
            return get_auth_failed_resp(req, err);
        }

        if !token_has_not_expired(&session_info.refresh_time, &max_duration) {
            return get_message_err(req, "Token has expired".to_string());
        }

        if !session_not_expired_action(&claims, &session_type, &mut conn, &mut err) {
            return get_auth_failed_resp(req, err);
        }

        Ok(req)
    } else {
        let err_resp =
            HttpResponse::build(StatusCode::from_u16(400).unwrap()).json(ErrorResponse {
                code: "400".to_string(),
                message: "Authentication failed".to_string(),
            });
        Err((err_resp, req))
    }
}

fn get_auth_failed_resp(
    req: ServiceRequest,
    err: diesel::result::Error,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    let err_resp = HttpResponse::build(StatusCode::from_u16(500).unwrap()).json(ErrorResponse {
        code: "400".to_string(),
        message: err.to_string(),
    });
    Err((err_resp, req))
}

fn get_message_err(
    req: ServiceRequest,
    err: String,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    let err_resp = HttpResponse::build(StatusCode::from_u16(500).unwrap()).json(ErrorResponse {
        code: "400".to_string(),
        message: err,
    });
    Err((err_resp, req))
}

pub fn get_jwt_claims_with_time<'a>(
    token_string: &str,
    jwt_secret: Hmac<Sha256>,
) -> std::result::Result<TokenClaimsWithTime, &'a str> {
    token_string
        .verify_with_key(&jwt_secret)
        .map_err(|_| "Invalid token")
}

fn get_session(
    claims: &TokenClaimsWithTime,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    session: &mut SessionInfo,
    err: &mut diesel::result::Error,
) -> bool {
    match schema::sessions::dsl::sessions
        .filter(user_id.eq(claims.id))
        .get_result::<SessionInfo>(conn)
    {
        Ok(session_info) => {
            *session = session_info;
            true
        }
        Err(err_info) => {
            *err = err_info;
            false
        }
    }
}

fn session_not_expired_action(
    claims: &TokenClaimsWithTime,
    session_type: &SessionType,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    err: &mut diesel::result::Error,
) -> bool {
    let new_session = SessionInfo {
        session_type: session_type.clone().to_string(),
        refresh_time: SystemTime::now(),
        user_id: claims.id,
    };
    match diesel::insert_into(schema::sessions::dsl::sessions)
        .values(new_session)
        .get_result::<SessionInfo>(conn)
    {
        Ok(_) => true,
        Err(error_info) => {
            *err = error_info;
            false
        }
    }
}
