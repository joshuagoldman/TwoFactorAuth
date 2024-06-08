use std::time::SystemTime;

use actix_web::{dev::ServiceRequest, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::*;
use hmac::{digest::KeyInit, Hmac};
use jwt::VerifyWithKey;
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    actor::{get_auth_failed_resp, get_message_err, DbActor},
    schema,
};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
};

use super::{
    models::{SessionInfo, SessionType, TokenClaimsWithTime},
    token_has_not_expired,
};
use crate::schema::sessions::dsl::user_id;

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    dotenv().ok();
    let token_str = credentials.token();
    let app_data: &DbActor;
    let mut err: String = String::new();
    let mut session_info: SessionInfo = SessionInfo::new();
    let mut err_db: diesel::result::Error = diesel::result::Error::NotFound;

    if let Some(app_data_found) = req.app_data::<DbActor>() {
        app_data = app_data_found;
    } else {
        return get_message_err(req, err);
    }

    let mut conn = app_data.pool.get().expect("unable to get connection");

    let mut basic_info = ValidationBasicInfo::new();
    if !get_validation_basic_info(app_data, token_str, &mut basic_info, &mut err) {
        return get_message_err(req, err);
    }

    if !get_session(
        &basic_info.claims,
        &mut conn,
        &mut session_info,
        &mut err_db,
    ) {
        return get_auth_failed_resp(req, err_db);
    }

    if !token_has_not_expired(&session_info.refresh_time, &basic_info.max_duration) {
        return get_message_err(req, "Token has expired".to_string());
    }

    if !session_not_expired_action(
        &basic_info.claims,
        &basic_info.session_type,
        &mut conn,
        &mut err_db,
    ) {
        return get_auth_failed_resp(req, err_db);
    }

    Ok(req)
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

struct ValidationBasicInfo {
    claims: TokenClaimsWithTime,
    max_duration: String,
    session_type: SessionType,
}

impl ValidationBasicInfo {
    fn new() -> Self {
        let claims = TokenClaimsWithTime {
            id: Uuid::new_v4(),
            created: SystemTime::now(),
        };
        Self {
            claims,
            max_duration: "1 hour".to_string(),
            session_type: SessionType::UserPage,
        }
    }
}

fn get_validation_basic_info(
    app_data: &DbActor,
    token_str: &str,
    basic_info: &mut ValidationBasicInfo,
    err: &mut String,
) -> bool {
    let jwt_secret_opt: Hmac<Sha256> =
        Hmac::new_from_slice(app_data.config.jwt_secret_otp.as_bytes())
            .expect("expected jwt otp secret");
    let jwt_secret: Hmac<Sha256> =
        Hmac::new_from_slice(app_data.config.jwt_secret.as_bytes()).expect("expected jwt secret");
    if let Ok(claims_otp) = get_jwt_claims_with_time(token_str, jwt_secret_opt) {
        basic_info.claims = claims_otp;
        basic_info.max_duration = app_data.config.otp_duration.clone();
        basic_info.session_type = SessionType::OTP;
        true
    } else if let Ok(claims_user) = get_jwt_claims_with_time(token_str, jwt_secret) {
        basic_info.claims = claims_user;
        basic_info.max_duration = app_data.config.session_duration.clone();
        basic_info.session_type = SessionType::UserPage;
        true
    } else {
        *err = "Authentication failed".to_string();
        false
    }
}
