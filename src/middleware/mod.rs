use actix_web::{dev::ServiceRequest, http::header::HeaderValue};
use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    ExpressionMethods, PgConnection, QueryDsl,
};
use hmac::{digest::KeyInit, Hmac};
use jwt::VerifyWithKey;
use models::{SessionInfo, SessionType, TokenClaims, TokenClaimsWithTime};
use parse_duration::parse;
use sha2::Sha256;

use crate::{actor::DbActor, schema};
use diesel::prelude::*;

pub mod authentication;
pub mod expiration;
pub mod models;

pub fn token_has_not_expired(
    token_created_time: &std::time::SystemTime,
    session_duration_str: &String,
) -> bool {
    let max_duration = parse(session_duration_str).unwrap_or(std::time::Duration::new(3600, 0));

    let elapsed_time = token_created_time.elapsed().unwrap();

    if elapsed_time.as_secs() > max_duration.as_secs() {
        false
    } else {
        true
    }
}

pub fn get_jwt_claims_with_time<'a>(
    token_string: &str,
    jwt_secret: Hmac<Sha256>,
) -> std::result::Result<TokenClaimsWithTime, &'a str> {
    token_string
        .verify_with_key(&jwt_secret)
        .map_err(|_| "Invalid token")
}

pub fn get_jwt_claims<'a>(
    token_string: &str,
    jwt_secret: Hmac<Sha256>,
) -> std::result::Result<TokenClaims, &'a str> {
    token_string
        .verify_with_key(&jwt_secret)
        .map_err(|_| "Invalid token")
}

pub struct ValidationBasicInfo {
    pub claims: TokenClaims,
    pub max_duration: String,
    pub session_type: SessionType,
}

pub fn get_validation_basic_info(
    app_data: &DbActor,
    token_str: &str,
) -> std::result::Result<ValidationBasicInfo, String> {
    let jwt_secret_opt: Hmac<Sha256> =
        Hmac::new_from_slice(app_data.config.jwt_secret_otp.as_bytes())
            .expect("expected jwt otp secret");
    let jwt_secret: Hmac<Sha256> =
        Hmac::new_from_slice(app_data.config.jwt_secret.as_bytes()).expect("expected jwt secret");
    if let Ok(claims_otp) = get_jwt_claims(token_str, jwt_secret_opt) {
        Ok(ValidationBasicInfo {
            claims: claims_otp,
            max_duration: app_data.config.otp_duration.clone(),
            session_type: SessionType::OTP,
        })
    } else if let Ok(claims_user) = get_jwt_claims(token_str, jwt_secret) {
        Ok(ValidationBasicInfo {
            claims: claims_user,
            max_duration: app_data.config.session_duration.clone(),
            session_type: SessionType::UserPage,
        })
    } else {
        std::result::Result::Err("Authentication failed".to_string())
    }
}

pub fn get_session(
    claims: &TokenClaims,
    session_type: &SessionType,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> std::result::Result<SessionInfo, String> {
    match schema::sessions::dsl::sessions
        .filter(crate::schema::sessions::user_id.eq(claims.id))
        .filter(crate::schema::sessions::session_type.eq(session_type.clone().to_string()))
        .get_result::<SessionInfo>(conn)
    {
        Ok(session_info) => Ok(session_info),
        Err(err_info) => std::result::Result::Err(err_info.to_string()),
    }
}

pub fn get_token_str(req: &ServiceRequest) -> std::result::Result<String, String> {
    let token_str_res = get_token_str_res(req.headers().get("AUTHORIZATION"))?;

    match token_str_res.to_str() {
        Ok(token_str) => Ok(token_str.to_string()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

fn get_token_str_res(
    token_str_res_opt: Option<&HeaderValue>,
) -> std::result::Result<&HeaderValue, String> {
    match token_str_res_opt {
        Some(token_str_res) => Ok(token_str_res),
        _ => std::result::Result::Err("Could extract token from header".to_string()),
    }
}
