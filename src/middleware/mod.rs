use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    ExpressionMethods, PgConnection, QueryDsl,
};
use hmac::Hmac;
use jwt::VerifyWithKey;
use models::{SessionInfo, SessionType, TokenClaims, TokenClaimsWithTime};
use parse_duration::parse;
use sha2::Sha256;

use crate::schema::{self};
use diesel::prelude::*;

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
