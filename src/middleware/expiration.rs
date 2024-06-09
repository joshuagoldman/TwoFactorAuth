use std::time::SystemTime;

use actix_web::{dev::ServiceRequest, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::*;
use hmac::{digest::KeyInit, Hmac};
use sha2::Sha256;

use crate::{
    actor::{get_message_err, DbActor},
    schema,
};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
};

use super::{
    get_jwt_claims, get_session,
    models::{SessionInfo, SessionType, TokenClaims},
    token_has_not_expired,
};

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> std::result::Result<ServiceRequest, (HttpResponse, ServiceRequest)> {
    match validator_std_res(&req, credentials).await {
        std::result::Result::Ok(()) => Ok(req),
        std::result::Result::Err(err) => get_message_err(req, err),
    }
}

pub async fn validator_std_res(
    req: &ServiceRequest,
    credentials: BearerAuth,
) -> std::result::Result<(), String> {
    dotenv().ok();
    let token_str = credentials.token();

    let app_data = get_app_data(&req)?;

    let mut conn = app_data.pool.get().expect("unable to get connection");

    let basic_info = get_validation_basic_info(app_data, token_str)?;

    let session = get_session(&basic_info.claims, &basic_info.session_type, &mut conn)?;

    if !token_has_not_expired(&session.refresh_time, &basic_info.max_duration) {
        return std::result::Result::Err("Token has expired".to_string());
    }

    session_not_expired_action(&basic_info.claims, &basic_info.session_type, &mut conn)?;

    Ok(())
}

fn get_app_data(req: &ServiceRequest) -> std::result::Result<&DbActor, String> {
    match req.app_data::<DbActor>() {
        Some(app_data_found) => Ok(app_data_found),
        None => std::result::Result::Err("Could not get app data".to_string()),
    }
}

fn session_not_expired_action(
    claims: &TokenClaims,
    session_type: &SessionType,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> std::result::Result<(), String> {
    let new_session = SessionInfo {
        session_type: session_type.clone().to_string(),
        refresh_time: SystemTime::now(),
        user_id: claims.id,
    };
    match diesel::insert_into(schema::sessions::dsl::sessions)
        .values(new_session)
        .get_result::<SessionInfo>(conn)
    {
        Ok(_) => Ok(()),
        Err(error_info) => std::result::Result::Err(error_info.to_string()),
    }
}

struct ValidationBasicInfo {
    claims: TokenClaims,
    max_duration: String,
    session_type: SessionType,
}

fn get_validation_basic_info(
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
