use std::time::SystemTime;

use actix_web::dev::ServiceRequest;
use dotenv::*;

use crate::{actor::DbActor, schema};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
};

use super::{
    get_session, get_token_str, get_validation_basic_info,
    models::{SessionInfo, SessionType, TokenClaims},
    token_has_not_expired,
};

pub fn validator(req: &ServiceRequest) -> std::result::Result<(), String> {
    dotenv().ok();
    let token_str = get_token_str(req)?;

    let app_data = get_app_data(&req)?;

    let mut conn = app_data.pool.get().expect("unable to get connection");

    let basic_info = get_validation_basic_info(app_data, &token_str)?;

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
