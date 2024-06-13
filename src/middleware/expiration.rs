use std::time::SystemTime;

use actix_web::{dev::ServiceRequest, web::Data};
use dotenv::*;

use crate::{actor::DbActor, handlers::Authenticate, schema, AppState};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
};

use super::{
    get_app_data, get_session, get_token_str, get_validation_basic_info,
    models::{SessionInfo, SessionType, TokenClaims},
    token_has_not_expired,
};

pub fn validator(
    db_actor: &DbActor,
    msg: Authenticate,
) -> std::result::Result<TokenClaims, String> {
    dotenv().ok();

    let mut conn = db_actor.pool.get().expect("unable to get connection");

    let basic_info = get_validation_basic_info(db_actor, &msg.token)?;

    let session = get_session(&basic_info.claims, &basic_info.session_type, &mut conn)?;

    if !token_has_not_expired(&session.refresh_time, &basic_info.max_duration) {
        return std::result::Result::Err("Token has expired".to_string());
    }

    session_not_expired_action(&basic_info.claims, &basic_info.session_type, &mut conn)?;

    Ok(basic_info.claims)
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

pub async fn validation(req: &ServiceRequest) -> std::result::Result<TokenClaims, String> {
    let header_value_opt = req.headers().get("AUTHORIZATION");
    let token_str = get_token_str(header_value_opt)?;
    let addr = get_app_data(req)?;
    is_valid(&token_str, &addr).await
}

pub async fn is_valid(
    token_str: &String,
    state: &Data<AppState>,
) -> std::result::Result<TokenClaims, String> {
    let addr = state.addr.clone();

    match addr
        .send(Authenticate {
            token: token_str.clone(),
        })
        .await
    {
        Ok(Ok(token_claims)) => Ok(token_claims),
        Ok(Err(err)) => std::result::Result::Err(format!("{:?>}", err)),
        Err(err) => std::result::Result::Err(format!("{:?>}", err)),
    }
}
