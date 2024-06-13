use std::time::SystemTime;

use actix_web::{dev::ServiceRequest, web::Data};
use dotenv::*;

use crate::{
    actor::{actions::insert_or_update_session, DbActor},
    handlers::Authenticate,
    AppState,
};

use super::{
    get_app_data, get_session, get_token_str, get_validation_basic_info,
    models::{SessionInfo, TokenClaims},
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

    let new_session = SessionInfo {
        id: session.id,
        session_type: session.session_type.clone().to_string(),
        refresh_time: SystemTime::now(),
        user_id: session.user_id,
    };
    insert_or_update_session(&new_session, &mut conn)?;

    Ok(basic_info.claims)
}

pub async fn validation(req: &ServiceRequest) -> std::result::Result<TokenClaims, String> {
    let header_value_opt = req.headers().get("AUTHORIZATION");
    let token_str = get_token_str(header_value_opt)?.replace("Bearer ", "");
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
