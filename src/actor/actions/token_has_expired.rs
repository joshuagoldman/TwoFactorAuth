use crate::{
    actor::{user::TokenHasExpired, DbActor},
    middleware::{get_session, get_validation_basic_info, token_has_not_expired},
};

pub fn token_has_expired(
    db_actor: &DbActor,
    msg: TokenHasExpired,
) -> std::result::Result<bool, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let basic_info = get_validation_basic_info(db_actor, &msg.token)?;

    let session = get_session(&basic_info.claims, &basic_info.session_type, &mut conn)?;

    if !token_has_not_expired(&session.refresh_time, &basic_info.max_duration) {
        return Ok(true);
    }

    Ok(false)
}
