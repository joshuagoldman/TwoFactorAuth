use crate::actor::{get_user_db, user::VerifyPassword, DbActor};

use super::is_valid;

pub fn verify_password(db_actor: &DbActor, msg: VerifyPassword) -> std::result::Result<(), String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user_db(msg.username.clone(), &mut conn)?;

    is_valid(&user, &msg.password, db_actor)?;

    Ok(())
}
