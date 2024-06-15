use crate::actor::{get_user_by_id, models::UserResponse, user::VerifyPassword, DbActor};

use super::is_valid;

pub fn verify_password(
    db_actor: &DbActor,
    msg: VerifyPassword,
) -> std::result::Result<UserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user_by_id(&msg.id, &mut conn)?;

    is_valid(&user, &msg.password, db_actor)?;

    Ok(UserResponse {
        username: user.username,
        email: user.email,
        full_name: user.full_name,
    })
}
