use crate::actor::{get_user_db, models::UserResponse, user::GetUser, DbActor};

pub fn get_user(db_actor: &DbActor, msg: GetUser) -> std::result::Result<UserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user_db(msg.username.clone(), &mut conn)?;

    Ok(UserResponse {
        username: user.username,
        email: user.email,
        full_name: user.full_name,
    })
}
