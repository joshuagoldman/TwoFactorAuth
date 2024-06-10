use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};

use crate::{
    actor::{
        get_claims, get_user_by_id, models::UserResponse, to_hash, user::ResetPassword, DbActor,
    },
    database::models::User,
    middleware::models::SessionType,
};

pub fn reset_password(
    db_actor: &DbActor,
    msg: ResetPassword,
) -> std::result::Result<UserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let claims = get_claims(db_actor, &msg.token, SessionType::UserPage)?;
    let user = get_user_by_id(&claims.id, &mut conn)?;

    let password_hash = to_hash(&db_actor.config.hash_secret, &msg.password)?;

    change_password(&user.username, &password_hash, &mut conn)?;

    Ok(UserResponse {
        username: user.username,
        email: user.email,
        full_name: user.full_name,
    })
}

fn change_password(
    username: &String,
    password_hash: &String,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<(), String> {
    use diesel::prelude::*;

    let res = diesel::update(crate::schema::users::dsl::users)
        .filter(crate::schema::users::username.eq(username))
        .set(crate::schema::users::password_hash.eq(password_hash))
        .get_result::<User>(conn);

    match res {
        Ok(_) => Ok(()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
