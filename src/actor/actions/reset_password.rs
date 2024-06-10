use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};

use crate::actor::{
    models::{User, UserResponse},
    to_hash,
    user::ResetPassword,
    DbActor,
};

use super::is_valid;

pub fn reset_password(
    db_actor: &DbActor,
    msg: ResetPassword,
) -> std::result::Result<UserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user(msg.username.clone(), &mut conn)?;

    is_valid(&user, &msg.password, db_actor)?;

    let password_hash = to_hash(&db_actor.config.hash_secret, &msg.password)?;

    change_password(&user.username, &password_hash, &mut conn)?;

    Ok(UserResponse {
        username: user.username,
        email: user.email,
        full_name: user.full_name,
    })
}

fn get_user(
    username_fr_client: String,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<User, String> {
    use crate::schema::users::dsl::{username, users};
    use diesel::prelude::*;
    let found_user = users
        .filter(username.eq(username_fr_client))
        .get_result::<User>(conn);

    match found_user {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
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
