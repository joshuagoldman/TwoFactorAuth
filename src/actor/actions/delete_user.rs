use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};

use crate::actor::{
    models::{User, UserResponse},
    user::DeleteUser,
    DbActor,
};

use super::is_valid;

pub fn delete_user(
    db_actor: &DbActor,
    msg: DeleteUser,
) -> std::result::Result<UserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user(msg.username.clone(), &mut conn)?;

    is_valid(&user, &msg.password, db_actor)?;

    delete_user_db(&user.username, &mut conn)?;

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

fn delete_user_db(
    username: &String,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<(), String> {
    use diesel::prelude::*;

    let res = diesel::delete(crate::schema::users::dsl::users)
        .filter(crate::schema::users::username.eq(username))
        .get_result::<User>(conn);

    match res {
        Ok(_) => Ok(()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
