use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};

use crate::{
    actor::{get_user_by_id, models::UserResponse, user::DeleteUser, DbActor},
    database::models::User,
    middleware::models::SessionInfo,
};

pub fn delete_user(
    db_actor: &DbActor,
    msg: DeleteUser,
) -> std::result::Result<UserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user_by_id(&msg.id, &mut conn)?;

    delete_user_db(&user.username, &mut conn)?;
    delete_user_session_db(&user.id, &mut conn)?;

    Ok(UserResponse {
        username: user.username,
        email: user.email,
        full_name: user.full_name,
    })
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

fn delete_user_session_db(
    user_id: &uuid::Uuid,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<(), String> {
    use diesel::prelude::*;

    let res = diesel::delete(crate::schema::sessions::dsl::sessions)
        .filter(crate::schema::sessions::user_id.eq(user_id))
        .get_result::<SessionInfo>(conn);

    match res {
        Ok(_) => Ok(()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
