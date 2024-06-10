use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};

use crate::actor::{models::User, user::VerifyPassword, DbActor};

use super::is_valid;

pub fn verify_password(db_actor: &DbActor, msg: VerifyPassword) -> std::result::Result<(), String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user(msg.username.clone(), &mut conn)?;

    is_valid(&user, &msg.password, db_actor)?;

    Ok(())
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
