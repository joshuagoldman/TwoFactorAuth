use crate::actor::{
    get_auth_failed_resp, get_db_fail_res,
    models::{LoginResponse, User},
    user::Login,
    DbActor,
};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};

pub fn login(db_actor: &DbActor, msg: Login) -> QueryResult<LoginResponse> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let mut err = diesel::result::Error::NotFound;
    let mut user: User = User::new();

    if !get_user(&mut conn, msg, &mut user, &mut err) {
        return QueryResult::Err(err);
    }

    Ok(LoginResponse {
        token: "sss".to_string(),
    })
}

fn get_user(
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    msg: Login,
    user: &mut User,
    err: &mut diesel::result::Error,
) -> bool {
    let found_user_res = crate::schema::users::dsl::users
        .filter(crate::schema::users::username.eq(msg.username))
        .get_result::<User>(conn);

    match found_user_res {
        std::result::Result::Ok(found_user) => {
            *user = found_user;
            true
        }
        std::result::Result::Err(err) => {
            err = err;
            false
        }
    }
}
