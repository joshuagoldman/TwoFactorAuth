use std::time::SystemTime;

use argonautica::Verifier;
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};
use hmac::{
    digest::{InvalidLength, KeyInit},
    Hmac,
};
use jwt::SignWithKey;
use sha2::Sha256;

use crate::{
    actor::{diesel_err_to_string, models::LoginResponse, user::Login, DbActor},
    database::models::User,
    middleware::models::{SessionInfo, SessionType, TokenClaimsWithTime},
};

pub fn login(db_actor: &DbActor, msg: Login) -> std::result::Result<LoginResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let found_user = get_user(msg.clone(), &mut conn)?;

    is_valid(&found_user, msg, db_actor)?;

    let claims = TokenClaimsWithTime {
        id: found_user.id,
        created: SystemTime::now(),
    };

    let jwt_secret = get_jwt_secret(db_actor)?;
    let token_str = get_token_str(&claims, jwt_secret)?;

    insert_new_otp_session(&claims, found_user, token_str, &mut conn)
}

fn get_user(
    msg: Login,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<User, String> {
    use crate::schema::users::dsl::{username, users};
    use diesel::prelude::*;
    let found_user = users
        .filter(username.eq(msg.username))
        .get_result::<User>(conn);

    match found_user {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(diesel_err_to_string(err)),
    }
}

fn is_valid(found_user: &User, msg: Login, db_actor: &DbActor) -> std::result::Result<(), String> {
    let mut verifier = Verifier::default();
    let is_valid = verifier
        .with_hash(found_user.password_hash.clone())
        .with_password(msg.password)
        .with_secret_key(db_actor.config.hash_secret.clone())
        .verify();

    match is_valid {
        Ok(true) => std::result::Result::Ok(()),
        Ok(false) => std::result::Result::Err("User validation failed".to_string()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

fn get_jwt_secret(db_actor: &DbActor) -> std::result::Result<Hmac<Sha256>, String> {
    let jwt_secret_res: Result<Hmac<Sha256>, InvalidLength> =
        Hmac::new_from_slice(db_actor.config.jwt_secret_otp.as_bytes());

    match jwt_secret_res {
        Ok(jwt_secret) => Ok(jwt_secret),
        Err(err) => return std::result::Result::Err(err.to_string()),
    }
}

fn get_token_str(claims: &TokenClaimsWithTime, jwt_secret: Hmac<Sha256>) -> Result<String, String> {
    let token_str_resp = claims.sign_with_key(&jwt_secret);

    match token_str_resp {
        Ok(token_str) => Ok(token_str),
        Err(err) => Result::Err(err.to_string()),
    }
}

fn insert_new_otp_session(
    claims: &TokenClaimsWithTime,
    found_user: User,
    token_str: String,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<LoginResponse, String> {
    let insert_resp = diesel::insert_into(crate::schema::sessions::dsl::sessions)
        .values(SessionInfo {
            session_type: SessionType::OTP.to_string(),
            refresh_time: claims.created.clone(),
            user_id: found_user.id.clone(),
        })
        .get_result::<SessionInfo>(conn);

    match insert_resp {
        Ok(_) => Ok(LoginResponse {
            token: token_str,
            username: found_user.username,
        }),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
