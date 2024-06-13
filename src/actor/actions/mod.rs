use argonautica::Verifier;
use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{database::models::User, middleware::models::SessionInfo, schema};

use super::DbActor;

pub mod create_user;
pub mod delete_user;
pub mod get_user;
pub mod login;
pub mod reset_password;
pub mod token_has_expired;
pub mod verify_otp;
pub mod verify_password;

fn is_valid(
    found_user: &User,
    password_entered: &String,
    db_actor: &DbActor,
) -> std::result::Result<(), String> {
    let mut verifier = Verifier::default();
    let is_valid = verifier
        .with_hash(found_user.password_hash.clone())
        .with_password(password_entered)
        .with_secret_key(db_actor.config.hash_secret.clone())
        .verify();

    match is_valid {
        Ok(true) => std::result::Result::Ok(()),
        Ok(false) => std::result::Result::Err("User validation failed".to_string()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

pub fn generate_secret_raw(secret: &String) -> std::result::Result<Vec<u8>, String> {
    let res = Secret::Raw(secret.as_bytes().to_vec()).to_bytes();

    match res {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(format!("{:?>}", err)),
    }
}

fn create_totp(secret: &String, email: &String) -> std::result::Result<TOTP, String> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        generate_secret_raw(secret)?,
        Some("Auth2fa".to_string()),
        email.to_owned(),
    );

    match totp {
        Ok(ok_totp) => Ok(ok_totp),
        Err(err) => std::result::Result::Err(format!("{:?>}", err)),
    }
}

pub fn insert_or_update_session(
    new_session: &SessionInfo,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<SessionInfo, String> {
    use crate::schema::sessions::dsl::{refresh_time, session_type, sessions, user_id};
    use diesel::prelude::*;

    let session_exists_res = sessions
        .filter(user_id.eq(new_session.user_id))
        .filter(session_type.eq(new_session.session_type.to_string()))
        .get_result::<SessionInfo>(conn);

    if let Ok(_) = session_exists_res {
        diesel::update(schema::sessions::dsl::sessions)
            .filter(user_id.eq(new_session.user_id))
            .filter(session_type.eq(new_session.session_type.to_string()))
            .set(refresh_time.eq(&new_session.refresh_time))
            .get_result::<SessionInfo>(conn)
            .map_err(|err| format!("{:?>}", err))
    } else {
        diesel::insert_into(sessions)
            .values(new_session)
            .get_result::<SessionInfo>(conn)
            .map_err(|err| format!("{:?>}", err))
    }
}
