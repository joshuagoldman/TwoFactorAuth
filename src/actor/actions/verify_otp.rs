use std::time::SystemTime;

use diesel::{
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};
use hmac::{
    digest::{InvalidLength, KeyInit},
    Hmac,
};
use jwt::SignWithKey;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use sha2::Sha256;

use crate::{
    actor::{get_claims, get_user_by_id, models::LoginResponse, user::VerifyOtp, DbActor},
    database::models::User,
    middleware::models::{SessionInfo, SessionType, TokenClaims},
};

pub fn verify_otp(
    db_actor: &DbActor,
    msg: VerifyOtp,
) -> std::result::Result<LoginResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let claims = get_claims(db_actor, &msg.token, SessionType::OTP)?;
    let user = get_user_by_id(&claims.id, &mut conn)?;

    let decrypt_secret = get_decrypt_secret(db_actor, &user)?;

    let code = get_code(&decrypt_secret)?;

    otps_are_equal(&code, &msg.otp)?;

    let jwt_secret = get_jwt_secret(db_actor)?;

    let token_str = get_token_str(jwt_secret, user.id)?;

    let session_info = SessionInfo {
        user_id: user.id,
        session_type: SessionType::UserPage.to_string(),
        refresh_time: std::time::SystemTime::now(),
    };

    insert_or_update_session(&session_info, &mut conn)?;

    Ok(LoginResponse {
        token: token_str,
        username: user.username,
    })
}

fn get_decrypt_secret(
    db_actor: &DbActor,
    found_user: &User,
) -> std::result::Result<String, String> {
    let mc = new_magic_crypt!(&db_actor.config.secret_otp_encrypted, 256);
    let decrypt_secret_res =
        mc.decrypt_base64_to_string(found_user.otp_secret_encrypted.clone().unwrap());

    match decrypt_secret_res {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

fn get_code(decrypt_secret: &String) -> std::result::Result<String, String> {
    let auth = google_authenticator::GoogleAuthenticator::new();
    let code_res = auth.get_code(decrypt_secret.as_str(), 0);

    match code_res {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

fn otps_are_equal(otp_google: &String, otp_entered: &String) -> std::result::Result<(), String> {
    match otp_google == otp_entered {
        true => Ok(()),
        false => std::result::Result::Err("OTP validation failed".to_string()),
    }
}

fn get_jwt_secret(db_actor: &DbActor) -> std::result::Result<Hmac<Sha256>, String> {
    let jwt_secret_res: Result<Hmac<Sha256>, InvalidLength> =
        Hmac::new_from_slice(db_actor.config.jwt_secret.as_bytes());

    match jwt_secret_res {
        Ok(jwt_secret) => Ok(jwt_secret),
        Err(err) => return std::result::Result::Err(err.to_string()),
    }
}

fn get_token_str(
    jwt_secret: Hmac<Sha256>,
    user_id: uuid::Uuid,
) -> std::result::Result<String, String> {
    let claims = TokenClaims { id: user_id };
    let token_str_res = claims.sign_with_key(&jwt_secret);

    match token_str_res {
        Ok(token_str) => Ok(token_str),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}

fn insert_or_update_session(
    new_session: &SessionInfo,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<(), String> {
    use crate::schema::sessions::dsl::{refresh_time, session_type, sessions, user_id};
    use diesel::prelude::*;
    let res = diesel::insert_into(sessions)
        .values(new_session)
        .on_conflict((user_id, session_type))
        .do_update()
        .set((
            refresh_time.eq(SystemTime::now()),
            session_type.eq(SessionType::UserPage.to_string()),
        ))
        .execute(conn);

    match res {
        Ok(_) => Ok(()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
