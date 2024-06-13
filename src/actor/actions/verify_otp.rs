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
use totp_rs::TOTP;
use uuid::Uuid;

use crate::{
    actor::{get_user_by_id, models::LoginResponse, user::VerifyOtp, DbActor},
    database::models::User,
    middleware::models::{SessionInfo, SessionType, TokenClaims},
    schema,
};

use super::create_totp;

pub fn verify_otp(
    db_actor: &DbActor,
    msg: VerifyOtp,
) -> std::result::Result<LoginResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let user = get_user_by_id(&msg.id, &mut conn)?;

    let decrypt_secret = get_decrypt_secret(db_actor, &user)?;

    let totp = create_totp(&decrypt_secret, &user.email)?;
    let code = get_code(&totp)?;
    println!("koden e: {}", code);

    otps_are_equal(&code, &msg.otp)?;

    let jwt_secret = get_jwt_secret(db_actor)?;

    let token_str = get_token_str(jwt_secret, user.id)?;

    let session_info = SessionInfo {
        id: Uuid::new_v4(),
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

fn get_code(totp: &TOTP) -> std::result::Result<String, String> {
    let res = totp.generate_current();

    match res {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(format!("{:?>}", err)),
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
