use argonautica::Hasher;
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

use crate::actor::{
    models::{CreateUserResponse, NewUser, User},
    user::Create,
    DbActor,
};

pub fn create_user(
    db_actor: &DbActor,
    msg: Create,
) -> std::result::Result<CreateUserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let hash = to_hash(&db_actor.config.hash_secret, &msg.password)?;

    let auth = google_authenticator::GoogleAuthenticator::new();
    let secret = auth.create_secret(16);
    let mc = new_magic_crypt!(&db_actor.config.secret_otp_encrypted, 256);
    let encrypt_otp_secret = mc.encrypt_bytes_to_base64(&secret);

    let new_user = NewUser {
        id: uuid::Uuid::new_v4(),
        username: msg.username.clone(),
        email: msg.email,
        password_hash: hash,
        full_name: Some(msg.full_name),
        otp_secret_encrypted: Some(encrypt_otp_secret),
    };

    insert_new_user(new_user.clone(), &mut conn)?;

    let qr_code = auth.qr_code_url(
        &secret,
        &msg.username,
        "OTP verification code",
        0,
        0,
        google_authenticator::ErrorCorrectionLevel::High,
    );

    Ok(CreateUserResponse {
        user: new_user,
        qr_code,
    })
}

fn insert_new_user(
    new_user: NewUser,
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
) -> Result<User, String> {
    let resp = diesel::insert_into(crate::schema::users::dsl::users)
        .values(new_user)
        .get_result::<User>(conn);

    match resp {
        Ok(user) => Ok(user),
        std::result::Result::Err(err) => std::result::Result::Err(err.to_string()),
    }
}

fn to_hash(secret_key: &String, password: &String) -> std::result::Result<String, String> {
    let mut hasher = Hasher::default();
    let hasher_res = hasher
        .with_password(password)
        .with_secret_key(secret_key)
        .hash();

    match hasher_res {
        Ok(hash_str) => Ok(hash_str),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
