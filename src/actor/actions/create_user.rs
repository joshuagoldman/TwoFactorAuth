use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
    PgConnection,
};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use totp_rs::TOTP;
use uuid::Uuid;

use crate::{
    actor::{
        actions::create_totp,
        models::{CreateUserResponse, UserResponse},
        to_hash,
        user::Create,
        DbActor,
    },
    database::models::{NewUser, User},
};

pub fn create_user(
    db_actor: &DbActor,
    msg: Create,
) -> std::result::Result<CreateUserResponse, String> {
    let mut conn = db_actor.pool.get().expect("Unable to get a connection");

    let hash = to_hash(&db_actor.config.hash_secret, &msg.password)?;

    let secret = Uuid::new_v4().to_string();
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

    let totp = create_totp(&secret, &new_user.email)?;
    let qr_code_cntnt = generate_qr_code(&totp)?;
    let qr_code = format!("data:image/png;base64,{}", qr_code_cntnt);

    Ok(CreateUserResponse {
        user: UserResponse {
            username: new_user.username,
            email: new_user.email,
            full_name: new_user.full_name,
        },
        qr_code,
    })
}

fn generate_qr_code(totp: &TOTP) -> std::result::Result<String, String> {
    let res = totp.get_qr_base64();

    match res {
        Ok(ok_res) => Ok(ok_res),
        Err(err) => std::result::Result::Err(format!("{:?>}", err)),
    }
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
        std::result::Result::Err(err) => std::result::Result::Err(format!("{:?>}", err)),
    }
}
