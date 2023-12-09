use crate::schema::users;
use actix::Addr;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

pub struct AppState {
    pub addr: Addr<crate::actors::DbActor>,
}

#[derive(Queryable, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
    pub otp_secret_encrypted: Option<String>,
    pub created_at: std::time::SystemTime,
    pub updated_at: std::time::SystemTime,
}

#[derive(Queryable, Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}

#[derive(Queryable, Debug, Serialize, Deserialize)]
pub struct OtpResponse {
    pub user: UserResponse,
    pub qr_code: String,
}

#[derive(Queryable, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub id: &'a uuid::Uuid,
    pub username: &'a String,
    pub email: &'a String,
    pub password_hash: &'a String,
    pub full_name: &'a String,
    pub otp_secret_encrypted: Option<&'a String>,
}
