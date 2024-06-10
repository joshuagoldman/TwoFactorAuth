use std::time::SystemTime;

use diesel::{deserialize::Queryable, pg::Pg, prelude::Insertable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::users;

pub struct GetTestTokenResponse {
    pub token: String,
}

#[derive(Clone, Queryable, Selectable, Insertable, Debug, Serialize, Deserialize)]
#[diesel(table_name = users, check_for_backend(Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
    pub otp_secret_encrypted: Option<String>,
    pub created_at: std::time::SystemTime,
    pub updated_at: std::time::SystemTime,
}

impl User {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            username: String::new(),
            email: String::new(),
            password_hash: String::new(),
            full_name: None,
            otp_secret_encrypted: None,
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
        }
    }
}
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

pub struct CreateUserResponse {
    pub user: NewUser,
    pub qr_code: String,
}

#[derive(Clone, Queryable, Selectable, Insertable, Debug, Serialize, Deserialize)]
#[diesel(table_name = users, check_for_backend(Pg))]
pub struct NewUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
    pub otp_secret_encrypted: Option<String>,
}

#[derive(Queryable, Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}
