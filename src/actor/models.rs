use std::time::SystemTime;

use diesel::{deserialize::Queryable, prelude::Insertable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::users;

pub struct GetTestTokenResponse {
    pub token: String,
}

#[derive(Clone, Queryable, Insertable, Debug, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
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
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
        }
    }
}
pub struct LoginResponse {
    pub token: String,
}