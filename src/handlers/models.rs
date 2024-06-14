use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NewUserData {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginData {
    pub password: String,
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordRequest {
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChangePasswordData {
    pub password: String,
    pub id: uuid::Uuid,
}
