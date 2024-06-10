use serde::{Deserialize, Serialize};

use crate::database::models::NewUser;

#[derive(Clone, Serialize)]
pub struct GetTokenResponse {
    pub token: String,
}

#[derive(Clone, Serialize)]
pub struct TokenRequest {
    pub token: String,
}

#[derive(Clone, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

#[derive(Clone, Serialize)]
pub struct CreateUserResponse {
    pub user: NewUser,
    pub qr_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}
