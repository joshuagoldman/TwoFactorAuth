use serde::{Deserialize, Serialize};

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
    pub user: UserResponse,
    pub qr_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionForDisplay {
    pub session_type: String,
    pub refresh_time: std::time::SystemTime,
}
