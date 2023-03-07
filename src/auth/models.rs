use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub id: uuid::Uuid
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaimsWithTime {
    pub id: uuid::Uuid,
    pub created: std::time::SystemTime
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionInfo {
    pub id: uuid::Uuid,
    pub logged_in: bool,
    pub refresh_time: std::time::SystemTime
}