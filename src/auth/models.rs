use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub id: uuid::Uuid,
    pub created: std::time::SystemTime
}