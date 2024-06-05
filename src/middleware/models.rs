use std::time::SystemTime;

use crate::schema::sessions;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaimsWithTime {
    pub id: uuid::Uuid,
    pub created: std::time::SystemTime,
}

#[derive(Clone, Queryable, Insertable, Debug, Serialize, Deserialize)]
#[diesel(table_name = sessions)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub session_type: String,
    pub refresh_time: std::time::SystemTime,
}

impl SessionInfo {
    pub fn new() -> Self {
        Self {
            user_id: Uuid::new_v4(),
            session_type: SessionType::UserPage.to_string(),
            refresh_time: SystemTime::now(),
        }
    }
}

#[derive(Clone)]
pub enum SessionType {
    OTP,
    UserPage,
}

impl SessionType {
    pub fn to_string(self) -> String {
        match self {
            SessionType::OTP => "OTP".to_string(),
            SessionType::UserPage => "UserPage".to_string(),
        }
    }
}
