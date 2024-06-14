use std::time::SystemTime;

use actix::{Handler, Message};
use diesel::QueryResult;
use hmac::{digest::KeyInit, Hmac};
use jwt::SignWithKey;
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;

use crate::middleware::models::TokenClaimsWithTime;

use super::{
    actions::{
        create_user::create_user, delete_user::delete_user, get_user::get_user, login::login,
        reset_password::reset_password, token_has_expired::token_has_expired,
        verify_otp::verify_otp, verify_password::verify_password,
    },
    models::{CreateUserResponse, GetTokenResponse, LoginResponse, UserResponse},
    DbActor,
};

#[derive(Message)]
#[rtype(result = "QueryResult<GetTokenResponse>")]
pub struct EmptyReq();

impl Handler<EmptyReq> for DbActor {
    type Result = QueryResult<GetTokenResponse>;

    fn handle(&mut self, _msg: EmptyReq, _: &mut Self::Context) -> Self::Result {
        let jwt_secret: Hmac<Sha256> =
            Hmac::new_from_slice(self.config.jwt_secret.as_bytes()).unwrap();
        let uuid_example = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let claims = TokenClaimsWithTime {
            id: uuid_example,
            created: SystemTime::now(),
        };
        let token_str = claims.sign_with_key(&jwt_secret).unwrap();

        Result::Ok(GetTokenResponse { token: token_str })
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<LoginResponse,String>")]
pub struct Login {
    pub password: String,
    pub username: String,
}

impl Handler<Login> for DbActor {
    type Result = std::result::Result<LoginResponse, String>;

    fn handle(&mut self, msg: Login, _: &mut Self::Context) -> Self::Result {
        login(self, msg)
    }
}

#[derive(Message, Clone, Serialize)]
#[rtype(result = "std::result::Result<CreateUserResponse,String>")]
pub struct Create {
    pub password: String,
    pub username: String,
    pub email: String,
    pub full_name: String,
}

impl Handler<Create> for DbActor {
    type Result = std::result::Result<CreateUserResponse, String>;

    fn handle(&mut self, msg: Create, _: &mut Self::Context) -> Self::Result {
        create_user(&self, msg)
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<LoginResponse,String>")]
pub struct VerifyOtp {
    pub otp: String,
    pub id: Uuid,
}

impl Handler<VerifyOtp> for DbActor {
    type Result = std::result::Result<LoginResponse, String>;

    fn handle(&mut self, msg: VerifyOtp, _: &mut Self::Context) -> Self::Result {
        verify_otp(&self, msg)
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<UserResponse,String>")]
pub struct ResetPassword {
    pub password: String,
    pub id: Uuid,
}

impl Handler<ResetPassword> for DbActor {
    type Result = std::result::Result<UserResponse, String>;

    fn handle(&mut self, msg: ResetPassword, _: &mut Self::Context) -> Self::Result {
        reset_password(&self, msg)
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<UserResponse,String>")]
pub struct DeleteUser {
    pub id: Uuid,
}

impl Handler<DeleteUser> for DbActor {
    type Result = std::result::Result<UserResponse, String>;

    fn handle(&mut self, msg: DeleteUser, _: &mut Self::Context) -> Self::Result {
        delete_user(&self, msg)
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<(),String>")]
pub struct VerifyPassword {
    pub password: String,
    pub id: Uuid,
}

impl Handler<VerifyPassword> for DbActor {
    type Result = std::result::Result<(), String>;

    fn handle(&mut self, msg: VerifyPassword, _: &mut Self::Context) -> Self::Result {
        verify_password(&self, msg)
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<bool,String>")]
pub struct TokenHasExpired {
    pub token: String,
}

impl Handler<TokenHasExpired> for DbActor {
    type Result = std::result::Result<bool, String>;

    fn handle(&mut self, msg: TokenHasExpired, _: &mut Self::Context) -> Self::Result {
        token_has_expired(&self, msg)
    }
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<UserResponse,String>")]
pub struct GetUser {
    pub username: String,
}

impl Handler<GetUser> for DbActor {
    type Result = std::result::Result<UserResponse, String>;

    fn handle(&mut self, msg: GetUser, _: &mut Self::Context) -> Self::Result {
        get_user(&self, msg)
    }
}
