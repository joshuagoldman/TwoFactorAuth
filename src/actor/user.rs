use std::time::SystemTime;

use actix::{Handler, Message};
use diesel::QueryResult;
use hmac::{digest::KeyInit, Hmac};
use jwt::SignWithKey;
use sha2::Sha256;

use crate::middleware::models::TokenClaimsWithTime;

use super::{
    actions::{create_user::create_user, login::login},
    models::{CreateUserResponse, GetTestTokenResponse, LoginResponse},
    DbActor,
};

#[derive(Message)]
#[rtype(result = "QueryResult<GetTestTokenResponse>")]
pub struct EmptyReq();

impl Handler<EmptyReq> for DbActor {
    type Result = QueryResult<GetTestTokenResponse>;

    fn handle(&mut self, _msg: EmptyReq, _: &mut Self::Context) -> Self::Result {
        let jwt_secret: Hmac<Sha256> =
            Hmac::new_from_slice(self.config.jwt_secret.as_bytes()).unwrap();
        let uuid_example = uuid::uuid!("550e8400-e29b-41d4-a716-446655440000");
        let claims = TokenClaimsWithTime {
            id: uuid_example,
            created: SystemTime::now(),
        };
        let token_str = claims.sign_with_key(&jwt_secret).unwrap();

        Result::Ok(GetTestTokenResponse { token: token_str })
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

#[derive(Message, Clone)]
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
