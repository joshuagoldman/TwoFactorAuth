use std::time::SystemTime;

use actix::{Handler, Message};
use diesel::QueryResult;
use hmac::{digest::KeyInit, Hmac};
use jwt::SignWithKey;
use sha2::Sha256;

use crate::middleware::models::TokenClaimsWithTime;

use super::{models::GetTokenResponse, DbActor};

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
