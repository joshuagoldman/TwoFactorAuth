use std::time::SystemTime;

use actix::{Handler, Message};
use diesel::QueryResult;
use hmac::{digest::KeyInit, Hmac};
use jwt::SignWithKey;
use sha2::Sha256;

use crate::middleware::models::TokenClaimsWithTime;

use super::{models::GetTestTokenResponse, DbActor};

#[derive(Message)]
#[rtype(result = "QueryResult<GetTestTokenResponse>")]
pub struct EmptyReq();

impl Handler<EmptyReq> for DbActor {
    type Result = QueryResult<GetTestTokenResponse>;

    fn handle(&mut self, msg: EmptyReq, _: &mut Self::Context) -> Self::Result {
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
