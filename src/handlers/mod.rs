pub mod models;
pub mod user;

use actix::{Handler, Message};
use actix_web::{get, HttpResponse, Responder};

use crate::{
    actor::DbActor,
    middleware::{expiration::validator, models::TokenClaims},
};

#[derive(Debug, serde::Serialize)]
struct StrResponse {
    str_resp: String,
}
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(StrResponse {
        str_resp: "Welcome to auth web api!".to_string(),
    })
}

#[derive(Message, Clone)]
#[rtype(result = "std::result::Result<TokenClaims,String>")]
pub struct Authenticate {
    pub token: String,
}

impl Handler<Authenticate> for DbActor {
    type Result = std::result::Result<TokenClaims, String>;

    fn handle(&mut self, msg: Authenticate, _: &mut Self::Context) -> Self::Result {
        validator(&self, msg)
    }
}
