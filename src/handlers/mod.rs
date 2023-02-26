pub mod user;

use actix_web::{Responder, get};

#[get("/")]
async fn index() -> impl Responder {
    "Welcome to auth web api!"
}