pub mod models;
pub mod user;

use actix_web::{get, HttpResponse, Responder};

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
