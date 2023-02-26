use actix_web::{HttpResponse,Responder, post, delete, web::{Data, Json, ReqData, Path}, get};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::{Serialize, Deserialize};

use crate::database;


#[derive(Serialize, Deserialize, Debug)]
pub struct NewUserData {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: String
}

#[post("/create")]
async fn create_user(user: Json<NewUserData>, state: Data<database::models::AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let user = user.into_inner();

    match addr.send(
        crate::actors::user::Create { 
            username: user.username,
            email: user.email,
            password: user.password,
            full_name: user.full_name
        }).await {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong")
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginData {
    pub password: String,
    pub username: String
}

#[post("/login")]
async fn login(user: Json<LoginData>, state: Data<database::models::AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let user = user.into_inner();

    match addr.send(
        crate::actors::user::Login { 
            username: user.username,
            password: user.password
        }).await {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        Ok(Err(err)) => HttpResponse::InternalServerError().json(err),
        _ => HttpResponse::InternalServerError().json("Something went wrong")
    }
}

#[get("/verifyotp/{otp}")]
async fn verify_otp(otp: Path<String>,
                    credentials: BearerAuth,
                    state: Data<database::models::AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr.send(
        crate::actors::user::VerifyOtp { 
            otp: otp.into_inner(),
            token: credentials.token().to_string()
        }).await {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        Ok(Err(err)) => HttpResponse::InternalServerError().json(err),
        _ => HttpResponse::InternalServerError().json("Something went wrong")
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct ChangePasswordData {
    pub password: String,
    pub id: uuid::Uuid
}

#[post("/changepass/{password}")]
async fn change_password(password: Path<String>,
                         req_user: Option<ReqData<crate::auth::models::TokenClaims>>,
                         state: Data<database::models::AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr.send(
        crate::actors::user::ChangePassword { 
            id: req_user.unwrap().into_inner().id,
            password: password.into_inner()
        }).await {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong")
    }
}

#[delete("/")]
async fn delete_user(req_user: Option<ReqData<crate::auth::models::TokenClaims>> ,
                     state: Data<database::models::AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr.send(
        crate::actors::user::RemoveUser { 
            id: req_user.unwrap().into_inner().id
        }).await {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong")
    }
}