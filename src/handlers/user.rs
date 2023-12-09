use std::sync::Arc;

use actix_web::{
    delete, get, post,
    web::{Data, Json, Path, ReqData},
    HttpResponse, Responder,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    auth::{self, cache::Cache, models::SessionInfo},
    database::{self},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct NewUserData {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: String,
}

#[post("/create")]
async fn create_user(
    user: Json<NewUserData>,
    state: Data<database::models::AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let user = user.into_inner();

    match addr
        .send(crate::actors::user::Create {
            username: user.username,
            email: user.email,
            password: user.password,
            full_name: user.full_name,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginData {
    pub password: String,
    pub username: String,
}

#[post("/login")]
async fn login(user: Json<LoginData>, state: Data<database::models::AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let user = user.into_inner();

    match addr
        .send(crate::actors::user::Login {
            username: user.username,
            password: user.password,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        Ok(Err(err)) => HttpResponse::InternalServerError().json(err),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[get("/verifyotp/{otp}")]
async fn verify_otp(
    otp: Path<String>,
    credentials: BearerAuth,
    state: Data<database::models::AppState>,
    login_cache_data: Data<Arc<Mutex<Cache<Uuid>>>>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr
        .send(crate::actors::user::VerifyOtp {
            otp: otp.into_inner(),
            token: credentials.token().to_string(),
            login_cache: login_cache_data,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        Ok(Err(err)) => HttpResponse::InternalServerError().json(err),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChangePasswordData {
    pub password: String,
    pub id: uuid::Uuid,
}

#[post("/changepass/{password}")]
async fn change_password(
    password: Path<String>,
    req_user: Option<ReqData<crate::auth::models::TokenClaims>>,
    state: Data<database::models::AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr
        .send(crate::actors::user::ChangePassword {
            id: req_user.unwrap().into_inner().id,
            password: password.into_inner(),
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[delete("/")]
async fn delete_user(
    req_user: Option<ReqData<crate::auth::models::TokenClaims>>,
    state: Data<database::models::AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr
        .send(crate::actors::user::RemoveUser {
            id: req_user.unwrap().into_inner().id,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[get("/user")]
async fn get_user(
    req_user: Option<ReqData<crate::auth::models::TokenClaims>>,
    state: Data<database::models::AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr
        .send(crate::actors::user::GetUser {
            id: req_user.unwrap().into_inner().id,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[get("/expired")]
async fn has_expired(
    credentials: BearerAuth,
    login_cache_data: Data<Arc<Mutex<Cache<Uuid>>>>,
) -> impl Responder {
    let jwt_secret: String = std::env::var("JWT_SECRET_OTP").expect("JWT_SECRET_OTP must be set!");

    let claims = auth::middle_ware::get_jwt_claims(&credentials.token(), &jwt_secret);

    match claims {
        Ok(claims_val) => {
            let mut res = true;

            {
                let local_cache = login_cache_data.lock().await;
                println!("at expired {}", local_cache.life_time_guid);

                if local_cache.check(claims_val.id) {
                    res = false;
                }
            }

            HttpResponse::Ok().json(res)
        }
        _ => HttpResponse::Ok().json(true),
    }
}

#[get("/logout")]
async fn logout(
    credentials: BearerAuth,
    login_cache_data: Data<Arc<Mutex<Cache<Uuid>>>>,
) -> impl Responder {
    let jwt_secret: String = std::env::var("JWT_SECRET_OTP").expect("JWT_SECRET_OTP must be set!");

    let claims = auth::middle_ware::get_jwt_claims(&credentials.token(), &jwt_secret);

    match claims {
        Ok(claims_val) => {
            {
                let mut local_cache = login_cache_data.lock().await;

                let session_info = SessionInfo {
                    id: claims_val.id,
                    logged_in: false,
                    refresh_time: std::time::SystemTime::now(),
                };

                local_cache.set(claims_val.id, session_info).unwrap();
            }

            HttpResponse::Ok().json("logout success")
        }
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}
