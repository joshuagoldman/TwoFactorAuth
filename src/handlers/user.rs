use actix_web::{
    delete, get, post,
    web::{self, Data, Json, Path},
    HttpResponse, Responder,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;

use crate::{
    actor::user::{Create, DeleteUser, GetUser, Login, ResetPassword, TokenHasExpired, VerifyOtp},
    handlers::models::{LoginData, NewUserData},
    middleware::models::TokenClaims,
    AppState,
};

#[post("/create")]
async fn create_user(user: Json<NewUserData>, state: Data<AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let user = user.into_inner();

    match addr
        .send(Create {
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

#[post("/login")]
async fn login(user: Json<LoginData>, state: Data<AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let user = user.into_inner();

    match addr
        .send(Login {
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
    claims_opt: Option<web::ReqData<TokenClaims>>,
    state: Data<AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    if claims_opt.is_none() {
        return HttpResponse::NonAuthoritativeInformation().json("Something went wrong");
    }

    match addr
        .send(VerifyOtp {
            otp: otp.into_inner(),
            id: claims_opt.unwrap().id,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        Ok(Err(err)) => HttpResponse::InternalServerError().json(err),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[post("/changepass/{password}")]
async fn change_password(
    password: Path<String>,
    claims_opt: Option<web::ReqData<TokenClaims>>,
    state: Data<AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let password = password.into_inner();

    if claims_opt.is_none() {
        return HttpResponse::NonAuthoritativeInformation().json("Something went wrong");
    }

    match addr
        .send(ResetPassword {
            password,
            id: claims_opt.unwrap().id,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[delete("/")]
async fn delete_user(
    claims_opt: Option<web::ReqData<TokenClaims>>,
    state: Data<AppState>,
) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    if claims_opt.is_none() {
        return HttpResponse::NonAuthoritativeInformation().json("Something went wrong");
    }
    match addr
        .send(DeleteUser {
            id: claims_opt.unwrap().id,
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[get("/user/{username}")]
async fn get_user(username: Path<String>, state: Data<AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();
    let username = username.into_inner();

    match addr.send(GetUser { username }).await {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}

#[get("/expired")]
async fn has_expired(credentials: BearerAuth, state: Data<AppState>) -> impl Responder {
    let addr = state.as_ref().addr.clone();

    match addr
        .send(TokenHasExpired {
            token: credentials.token().to_string(),
        })
        .await
    {
        Ok(Ok(user)) => HttpResponse::Ok().json(user),
        _ => HttpResponse::InternalServerError().json("Something went wrong"),
    }
}
