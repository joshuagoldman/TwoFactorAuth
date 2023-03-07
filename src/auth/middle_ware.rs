use actix_web::{
    dev::ServiceRequest,
    error::Error,
    HttpMessage, web::Data,
};
use actix_web_httpauth::{
    extractors::{
        bearer::{self, BearerAuth},
        AuthenticationError,
    },
};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use sha2::Sha256;
use crate::{auth::models::TokenClaims};

use crate::auth::cache::AppCache;

use super::models::{SessionInfo, TokenClaimsWithTime};

pub fn get_jwt_claims<'a>(token_string: &str, jwt_secret: &'a String) ->  Result<TokenClaims, &'a str> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_secret.as_bytes()).unwrap();

    token_string
        .verify_with_key(&key)
        .map_err(|_| "Invalid token")
}

pub fn get_jwt_claims_with_time<'a>(token_string: &str, jwt_secret: &'a String) ->  Result<TokenClaimsWithTime, &'a str> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_secret.as_bytes()).unwrap();

    token_string
        .verify_with_key(&key)
        .map_err(|_| "Invalid token")
}

fn get_error_res(req: ServiceRequest) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let config = req
    .app_data::<bearer::Config>()
    .cloned()
    .unwrap_or_default()
    .scope("");

    Err((AuthenticationError::from(config).into(), req))
}

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    dotenv().ok();
    let jwt_secret: String = std::env::var("JWT_SECRET_OTP").expect("JWT_SECRET_OTP must be set!");
    let token_string = credentials.token();

    let claims = get_jwt_claims(token_string, &jwt_secret);
    let login_cache_data = req.app_data::<Data<AppCache<uuid::Uuid>>>().unwrap();
    let mut res = true;

    match claims {
        Ok(value) => {

            {
                let mut local_cache = login_cache_data.lock().await;

                if local_cache.check(value.id) {
                    let session_info = SessionInfo {
                        id: value.id,
                        logged_in: true,
                        refresh_time: std::time::SystemTime::now()
                    };
    
                    local_cache.set(value.id, session_info).unwrap();

                    req.extensions_mut().insert(value);
                }
                else {
                    res = false;
                }
            }
            if res == true {
                Ok(req)
            }
            else {
                get_error_res(req)
            }
        },
        Err(_) => {
            get_error_res(req)
        }
    }
}