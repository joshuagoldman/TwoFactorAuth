use actix_web::{
    dev::ServiceRequest,
    error::Error,
    HttpMessage,
};
use actix_web_httpauth::{
    extractors::{
        bearer::{self, BearerAuth},
        AuthenticationError,
    },
};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use parse_duration::parse;
use jwt::VerifyWithKey;
use sha2::Sha256;
use crate::auth::models::TokenClaims;

pub fn token_has_not_expired(token_created_time: &std::time::SystemTime, session_duration_str: &String) -> bool {
    let max_duration = parse(session_duration_str)
        .unwrap_or( std::time::Duration::new(3600, 0));

    let elapsed_time = token_created_time.elapsed().unwrap();

    if elapsed_time.as_secs() > max_duration.as_secs() {
        false
    }
    else {
        true
    }
}

pub fn get_jwt_claims<'a>(token_string: &str, jwt_secret: &'a String) ->  Result<TokenClaims, &'a str> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_secret.as_bytes()).unwrap();

    token_string
        .verify_with_key(&key)
        .map_err(|_| "Invalid token")
}

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    dotenv().ok();
    let jwt_secret: String = std::env::var("JWT_SECRET_OTP").expect("JWT_SECRET_OTP must be set!");
    let session_duration_str: String = std::env::var("SESSION_DURATION").expect("SESSION_DURATION must be set!");
    let token_string = credentials.token();

    let claims = get_jwt_claims(token_string, &jwt_secret);

    match claims {
        Ok(value) => {
            if token_has_not_expired(&value.created, &session_duration_str) {
                req.extensions_mut().insert(value);
                Ok(req)
            }
            else {
                let config = req
                    .app_data::<bearer::Config>()
                    .cloned()
                    .unwrap_or_default()
                    .scope("");

                Err((AuthenticationError::from(config).into(), req))
            }
        }
        Err(_) => {
            let config = req
                .app_data::<bearer::Config>()
                .cloned()
                .unwrap_or_default()
                .scope("");

            Err((AuthenticationError::from(config).into(), req))
        }
    }
}



#[actix_web::test]
async fn test_not_expired() {
    let max_duration_str = "1 minutes".to_string();

    let create_time = std::time::SystemTime::now();

    actix::clock::sleep(std::time::Duration::new(1,0)).await;

    assert_eq!(token_has_not_expired(&create_time, &max_duration_str), true)
    
}

#[actix_web::test]
async fn test_expiredd() {
    let max_duration_str = "2 seconds".to_string();

    let create_time = std::time::SystemTime::now();

    actix::clock::sleep(std::time::Duration::new(3,0)).await;

    assert_eq!(token_has_not_expired(&create_time, &max_duration_str), false)
    
}