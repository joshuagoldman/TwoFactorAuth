use actix::{Handler, Message};
use diesel::prelude::*;
use crate::{actors::*, database::{models::{User, NewUser, UserResponse, LoginResponse, OtpResponse}}, schema, auth};
use argonautica::{Hasher, Verifier};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

use crate::schema::users::dsl::{users, username};

fn get_user_resp(resp: QueryResult<User>) -> QueryResult<UserResponse> {
    match resp {
        Ok(ok_resp) => {
            Ok(
                UserResponse {
                    username: ok_resp.username,
                    email: ok_resp.email,
                    full_name: ok_resp.full_name
                }
            )
        },
        Err(err) => Err(err)
    }
}

fn get_otp_resp(resp: QueryResult<UserResponse>, qr_code: String) -> QueryResult<OtpResponse> {
    match resp {
        Ok(ok_resp) => {
            Ok(
                OtpResponse {
                    user: UserResponse {
                        username: ok_resp.username,
                        email: ok_resp.email,
                        full_name: ok_resp.full_name
                    },
                    qr_code
                }
            )
        },
        Err(err) => Err(err)
    }
}

#[derive(Message)]
#[rtype(result="QueryResult<OtpResponse>")]
pub struct Create {
    pub password: String,
    pub username: String,
    pub email: String,
    pub full_name: String
}

impl Handler<Create> for DbActor {
    type Result = QueryResult<OtpResponse>;

    
    fn handle(&mut self, msg: Create, _: &mut Self::Context) -> Self::Result {
        let mut conn = self.pool.get().expect("Unable to get a connection");

        let hash = to_hash(&self.config.hash_secret, &msg.password);

        let auth = google_authenticator::GoogleAuthenticator::new();
        let secret = auth.create_secret(16);
        let mc = new_magic_crypt!(&self.config.secret_otp_encrypted, 256);
        let encrypt_otp_secret = 
                    mc.encrypt_bytes_to_base64(&secret);

        let new_article = NewUser {
            id: &uuid::Uuid::new_v4(),
            username: &msg.username,
            email: &msg.email,
            password_hash: &hash,
            full_name: &msg.full_name,
            otp_secret_encrypted: Some(&encrypt_otp_secret)
        };

        let resp = 
            diesel::insert_into(schema::users::dsl::users)
                .values(new_article)
                .get_result::<User>(&mut conn);

        let qr_code = auth
            .qr_code_url(&secret, 
                         &msg.username, 
                         "OTP verification code", 
                         0,
                         0, 
                         google_authenticator::ErrorCorrectionLevel::High);

        let usr_resp = get_user_resp(resp);
        get_otp_resp(usr_resp, qr_code)
    }
}

#[derive(Message)]
#[rtype(result="Result<LoginResponse, String>")]
pub struct Login {
    pub password: String,
    pub username: String
}

impl Handler<Login> for DbActor {
    type Result = Result<LoginResponse, String>;

    
    fn handle(&mut self, msg: Login, _: &mut Self::Context) -> Self::Result {
        let mut conn = self.pool.get().expect("Unable to get a connection");

        let foun_user_res =
            users.filter(username.eq(msg.username))
                    .get_result::<User>(&mut conn);
        
        match foun_user_res {
            Ok(found_user) => {
                let mut verifier = Verifier::default();
                let is_valid = verifier
                    .with_hash(found_user.password_hash)
                    .with_password(msg.password)
                    .with_secret_key(&self.config.hash_secret)
                    .verify()
                    .unwrap();

                if is_valid {
                    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(self.config.jwt_secret_basic.as_bytes(),).unwrap();
                    let claims = auth::models::TokenClaims { id: found_user.id, created: std::time::SystemTime::now()};
                    let token_str = claims.sign_with_key(&jwt_secret).unwrap();

                    Ok(
                        LoginResponse {
                            token: token_str,
                            username: found_user.username
                        }
                    )
                } else {
                    Err("Validation of user credentials failed!".to_string())
                }
            },
            Err(err) => Err(err.to_string())
        }
    }
}

#[derive(Message)]
#[rtype(result="Result<LoginResponse, String>")]
pub struct VerifyOtp {
    pub otp: String,
    pub token: String
}

impl Handler<VerifyOtp> for DbActor {
    type Result = Result<LoginResponse, String>;

    
    fn handle(&mut self, msg: VerifyOtp, _: &mut Self::Context) -> Self::Result {
        let mut conn = self.pool.get().expect("Unable to get a connection");

        let claims = auth::middle_ware::get_jwt_claims(&msg.token, &self.config.jwt_secret_basic).unwrap();

        if !auth::middle_ware::token_has_not_expired(&claims.created, &self.config.otp_duration) {
            return Err("Token for validating otp has expired!".to_string());
        }

        let found_user_res =
            users.filter(crate::schema::users::dsl::id.eq(claims.id))
                    .get_result::<User>(&mut conn);
        
        match found_user_res {
            Ok(found_user) => {
                let mc = new_magic_crypt!(&self.config.secret_otp_encrypted, 256);
                let decrypt_secret = 
                    mc.decrypt_base64_to_string(found_user.otp_secret_encrypted.unwrap()).unwrap();
        
                let auth = google_authenticator::GoogleAuthenticator::new();
                let code = auth.get_code(decrypt_secret.as_str(),0).unwrap();

                if code == msg.otp {
                    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(self.config.jwt_secret_otp.as_bytes(),).unwrap();
                    let claims = auth::models::TokenClaims { id: found_user.id, created: std::time::SystemTime::now()};
                    let token_str = claims.sign_with_key(&jwt_secret).unwrap();

                    Ok(
                        LoginResponse {
                            token: token_str,
                            username: found_user.username
                        }
                    )
                } else {
                    Err("Validation of otp failed!".to_string())
                }
            },
            Err(err) => Err(err.to_string())
        }
    }
}

#[derive(Message)]
#[rtype(result="QueryResult<UserResponse>")]
pub struct ChangePassword {
    pub password: String,
    pub id: uuid::Uuid
}

impl Handler<ChangePassword> for DbActor {
    type Result = QueryResult<UserResponse>;

    
    fn handle(&mut self, msg: ChangePassword, _: &mut Self::Context) -> Self::Result {
        let mut conn = self.pool.get().expect("Unable to get a connection");

        let password_hash = to_hash(&self.config.hash_secret, &msg.password);

        let res =
            diesel::update(schema::users::dsl::users)
                .filter(schema::users::dsl::id.eq(msg.id))
                .set(schema::users::dsl::password_hash.eq(password_hash))
                .get_result::<User>(&mut conn);

        get_user_resp(res)
    }
}

fn to_hash(secret_key: &String, password: &String) -> String {
    let mut hasher = Hasher::default();
    hasher
        .with_password(password)
        .with_secret_key(secret_key)
        .hash()
        .unwrap()
}


#[derive(Message)]
#[rtype(result="QueryResult<UserResponse>")]
pub struct RemoveUser {
    pub id: uuid::Uuid
}

impl Handler<RemoveUser> for DbActor {
    type Result = QueryResult<UserResponse>;

    
    fn handle(&mut self, msg: RemoveUser, _: &mut Self::Context) -> Self::Result {
        let mut conn = self.pool.get().expect("Unable to get a connection");

        let res =
            diesel::delete(schema::users::dsl::users)
                .filter(schema::users::dsl::id.eq(msg.id))
                .get_result::<User>(&mut conn);

        get_user_resp(res)
    }
}
