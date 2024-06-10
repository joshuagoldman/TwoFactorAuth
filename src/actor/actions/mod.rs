use argonautica::Verifier;

use crate::database::models::User;

use super::DbActor;

pub mod create_user;
pub mod delete_user;
pub mod get_user;
pub mod login;
pub mod reset_password;
pub mod token_has_expired;
pub mod verify_otp;
pub mod verify_password;

fn is_valid(
    found_user: &User,
    password_entered: &String,
    db_actor: &DbActor,
) -> std::result::Result<(), String> {
    let mut verifier = Verifier::default();
    let is_valid = verifier
        .with_hash(found_user.password_hash.clone())
        .with_password(password_entered)
        .with_secret_key(db_actor.config.hash_secret.clone())
        .verify();

    match is_valid {
        Ok(true) => std::result::Result::Ok(()),
        Ok(false) => std::result::Result::Err("User validation failed".to_string()),
        Err(err) => std::result::Result::Err(err.to_string()),
    }
}
