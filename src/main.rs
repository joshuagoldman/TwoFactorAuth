use actix_web_httpauth::middleware::HttpAuthentication;
use dotenv::dotenv;

use actix::{SyncArbiter};
use actix_web::{App, HttpServer, web::{self, Data}};
use authentication_web_api::database::{connection, self};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let host = std::env::var("HOST").expect("HOST is expected") ;
    let port = std::env::var("PORT").expect("PORT is expected") ;

    println!("Running on address {}:{}", &host, &port);

    HttpServer::new(move || {
        let bearer_middleware = 
            HttpAuthentication::bearer(authentication_web_api::auth::middle_ware::validator); 
        
        let pool = connection::get_pool(&database_url); 
        let config = authentication_web_api::config::Config::from_env().unwrap();
        let db_addr = SyncArbiter::start(5, move || 
            authentication_web_api::actors::DbActor {
                pool: pool.clone(),
                config: config.clone()
            });
            
        App::new()
            .app_data(Data::new(database::models::AppState { addr: db_addr}))
            .service(authentication_web_api::handlers::index)
            .service(authentication_web_api::handlers::user::create_user)
            .service(authentication_web_api::handlers::user::login)
            .service(authentication_web_api::handlers::user::verify_otp)
            .service(
                web::scope("")
                    .wrap(bearer_middleware)
                    .service(authentication_web_api::handlers::user::change_password)
                    .service(authentication_web_api::handlers::user::delete_user)
            )
    })
    .bind(format!("{}:{}", &host, &port))?
    .run()
    .await
}
