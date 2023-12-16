use actix::SyncArbiter;
use actix_cors::Cors;
use actix_web::{
    http,
    web::{self, Data},
    App, HttpServer,
};
use actix_web_httpauth::middleware::HttpAuthentication;
use authentication_web_api::{
    auth::{self, cache::AppCache},
    database::{self, connection},
};
use dotenv::dotenv;

fn cors_middle_ware() -> Cors {
    Cors::permissive()
    // Cors::default() // <- Construct CORS middleware builder
    //    .allowed_methods(vec!["GET", "POST", "DELETE", "PUT"])
    //   .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
    //  .allowed_header(http::header::CONTENT_TYPE)
    // .max_age(3600)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let host = std::env::var("HOST").expect("HOST is expected");
    let port = std::env::var("PORT").expect("PORT is expected");
    //let allowed_origin = std::env::var("ALLOWED_ORIGIN").expect("ALLOWED_ORIGIN is expected");
    let session_duration_str: String =
        std::env::var("SESSION_DURATION").expect("SESSION_DURATION must be set!");

    println!("Running on address {}:{}", &host, &port);

    let login_cache: AppCache<uuid::Uuid> =
        crate::auth::cache::Cache::new_app_cache(session_duration_str);

    HttpServer::new(move || {
        let bearer_middleware =
            HttpAuthentication::bearer(authentication_web_api::auth::middle_ware::validator);

        let pool = connection::get_pool(&database_url);
        let config = authentication_web_api::config::Config::from_env().unwrap();
        let db_addr = SyncArbiter::start(5, move || authentication_web_api::actors::DbActor {
            pool: pool.clone(),
            config: config.clone(),
        });

        App::new()
            .wrap(cors_middle_ware())
            .app_data(Data::new(database::models::AppState { addr: db_addr }))
            .app_data(Data::new(login_cache.clone()))
            .service(authentication_web_api::handlers::index)
            .service(authentication_web_api::handlers::user::create_user)
            .service(authentication_web_api::handlers::user::login)
            .service(authentication_web_api::handlers::user::verify_otp)
            .service(authentication_web_api::handlers::user::has_expired)
            .service(
                web::scope("")
                    .wrap(bearer_middleware)
                    .service(authentication_web_api::handlers::user::change_password)
                    .service(authentication_web_api::handlers::user::delete_user)
                    .service(authentication_web_api::handlers::user::get_user),
            )
    })
    .bind(format!("{}:{}", &host, &port))?
    .run()
    .await
}
