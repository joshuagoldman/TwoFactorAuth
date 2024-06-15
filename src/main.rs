use actix_cors::Cors;
use actix_web_lab::middleware::from_fn;

use actix::SyncArbiter;
use actix_web::{
    http,
    web::{self, Data},
    App, HttpServer,
};
use dotenv::dotenv;
use two_factor_auth_gen::{
    actor::DbActor, config::Config, database::connect::get_pool, handlers,
    middleware::authentication::authentication_middleware, AppState,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let host = std::env::var("HOST").expect("HOST is expected");
    let port = std::env::var("PORT").expect("PORT is expected");
    let allowe_origin = std::env::var("ALLOWED_ORIGIN").expect("ALLOWED ORIGIN is expected");
    //let allowed_origin = std::env::var("ALLOWED_ORIGIN").expect("ALLOWED_ORIGIN is expected");

    println!("Running on address {}:{}", &host, &port);

    HttpServer::new(move || {
        let pool = get_pool(&database_url);
        let config = Config::from_env().unwrap();
        let db_addr = SyncArbiter::start(5, move || DbActor {
            pool: pool.clone(),
            config: config.clone(),
        });

        let cors = Cors::default()
            .allowed_origin(allowe_origin.as_str())
            .allowed_methods(vec!["GET", "POST", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(Data::new(AppState { addr: db_addr }))
            .service(handlers::index)
            .service(handlers::user::create_user)
            .service(handlers::user::login)
            .service(handlers::user::has_expired)
            .service(
                web::scope("")
                    .wrap(from_fn(authentication_middleware))
                    .service(handlers::user::verify_otp)
                    .service(handlers::user::change_password)
                    .service(handlers::user::delete_user)
                    .service(handlers::user::get_user)
                    .service(handlers::user::verify_password),
            )
    })
    .bind(format!("{}:{}", &host, &port))?
    .run()
    .await
}
