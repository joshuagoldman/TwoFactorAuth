use actix::Addr;
use actor::DbActor;

pub mod actor;
pub mod config;
pub mod database;
pub mod handlers;
pub mod middleware;
pub mod schema;

#[derive(Clone)]
pub struct AppState {
    pub addr: Addr<DbActor>,
}
