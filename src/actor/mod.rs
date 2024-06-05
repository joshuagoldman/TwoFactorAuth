use actix::{Actor, SyncContext};

use actix_web::ResponseError;
use diesel::{
    r2d2::{ConnectionManager, Pool},
    PgConnection,
};

impl Actor for DbActor {
    type Context = SyncContext<Self>;
}

pub struct DbActor {
    pub pool: Pool<ConnectionManager<PgConnection>>,
    pub config: crate::config::Config,
}
