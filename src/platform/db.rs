use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::{Connection, PgPool};

use crate::config::DatabaseConfig;

pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<PgPool> {
    let options: PgConnectOptions = config
        .database_url
        .parse()
        .context("DATABASE_URL is not a valid PostgreSQL connection URL")?;

    let options = options.application_name("ultrivly");

    
    
    
    PgConnection::connect_with(&options)
        .await
        .context("could not connect to PostgreSQL")?
        .close()
        .await?;

    PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_secs))
        .connect_with(options)
        .await
        .context("could not connect to PostgreSQL")
}
