



use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, bail};
use sqlx::PgPool;
use sqlx::migrate::Migrator;

static MIGRATOR: Migrator = sqlx::migrate!();


const MIGRATIONS_TABLE: &str = "_sqlx_migrations";


const MIN_SERVER_VERSION_NUM: i32 = 150_000;



pub async fn run(pool: &PgPool) -> anyhow::Result<()> {
    check_server_version(pool).await?;

    let before = status(pool).await?;
    if let Some(m) = before
        .entries
        .iter()
        .find(|m| m.state == State::ChecksumMismatch)
    {
        bail!(
            "migration {} ({}) was changed after it was applied; add a new migration instead",
            m.version,
            m.description
        );
    }
    if let Some(m) = before.entries.iter().find(|m| m.state == State::Failed) {
        bail!(
            "migration {} ({}) failed partway through an earlier run; repair the schema by hand \
             and delete its row from {MIGRATIONS_TABLE} before retrying",
            m.version,
            m.description
        );
    }
    if !before.unknown_applied.is_empty() {
        bail!(
            "the database has migrations this build does not know about ({}); \
             it was migrated by a newer version of Ultrivly",
            join_versions(&before.unknown_applied)
        );
    }

    let pending: Vec<_> = before
        .entries
        .iter()
        .filter(|m| m.state != State::Applied)
        .collect();
    if pending.is_empty() {
        tracing::info!("database schema is up to date");
        return Ok(());
    }

    MIGRATOR.run(pool).await.context("migration failed")?;

    for m in pending {
        tracing::info!(version = m.version, "applied migration: {}", m.description);
    }
    Ok(())
}



pub async fn status(pool: &PgPool) -> anyhow::Result<Status> {
    let table_exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(MIGRATIONS_TABLE)
        .fetch_one(pool)
        .await?;

    let mut applied: BTreeMap<i64, (Vec<u8>, bool)> = BTreeMap::new();
    if table_exists {
        let rows: Vec<(i64, Vec<u8>, bool)> =
            sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations")
                .fetch_all(pool)
                .await?;
        applied.extend(
            rows.into_iter()
                .map(|(v, checksum, ok)| (v, (checksum, ok))),
        );
    }

    let entries = MIGRATOR
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .map(|m| {
            let state = match applied.remove(&m.version) {
                None => State::Pending,
                Some((_, false)) => State::Failed,
                Some((checksum, true)) if checksum != *m.checksum => State::ChecksumMismatch,
                Some(_) => State::Applied,
            };
            Entry {
                version: m.version,
                description: m.description.to_string(),
                state,
            }
        })
        .collect();

    Ok(Status {
        entries,
        unknown_applied: applied.into_keys().collect(),
    })
}

async fn check_server_version(pool: &PgPool) -> anyhow::Result<()> {
    let version: String = sqlx::query_scalar("SHOW server_version_num")
        .fetch_one(pool)
        .await?;
    let version: i32 = version.parse().context("unexpected server_version_num")?;
    if version < MIN_SERVER_VERSION_NUM {
        bail!("PostgreSQL 15 or newer is required (server reports version number {version})");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Applied,
    Pending,
    
    ChecksumMismatch,
    
    Failed,
}

pub struct Entry {
    pub version: i64,
    pub description: String,
    pub state: State,
}

pub struct Status {
    pub entries: Vec<Entry>,
    
    pub unknown_applied: Vec<i64>,
}

impl Status {
    
    pub fn is_current(&self) -> bool {
        self.unknown_applied.is_empty() && self.entries.iter().all(|m| m.state == State::Applied)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for m in &self.entries {
            let state = match m.state {
                State::Applied => "applied",
                State::Pending => "pending",
                State::ChecksumMismatch => "CHANGED AFTER APPLY",
                State::Failed => "FAILED",
            };
            writeln!(f, "{:<16} {:<20} {}", m.version, state, m.description)?;
        }
        for version in &self.unknown_applied {
            writeln!(f, "{version:<16} {:<20} (not in this build)", "applied")?;
        }
        Ok(())
    }
}

fn join_versions(versions: &[i64]) -> String {
    versions
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
