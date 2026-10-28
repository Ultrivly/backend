


use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::json;
use sqlx::{PgConnection, PgPool};

use crate::identity::{accounts, emails};
use crate::platform::blob::BlobStore;
use crate::integrations::webhooks;
use crate::platform::deletion;
use crate::platform::net::HttpClient;
use crate::platform::jobs::{self, ClaimedJob, NewJob};
use crate::platform::mail::{Email, Mailer};
use crate::platform::rate_limit::{self, Decision};
use crate::platform::secrets::{Secrets, token_hash};

pub const SEND_EMAIL: &str = "email.send";
pub const PASSWORD_RESET: &str = "auth.password_reset";

const IDLE_POLL: Duration = Duration::from_secs(1);
const LEASE_CHECK_EVERY: Duration = Duration::from_secs(60);
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(15 * 60);

const RESETS_PER_HOUR: i32 = 3;


pub async fn enqueue_email(
    conn: &mut PgConnection,
    secrets: &Secrets,
    email: &Email,
) -> sqlx::Result<()> {
    let payload = jobs::seal(
        secrets,
        SEND_EMAIL,
        &serde_json::to_value(email).expect("email serializes"),
    );
    jobs::enqueue(conn, NewJob::new(SEND_EMAIL, payload)).await?;
    Ok(())
}




pub async fn enqueue_password_reset(
    conn: &mut PgConnection,
    secrets: &Secrets,
    email: &str,
) -> sqlx::Result<()> {
    let email = email.trim().to_lowercase();
    let dedupe = hex(&token_hash(&email));
    let payload = jobs::seal(secrets, PASSWORD_RESET, &json!({ "email": email }));
    jobs::enqueue(
        conn,
        NewJob {
            dedupe_key: Some(&dedupe),
            max_attempts: 5,
            ..NewJob::new(PASSWORD_RESET, payload)
        },
    )
    .await?;
    Ok(())
}

pub struct Worker {
    pub pool: PgPool,
    pub secrets: Secrets,
    pub mailer: Mailer,
    pub public_url: String,
    
    pub blobs: Option<BlobStore>,
    pub http: HttpClient,
    pub id: String,
}

impl Worker {
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        tracing::info!(worker = %self.id, "worker started");
        let mut last_lease_check = Instant::now() - LEASE_CHECK_EVERY;
        let mut last_housekeeping = Instant::now() - HOUSEKEEPING_EVERY;
        loop {
            if last_lease_check.elapsed() >= LEASE_CHECK_EVERY {
                last_lease_check = Instant::now();
                if let Err(err) = jobs::release_expired_leases(&self.pool).await {
                    tracing::warn!("releasing expired job leases failed: {err}");
                }
            }
            if last_housekeeping.elapsed() >= HOUSEKEEPING_EVERY {
                last_housekeeping = Instant::now();
                self.housekeeping().await;
            }

            let worked = match self.run_once().await {
                Ok(worked) => worked,
                Err(err) => {
                    tracing::error!("worker error: {err:#}");
                    false
                }
            };
            if !worked {
                tokio::select! {
                    _ = &mut shutdown => break,
                    _ = tokio::time::sleep(IDLE_POLL) => {}
                }
            }
        }
        tracing::info!(worker = %self.id, "worker stopped");
    }

    
    pub async fn run_once(&self) -> anyhow::Result<bool> {
        let dispatched = webhooks::dispatch_events(&self.pool).await?;
        let Some(job) = jobs::claim(&self.pool, &self.id).await? else {
            return Ok(dispatched > 0);
        };
        match self.handle(&job).await {
            Ok(()) => jobs::succeed(&self.pool, job.id).await?,
            Err(err) => {
                tracing::warn!(job = %job.id, kind = %job.kind, attempt = job.attempt, "job failed: {err:#}");
                jobs::fail(&self.pool, &job, &format!("{err:#}")).await?;
            }
        }
        Ok(true)
    }

    async fn handle(&self, job: &ClaimedJob) -> anyhow::Result<()> {
        match job.kind.as_str() {
            SEND_EMAIL => {
                let email: Email =
                    serde_json::from_value(jobs::unseal(&self.secrets, SEND_EMAIL, &job.payload)?)?;
                self.mailer.send(&email).await
            }
            PASSWORD_RESET => {
                let payload = jobs::unseal(&self.secrets, PASSWORD_RESET, &job.payload)?;
                let email = payload["email"].as_str().unwrap_or_default();
                let key = format!("reset-email:{}", hex(&token_hash(email)));
                if rate_limit::check(&self.pool, &key, RESETS_PER_HOUR, Duration::from_secs(3600))
                    .await?
                    != Decision::Allowed
                {
                    return Ok(());
                }
                let mut conn = self.pool.acquire().await?;
                if let Some((_, token)) = accounts::request_password_reset(&mut conn, email).await?
                {
                    self.mailer
                        .send(&emails::password_reset(email, &self.public_url, &token))
                        .await?;
                }
                Ok(())
            }
            webhooks::DELIVER => {
                let id = job.payload["delivery_id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| anyhow::anyhow!("invalid delivery job"))?;
                webhooks::deliver(&self.pool, &self.http, &self.secrets, id).await
            }
            webhooks::EVALUATE_WORKFLOWS => {
                let id = job.payload["event_id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| anyhow::anyhow!("invalid workflow job"))?;
                crate::workflows::evaluate(&self.pool, id).await
            }
            other => anyhow::bail!("unknown job kind {other:?}"),
        }
    }

    
    pub async fn housekeeping(&self) {
        for (what, sql) in [
            (
                "auth tokens",
                "DELETE FROM auth_tokens WHERE expires_at < now()",
            ),
            (
                "SAML requests",
                "DELETE FROM saml_requests WHERE expires_at < now()",
            ),
            (
                "used SAML assertions",
                "DELETE FROM saml_assertions_used WHERE expires_at < now()",
            ),
            (
                "passkey ceremonies",
                "DELETE FROM webauthn_ceremonies WHERE expires_at < now()",
            ),
            (
                "sign-in states",
                "DELETE FROM oidc_login_states WHERE expires_at < now()",
            ),
            (
                "login throttles",
                "DELETE FROM login_throttles WHERE updated_at < now() - interval '1 day'",
            ),
            (
                "finished jobs",
                "DELETE FROM jobs WHERE state = 'succeeded' AND finished_at < now() - interval '7 days'",
            ),
            (
                "idempotency keys",
                "DELETE FROM idempotency_keys WHERE expires_at < now()",
            ),
        ] {
            if let Err(err) = sqlx::query(sql).execute(&self.pool).await {
                tracing::warn!("cleaning up {what} failed: {err}");
            }
        }
        if let Err(err) = rate_limit::delete_old_windows(&self.pool).await {
            tracing::warn!("cleaning up rate limits failed: {err}");
        }
        if let Some(blobs) = &self.blobs {
            match deletion::purge_due(&self.pool, blobs).await {
                Ok(report) if report != deletion::PurgeReport::default() => {
                    tracing::info!(?report, "purged deleted items")
                }
                Ok(_) => {}
                Err(err) => tracing::error!("purge failed: {err:#}"),
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
