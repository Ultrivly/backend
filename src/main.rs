use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use ultrivly::config::{
    AuthConfig, DatabaseConfig, Deployment, HttpConfig, MailConfig, MetricsConfig, SocialConfig,
    StorageConfig,
};
use ultrivly::http::{self, AppState, Settings};
use ultrivly::identity::sso::{SocialProvider, Sso};
use ultrivly::platform::blob::BlobStore;
use ultrivly::platform::mail::{self, Mailer};
use ultrivly::platform::net::{HttpClient, NetPolicy};
use ultrivly::platform::secrets::Secrets;
use ultrivly::platform::{db, deletion, jobs, migrations, telemetry};
use ultrivly::worker::Worker;

#[derive(Parser)]
#[command(name = "ultrivly", version, about = "Ultrivly helpdesk backend")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Apply or inspect database migrations (applies pending migrations by default)"
    )]
    Migrate {
        #[command(flatten)]
        db: DatabaseConfig,

        #[command(subcommand)]
        action: Option<MigrateAction>,
    },

    #[command(
        about = "Permanently delete items whose retention period has ended, including stored files"
    )]
    Purge {
        #[command(flatten)]
        db: DatabaseConfig,

        #[command(flatten)]
        storage: StorageConfig,
    },

    #[command(about = "Inspect and retry background jobs across all organizations")]
    Jobs {
        #[command(flatten)]
        db: DatabaseConfig,

        #[command(subcommand)]
        action: JobsAction,
    },

    #[command(about = "Manage the outgoing email suppression list")]
    Mail {
        #[command(flatten)]
        db: DatabaseConfig,

        #[command(subcommand)]
        action: MailAction,
    },

    #[command(
        about = "Check a running server's readiness endpoint; exits 0 when ready (for container health checks)"
    )]
    Probe {
        #[arg(
            long,
            default_value = "http://127.0.0.1:8080/readyz",
            help = "Readiness URL to request"
        )]
        url: String,
    },

    #[command(about = "Print a new random key for ULTRIVLY_SECRET_KEY")]
    SecretKey,

    #[command(about = "Run the HTTP API")]
    Serve {
        #[command(flatten)]
        db: DatabaseConfig,
        #[command(flatten)]
        auth: AuthConfig,
        #[command(flatten)]
        mail: MailConfig,
        #[command(flatten)]
        http: HttpConfig,
        #[command(flatten)]
        social: SocialConfig,
        #[command(flatten)]
        storage: StorageConfig,
        #[command(flatten)]
        metrics: MetricsConfig,

        #[arg(long, help = "Also run the background worker in this process")]
        with_worker: bool,
    },

    #[command(about = "Run background jobs: email, webhooks, workflows, cleanup, and purging")]
    Worker {
        #[command(flatten)]
        db: DatabaseConfig,
        #[command(flatten)]
        auth: AuthConfig,
        #[command(flatten)]
        mail: MailConfig,
        #[command(flatten)]
        storage: StorageConfig,
        #[command(flatten)]
        metrics: MetricsConfig,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    #[command(about = "Apply all pending migrations")]
    Run,

    #[command(about = "List migrations; exits with 1 unless the database matches this build")]
    Status,
}

#[derive(Subcommand)]
enum JobsAction {
    #[command(about = "Show queued, running, and dead job counts by kind")]
    Stats,

    #[command(about = "List jobs, newest first")]
    List {
        #[arg(long, help = "queued, running, succeeded, or dead")]
        state: Option<String>,
        #[arg(long, help = "Only jobs of this kind, e.g. webhook.deliver")]
        kind: Option<String>,
        #[arg(long, help = "Only jobs for this organization")]
        org: Option<uuid::Uuid>,
        #[arg(long, default_value_t = 50, help = "Maximum jobs to list")]
        limit: i64,
    },

    #[command(about = "Queue dead jobs to run again")]
    Retry {
        #[arg(
            help = "Job ID to retry",
            conflicts_with = "all_dead",
            required_unless_present = "all_dead"
        )]
        id: Option<uuid::Uuid>,
        #[arg(long, help = "Retry every dead job")]
        all_dead: bool,
        #[arg(
            long,
            requires = "all_dead",
            help = "With --all-dead, only jobs of this kind"
        )]
        kind: Option<String>,
    },
}

#[derive(Subcommand)]
enum MailAction {
    #[command(about = "List suppressed addresses, newest first")]
    Suppressions {
        #[arg(long, default_value_t = 100, help = "Maximum addresses to list")]
        limit: i64,
    },

    #[command(about = "Stop all email to an address")]
    Suppress {
        #[arg(help = "Email address")]
        email: String,
    },

    #[command(about = "Allow email to a suppressed address again")]
    Unsuppress {
        #[arg(help = "Email address")]
        email: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = dotenvy::dotenv();
    init_tracing();

    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Migrate { db, action } => {
            let pool = db::connect(&db).await?;
            match action.unwrap_or(MigrateAction::Run) {
                MigrateAction::Run => {
                    migrations::run(&pool).await?;
                    Ok(ExitCode::SUCCESS)
                }
                MigrateAction::Status => {
                    let status = migrations::status(&pool).await?;
                    print!("{status}");
                    Ok(if status.is_current() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    })
                }
            }
        }
        Command::Serve {
            db,
            auth,
            mail,
            http: http_config,
            social,
            storage,
            metrics,
            with_worker,
        } => {
            let secrets = check_auth_config(&auth)?;
            let pool = db::connect(&db).await?;
            require_current_schema(&pool).await?;

            let net = HttpClient::new(NetPolicy::new(auth.deployment, &auth.net_allow))?;
            let mut providers = Vec::new();
            if let (Some(id), Some(secret)) = (social.google_client_id, social.google_client_secret)
            {
                providers.push(SocialProvider::google(id, secret));
            }
            let sso = Sso::new(secrets.clone(), net, &auth.public_url, providers)?;
            let state = AppState::new(
                pool.clone(),
                secrets.clone(),
                sso,
                BlobStore::from_url(&storage.storage_url)?,
                Settings {
                    public_url: auth.public_url.parse()?,
                    trusted_proxy_hops: http_config.trusted_proxy_hops,
                    mail_events_secret: mail.mail_events_secret.clone(),
                    limits: http::throttle::Limits {
                        per_caller: http_config.rate_limit_per_caller,
                        per_ip: http_config.rate_limit_per_ip,
                    },
                },
            )?;

            let (stop, stopped) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = stop.send(true);
            });
            start_metrics(&metrics, stopped.clone())?;
            let worker = if with_worker {
                let worker = build_worker(pool, secrets, &auth, &mail, &storage)?;
                let stopped = stopped.clone();
                Some(tokio::spawn(worker.run(wait_for(stopped))))
            } else {
                None
            };
            http::serve(state, http_config.bind, wait_for(stopped)).await?;
            if let Some(worker) = worker {
                worker.await?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Worker {
            db,
            auth,
            mail,
            storage,
            metrics,
        } => {
            let secrets = check_auth_config(&auth)?;
            let pool = db::connect(&db).await?;
            require_current_schema(&pool).await?;
            let (stop, stopped) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = stop.send(true);
            });
            start_metrics(&metrics, stopped.clone())?;
            build_worker(pool, secrets, &auth, &mail, &storage)?
                .run(wait_for(stopped))
                .await;
            Ok(ExitCode::SUCCESS)
        }
        Command::Jobs { db, action } => {
            let pool = db::connect(&db).await?;
            jobs_command(&pool, action).await
        }
        Command::Mail { db, action } => {
            let pool = db::connect(&db).await?;
            match action {
                MailAction::Suppressions { limit } => {
                    for row in mail::suppressions(&pool, limit.clamp(1, 10_000)).await? {
                        println!(
                            "{}  {:<9} {}  {}",
                            row.created_at.format("%Y-%m-%d %H:%M"),
                            row.reason,
                            row.email,
                            row.detail.unwrap_or_default()
                        );
                    }
                }
                MailAction::Suppress { email } => {
                    if mail::suppress(&pool, &email, "manual", None).await? {
                        println!("suppressed {email}");
                    } else {
                        println!("{email} was already suppressed or is not an address");
                    }
                }
                MailAction::Unsuppress { email } => {
                    if !mail::unsuppress(&pool, &email).await? {
                        anyhow::bail!("{email} is not suppressed");
                    }
                    println!("removed {email} from the suppression list");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Probe { url } => {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => Ok(ExitCode::SUCCESS),
                Ok(response) => {
                    eprintln!("{url} answered {}", response.status());
                    Ok(ExitCode::FAILURE)
                }
                Err(err) => {
                    eprintln!("{url} is unreachable: {err}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::SecretKey => {
            println!("{}", Secrets::generate_key());
            Ok(ExitCode::SUCCESS)
        }
        Command::Purge { db, storage } => {
            let blobs = BlobStore::from_url(&storage.storage_url)?;
            let pool = db::connect(&db).await?;
            let report = deletion::purge_due(&pool, &blobs).await?;
            tracing::info!(
                organizations = report.organizations,
                workspaces = report.workspaces,
                cases = report.cases,
                attachments = report.attachments,
                files_deleted = report.files_deleted,
                files_failed = report.files_failed,
                "purge finished"
            );
            Ok(if report.files_failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

async fn jobs_command(pool: &sqlx::PgPool, action: JobsAction) -> anyhow::Result<ExitCode> {
    match action {
        JobsAction::Stats => {
            let counts = jobs::counts(pool).await?;
            if counts.is_empty() {
                println!("no queued, running, or dead jobs");
            }
            for row in counts {
                println!("{:<28} {:<8} {}", row.kind, row.state, row.count);
            }
            Ok(ExitCode::SUCCESS)
        }
        JobsAction::List {
            state,
            kind,
            org,
            limit,
        } => {
            if state.as_deref().is_some_and(|s| !jobs::STATES.contains(&s)) {
                anyhow::bail!("--state must be one of {}", jobs::STATES.join(", "));
            }
            let mut conn = pool.acquire().await?;
            let rows = jobs::list(
                &mut conn,
                jobs::JobFilter {
                    org_id: org,
                    state: state.as_deref(),
                    kind: kind.as_deref(),
                },
                None,
                limit.clamp(1, 1000),
            )
            .await?;
            for job in rows {
                println!(
                    "{}  {:<9} {:<24} attempts {}/{}  org {}  {}",
                    job.id,
                    job.state,
                    job.kind,
                    job.attempts,
                    job.max_attempts,
                    job.org_id.map_or_else(|| "-".into(), |o| o.to_string()),
                    job.last_error
                        .unwrap_or_default()
                        .lines()
                        .next()
                        .unwrap_or_default()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        JobsAction::Retry { id, all_dead, kind } => {
            let mut conn = pool.acquire().await?;
            if all_dead {
                let (retried, skipped) = jobs::retry_dead(&mut conn, kind.as_deref()).await?;
                println!("queued {retried} dead jobs; skipped {skipped} already queued");
                return Ok(ExitCode::SUCCESS);
            }
            let id = id.expect("clap requires an id");
            match jobs::retry(&mut conn, id, None).await? {
                jobs::Retry::Queued => {
                    println!("queued {id}");
                    Ok(ExitCode::SUCCESS)
                }
                jobs::Retry::NotFound => anyhow::bail!("no dead job with id {id}"),
                jobs::Retry::AlreadyQueued => anyhow::bail!("an identical job is already queued"),
            }
        }
    }
}

fn start_metrics(
    config: &MetricsConfig,
    stopped: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let Some(addr) = config.metrics_bind else {
        return Ok(());
    };
    let handle = telemetry::install()?;
    tokio::spawn(async move {
        if let Err(err) = telemetry::serve(handle, addr, wait_for(stopped)).await {
            tracing::error!("metrics server failed: {err:#}");
        }
    });
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx::postgres::notice=warn"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if std::env::var("ULTRIVLY_LOG_FORMAT").is_ok_and(|v| v == "json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn check_auth_config(auth: &AuthConfig) -> anyhow::Result<Secrets> {
    let secrets = Secrets::from_base64_key(&auth.secret_key)?;
    let public_url: url::Url = auth
        .public_url
        .parse()
        .map_err(|_| anyhow::anyhow!("ULTRIVLY_PUBLIC_URL is not a valid URL"))?;
    match (public_url.scheme(), auth.deployment) {
        ("https", _) => {}
        ("http", Deployment::SelfHosted) => tracing::warn!(
            "ULTRIVLY_PUBLIC_URL uses http: cookies will not be marked Secure; use https in production"
        ),
        _ => anyhow::bail!("ULTRIVLY_PUBLIC_URL must use https on Ultrivly cloud"),
    }
    Ok(secrets)
}

async fn require_current_schema(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    if !migrations::status(pool).await?.is_current() {
        anyhow::bail!("the database schema does not match this build; run `ultrivly migrate`");
    }
    Ok(())
}

fn build_worker(
    pool: sqlx::PgPool,
    secrets: Secrets,
    auth: &AuthConfig,
    mail: &MailConfig,
    storage: &StorageConfig,
) -> anyhow::Result<Worker> {
    Ok(Worker {
        pool,
        secrets,
        mailer: Mailer::from_url(&mail.mail_url, &mail.mail_from, auth.deployment)?,
        public_url: auth.public_url.trim_end_matches('/').to_string(),
        blobs: Some(BlobStore::from_url(&storage.storage_url)?),
        http: HttpClient::new(NetPolicy::new(auth.deployment, &auth.net_allow))?,
        id: format!("{}-{}", hostname(), std::process::id()),
    })
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "worker".into())
}

async fn wait_for(mut stopped: tokio::sync::watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stop| *stop).await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
