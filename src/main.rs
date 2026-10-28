use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use ultrivly::config::{
    AuthConfig, DatabaseConfig, Deployment, HttpConfig, MailConfig, SocialConfig, StorageConfig,
};
use ultrivly::http::{self, AppState, Settings};
use ultrivly::identity::sso::{SocialProvider, Sso};
use ultrivly::platform::blob::BlobStore;
use ultrivly::platform::mail::Mailer;
use ultrivly::platform::net::{HttpClient, NetPolicy};
use ultrivly::platform::secrets::Secrets;
use ultrivly::platform::{db, deletion, migrations};
use ultrivly::worker::Worker;

#[derive(Parser)]
#[command(name = "ultrivly", version, about = "Ultrivly helpdesk backend")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    
    Migrate {
        #[command(flatten)]
        db: DatabaseConfig,

        #[command(subcommand)]
        action: Option<MigrateAction>,
    },
    
    
    Purge {
        #[command(flatten)]
        db: DatabaseConfig,

        #[command(flatten)]
        storage: StorageConfig,
    },
    
    SecretKey,
    
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
        
        #[arg(long)]
        with_worker: bool,
    },
    
    Worker {
        #[command(flatten)]
        db: DatabaseConfig,
        #[command(flatten)]
        auth: AuthConfig,
        #[command(flatten)]
        mail: MailConfig,
        #[command(flatten)]
        storage: StorageConfig,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    
    Run,
    
    
    Status,
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
                },
            )?;

            let (stop, stopped) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = stop.send(true);
            });
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
        } => {
            let secrets = check_auth_config(&auth)?;
            let pool = db::connect(&db).await?;
            require_current_schema(&pool).await?;
            build_worker(pool, secrets, &auth, &mail, &storage)?
                .run(shutdown_signal())
                .await;
            Ok(ExitCode::SUCCESS)
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
