use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use ultrivly::audit::Actor;
use ultrivly::identity::{self, NewOrganization};
use ultrivly::integrations::api_credentials::{self, NewCredential};
use ultrivly::platform::authz::Permission;
use uuid::Uuid;

#[derive(Parser)]
#[command(about = "Seed a test database with realistic volume and measure API latency against it")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Create organizations with cases, contacts and messages; prints an API key for the first one"
    )]
    Seed {
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value_t = 5, help = "Organizations to create")]
        orgs: u32,
        #[arg(long, default_value_t = 20_000, help = "Cases per organization")]
        cases: u32,
        #[arg(long, default_value_t = 4, help = "Messages per case")]
        messages: u32,
        #[arg(long, help = "Required: confirms this database holds no real data")]
        throwaway_database: bool,
    },

    #[command(about = "Send a mix of API requests and report latency per endpoint")]
    Run {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        base_url: String,
        #[arg(long, help = "Organization ID printed by seed")]
        org: Uuid,
        #[arg(
            long,
            env = "LOAD_API_KEY",
            hide_env_values = true,
            help = "API key printed by seed"
        )]
        api_key: String,
        #[arg(long, help = "Workspace ID printed by seed")]
        workspace: Uuid,
        #[arg(long, default_value_t = 32, help = "Concurrent clients")]
        concurrency: usize,
        #[arg(long, default_value_t = 60, help = "Seconds to run")]
        seconds: u64,
    },
}

const WORDS: &[&str] = &[
    "printer", "vpn", "password", "laptop", "invoice", "refund", "email", "login", "shipping",
    "outage", "billing", "access", "monitor", "license", "phone", "badge",
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Seed {
            database_url,
            orgs,
            cases,
            messages,
            throwaway_database,
        } => {
            if !throwaway_database {
                anyhow::bail!(
                    "seed writes a lot of fake data; pass --throwaway-database to confirm"
                );
            }
            seed(&database_url, orgs, cases, messages).await
        }
        Command::Run {
            base_url,
            org,
            api_key,
            workspace,
            concurrency,
            seconds,
        } => run(&base_url, org, &api_key, workspace, concurrency, seconds).await,
    }
}

async fn seed(database_url: &str, orgs: u32, cases: u32, messages: u32) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let run = Uuid::now_v7().simple().to_string()[24..].to_string();
    let mut first = None;
    for n in 0..orgs {
        let started = Instant::now();
        let owner = Uuid::now_v7();
        sqlx::query("INSERT INTO users (id, email, display_name, email_verified_at) VALUES ($1, $2, 'Load test', now())")
            .bind(owner)
            .bind(format!("owner-{run}-{n}@load.test"))
            .execute(&pool)
            .await?;
        let mut conn = pool.acquire().await?;
        let created = identity::create_organization(
            &mut conn,
            NewOrganization {
                name: &format!("Load {run} {n}"),
                slug: &format!("load-{run}-{n}"),
                workspace_name: "Support",
                workspace_slug: "support",
                owner_user_id: owner,
            },
        )
        .await?;
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        sqlx::query(
            "INSERT INTO contacts (id, org_id, email, display_name)
             SELECT gen_random_uuid(), $1, 'customer' || g || '@load.test', 'Customer ' || g
             FROM generate_series(1, greatest($2 / 5, 1)) g",
        )
        .bind(created.org_id)
        .bind(cases as i32)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "WITH c AS (SELECT array_agg(id) AS ids FROM contacts WHERE org_id = $1),
                  s AS (SELECT array_agg(id ORDER BY position) AS ids FROM case_statuses WHERE org_id = $1),
                  p AS (SELECT array_agg(id ORDER BY rank) AS ids FROM case_priorities WHERE org_id = $1)
             INSERT INTO cases (id, org_id, workspace_id, number, subject, description, status_id, priority_id,
                                requester_contact_id, source_channel, tags, created_at, updated_at)
             SELECT gen_random_uuid(), $1, $2, g,
                    'Problem with ' || ($4::text[])[1 + g % 16] || ' and ' || ($4::text[])[1 + (g / 16) % 16] || ' #' || g,
                    'The ' || ($4::text[])[1 + (g * 7) % 16] || ' stopped working after the update.',
                    s.ids[1 + g % array_length(s.ids, 1)], p.ids[1 + (g / 3) % array_length(p.ids, 1)],
                    c.ids[1 + g % array_length(c.ids, 1)], 'api',
                    ARRAY[($4::text[])[1 + g % 16]],
                    now() - make_interval(mins => (g * 37) % 525600), now() - make_interval(mins => (g * 11) % 10000)
             FROM generate_series(1, $3) g, c, s, p",
        )
        .bind(created.org_id)
        .bind(created.workspace_id)
        .bind(cases as i32)
        .bind(WORDS)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE case_number_counters SET last_value = $2 WHERE org_id = $1")
            .bind(created.org_id)
            .bind(cases as i64)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO case_messages (id, org_id, case_id, visibility, author_kind, author_contact_id, author_user_id,
                                        body, body_format, source_channel, created_at)
             SELECT gen_random_uuid(), c.org_id, c.id,
                    CASE WHEN m % 4 = 3 THEN 'internal' ELSE 'public' END,
                    CASE WHEN m % 2 = 0 THEN 'contact' ELSE 'user' END,
                    CASE WHEN m % 2 = 0 THEN c.requester_contact_id END,
                    CASE WHEN m % 2 = 1 THEN $2::uuid END,
                    'Message ' || m || ' about case ' || c.number, 'text', 'api',
                    c.created_at + make_interval(mins => m * 15)
             FROM cases c, generate_series(0, $3 - 1) m WHERE c.org_id = $1",
        )
        .bind(created.org_id)
        .bind(owner)
        .bind(messages as i32)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if first.is_none() {
            let key = api_credentials::create(
                &mut conn,
                created.org_id,
                Actor::User(owner),
                NewCredential {
                    name: "Load test",
                    permissions: &[
                        Permission::CasesRead,
                        Permission::CasesCreate,
                        Permission::CasesEdit,
                    ],
                    expires_in_days: Some(7),
                },
            )
            .await?;
            first = Some((created.org_id, created.workspace_id, key.token));
        }
        println!(
            "seeded organization {} with {cases} cases in {:.1}s",
            created.org_id,
            started.elapsed().as_secs_f64()
        );
    }
    sqlx::query("ANALYZE").execute(&pool).await?;
    if let Some((org, workspace, key)) = first {
        println!(
            "\nrun with:\n  LOAD_API_KEY={key} cargo run --release --example load -- run --org {org} --workspace {workspace}"
        );
    }
    Ok(())
}

type Samples = Arc<Mutex<BTreeMap<&'static str, (Vec<Duration>, u64, u64)>>>;

async fn run(
    base_url: &str,
    org: Uuid,
    api_key: &str,
    workspace: Uuid,
    concurrency: usize,
    seconds: u64,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(concurrency)
        .timeout(Duration::from_secs(30))
        .build()?;
    let base = format!("{}/api/v1/orgs/{org}", base_url.trim_end_matches('/'));
    let auth = format!("Bearer {api_key}");
    let listing: Value = client
        .get(format!("{base}/cases?limit=100"))
        .header("authorization", &auth)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let ids: Arc<Vec<String>> = Arc::new(
        listing["data"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("no cases found; run seed first"))?
            .iter()
            .filter_map(|c| c["id"].as_str().map(String::from))
            .collect(),
    );
    let samples: Samples = Arc::default();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = Vec::new();
    for worker in 0..concurrency {
        let (client, base, auth, ids, samples) = (
            client.clone(),
            base.clone(),
            auth.clone(),
            ids.clone(),
            samples.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let mut i = worker;
            while Instant::now() < deadline {
                i = i.wrapping_mul(1_103_515_245).wrapping_add(12_345) % 1_000_003;
                let id = &ids[i % ids.len()];
                let word = WORDS[i % WORDS.len()];
                let (name, request) = match i % 20 {
                    0..=5 => ("list cases", client.get(format!("{base}/cases?limit=50"))),
                    6..=9 => ("search cases", client.get(format!("{base}/cases?q={word}&limit=50"))),
                    10..=12 => ("filter cases", client.get(format!("{base}/cases?status=open&priority=high&limit=50"))),
                    13..=16 => ("get case", client.get(format!("{base}/cases/{id}"))),
                    17..=18 => (
                        "create case",
                        client.post(format!("{base}/cases")).json(&json!({
                            "workspace_id": workspace, "subject": format!("Load test {word} {i}"),
                            "requester": { "email": format!("load{}@load.test", i % 500) }
                        })),
                    ),
                    _ => (
                        "add message",
                        client
                            .post(format!("{base}/cases/{id}/messages"))
                            .json(&json!({ "visibility": "public", "body": "Load test reply" })),
                    ),
                };
                let started = Instant::now();
                let ok = matches!(request.header("authorization", &auth).send().await, Ok(r) if r.status().is_success());
                let elapsed = started.elapsed();
                let mut samples = samples.lock().unwrap();
                let entry = samples.entry(name).or_default();
                entry.0.push(elapsed);
                if ok { entry.1 += 1 } else { entry.2 += 1 }
            }
        }));
    }
    for task in tasks {
        task.await?;
    }
    let samples = samples.lock().unwrap();
    println!(
        "{:<14} {:>8} {:>7} {:>9} {:>9} {:>9} {:>9}",
        "endpoint", "requests", "errors", "p50 ms", "p95 ms", "p99 ms", "max ms"
    );
    let mut total = 0;
    for (name, (durations, ok, failed)) in samples.iter() {
        let mut sorted = durations.clone();
        sorted.sort();
        let pct = |p: f64| {
            sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)].as_secs_f64()
                * 1000.0
        };
        total += ok + failed;
        println!(
            "{:<14} {:>8} {:>7} {:>9.1} {:>9.1} {:>9.1} {:>9.1}",
            name,
            ok + failed,
            failed,
            pct(0.50),
            pct(0.95),
            pct(0.99),
            pct(1.0)
        );
    }
    println!(
        "\n{total} requests in {seconds}s = {:.0} requests/s at concurrency {concurrency}",
        total as f64 / seconds as f64
    );
    Ok(())
}
