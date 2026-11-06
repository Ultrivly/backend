use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use sqlx::PgPool;

use crate::platform::jobs;

const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

pub fn install() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("duration_seconds".into()), DURATION_BUCKETS)?
        .install_recorder()?;
    metrics::describe_counter!(
        "ultrivly_http_requests_total",
        "HTTP requests by method, route and status"
    );
    metrics::describe_histogram!(
        "ultrivly_http_request_duration_seconds",
        "HTTP request latency by method and route"
    );
    metrics::describe_counter!(
        "ultrivly_jobs_finished_total",
        "Background job attempts by kind and outcome (succeeded, retrying, dead)"
    );
    metrics::describe_histogram!(
        "ultrivly_job_duration_seconds",
        "Background job run time by kind"
    );
    metrics::describe_gauge!(
        "ultrivly_jobs",
        "Jobs by kind and state (queued, running, dead)"
    );
    metrics::describe_gauge!(
        "ultrivly_outbox_lag_seconds",
        "Age of the oldest domain event not yet dispatched"
    );
    metrics::describe_counter!("ultrivly_workflow_runs_total", "Workflow runs by status");
    metrics::describe_counter!(
        "ultrivly_channel_messages_total",
        "Inbound channel messages by channel kind and outcome"
    );
    metrics::describe_counter!(
        "ultrivly_ai_requests_total",
        "AI assist requests by task and outcome"
    );
    metrics::describe_counter!(
        "ultrivly_emails_suppressed_total",
        "Outgoing emails skipped because the recipient is suppressed"
    );
    Ok(handle)
}

pub async fn serve(
    handle: PrometheusHandle,
    addr: SocketAddr,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let upkeep = handle.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            upkeep.run_upkeep();
        }
    });
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let handle = handle.clone();
            async move { handle.render() }
        }),
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

pub async fn track_http(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |p| p.as_str().to_string());
    let response = next.run(request).await;
    let status = response.status().as_u16().to_string();
    metrics::counter!(
        "ultrivly_http_requests_total",
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "ultrivly_http_request_duration_seconds",
        "method" => method,
        "route" => route
    )
    .record(started.elapsed().as_secs_f64());
    response
}

pub fn job_finished(kind: &str, outcome: &'static str, elapsed: Duration) {
    metrics::counter!("ultrivly_jobs_finished_total", "kind" => kind.to_string(), "outcome" => outcome)
        .increment(1);
    metrics::histogram!("ultrivly_job_duration_seconds", "kind" => kind.to_string())
        .record(elapsed.as_secs_f64());
}

static QUEUE_LABELS: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());

pub async fn record_queue(pool: &PgPool) -> sqlx::Result<()> {
    let mut current = BTreeSet::new();
    let mut totals: BTreeMap<String, f64> = ["queued", "running", "dead"]
        .into_iter()
        .map(|s| (s.to_string(), 0.0))
        .collect();
    for row in jobs::counts(pool).await? {
        *totals.entry(row.state.clone()).or_default() += row.count as f64;
        metrics::gauge!("ultrivly_jobs", "kind" => row.kind.clone(), "state" => row.state.clone())
            .set(row.count as f64);
        current.insert((row.kind, row.state));
    }
    {
        let mut seen = QUEUE_LABELS.lock().unwrap_or_else(|e| e.into_inner());
        for (kind, state) in seen.difference(&current) {
            metrics::gauge!("ultrivly_jobs", "kind" => kind.clone(), "state" => state.clone())
                .set(0.0);
        }
        *seen = current;
    }
    for (state, total) in totals {
        metrics::gauge!("ultrivly_jobs", "kind" => "all", "state" => state).set(total);
    }
    let lag: Option<f64> = sqlx::query_scalar(
        "SELECT extract(epoch FROM now() - min(occurred_at))::float8 FROM domain_events WHERE dispatched_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    metrics::gauge!("ultrivly_outbox_lag_seconds").set(lag.unwrap_or(0.0));
    Ok(())
}
