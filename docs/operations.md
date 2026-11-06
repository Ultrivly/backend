# Operating Ultrivly

## Logs

Every process logs to standard error. Set `ULTRIVLY_LOG_FORMAT=json` for one JSON object per line; the container image does this by default. Each HTTP request is logged with its method, path and request ID. Every response carries the same ID in an `x-request-id` header, so a customer can quote it when asking for help. Logs never contain passwords, tokens, secrets or message bodies. The one exception is the development `log://` mailer, which prints each email instead of sending it.

Useful log messages:

| Level | Message | Meaning |
|---|---|---|
| `ERROR` | `job failed permanently` | A job used its last attempt and is now dead. See [Dead jobs](#dead-jobs). |
| `WARN` | `job failed` | A job failed and will be retried with backoff. |
| `ERROR` | `purge failed` / `file deletion failed, will retry` | Permanent deletion could not finish. See [Purge failures](#purge-failures). |
| `ERROR` | `internal error` | A request failed with a 500. The log line has the request ID and the cause. |

## Metrics

Set `ULTRIVLY_METRICS_BIND` (for example `0.0.0.0:9090`) on API and worker processes to serve Prometheus metrics at `/metrics` on a separate port. Don't expose that port publicly. Metrics carry no organization IDs or personal data.

| Metric | Type | Labels | Reported by |
|---|---|---|---|
| `ultrivly_http_requests_total` | counter | `method`, `route`, `status` | API |
| `ultrivly_http_request_duration_seconds` | histogram | `method`, `route` | API |
| `ultrivly_http_throttled_total` | counter | | API |
| `ultrivly_jobs_finished_total` | counter | `kind`, `outcome` (`succeeded`, `retrying`, `dead`) | Worker |
| `ultrivly_job_duration_seconds` | histogram | `kind` | Worker |
| `ultrivly_jobs` | gauge | `kind` (or `all`), `state` (`queued`, `running`, `dead`) | Worker, every minute |
| `ultrivly_outbox_lag_seconds` | gauge | | Worker, every minute |
| `ultrivly_workflow_runs_total` | counter | `status` | Worker |
| `ultrivly_channel_messages_total` | counter | `kind` (`email`, `social`, `chat`), `outcome` | API |
| `ultrivly_ai_requests_total` | counter | `task`, `outcome` | API |
| `ultrivly_emails_suppressed_total` | counter | | Worker |

`route` is the route template, such as `/api/v1/orgs/{org_id}/cases/{id}`, never the real path.

### Suggested alerts

| Alert | Condition | Why |
|---|---|---|
| API errors | `sum(rate(ultrivly_http_requests_total{status=~"5.."}[5m])) / sum(rate(ultrivly_http_requests_total[5m])) > 0.01` for 10 minutes | More than 1% of requests are failing. |
| Slow API | p95 of `ultrivly_http_request_duration_seconds` above 1 second for 10 minutes | Users will notice. Usually database pressure. |
| Dead jobs | `ultrivly_jobs{kind="all",state="dead"} > 0` increasing | Email, webhooks or exports are being dropped. |
| Queue backlog | `ultrivly_jobs{kind="all",state="queued"} > 1000` for 15 minutes | Workers can't keep up. Add workers. |
| Outbox lag | `ultrivly_outbox_lag_seconds > 300` | Webhooks and workflows are delayed. The worker is down or stuck. |
| Worker down | No `ultrivly_jobs` samples for 5 minutes | No worker is running. |
| Readiness | `/readyz` failing | The database is down, or the schema doesn't match the running version. |

## Runbooks

### Dead jobs

A job is dead after its last retry fails. Retries back off from 30 seconds up to an hour. Dead jobs are kept for 30 days and then deleted.

1. See what is failing: `ultrivly jobs stats`, then `ultrivly jobs list --state dead --kind <kind>`. The last column is the last error.
2. Fix the cause: SMTP credentials, a customer's webhook endpoint, file storage permissions, and so on.
3. Retry: `ultrivly jobs retry <id>`, or `ultrivly jobs retry --all-dead [--kind <kind>]`.

Organization admins can also see their own organization's jobs at `GET /api/v1/orgs/{org_id}/jobs?state=dead` and retry them. Retrying never creates a duplicate of a job that is already queued.

Retrying an `email.send` job sends that email again. Webhook deliveries carry an `ultrivly-delivery` ID so receivers can ignore duplicates.

### Outbox lag

Domain events are written in the same transaction as each change, and the worker turns them into webhook deliveries and workflow runs. If `ultrivly_outbox_lag_seconds` grows:

1. Check that at least one worker is running and logging `worker started`.
2. Check worker logs for repeated errors.
3. Check database load. The dispatcher only needs the `domain_events_undispatched_idx` index.

### Email isn't arriving

1. Look for `email.send` or `channel.email_reply` jobs that are retrying or dead (`ultrivly jobs list --kind email.send`).
2. Check whether the address is suppressed: `ultrivly mail suppressions`. Remove it with `ultrivly mail unsuppress <email>` once the cause is fixed.
3. For replies sent from an organization's own domain, check that its DKIM record still matches. See [Email](email.md).

### Purge failures

After the retention period, `ultrivly purge` (also run by the worker every 15 minutes) deletes database rows and queues stored files for deletion. Failed file deletions are retried with backoff and logged as `file deletion failed, will retry`. Check the storage credentials and that the storage service allows `DeleteObject` or file removal. Run `ultrivly purge` by hand to retry right away. It exits with 1 while any file deletion is still failing.

### Lost or leaked secret key

`ULTRIVLY_SECRET_KEY` cannot be rotated yet.

- **If it leaks:** treat every stored secret as exposed. Rotate SSO client secrets, webhook and channel secrets (each has a rotate-secret endpoint), API keys for AI providers, and plugin installs.
- **If it is lost:** encrypted values can't be read. Admins have to enter SSO secrets, AI keys and plugin configuration again, and rotate webhook and channel secrets. Cases, messages and attachments are not encrypted with this key and are unaffected.

### Scaling

- **API:** stateless. Add containers behind the load balancer. Rate limits are counted per process, so the effective limit grows with the number of API containers.
- **Worker:** add containers. Jobs are claimed with `FOR UPDATE SKIP LOCKED`, so workers never run the same job twice at once.
- **Database:** each process opens up to `ULTRIVLY_DB_MAX_CONNECTIONS` connections. Keep the total across all processes below the database's `max_connections`, or put PgBouncer in front in transaction mode.

## Backups and restore

Back up three things:

1. **The database**, with `pg_dump` or your provider's snapshots and point-in-time recovery.
2. **File storage**: the bucket or directory in `ULTRIVLY_STORAGE_URL`.
3. **`ULTRIVLY_SECRET_KEY`**, kept separately from the other two, for example in a password manager or secret store.

### Database backup

```sh
pg_dump --format=custom --no-owner --file=ultrivly-$(date +%F).dump "$DATABASE_URL"
```

### Restore

1. Stop the API and worker containers.
2. Restore into an empty database:

   ```sh
   createdb ultrivly_restored
   pg_restore --no-owner --exit-on-error --dbname=postgres://…/ultrivly_restored ultrivly-2026-11-05.dump
   ```

3. Restore file storage from the same point in time. Files newer than the database are harmless. Files missing from storage show up as download errors and as `missing_attachments` in exports.
4. Point `DATABASE_URL` at the restored database. Run `ultrivly migrate status` with the same version you backed up; it should report every migration as applied.
5. Start the containers with the original `ULTRIVLY_SECRET_KEY`.

This procedure was rehearsed against the performance dataset below (5 tenants, 147,000 cases, 416,000 messages). The dump took 2 seconds and produced 41 MB, the restore took 4.5 seconds, the schema was reported current, and row counts matched exactly. Rehearse a restore on a schedule; a backup you haven't restored is only a hope.

Deleted data stays in backups until those backups expire. Set backup retention to match what you promise customers. See [Data lifecycle](data-lifecycle.md).

## Performance baseline

`examples/load.rs` seeds a throwaway database and measures API latency.

```sh
cargo build --release --bin ultrivly --example load
DATABASE_URL=postgres://…/perf ./target/release/ultrivly migrate
DATABASE_URL=postgres://…/perf ./target/release/examples/load seed --throwaway-database
ULTRIVLY_RATE_LIMIT_PER_CALLER=0 ULTRIVLY_RATE_LIMIT_PER_IP=0 ./target/release/ultrivly serve   # in another terminal, with the usual settings
LOAD_API_KEY=… ./target/release/examples/load run --org … --workspace … --seconds 60 --concurrency 32
```

`seed` creates 5 organizations, each with 20,000 cases, 4,000 contacts and 80,000 messages. `run` sends a fixed mix of requests through an API key: list, search, filter, get, create case, and reply.

### Results (2026-11-05)

Setup: one API process (release build, 20 database connections) and PostgreSQL 18 on the same Apple M4 laptop (10 cores, 16 GB). Rate limits off. 32 concurrent clients for 60 seconds.

| Endpoint | Requests | Errors | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| List cases (`GET /cases?limit=50`) | 97,852 | 0 | 4.4 ms | 6.3 ms | 9.2 ms |
| Search cases (`?q=word`) | 64,526 | 0 | 4.6 ms | 6.8 ms | 9.5 ms |
| Filter cases (status and priority) | 49,000 | 0 | 5.1 ms | 8.9 ms | 11.2 ms |
| Get case | 65,030 | 0 | 3.7 ms | 5.4 ms | 8.1 ms |
| Create case | 32,521 | 0 | 12.3 ms | 31.5 ms | 101.4 ms |
| Add reply | 16,126 | 0 | 6.0 ms | 9.1 ms | 14.2 ms |

Total: 325,055 requests, about 5,400 requests per second.

Query plans were checked at this volume. Listing and search use the primary key or `cases_search_idx` for large tenants and the organization-scoped indexes for small ones, so a small tenant doesn't scan other tenants' rows. Creating a case is the slowest call, because it writes the case, its history entry, the outbox event and possibly a new contact in one transaction.

These figures come from a single laptop with the database on the same machine. Treat them as a regression baseline, not as a capacity promise. Before launch, repeat the run on production-like hardware with network latency to the database, and record the results here.
