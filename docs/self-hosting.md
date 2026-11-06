# Self-hosting Ultrivly

Ultrivly ships as one container image that runs three roles from the same binary:

| Role | Command | What it does |
|---|---|---|
| Migrations | `ultrivly migrate` | Applies database migrations, then exits. Run it before starting a new version. |
| API | `ultrivly serve` | Serves the HTTP API on port 8080. Run as many copies as you need. |
| Worker | `ultrivly worker` | Sends email, delivers webhooks, runs workflows, builds exports, checks SLAs and cleans up. Run at least one. |

For a small install, `ultrivly serve --with-worker` runs the API and the worker in one process.

## Requirements

- **PostgreSQL 15 or newer.** Ultrivly is tested on 15 and 18. It needs its own database and a user that owns it.
- **File storage** for attachments and exports: an S3-compatible bucket (AWS S3, MinIO, Cloudflare R2, and so on) or a local directory. With more than one API or worker container, the directory must be shared storage.
- **An SMTP server** for outgoing email.
- **HTTPS in front of the API**, from a reverse proxy or load balancer. Session cookies are marked `Secure` only when `ULTRIVLY_PUBLIC_URL` uses `https`.
- About 256 MB of memory per process to start with. See [Operations](operations.md#performance-baseline) for capacity figures.

## Install with Docker Compose

`deploy/compose.yaml` runs Postgres, the migration step, one API container and one worker. The containers use a read-only root filesystem, drop all Linux capabilities and run as an unprivileged user.

1. Build the image from the repository root, or set `ULTRIVLY_IMAGE` to an image you have published:

   ```sh
   docker build -t ultrivly:latest .
   ```

2. Create the environment file and fill it in:

   ```sh
   cp deploy/.env.example deploy/.env
   docker run --rm ultrivly:latest secret-key
   ```

   Put the printed key in `ULTRIVLY_SECRET_KEY`, choose a strong `POSTGRES_PASSWORD`, and set `ULTRIVLY_PUBLIC_URL` and the mail settings. **Store the secret key somewhere safe, separately from your backups.** It encrypts stored secrets such as SSO client secrets, webhook secrets and API keys for AI providers. Without it, those values cannot be recovered.

3. Start everything:

   ```sh
   docker compose -f deploy/compose.yaml up -d
   docker compose -f deploy/compose.yaml ps
   ```

   The API is healthy once `GET /readyz` returns `{"status":"ready"}`.

4. Point your reverse proxy at port 8080 (or `ULTRIVLY_PORT`) and set `ULTRIVLY_TRUSTED_PROXY_HOPS` to the number of proxies in front of Ultrivly. With the wrong value, rate limits and audit logs see the proxy's address instead of the client's.

The first person to sign up can then create an organization.

## Running without Compose

Any orchestrator works. For each version:

1. Run `ultrivly migrate` once and wait for it to exit with code 0.
2. Start or roll the API and worker containers with the same environment.

Health checks:

| Check | Endpoint | Meaning |
|---|---|---|
| Liveness | `GET /healthz` | The process is running. |
| Readiness | `GET /readyz` | The database is reachable and its schema matches this version. Returns 503 otherwise. |

The image's built-in `HEALTHCHECK` runs `ultrivly probe`, which requests `/readyz`. Disable it for worker containers, because the worker serves no HTTP.

API and worker processes stop cleanly on `SIGTERM`: in-flight requests and the current job finish first. A job interrupted by a hard kill is retried once its five-minute lease expires.

## Reaching internal systems

On a self-hosted install, outbound requests (webhooks, plugins, SSO discovery, AI providers) may only reach public HTTPS addresses unless you allow more. To let them reach hosts on your network, list those hosts:

```sh
ULTRIVLY_NET_ALLOW=hr.internal:443,10.0.4.12:8443,llm.internal
```

Listed hosts may use private addresses and plain `http`. Redirects are never followed.

## Upgrading

1. Read the release notes for the version you are moving to.
2. Take a backup (see [Operations](operations.md#backups-and-restore)).
3. Run the new version's `ultrivly migrate`.
4. Roll the API and worker containers to the new version.

New versions refuse to start against a database whose schema doesn't match, and say to run `ultrivly migrate`. `ultrivly migrate status` lists applied and pending migrations, and exits with 1 if anything is pending or unknown.

Migrations only move forward. To roll back, restore the backup from step 2 and run the previous version. Applied migrations are checksummed, so a database migrated by a modified build is reported as not matching.

## Configuration reference

Every setting can be passed as an environment variable or as a command-line flag (`--database-url`, and so on).

### Required

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection URL. |
| `ULTRIVLY_SECRET_KEY` | Base64 32-byte key that encrypts stored secrets. Generate one with `ultrivly secret-key`. Never change it on an existing install. |
| `ULTRIVLY_PUBLIC_URL` | Public base URL, for example `https://support.example.com`. Used for links, cookies, SSO and passkeys. It must be a hostname, not an IP address. |
| `ULTRIVLY_STORAGE_URL` | `s3://bucket[/prefix]`, `file:///absolute/path`, or `memory://` (development only). |
| `ULTRIVLY_MAIL_URL` | `smtps://user:pass@host:465`, `smtp://user:pass@host:587?tls=required`, or `log://` (development only; not allowed on the cloud deployment). |

### Optional

| Variable | Default | Description |
|---|---|---|
| `ULTRIVLY_DEPLOYMENT` | `self_hosted` | `cloud` or `self_hosted`. `cloud` requires `https`, forbids `log://` email and ignores `ULTRIVLY_NET_ALLOW`. |
| `ULTRIVLY_BIND` | `0.0.0.0:8080` | Address the API listens on. |
| `ULTRIVLY_TRUSTED_PROXY_HOPS` | `0` | Number of reverse proxies whose `X-Forwarded-For` entries are trusted. |
| `ULTRIVLY_RATE_LIMIT_PER_CALLER` | `1200` | Requests per minute for one API key or session. `0` disables the limit. |
| `ULTRIVLY_RATE_LIMIT_PER_IP` | `3000` | Requests per minute from one client address. `0` disables the limit. |
| `ULTRIVLY_MAIL_FROM` | `Ultrivly <no-reply@localhost>` | Sender for account email, and the envelope sender for all email. |
| `ULTRIVLY_MAIL_EVENTS_SECRET` | unset | Secret for signed bounce and complaint events. While unset, `/api/v1/mail/events` returns 404. See [Email](email.md). |
| `ULTRIVLY_NET_ALLOW` | empty | Self-hosted only. Comma-separated hosts outbound requests may reach on private networks or over plain `http`. |
| `ULTRIVLY_METRICS_BIND` | unset | Serves Prometheus metrics at `/metrics` on this address, for example `0.0.0.0:9090`. Keep it off the public network. |
| `ULTRIVLY_DB_MAX_CONNECTIONS` | `10` | Database connections per process. |
| `ULTRIVLY_DB_ACQUIRE_TIMEOUT_SECS` | `5` | How long a request waits for a free database connection. |
| `ULTRIVLY_GOOGLE_CLIENT_ID`, `ULTRIVLY_GOOGLE_CLIENT_SECRET` | unset | Enables "Sign in with Google". |
| `ULTRIVLY_LOG_FORMAT` | `text` (`json` in the image) | `json` writes one JSON object per log line. |
| `RUST_LOG` | `info` | Log level, for example `info` or `warn,ultrivly=debug`. |
| `TMPDIR` | `/tmp` | Where the worker writes export archives before uploading them. It needs room for the largest organization's export. |

### S3-compatible storage

With `ULTRIVLY_STORAGE_URL=s3://bucket`, credentials and endpoints come from the standard AWS variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and for non-AWS services `AWS_ENDPOINT` (for example `https://minio.internal:9000`). If the endpoint uses plain `http`, also set `AWS_ALLOW_HTTP=true`. Enable versioning or replication on the bucket if you want file history beyond your own backups.

## Command reference

| Command | Purpose |
|---|---|
| `ultrivly serve [--with-worker]` | Run the API. |
| `ultrivly worker` | Run background jobs. |
| `ultrivly migrate [run \| status]` | Apply or inspect migrations. |
| `ultrivly purge` | Permanently delete everything whose retention period has ended, including files. The worker also does this every 15 minutes. |
| `ultrivly jobs stats \| list \| retry` | Inspect and retry background jobs across all organizations. |
| `ultrivly mail suppressions \| suppress \| unsuppress` | Manage the email suppression list. |
| `ultrivly probe [--url]` | Exit 0 if the readiness endpoint answers 200. |
| `ultrivly secret-key` | Print a new random secret key. |
