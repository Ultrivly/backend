# Ultrivly Backend Architecture

> **Status:** Proposed — the crate is currently an empty scaffold. This document describes the intended shape of the backend so that the first modules land in the right place.
> **Source of requirements:** [PRODUCT.md](PRODUCT.md). Section references (§) point there.
> **Labels:** **Decided** = reflected in the repo today. **Proposed** = recommended starting point, validate with a spike. **Open** = needs a decision.

## 1. Summary

The backend is a **modular monolith written in Rust**: one codebase and one binary, with strict internal module boundaries, a PostgreSQL database, and background workers running from the same binary. It serves the versioned HTTP API used by the web app, requesters, and third-party integrations.

```
                 ┌──────────────────────────────────────────────┐
  Web app ──────▶│                ultrivly (serve)              │
  API clients ──▶│  HTTP layer → tenant/auth context → modules  │──┐
  Webhooks in ──▶│                                              │  │
                 └──────────────────────────────────────────────┘  │
                                                                   ▼
                 ┌──────────────────────────────────────────────┐ ┌────────────┐
                 │               ultrivly (worker)              │ │ PostgreSQL │
                 │  job queue → workflows, webhooks, email,     │◀▶│ data, jobs,│
                 │  reports, search indexing                    │ │ search     │
                 └──────────────────────────────────────────────┘ └────────────┘
                                   │
                                   ▼
                     S3-compatible object storage (attachments)
                     Outbound (signed HTTPS): webhook targets, webhook plugins,
                     email, AI providers

  Same binary and dependencies on Ultrivly cloud and on self-hosted installs.
```

### 1.1 Departure from PRODUCT.md §7.1

PRODUCT.md proposes a TypeScript API. This repository is a Rust crate (`Cargo.toml`, edition 2024), so the backend is planned in Rust. The rest of §7.1 still applies: PostgreSQL, a Postgres-backed job queue, Postgres search first, S3-compatible storage, OpenAPI, and containers. The web front end can remain TypeScript/React and talk to this service only through the documented API.

### 1.2 Addition beyond PRODUCT.md: plugins

PRODUCT.md §4.4 describes custom integrations through the API and webhooks only. This design adds a **plugin system** (section 10) so organizations can connect Ultrivly to their internal services. Plugins are either built into the binary by Ultrivly or provided by the customer as a webhook service. Ultrivly never runs customer code, so PRODUCT.md's rule against running customer code inside the core process still holds.

## 2. Technology choices

| Concern | Choice | Status | Notes |
|---|---|---|---|
| Language | Rust (edition 2024) | Decided | From `Cargo.toml`. |
| Async runtime | `tokio` | Proposed | |
| HTTP framework | `axum` + `tower` middleware | Proposed | Middleware stack handles request IDs, tracing, limits, auth. |
| Database | PostgreSQL 15 or newer | Decided | Single primary for the prototype. 15 is needed for `UNIQUE NULLS NOT DISTINCT`; no extensions required. |
| Data access | `sqlx` 0.9 | Decided | SQL migrations in `migrations/`. Revisit if query boilerplate becomes a burden. |
| Background jobs | Postgres table polled with `FOR UPDATE SKIP LOCKED` | Proposed (§7.1) | No extra infrastructure. Move to a dedicated queue only if load justifies it. |
| Search | Postgres full-text search (`tsvector`) | Proposed (§7.1) | Dedicated engine only if needed. |
| Object storage | S3-compatible API behind a `BlobStore` trait | Proposed (§7.1) | Local filesystem implementation for dev and small self-hosted setups. |
| API description | OpenAPI generated from code (e.g. `utoipa`) | Proposed | Published per API version. |
| Auth | Argon2id (`argon2`), OpenID Connect (`openidconnect`), AES-256-GCM for stored secrets (`aes-gcm`), TOTP per RFC 6238 | Decided | Implemented in `identity::{accounts, sessions, mfa, passkeys, sso}` (section 13). |
| Passkeys | `webauthn-rs` | Decided | Needs the OpenSSL C library at build time (standard on Linux images; `brew install openssl` on macOS). |
| Observability | `tracing` + OpenTelemetry export | Proposed (§6.3) | JSON logs with request/trace IDs. |
| Packaging | Container image; single static binary | Proposed | Exact self-hosted packaging is Open (§13.4). |
| Plugins | Built-in Rust modules + signed webhook calls | Decided | No runtime code loading (section 10). |

## 3. Process model

A single binary, `ultrivly`, with subcommands:

- `ultrivly serve` — HTTP API.
- `ultrivly worker` — runs background jobs and scheduled triggers.
- `ultrivly migrate [run]` — applies pending migrations. Migrations are embedded in the binary, and an advisory lock makes concurrent runs safe.
- `ultrivly migrate status` — lists migrations; exits with 1 unless the database exactly matches this build (usable as a deploy gate).
- `ultrivly serve [--with-worker]` — the HTTP API (section 13.1). Refuses to start against a schema that does not match the build, or with unsafe settings (http public URL or log mailer on Ultrivly cloud).
- `ultrivly worker` — background jobs: email delivery, expired-token cleanup, and purging deleted data every 15 minutes.
- `ultrivly purge` — runs one purge immediately (section 7.1); the worker already does this on schedule.
- `ultrivly secret-key` — prints a new `ULTRIVLY_SECRET_KEY`.

Small self-hosted installs can run both in one process with `serve --with-worker`. Ultrivly cloud scales the two roles independently. Every role reads the same configuration and connects to the same database. There are no other components to deploy (section 14.1).

## 4. Module layout

Each module maps to a boundary in PRODUCT.md §7.2. Modules are folders under `src/` that expose a narrow public API (service functions and types). Other modules call that API and never touch another module's tables directly.

```
src/
├── main.rs              # CLI entry: serve / worker / migrate
├── config.rs            # Environment-based configuration
├── http/                # Router, middleware, error mapping, API versioning
├── platform/            # Shared kernel — used by every module
│   ├── tenant.rs        #   TenantContext (org, workspace, actor)
│   ├── authz.rs         #   Permission checks (the only place they live)
│   ├── db.rs            #   Pool, transactions, tenant-scoped helpers
│   ├── jobs.rs          #   Job queue: enqueue, claim, retry, dead-letter
│   ├── events.rs        #   Domain events (outbox) consumed by workflows/webhooks
│   ├── blob.rs          #   BlobStore trait + S3 / filesystem implementations
│   ├── secrets.rs       #   Encryption of stored credentials
│   └── net.rs           #   Safe outbound HTTP client (SSRF guard, self-hosted allowlist)
├── identity/            # Users, sessions, MFA, OAuth/SSO, orgs, workspaces, roles
├── cases/               # Cases, messages, internal notes, attachments, history
├── routing/             # Teams, departments, queues, assignment
├── knowledge/           # Articles, categories, visibility, search
├── workflows/           # Definitions, validation, execution engine
├── integrations/        # API credentials, webhooks, built-in connectors
├── plugins/             # Plugin trait, installs, grants, webhook plugin protocol
│   └── builtin/         #   Built-in plugins compiled into the binary
├── reporting/           # Metric definitions and report queries
├── channels/            # Intake adapters: web, API, later email/chat/social
├── audit/               # Audit event writing and querying
└── ai/                  # Provider adapters — added in Phase 3 only
```

**Dependency rules**

- Every module may depend on `platform`. `platform` depends on no feature module.
- Feature modules depend on each other only through public service functions, never through SQL against another module's tables.
- Cross-module reactions (for example, a case update triggering a workflow or webhook) go through domain events, not direct calls. This keeps `cases` unaware of `workflows` and `integrations`.
- If compile times or ownership boundaries call for it, a module can become its own crate in a Cargo workspace without changing its public API.

## 5. Request lifecycle

1. **Edge middleware:** assign a request ID, start a tracing span, enforce body-size limits and timeouts.
2. **Authentication:** resolve a session cookie or API credential into an `Actor` (user, API credential, or system/workflow).
3. **Tenant resolution:** load the actor's organization membership and build a `TenantContext`. A client-supplied organization ID is never trusted without this check (§5.2).
4. **Rate limiting:** per credential and per organization.
5. **Handler:** parse and validate input into typed request structs, then call a module service with `&TenantContext`.
6. **Service:** check permissions through `platform::authz`, run the change in a transaction, and write audit and domain events in **the same transaction**.
7. **Response:** map domain errors to the documented error format. Never expose stack traces or secrets (§5.4).

## 6. Multi-tenancy and authorization

Tenant isolation is the main security requirement (§5.2). It is enforced in layers:

- **Schema:** every tenant-owned table has a non-null `org_id`. Workspace-scoped tables also have `workspace_id`. Composite foreign keys include `org_id` so a row cannot reference another tenant's row.
- **Types:** service functions require a `TenantContext`. Repository functions take it and always filter by `org_id`. No public function loads a tenant-owned row by ID alone.
- **Authorization:** one permission model in `platform::authz` (role → permission set, scoped to organization and optionally workspace). Handlers, jobs, workflow actions, exports, and integration callbacks all use it (§3.3, §7.2). Permission names and the built-in roles (Administrator, Team lead, Agent, Knowledge editor, Developer, Auditor) are defined there in code; each organization gets its own copy of the built-in roles when `identity::create_organization` sets it up. Organizations can also define **custom roles** (`identity::roles`): any set of permissions, unique names per org (case-insensitive), and changes apply to members immediately. Built-in roles cannot be edited or deleted, a role still assigned to members cannot be deleted, every change needs `roles.manage` and is audited, and **nobody can grant a permission they do not hold themselves**, so role management cannot be used to escalate access. `authz::effective_permissions` / `authz::require` are the single place permissions are checked; a role granted in one workspace applies only there. Roles are given to members with `identity::members` (org-wide or per workspace): this needs `users.manage` in that scope, the actor must hold every permission in the role to assign *or remove* it, and the last active Administrator cannot lose the role. Services check permissions themselves rather than trusting their caller.
- **Background work:** every job payload carries `org_id` and the acting principal. Workers rebuild a `TenantContext` before doing anything.
- **Storage and caches:** object keys are prefixed `org/{org_id}/…`, and cache keys include `org_id`.
- **Defense in depth (Proposed):** Postgres row-level security with a per-transaction `app.org_id` setting. It supplements, but does not replace, application checks.
- **Platform operators** get no implicit access to customer content (§3.1).

Cross-tenant tests are a required suite. They cover reads, writes, search, attachments, exports, and indirect object references (§10).

## 7. Data model (initial)

Core entities for Phase 0–1. Exact columns come with migrations.

- **Identity:** `organizations`, `workspaces`, `users`, `memberships`, `roles`, `role_permissions`, `sessions`, `auth_identities` (OAuth/SSO links), `mfa_factors`.
- **Routing:** `teams`, `team_members`, `queues`.
- **Cases:** `cases`, `case_messages` (with `visibility`: public or internal), `case_events` (append-only history), `attachments`, `case_links`.
- **Knowledge:** `kb_categories`, `kb_articles` (with `visibility` and `state`: draft, published, archived).
- **Workflows:** `workflows`, `workflow_versions` (published definitions are immutable), `workflow_runs`, `workflow_run_steps`.
- **Integrations:** `api_credentials` (stores a hash only), `webhook_endpoints`, `webhook_deliveries`.
- **Platform:** `jobs`, `domain_events` (outbox), `audit_events`, `idempotency_keys`, `blob_deletions`.

Conventions:

- IDs are UUIDv7: sortable and not guessable. Cases also get a per-organization human-readable number (`#1042`).
- Statuses and priorities are stored as data so they can become configurable later. **Decided:** they are defined per organization, not per workspace, for now; per-workspace lists can be added later as an optional `workspace_id`. Every new organization gets New/Open/Pending/Resolved/Closed and Low/Normal/High/Urgent. Business logic keys off a status's *category* (open, pending, resolved, closed), never its display label (§4.1).
- Plan names, seat limits, and caps are not hard-coded. Any future entitlement checks go through one place (§12).

### 7.1 Deletion and retention

**Decided:** deletes are allowed, require confirmation, and become permanent after a short retention period. Implemented in `platform::deletion` for organizations, workspaces, cases, and attachments.

1. **Authorize and confirm.** Deleting or restoring needs `organization.delete`, `workspaces.manage` (both org-wide), `cases.delete`, or, for an attachment, `cases.edit` (these two may come from a role in the case's workspace). While an organization is scheduled for deletion its members have no access, except that holders of `organization.delete` can still restore it. The caller must also repeat a human-readable identifier: the org or workspace slug, the case number, or the attachment's file name. A mismatch is refused. This is enforced on the server, not only in the UI.
2. **Soft delete.** The row gets `deleted_at` and `purge_after` (default **7 days** later, `DEFAULT_RETENTION`). Application queries must treat it, and everything under it, as gone. An audit event is written.
3. **Restore.** Until `purge_after`, an authorized user can restore it unchanged.
4. **Purge.** `ultrivly purge` deletes expired rows. Foreign keys cascade to everything the row owns: an organization takes all its tenant data, including its own audit trail; a workspace takes its teams, queues, and cases; a case takes its messages, history, and attachments. The purge itself is audited, at platform level for organizations.
5. **Files.** Every deleted attachment row queues its object key in `blob_deletions` from a trigger, in the same transaction, and an organization purge also queues its whole `org/<id>/` prefix. The purge then removes them from object storage (S3, an S3-compatible server, or local disk), retrying failures with backoff, so no file is left behind.

Not yet covered: data still present in database backups until they expire (backup expiry is an open decision), per-organization retention settings, and deleting users and contacts, which needs an anonymization rule for the messages they wrote.

## 8. Events, jobs, and workflows

### 8.1 Domain events (transactional outbox)

State changes write a row to `domain_events` in the same transaction as the change. A dispatcher in the worker reads new events and fans them out into jobs: workflow trigger evaluation, webhook delivery, and search reindexing. This guarantees that no event is lost and none is emitted for a rolled-back change.

### 8.2 Job queue

- Jobs are stored in Postgres and claimed with `SELECT … FOR UPDATE SKIP LOCKED`.
- Each job has a type, a payload (including `org_id`), an attempt count, `run_at`, and a dedupe key.
- Failed jobs retry with bounded exponential backoff, then move to a dead state that admins can inspect and retry manually (§10 Reliability).
- Scheduled workflow triggers are jobs with a future `run_at`.

### 8.3 Workflow engine

- A published workflow version is an immutable JSON definition: trigger, conditions, and actions. The visual builder edits drafts; publishing validates the draft and creates a new version.
- Conditions and actions come from a fixed, typed set (§4.2), extended only by actions that installed plugins declare in their manifests (section 10). Plugin actions run as jobs, calling either a built-in plugin or a webhook plugin.
- **Loop protection:** each run carries a causation chain and depth. Changes made by a workflow are tagged with it. Runs stop past a depth limit, and a per-organization execution budget caps runaway volume.
- **Idempotency:** each (workflow version, triggering event) pair runs at most once.
- Actions run with the workflow's own principal and pass through `authz`. External calls go through `platform::net` with scoped credentials.
- Every run records its trigger, each step's outcome, and errors with secrets redacted.

## 9. Integrations and the public API

- **Versioning:** URL-prefixed (`/api/v1/…`). Breaking changes require a new version.
- **Conventions:** resource-oriented paths, cursor pagination, consistent filtering, and one error envelope with a request ID.
- **Idempotency:** `Idempotency-Key` header on create endpoints. The stored response is replayed for retries.
- **API credentials:** shown once at creation and stored as a hash. They carry scopes, can be revoked (taking effect on the next request), and record last-used time.
- **Webhooks:** per-organization endpoints with selected events. Payloads are signed with HMAC-SHA256 and a timestamp. Delivery uses the job queue with bounded retries. Delivery logs support manual retry. Secrets can be rotated with an overlap window.
- **Outbound safety (`platform::net`):** only `https` is allowed. Resolved IPs are checked against private, loopback, and link-local ranges both before connecting and after redirects. Redirects are limited, and timeouts and response sizes are capped (§4.4).
- **Private networks:** `platform::net` blocks private addresses by default. Self-hosted operators can allow specific internal hosts through configuration; on Ultrivly cloud this is always off. See section 10.5.
- **Custom code:** never runs inside this process (§4.4). Extensibility is through the API, webhooks, and plugins (section 10).

## 10. Plugins

Plugins let an organization extend Ultrivly with its own logic and connect it to internal systems, such as looking up a requester in an employee directory, creating a ticket in an internal tool, or checking an asset inventory.

There are exactly two kinds of plugin, and both work the same way on Ultrivly's cloud and on self-hosted installs:

| Kind | Where the code lives | Who writes it |
|---|---|---|
| **Built-in** | Rust code compiled into the `ultrivly` binary | Ultrivly |
| **Webhook** | An HTTPS service the customer hosts and registers with Ultrivly | The customer or a third party |

Ultrivly never loads or runs plugin code at runtime. There is no sandbox, script engine, or dynamic library loading, which keeps PRODUCT.md §4.4's rule that customer code does not run inside the core process.

### 10.1 What a plugin can do

Both kinds expose the same **capabilities**, so the rest of the system (workflow builder, case view, audit) treats them identically:

- **Workflow actions and conditions** (e.g. "Provision account in internal IAM"), shown in the visual builder with typed input fields.
- **Event subscriptions** (case created, status changed, …).
- **Lookups** that enrich a case, such as requester details or related assets, shown read-only in the case view.
- **Calls to the Ultrivly API** using a token limited to the scopes the admin approved.

Each plugin has a versioned **manifest** listing its capabilities, requested API scopes, and a configuration schema. Anything not declared is refused. Secret configuration fields are encrypted with `platform::secrets` and never shown again.

### 10.2 Built-in plugins

- Live in `src/plugins/builtin/<name>/` and implement a `Plugin` trait (manifest, `handle_event`, `run_action`, `lookup`). They are registered in a static list at compile time.
- Every built-in plugin ships in every build. Whether it is available is decided per organization by configuration, never by a separate build for cloud or self-hosted.
- They use `platform::net`, `platform::secrets`, and `platform::authz` like any other module, with no special privileges.
- Good fits: integrations many customers need (e.g. common identity providers, ticketing or chat tools), chosen from pilot feedback (§13.2).

### 10.3 Webhook plugins

- An admin registers a plugin by giving its base URL. Ultrivly fetches the manifest from `GET {base}/manifest`, shows the requested access, and the admin approves it.
- Ultrivly calls the plugin with `POST` requests for events, actions, and lookups. Requests are signed with HMAC-SHA256 plus a timestamp, using the same scheme as ordinary webhooks (section 9), so a recipient can reuse the same verification code.
- Event deliveries are one-way, like a normal webhook. Actions and lookups expect a JSON response within a timeout, and the response is validated against the schema in the manifest.
- To change data in Ultrivly, the plugin calls the public API with its install token. This keeps every write on the same validated, audited path as any other API client.
- The request/response format lives in a `plugin_protocol` module and is published as part of the OpenAPI document, so plugins can be written in any language.

### 10.4 Installation and permissions

- Plugins are installed **per organization**, optionally limited to specific workspaces.
- An admin approves the requested scopes and subscriptions. If a webhook plugin's manifest later asks for more access, the new access stays off until an admin re-approves it.
- Each install runs as its own principal (`Actor::Plugin`). Everything it does passes through `platform::authz` and is written to `audit`, the same as a person or workflow.
- Disabling an install takes effect immediately: no further calls, and its API token is revoked.
- Data model: `plugin_installs` (built-in name or webhook base URL, manifest snapshot, config), `plugin_grants`, `plugin_invocations` (execution log, secrets redacted).

### 10.5 Reaching internal services

- **Built-in plugins and webhook calls use the same outbound rules as all other traffic** (`platform::net`): HTTPS only, and private, loopback, and link-local addresses are blocked by default.
- **Self-hosted:** an operator can allow specific private hosts through configuration (e.g. `ULTRIVLY_NET_ALLOW=hr.internal:443,10.0.4.12:8443`). Because Ultrivly runs inside the customer network, this is how plugins reach internal services there.
- **Ultrivly cloud:** the allowlist is disabled, and private ranges are always blocked. To connect internal services, the customer exposes their webhook plugin at a public HTTPS address (for example through their existing reverse proxy or API gateway). That plugin then talks to internal systems on its side. Customers can verify that requests come from Ultrivly using the signature and the published list of outbound IP addresses.

### 10.6 Reliability and limits

- Plugin calls from workflows and event subscriptions run as jobs, with the same retry, dead-letter, and idempotency rules (section 8.2). The invocation ID is sent with each call so webhook plugins can ignore duplicates.
- Lookups in the case view are synchronous with a short timeout. A slow or failing plugin shows "unavailable" in its panel and never blocks loading or saving a case.
- Per-install rate limits and concurrency caps. Repeated failures pause the install automatically and notify admins.
- The plugin protocol is versioned separately from the public API. Ultrivly supports at least the current and previous version.

### 10.7 Build order

1. `Plugin` trait, manifest format, installs and grants, and the plugin protocol.
2. Webhook plugins, reusing the existing webhook signing and delivery code.
3. The first one or two built-in plugins, picked from pilot needs.
4. Later: example webhook plugins and SDK helpers in TypeScript and Rust.

## 11. Channels

Every case has a `source_channel`. Channel adapters in `channels/` convert inbound traffic into calls to `cases` services and send outbound replies; they hold no case logic. Web and API intake come first. Email, chat, and social adapters follow the order still to be decided (§13.1). Adapters for inbound providers that send webhooks verify each provider's signature.

## 12. Search and reporting

- **Search:** Postgres full-text indexes on cases and articles. Every query includes tenant and visibility filters inside SQL, so unauthorized titles or snippets never reach the application (§4.3).
- **Reporting:** metric definitions live in code and documentation together (§4.5). Heavy reports run as jobs or against a read replica so they do not slow case operations. Pre-aggregated rollup tables are added once data volume requires them.

## 13. Security foundations

Authentication is implemented as library services in `identity`; the HTTP layer will call them.

- **Passwords** (`identity::accounts`): Argon2id; at least 12 characters, not the email address. Wrong password, unknown email, and disabled account all return the same error after the same Argon2 work, so responses do not reveal which emails are registered. After 5 failures an email address is locked for 1 minute, doubling up to an hour. Unknown addresses are throttled the same way.
- **Email verification and password reset**: single-use tokens, of which only the SHA-256 is stored, with expiry (3 days and 1 hour). Only the newest reset link works. A reset signs the user out everywhere, and a password change signs out every other session. Sending the email is the caller's job: the functions return the token.
- **Sessions** (`identity::sessions`): 256-bit random tokens for an `HttpOnly`, `Secure`, `SameSite` cookie; only their hash is stored. They expire after 30 days, or after 7 days unused. Each records its sign-in method, and can be revoked singly or all at once.
- **MFA** (`identity::mfa`, `identity::passkeys`): authenticator apps (TOTP) and passkeys/security keys (WebAuthn), plus 10 single-use recovery codes stored as hashes and issued with the first factor.
  - *Authenticator apps*: each code is accepted once.
  - *Passkeys*: each ceremony has an encrypted, single-use, 5-minute challenge, and the library verifies origin, signature and user verification. A credential can belong to only one account.
  - *Sign-in*: 5 attempts per challenge, across either factor.
  - *Changing factors*: with MFA already on, adding a factor, removing one or regenerating recovery codes needs the password or a current code.
  - *At rest*: TOTP seeds and passkey credentials are encrypted.
- **Single sign-on** (`identity::sso`), OpenID Connect with discovery, PKCE, and verified signature, issuer, audience, expiry, and nonce:
  - *Enterprise connections* per organization (Okta, Entra ID, Google Workspace, Keycloak, …), managed with `security.manage`. Each has optional email-domain restrictions, optional just-in-time provisioning with a default role (no-escalation rule applies), and can be enabled, disabled, or enforced. The client secret is encrypted.
  - *Social providers* (Google) configured by the operator.
  - Identities are matched by (issuer, subject). An organization's provider never takes over an existing account by email: the account owner links it while signed in. Social providers link by email only when both the provider and the account have verified it.
  - Return paths after sign-in must be same-site paths.
- **Organization policies** (`sessions::check_org_access`, called by the API layer for every org-scoped request alongside permission checks):
  - *Require MFA*: password and social sessions need a verified second factor. Sessions through the organization's own SSO rely on the provider's MFA.
  - *Enforce SSO*: members must use one of the enforced connections. Holders of `security.manage` are exempt as break-glass in case the provider fails.
- **Stored secrets** (`platform::secrets`): AES-256-GCM under `ULTRIVLY_SECRET_KEY` (`ultrivly secret-key` generates one). Each ciphertext is bound to its row, so copying it elsewhere fails to decrypt. Key rotation and KMS support are later work. Secrets are never returned after creation and never logged.
- **Outbound requests** (`platform::net`): https only, with private, loopback, and link-local addresses refused both for IP literals and after DNS resolution. No redirects; capped time and size. Self-hosted operators can trust specific internal hosts (`ULTRIVLY_NET_ALLOW`); Ultrivly cloud ignores that list.
- Audit events (§5.3) are written in the same transaction as the action they describe; account events (sign-up, sign-in, MFA and password changes, linking) are platform-level. Retention and tamper resistance are Open (§13.7).
- Release process: `cargo audit` / `cargo deny` and dependency review.

- **Invitations** (`identity::invitations`): need `users.manage` in scope, plus every permission in the role (no escalation). They expire after 7 days, and inviting the same address again replaces the old link. Accepting requires being signed in with the invited address and holding the emailed token, and marks that email verified. An invitation never lifts a suspension.
- **Account pre-hijacking**: linking an SSO identity requires a verified email. A password reset on an unverified account (proof of inbox control) removes linked identities and MFA that someone else may have attached.
- **Email** (`platform::mail`, sent only by the worker): SMTP for production; `log://` for development only, refused on cloud. Plain text, with tokens in URL fragments so they never reach server logs. Queued email payloads are encrypted and cleared once sent. Users are notified when their password changes or MFA is turned off.

### 13.1 HTTP API security (`http`)

- **Cookies**: `__Host-` prefixed over https (no subdomain can set or override them), `HttpOnly`, `Secure`, `SameSite=Lax`.
- **CSRF**: state-changing requests are refused if `Origin` is another site or `Sec-Fetch-Site` is `cross-site`. Requests carrying our cookies must show an `Origin`/`Referer` from this site. Bodies must be `application/json`, which HTML forms cannot send cross-site.
- **SSO login CSRF**: the OIDC state is bound to the browser with a cookie, and the callback rejects a mismatched state. Errors redirect to `/sign-in?error=<code>` with no detail.
- **Enumeration**: sign-up and "forgot password" always answer `202 check_your_email`. The reset lookup happens in the worker, so timing is identical. A sign-up with a taken address emails the owner instead.
- **Rate limits** (PostgreSQL-backed, so they hold across instances; IPv6 per /64): sign-in 30/10 min per IP, plus the per-email lockout; sign-up 10/h; forgot-password 10/h per IP and 3 emails/h per address; tokens 30/h; MFA codes 5/10 min per user; invitations 100/day per user and 200/day per org.
- **Re-authentication**: turning MFA off or regenerating recovery codes needs the password or a current code, so a stolen cookie alone cannot weaken the account.
- **Client IP**: the socket address, unless `ULTRIVLY_TRUSTED_PROXY_HOPS` says how many proxies' `X-Forwarded-For` entries to trust.
- **Headers on every response**: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, restrictive CSP, COOP/CORP `same-origin`, `Cache-Control: no-store`, and HSTS over https. A request ID is added to each response and to logs.
- **Logs and errors**: logs record paths only, never query strings (SSO codes). Internal errors are logged and returned as a generic message.
- **Limits**: 1 MiB request bodies, 30 s request timeout.
- **Org-scoped endpoints** call `require_org_access` (enforced SSO, required MFA) before the services check permissions.

**SAML is deliberately not supported (decided).** Safe SAML needs the xmlsec1/libxml2 C libraries for XML signature checking, and hand-written XML signature checking is the most common source of SAML vulnerabilities. OpenID Connect covers Okta, Entra ID, Google Workspace, Keycloak, OneLogin, JumpCloud, and Auth0. Revisit only if a pilot customer's identity provider cannot do OIDC.

Not yet built: API credentials for integrations.

## 14. Configuration and deployment

- All configuration comes from environment variables, optionally layered over a config file. No cloud-vendor SDK calls in business logic. Vendor-specific code lives behind `platform` traits.
- `/healthz` (process is alive) and `/readyz` (database reachable, migrations current) endpoints.
- Migrations live in `migrations/` as `<UTC timestamp>_<name>.sql`. They are forward-only: never edit an applied file (the migrator refuses a changed checksum); add a new migration instead. They are tested against representative data. Releases are written to tolerate the previous app version during rolling deploys (expand, then contract).
- The same image serves hosted and self-hosted deployments. Edition differences are configuration, not forks.

### 14.1 Cloud and self-hosted from one codebase

Ultrivly is a self-hostable SaaS: every feature must run both on Ultrivly's cloud and on a customer's own infrastructure. In practice:

- **Required dependencies are only PostgreSQL and S3-compatible storage** (or a local disk). Everything else (queue, search, cache, scheduling) is built on Postgres so a self-hosted install needs nothing more.
- **No managed-service lock-in.** Anything provider-specific (KMS, email sending, object storage, metrics export) sits behind a `platform` trait with at least one implementation that works without that provider: for example a key from configuration instead of KMS, or SMTP instead of a hosted email API.
- **Deployment mode is one setting** (`ULTRIVLY_DEPLOYMENT=cloud|self_hosted`). It controls a few security defaults (private-network allowlist, operator access, signup) and nothing else. Feature code doesn't branch on it; it reads the specific setting it needs.
- **Multi-tenant everywhere.** A self-hosted install usually has one organization, but uses the same tenant-scoped code paths, so isolation is tested in both modes.
- **Upgrades follow the same path.** Cloud and self-hosted run the same migrations and release artifacts, and self-hosted operators may run a version or two behind.
- **CI runs the test suite in both modes.**

## 15. Observability

- `tracing` spans for every request and job, carrying request ID, `org_id`, and actor ID. Personal data and secrets are not logged.
- Metrics: request latency and error rate per route, job queue depth and age, workflow success/failure, webhook delivery success, and external provider errors.
- Alerts on growing dead jobs and webhook failure spikes.

## 16. Testing strategy

| Layer | What it covers |
|---|---|
| Unit | Status transitions, workflow condition evaluation, permission resolution, signature generation. |
| Integration (real Postgres) | Repositories, transactions, outbox, job claiming, schema constraints. `#[sqlx::test]` creates a fresh database per test from `DATABASE_URL` (start one with `docker compose up -d`; see `.env.example`). |
| API contract | Responses match the OpenAPI spec; error envelope; pagination. |
| Tenant isolation | A fixture with two organizations. Every endpoint and job type is exercised across the boundary. |
| End-to-end | Phase 0 exit journey: requester submits → agent resolves → outsider is denied. |

## 17. AI (later phase)

The `ai/` module is not built until Phase 3. When it is: a provider trait with per-organization configuration and customer-supplied keys, disabled by default; every AI action goes through `authz` and `audit` as its own principal; outputs are marked as AI-generated; provider failures degrade to normal case handling (§4.7).

## 18. Open decisions affecting this design

- Rust stack confirmation (axum / sqlx / Postgres queue) — validate with a spike against the Phase 0 scope.
- Whether to adopt Postgres row-level security from the start.
- Self-hosted packaging: container only, or also a single-host bundle (§13.4).
- SAML: deferred (section 13). Reopen only for a pilot customer whose identity provider lacks OIDC.
- Audit retention and tamper-resistance requirements (§13.7).
- Degree of status and custom-field configurability in the MVP (§13.5).
- Plugins: which phase they belong to (PRODUCT.md does not schedule them).
- Which built-in plugins come first, based on the internal systems pilot customers most need.
- Whether cloud customers need a way to reach internal services that can't be exposed publicly. Webhook plugins currently require a public HTTPS endpoint on our cloud.
