# Data lifecycle

This page describes what Ultrivly stores, for how long, and how it is exported and deleted. It describes the software's behavior. It is not a compliance statement: what a given install promises its customers also depends on how that install is run, including backups, hosting region and providers.

## Where data lives

| Data | Where | Notes |
|---|---|---|
| Organizations, members, cases, messages, contacts, knowledge base, settings, audit log | PostgreSQL | Every tenant-owned row carries its organization ID. Queries are always scoped to it. |
| Attachments and export archives | File storage (`ULTRIVLY_STORAGE_URL`) under `org/{org_id}/` | Downloads go through the API and its permission checks. Files are never served directly. |
| Secrets: SSO client secrets, webhook and channel secrets, DKIM keys, AI and plugin credentials, sealed job payloads, stored idempotent responses | PostgreSQL, encrypted with AES-256-GCM using `ULTRIVLY_SECRET_KEY` | Each value is bound to its purpose, so a ciphertext can't be moved to another field. |
| Passwords, session tokens, API keys, invitation and reset tokens | PostgreSQL, as Argon2id hashes (passwords) or SHA-256 hashes (tokens) | The plaintext is shown once, if at all, and never stored. |
| Passkeys | PostgreSQL | Public keys only. |

## External services

An install only sends data to services its operator or its organizations configure:

| Service | Configured by | What is sent |
|---|---|---|
| SMTP server | Operator | Outgoing email: recipient, subject, body. |
| File storage (for example S3) | Operator | Attachments and export archives. |
| Identity providers (Google, OIDC, SAML) | Operator (Google) or organization admins | Sign-in requests. Ultrivly receives the user's identity. |
| Webhook endpoints and webhook plugins | Organization admins | Event payloads for the events they subscribe to. Plugins also get an API key limited to the permissions an admin approved. |
| Slack (built-in plugin) | Organization admins | The message text configured in a workflow. |
| AI provider (OpenAI or an OpenAI-compatible server) | Organization admins; off by default | When an agent asks for a summary or draft: the case subject, description and messages the agent can see. Internal notes are included only if the organization turns that on. OpenAI requests set `store: false`. |

Operators should list these as subprocessors where relevant, and should name the hosting provider and region.

## Retention

| Data | Kept for |
|---|---|
| Cases, messages, contacts, attachments, knowledge articles, settings | Until deleted |
| Deleted organizations, workspaces, cases and attachments | 7 days (restorable), then purged together with their files |
| Audit log | For the life of the organization. How long it should be kept is still an open product decision. |
| Data exports | 7 days after they are built. Failed exports: 7 days. |
| Webhook delivery log | 30 days |
| Dispatched domain events (internal outbox) | 30 days |
| Workflow run history | 90 days |
| Finished background jobs | 7 days. Dead jobs: 30 days. |
| Idempotency keys and their stored responses | 24 hours |
| Sessions | Up to 30 days. Ended sessions are deleted 7 days after they expire or are revoked. |
| Sign-in, reset, verification, SSO and passkey ceremony tokens | Until they expire, typically minutes to days |
| Email suppression list | Until an operator removes an entry |

The worker applies these limits every 15 minutes.

## Deleting data

Deleting an organization, workspace, case or attachment needs explicit confirmation (the item's name or slug) and the matching permission:

1. The item disappears immediately for everyone, and is kept for 7 days so it can be restored.
2. After that, the worker deletes the rows. All files are queued for deletion: for a whole organization, everything under `org/{org_id}/`, including exports. Failed file deletions are retried until they succeed.
3. Data still exists in **backups** until those expire. Operators should set backup retention to match what they tell customers. A restored backup brings deleted data back, so after a restore, delete again any data that was deleted after the backup was taken.

Removing a member stops their access immediately. Their past messages and audit entries stay, attributed to them.

## Exporting data

A member with `data.export` can request:

- **A full organization export**: `POST /api/v1/orgs/{org_id}/exports` with an empty body.
- **A contact export**, for a requester's access request: `POST /api/v1/orgs/{org_id}/exports` with `{"contact_id": "…"}`. It contains the contact, their linked identities, the cases where they are the requester (with messages, history and attachment metadata), and the files on those cases' public messages.

The worker builds a zip archive in the background. Check its status with `GET …/exports/{id}` and download it with `GET …/exports/{id}/download` once its status is `ready`. Each request and each download is written to the audit log. An organization can have at most three exports in progress at once.

Archive layout:

```
manifest.json                       format version, counts, missing files, generation time
data/<table>.jsonl                  one JSON object per row
attachments/<attachment_id>/<name>  original files
```

Encrypted secrets, password and token hashes, file storage keys and search indexes are left out. `data.export` gives access to every case and internal note in the organization, so grant it only to roles that should have that access.
