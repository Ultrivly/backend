# Ultrivly API

Every install serves an OpenAPI 3.0 description of the whole API at **`/api/v1/openapi.json`**. Load it into an HTTP client or code generator for exact parameters and request bodies. This page covers the conventions that the OpenAPI document doesn't capture on its own.

## Authentication

| Caller | How | Use for |
|---|---|---|
| A person in a browser | The session cookie set by `POST /api/v1/auth/sign-in` (`__Host-ultrivly_session` on https installs) | The Ultrivly web app |
| A script or integration | `Authorization: Bearer ult_…` with an API key | Everything under `/api/v1/orgs/{org_id}/` |

Create API keys with `POST /api/v1/orgs/{org_id}/api-credentials`. Each key belongs to one organization, holds only the permissions you list (never more than your own), and can expire. The key is shown once in the response. Revoked keys stop working immediately. Using a key on another organization's routes returns 404.

Requests that change data are checked for cross-site forgery. If a request has an `Origin` header, it must be the install's own origin. If it has a session cookie but no `Origin`, it needs a same-origin `Referer`. Server-to-server clients that send no `Origin` header, which is typical for API-key integrations, aren't affected. The inbound channel, chat and mail-event endpoints are exempt, because they are authenticated by signatures or tokens instead.

## Conventions

- **Versioning:** everything is under `/api/v1`. Fields may be added within v1; existing fields are not removed or changed.
- **IDs:** UUIDs (version 7, so they sort by creation time).
- **Pagination:** list endpoints take `?limit=` (1–100, default 50) and `?cursor=`, and return `{"data": [...], "next_cursor": "…" | null}`. Pass `next_cursor` back as `cursor` to get the next page.
- **Errors:** `{"error": {"code": "…", "message": "…", "field": "…"}}`. The `field` key appears only for validation errors.

  | Status | Meaning |
  |---|---|
  | 400 | Malformed request |
  | 401 | Not signed in, or the API key is invalid |
  | 403 | Signed in but not allowed. This includes failed signature checks on inbound endpoints. |
  | 404 | Doesn't exist, or you can't see it. Other organizations' resources always return 404, never 403. |
  | 409 | Conflicts with the current state, for example the item is in use, already exists, or isn't ready |
  | 422 | Validation failed. `field` says which field. |
  | 429 | Rate limited. `Retry-After` gives the seconds to wait. |

- **Request IDs:** every response has an `x-request-id` header. Quote it when reporting a problem.

## Rate limits

By default, one API key or session can make 1,200 requests a minute, and one client IP address 3,000. Operators can change both limits. Some endpoints have their own tighter limits, such as sign-in, password reset, chat, inbound channels, mail-domain checks and AI assist. Over a limit, the API returns `429` with `Retry-After`.

## Idempotency

Any `POST` under `/api/v1/orgs/{org_id}/` accepts an `Idempotency-Key` header of 1–255 printable characters. Use a new random value for each logical operation and resend it on retries.

| Situation | Result |
|---|---|
| First request with this key | Runs normally. The response is stored, encrypted, for 24 hours. |
| Same key, same request | The stored response is returned, with `idempotent-replayed: true`. |
| Same key, different body or path | `422 idempotency_key_reused` |
| Same key while the first request is still running | `409 idempotency_in_progress` |
| First request failed with a 5xx | Nothing is stored, so a retry runs again. |

Keys are scoped to the organization and to the caller.

## Webhooks

Create an endpoint with `POST /api/v1/orgs/{org_id}/webhooks`, giving its URL (a public HTTPS address) and the events to receive (`["*"]` for all). The signing secret (`whsec_…`) is shown once. Rotate it with `…/webhooks/{id}/rotate-secret`.

Each delivery is a `POST`:

```http
Content-Type: application/json
Ultrivly-Event: case.created
Ultrivly-Delivery: 01a1ab3d-…          unique per delivery; use it to ignore duplicates
Ultrivly-Signature: t=1762339200,v1=5f2b…

{"id": "<event id>", "type": "case.created", "created_at": "2026-11-05T10:00:00Z",
 "org_id": "…", "data": {"case_id": "…"}}
```

To verify a delivery, compute the hex HMAC-SHA256 of `<t>.<raw body>` keyed with the secret, compare it with `v1` in constant time, and reject anything where `t` is more than 5 minutes off:

```python
import hmac, hashlib, time

def verify(secret: str, header: str, body: bytes) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t = int(parts["t"])
    expected = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return abs(time.time() - t) <= 300 and hmac.compare_digest(expected, parts["v1"])
```

Answer with any 2xx within 10 seconds. Each delivery is attempted up to 8 times, with backoff from 30 seconds up to an hour between attempts. The delivery log is at `…/webhooks/{id}/deliveries` (kept for 30 days), and `…/webhook-deliveries/{id}/redeliver` sends one again. Ultrivly never follows redirects and won't deliver to private or loopback addresses unless the operator has allowed that host.

Event types: `case.created`, `case.updated`, `case.status_changed`, `case.assigned`, `case.message_added`, `case.deleted`, `case.sla_breached`, `contact.created` and `article.published`.

## Inbound channels

Email and social channels receive messages from a relay you run, signed with the channel's secret using the same scheme as webhooks.

- **Email:** `POST /api/v1/inbound/{channel_id}/email`. See [Email](email.md#receiving-email).
- **Social:** `POST /api/v1/inbound/{channel_id}/social`:

  ```json
  {"platform": "instagram", "external_user_id": "17841…", "name": "Pat",
   "text": "Where is my order?", "message_id": "m_123", "thread_id": "t_456"}
  ```

  Messages with the same `thread_id` go on the same case. Senders are matched by platform user ID only, never by email.

## Chat widget

A chat channel lists the website origins allowed to embed it. The widget calls these endpoints directly from the browser. CORS headers are sent only to allowed origins.

1. `POST /api/v1/chat/{channel_id}/conversations` with `{"name", "email", "message"}`. This returns `{"conversation_id", "token"}`. Store the token in the page; it is valid for 30 days.
2. `GET /api/v1/chat/{channel_id}/conversations/{conversation_id}/messages?after=<message id>` with `Authorization: Bearer <token>`, polled every few seconds. It returns only public messages.
3. `POST` to the same path with `{"body"}` to send a message.

Chat requesters are marked `requester_unverified` on the case, because the email they type isn't proven.

## Plugins

A webhook plugin is an HTTPS service you host. To install one, an admin calls `POST /api/v1/orgs/{org_id}/plugins` with `{"kind": "webhook", "base_url": "https://plugin.example.com"}`.

**1. Manifest.** Ultrivly fetches `GET {base_url}/manifest`:

```json
{
  "key": "crm_sync",
  "name": "CRM sync",
  "version": "1.2.0",
  "permissions": ["cases.read"],
  "events": ["case.created"],
  "actions": [
    {"key": "notify", "name": "Notify CRM",
     "inputs": [{"key": "text", "label": "Text", "type": "text", "required": true}]}
  ]
}
```

Unknown fields are rejected. Input types are `text`, `number` and `boolean`. The installing admin must already hold every permission listed.

**2. Install response.** Returned once: `api_token` (an API key limited to `permissions`, which the plugin uses to call the Ultrivly API) and `signing_secret`. Store both in the plugin.

**3. Events.** If `events` isn't empty, Ultrivly delivers them as ordinary webhooks to `POST {base_url}/events`.

**4. Actions.** Workflows can run plugin actions as a step: `{"type": "plugin", "install_id": "…", "action": "notify", "input": {"text": "…"}}`. The input is checked against the manifest when the workflow is saved and again when it runs. Each run sends:

```http
POST {base_url}/actions/notify
Ultrivly-Signature: t=…,v1=…        (keyed with signing_secret)

{"install_id": "…", "org_id": "…", "action": "notify", "input": {"text": "…"},
 "case": {"id": "…", "number": 42, "subject": "…", "status": "open",
          "priority": "high", "tags": [], "workspace_id": "…"}}
```

Answer with any 2xx within 10 seconds. Each action is attempted up to 5 times.

**5. Disable and uninstall.** `PATCH …/plugins/{id}` with `{"enabled": false}` stops events and actions and suspends the plugin's API token until it is re-enabled. `DELETE` revokes the token and removes the event subscription.

The built-in `slack_notify` plugin needs only `{"kind": "builtin", "plugin_key": "slack_notify", "config": {"webhook_url": "https://hooks.slack.com/…"}}`. `GET /api/v1/plugins` lists built-in plugins.
