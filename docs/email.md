# Email

Ultrivly sends email through one SMTP server, set by `ULTRIVLY_MAIL_URL`. It doesn't run a mail server for receiving. Inbound mail arrives from a relay or mail provider as signed JSON.

## What gets sent, and from which address

| Email | From | Reply-To |
|---|---|---|
| Account email: verification, password reset, invitations, security notices | `ULTRIVLY_MAIL_FROM` | none |
| Agent replies on email cases, when the channel's domain is **not verified** | `ULTRIVLY_MAIL_FROM` | the channel address, for example `help@acme.com` |
| Agent replies on email cases, when the channel's domain **is verified** | the channel address, for example `"Acme Support" <help@acme.com>`, DKIM-signed for `acme.com` | the channel address |

The SMTP envelope sender (`MAIL FROM`) is always `ULTRIVLY_MAIL_FROM`, so bounces come back to the operator's own address. SPF is checked against that domain. Publish SPF and DKIM for it as your SMTP provider instructs.

Internal notes are never emailed. Each reply carries a `Message-ID`, `In-Reply-To` and `References` header, and a `[#123]` case number in the subject, so the customer's answer threads back onto the same case.

## Sending domains (per organization)

An organization admin with `organization.manage` can let replies go out from the organization's own address instead of the operator's.

1. Add the domain:

   ```http
   POST /api/v1/orgs/{org_id}/mail-domains
   {"domain": "acme.com"}
   ```

   The response includes a DNS record to publish:

   ```json
   {"mail_domain": {"id": "…", "domain": "acme.com", "verified": false,
     "dns_record": {"name": "ultrivly-3f9c2a1b._domainkey.acme.com", "type": "TXT",
                    "value": "v=DKIM1; k=rsa; p=MIIBIjANBg…"}}}
   ```

2. Publish that TXT record in the domain's DNS.
3. Verify it:

   ```http
   POST /api/v1/orgs/{org_id}/mail-domains/{id}/verify
   ```

   Ultrivly looks up the record and marks the domain verified if the public key matches. If the record is later removed, checking again marks the domain unverified. Verification is limited to 30 checks per organization per hour.

Each domain gets its own 2048-bit RSA key and selector. The private key is encrypted with `ULTRIVLY_SECRET_KEY` and never leaves the server. Because only the domain's owner can publish the record, verification also proves the organization controls the domain. A DKIM signature aligned with the From domain is enough for DMARC to pass, even though SPF is checked against the operator's domain.

Removing a domain (`DELETE …/mail-domains/{id}`) takes effect immediately. Later replies go out from `ULTRIVLY_MAIL_FROM` again.

## Bounces, complaints and suppression

Repeatedly sending to addresses that bounce or complain hurts the reputation of everyone sharing the SMTP server. Ultrivly keeps one suppression list for the whole install.

- A **permanent bounce** or a **spam complaint** adds the address to the list.
- Soft bounces and delivery notices are accepted and ignored.
- Helpdesk mail to a suppressed address is skipped and counted in `ultrivly_emails_suppressed_total`. The job still succeeds, so it doesn't become a dead job.
- Verification, password reset, password-changed and MFA-disabled emails are still sent, because the address owner asked for them or needs to know.

### Sending events to Ultrivly

Set `ULTRIVLY_MAIL_EVENTS_SECRET`, then have your mail provider (directly, or through a small adapter) post events:

```http
POST /api/v1/mail/events
Content-Type: application/json
Ultrivly-Signature: t=1762339200,v1=<hex HMAC-SHA256>

{"events": [
  {"type": "bounce", "email": "gone@customer.com", "permanent": true, "detail": "550 5.1.1 no such user"},
  {"type": "complaint", "email": "angry@customer.com"},
  {"type": "delivery", "email": "fine@customer.com"}
]}
```

The signature is the hex HMAC-SHA256, keyed with the secret, of `<t>.<raw body>`, where `t` is the current Unix time in seconds. Requests more than 5 minutes old are rejected. Each request can carry up to 500 events. The response is `202 {"received": 3, "suppressed": 2}`. While the secret is unset, the endpoint returns 404.

Providers such as Amazon SES, Postmark and SendGrid each have their own webhook format. Translate theirs into this one in whatever relay you already run.

### Managing the list

The list is operator-only. It isn't shown to organizations, because it would reveal that another tenant's mail bounced or was reported.

```sh
ultrivly mail suppressions --limit 50
ultrivly mail unsuppress pat@customer.com
ultrivly mail suppress pat@customer.com
```

## Receiving email

Each email channel has an address and a signing secret, which is shown once at creation and can be rotated with `POST …/channels/{id}/rotate-secret`. Point that address's MX records at a provider or relay that can POST each message as JSON to:

```http
POST /api/v1/inbound/{channel_id}/email
Ultrivly-Signature: t=…,v1=…   (same scheme as above, keyed with the channel secret)

{
  "from": {"email": "pat@customer.com", "name": "Pat"},
  "subject": "Printer on fire",
  "text": "Please help",
  "message_id": "<abc@customer.com>",
  "in_reply_to": "<previous@acme.com>",
  "references": ["<previous@acme.com>"],
  "auto_submitted": false
}
```

How messages are handled:

- Messages are de-duplicated by `message_id`, so the relay can safely retry.
- A message joins an existing case only if it comes from **that case's requester** and either references an earlier message or has the case's `[#123]` tag in the subject. Anything else starts a new case, so forwarding a thread can't expose someone else's case.
- Messages with `auto_submitted: true`, and messages from the channel's own address, are dropped to avoid mail loops.
- Each channel accepts up to 600 messages a minute.

Responses: `202 {"case_id": "…", "duplicate": false}` when accepted, `403` for a missing or wrong signature, and `422` for malformed JSON.
