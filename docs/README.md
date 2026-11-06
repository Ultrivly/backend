# Ultrivly documentation

| Guide | For | Covers |
|---|---|---|
| [Self-hosting](self-hosting.md) | Operators | Requirements, installing with Docker Compose, reverse proxies, upgrades, every configuration setting |
| [Operations](operations.md) | Operators and the cloud on-call team | Metrics and alerts, runbooks, backups and restore, performance baseline |
| [Email](email.md) | Operators and organization admins | Sending, sending domains and DKIM, bounces and suppression, receiving email |
| [Data lifecycle](data-lifecycle.md) | Operators, admins, privacy reviewers | What is stored where, retention, deletion, export, backups |
| [API](api.md) | Integrators and plugin authors | Authentication, conventions, webhooks, inbound channels, chat, plugin protocol |

The design and the reasons behind it are in [ARCHITECTURE.md](../ARCHITECTURE.md). The machine-readable API reference is served by every install at `/api/v1/openapi.json`.
