# Ultrivly Product Requirements

> **Document status:** Prototype specification  
> **Document type:** Product definition and implementation guide  
> **Audience:** Product, design, engineering, security, and operations  
> **Decision labels:** **Confirmed** means explicitly chosen for Ultrivly; **Proposed** means a recommended starting point; **Future** means outside the initial MVP; **Open** means a decision still needs to be made.

## 1. Product overview

Ultrivly is a helpdesk platform that brings customer support and internal employee support into one system. It provides a unified case engine, configurable workflows, knowledge bases, integrations, reporting, and a developer platform. AI capabilities are optional and should be configurable by each organization.

Ultrivly is intended to serve individuals and small teams through large enterprises, with both cloud-hosted and self-hosted deployment options. It should offer a straightforward experience for support teams while providing the APIs, extension points, controls, and operational visibility needed by developers and administrators.

### 1.1 Product vision

Make support easier to deliver, manage, automate, and extend without forcing organizations to maintain separate systems for every support function.

### 1.2 Product goals

1. Centralize customer-facing and internal support cases in one platform.
2. Make it easy to create, assign, prioritize, track, and resolve cases.
3. Allow teams to automate routine work using a visual workflow builder.
4. Provide public and private knowledge bases that help people solve problems.
5. Support integrations through built-in connectors and a documented custom integration platform.
6. Provide reporting that helps teams understand case volume, workload, resolution, and service performance.
7. Keep AI optional, provider-configurable, and subject to explicit permissions and safeguards.
8. Support both hosted and self-hosted deployments with a consistent core product.
9. Provide desktop and mobile-responsive web interfaces.
10. Balance usability, developer experience, extensibility, and reliable operation.

### 1.3 Non-goals for the initial MVP

Unless explicitly added to scope, the MVP is not required to include:

- Autonomous AI resolution or AI voice calling.
- Native iOS or Android applications.
- Every social network or third-party service as a built-in integration.
- A fully featured IT asset management or configuration management database.
- Complex enterprise service-management features such as change, problem, and release management.
- A finalized pricing system, billing engine, or usage-metering platform.
- Certifications or claims of compliance that have not been independently assessed.
- A marketplace with public publishing, payments, reviews, and partner management.
- Guaranteed feature parity between hosted and self-hosted editions on the first release.

These may be evaluated after the core product is validated.

## 2. Confirmed product decisions

| Area | Confirmed decision |
|---|---|
| Stage | Prototype |
| Audiences | Customer support and internal IT/employee support |
| Case model | Unified case engine with configurable workflows |
| Organization structure | Organizations with teams, departments, and multiple workspaces |
| Hosting | Hosted cloud and self-hosted deployments |
| Authentication | Standard sign-in plus OAuth/social sign-in and enterprise SSO |
| Automation | Visual workflow builder |
| AI | Optional; multiple configurable providers and customer-supplied keys are desired |
| Knowledge | Public and private knowledge bases |
| Integrations | Built-in integrations and a custom integration development platform |
| Organization size | Small teams through enterprises |
| Channels | Email, web, chat, API, and social channels are part of the product direction |
| Interface | Desktop web and responsive mobile web |
| Initial priorities | Ticket management, automation, knowledge, integrations, and analytics |
| Security priorities | RBAC, audit logs, SSO/MFA, secure API credentials, and tenant isolation |
| Pricing | Undecided |
| Differentiation | Balanced emphasis on meaningful automation/AI, developer-first extensibility, and simplicity |
| Technology stack | Recommend a stack based on product needs |

**Scope clarification:** Email, web, chat, API, and social are confirmed as desired channels, but the selected MVP priorities do not explicitly include all of them. This document therefore treats the core case-management interface and APIs as MVP foundations. Channel adapters beyond the minimum needed to create and update cases should be staged according to the release plan. AI, social integrations, and advanced channel features should not block validation of the core workflow.

## 3. Users and permissions

### 3.1 User groups

- **Requester:** A customer or employee who submits a case, adds information, and checks progress.
- **Agent:** A support worker who owns, updates, communicates on, and resolves cases.
- **Team lead:** A person who monitors a team queue, redistributes workload, and reviews service performance.
- **Administrator:** A person who configures an organization, workspaces, users, permissions, channels, workflows, and integrations.
- **Knowledge editor:** A person who writes, reviews, publishes, and maintains knowledge articles.
- **Developer/integration owner:** A person who configures API access, webhooks, and custom integrations.
- **Auditor/security operator:** A person who reviews security-sensitive actions and audit records.
- **Platform operator:** For hosted deployments, an authorized operator responsible for platform availability and operations. Platform access must not automatically grant access to customer content.

One person may hold multiple roles. Permissions must be enforced server-side, not only by hiding interface controls.

### 3.2 Organization and workspace model

**Confirmed:** Organizations are the main tenant boundary, with support for teams, departments, and multiple workspaces.

**Proposed starting model:**

- **Organization:** Tenant, billing boundary if billing is later introduced, and primary security boundary.
- **Workspace:** A scoped operational area, such as Customer Support, Internal IT, or a regional support team.
- **Department/team:** Groups of users that own queues, assignments, and reporting responsibilities.
- **Queue:** A view and routing destination for cases matching configured criteria.

A case, article, workflow, integration, and report must have an explicit organization scope. Where workspace scope applies, it must also be explicit. Cross-workspace visibility must be granted intentionally.

### 3.3 Role-based access control

The product must support configurable roles and permissions. The initial system should provide sensible built-in roles, while allowing organization administrators to define narrower roles where practical.

At minimum, permissions should distinguish:

- Reading, creating, editing, assigning, merging, and resolving cases.
- Viewing private notes versus public requester replies.
- Managing users, teams, workspaces, and roles.
- Creating, publishing, and deleting knowledge articles.
- Creating, enabling, disabling, and editing workflows.
- Managing integrations, credentials, webhooks, and API tokens.
- Viewing reports and exporting data.
- Viewing audit logs and changing security settings.

Access checks must cover API requests, background jobs, workflow actions, exports, and integration callbacks as well as the user interface.

## 4. Core product capabilities

### 4.1 Unified case management — MVP

A case is the common record for customer support and internal employee support. Workspaces and configurable fields/workflows should allow different support functions to use the same underlying system without forcing identical processes.

#### Required case fields

- Unique case identifier.
- Organization and applicable workspace.
- Subject and description.
- Requester and contact details appropriate to the channel.
- Status.
- Priority.
- Type/category and tags.
- Assignee and owning team/queue.
- Creation, update, and resolution timestamps.
- Source channel.
- Public conversation messages and private internal notes.
- Attachments, subject to configured limits and validation.
- Related cases or duplicate links where supported.

Custom fields should be supported in the product direction. A minimal field configuration model may be included in the prototype, but a general-purpose custom-field designer is not a release blocker unless required by pilot users.

#### Case behavior

- Agents can create, view, update, assign, prioritize, and resolve cases according to permissions.
- Authorized users can reopen resolved cases.
- Cases retain a chronological activity and conversation history.
- Public replies are distinguishable from internal notes.
- Case lists support search, filtering, sorting, pagination, and saved views where practical.
- Teams can view queues and cases assigned to them.
- The system records important case changes for audit and troubleshooting.
- Duplicate submission should be handled gracefully; merging can follow if it is too expensive for the MVP.
- Requesters can see only cases they are authorized to access.
- Case status transitions must be validated on the server.

**Proposed initial statuses:** New, Open, Pending, Resolved, Closed. Keep status definitions configurable in the future; do not hard-code business logic throughout the application around display labels.

**Proposed initial priorities:** Low, Normal, High, Urgent. Priority semantics should be configurable later.

#### Acceptance criteria

- An authorized agent can create a case and assign it to a team and/or agent.
- The requester, authorized agents, and permitted administrators see the correct case details for their roles.
- Public messages and private notes are clearly distinguished in the UI and API.
- Case updates preserve history and record the actor and timestamp.
- Unauthorized users cannot access a case by guessing its identifier or calling the API directly.
- Lists can be filtered by status, priority, team, assignee, and date, and return paginated results.
- A case can be resolved and, where permitted, reopened without losing its history.

### 4.2 Workflow automation — MVP

Provide a visual builder for event-driven and scheduled workflows. The builder should let authorized administrators assemble a workflow from a trigger, conditions, and actions.

#### Proposed initial components

- **Triggers:** Case created, case updated, status changed, assignment changed, new message received, scheduled time reached.
- **Conditions:** Status, priority, source channel, team, assignee, tags, requester attributes, and selected fields.
- **Actions:** Set fields, add/remove tags, assign to a team or agent, send a notification, add an internal note, call a permitted webhook, and resolve a case when configured criteria are satisfied.
- **Controls:** Enable/disable, draft/publish, execution history, validation, and error reporting.

The workflow engine must prevent unbounded loops and runaway execution. It should support idempotency where possible, bounded retries, timeouts, and per-organization execution limits. External actions must use scoped credentials and must not bypass authorization rules.

#### Acceptance criteria

- An administrator can create and validate a workflow using the visual builder.
- A published workflow executes when its trigger and conditions match.
- A workflow's execution record shows the trigger, result, and any actionable error without exposing secrets.
- A disabled workflow does not execute.
- Repeated events do not cause uncontrolled duplicate actions.
- Failures are retried only according to a bounded policy and can be inspected by an authorized administrator.

### 4.3 Knowledge base — MVP

Support both public articles for customers and private articles for agents or employees.

#### Required capabilities

- Create, edit, preview, publish, unpublish, and archive articles.
- Organize articles by categories and tags.
- Search published articles.
- Apply visibility and access controls.
- Provide a public-facing help center and an authenticated/private knowledge experience as appropriate.
- Record authorship and timestamps.
- Keep draft content unavailable to unauthorized readers.

**Proposed follow-up:** Version history, approval workflows, article feedback, localized content, and AI-assisted article suggestions.

#### Acceptance criteria

- A knowledge editor can draft and publish an article.
- Public visitors can access published public articles but cannot access private articles or drafts.
- Authorized internal users can find private articles according to their permissions.
- Search results never reveal titles, snippets, or content from articles the user is not authorized to read.
- Unpublishing an article removes it from public access.

### 4.4 Integrations and developer platform — MVP foundation

Integrations are a core product capability. Ultrivly should provide a documented, versioned API and webhook mechanism, alongside a small set of built-in integrations chosen after target users are identified.

#### API requirements

- Consistent resource-oriented API design.
- Versioning and documented error responses.
- Authentication using scoped API credentials or tokens.
- Pagination, filtering, validation, and rate limits.
- Idempotency support for suitable write operations.
- Request IDs or trace IDs for support and debugging.
- OpenAPI documentation is recommended.
- Secrets must never be returned in full after initial creation.

#### Webhook requirements

- Organization-scoped endpoint configuration.
- Event selection and payload schemas.
- Request signing or equivalent authenticity verification.
- Retry policy with bounded backoff.
- Delivery logs, failure details, and manual retry where safe.
- Secret rotation and endpoint disablement.
- Protection against SSRF, private-network access, redirect abuse, and unsafe URL schemes.

#### Custom integrations

The long-term platform should allow developers to connect Ultrivly to external systems through documented APIs, webhooks, and a controlled integration model. Do not execute arbitrary customer code inside the core application process.

**Proposed MVP:** API documentation, secure API credentials, webhooks, and one or two high-value built-in integrations chosen from pilot feedback. A public integration marketplace is future scope.

#### Acceptance criteria

- An authorized administrator can create and revoke an API credential with defined scopes.
- Revoked credentials stop working promptly.
- API calls enforce organization and role permissions.
- Webhook requests can be authenticated by recipients.
- Failed deliveries are observable and retried within configured limits.
- Logs and error responses do not expose credentials or unnecessary personal data.

### 4.5 Analytics and reporting — MVP

Provide basic operational visibility for support teams and administrators.

#### Initial reports

- Case volume over time.
- Open cases by status and priority.
- Cases by team and assignee.
- Resolution volume and time to resolution.
- Workload and backlog trends.
- Workflow execution success and failure counts.

Definitions for metrics such as first response time and resolution time must be documented before those metrics are used for operational comparisons. Exclude or label incomplete data where the reporting window or channel history is insufficient.

#### Acceptance criteria

- Authorized users can filter core reports by time period and supported organizational scope.
- Report results respect the user's permissions.
- Metric definitions are documented and consistent across views.
- Reports do not combine data from different organizations.
- Expensive reports do not block normal case operations.

### 4.6 Channels and case intake

**Confirmed product direction:** Email, web, chat, API, and social channels.

**MVP approach:** Make channel identity part of the case model from the beginning. The first release must provide the case interface and API; the exact order for email, live chat, and social connectors remains open because the initial MVP selection did not explicitly prioritize all channel adapters.

- **Web:** Authenticated requester portal and/or web forms for creating and tracking cases.
- **Email:** Inbound email creates or updates a case; outbound replies are associated with the correct case and requester.
- **Chat:** Conversation intake with a clear path to case creation or escalation.
- **API:** External systems can create and update cases through authorized API operations.
- **Social:** Connectors for selected social platforms, subject to their APIs, permissions, and policies.

Do not promise a built-in connector for every social platform. Select platforms based on user demand and technical feasibility. Phone/voice support is not currently a confirmed MVP requirement; it can be evaluated as a later channel.

### 4.7 AI capabilities — optional, designed for later enablement

AI is a desired product capability, but the MVP priorities do not include it. The core product must remain useful when AI is disabled or unavailable.

#### Product requirements for future AI support

- AI is disabled by default unless an organization explicitly enables it.
- Organizations can configure supported providers and, where feasible, their own API credentials.
- Provider credentials are encrypted at rest and never exposed in client responses or logs.
- Administrators can define which data and tools an AI feature may access.
- AI actions run through the same permission checks, tenant boundaries, and audit mechanisms as human-triggered actions.
- AI-generated content is distinguishable from human-authored content where relevant.
- The system supports human handoff and records the reason for escalation.
- Organizations can disable AI globally or by feature.
- Errors, timeouts, and provider outages do not prevent normal case handling.
- AI must not be allowed to execute arbitrary code or unrestricted external actions.
- Data sent to providers, retention behavior, and provider-specific training policies must be disclosed and configurable where supported.

#### Suggested phased AI roadmap

1. **Phase 1:** Agent-assist features such as summarization, classification, and reply drafting.
2. **Phase 2:** Retrieval-assisted answers grounded in authorized knowledge articles.
3. **Phase 3:** Bounded autonomous resolution for explicitly permitted, low-risk case types, with escalation and audit records.
4. **Later evaluation:** Voice AI and more complex multi-step agents.

Autonomous resolution is not part of the MVP commitment. Any future launch requires measurable evaluation, abuse testing, cost controls, clear customer disclosures, and safe fallback behavior.

## 5. Authentication and security

### 5.1 Authentication

**Confirmed:** Standard login plus OAuth/social sign-in and enterprise SSO.

The implementation should support:

- Secure account creation and recovery.
- Strong password storage using a modern password-hashing algorithm.
- MFA, including for privileged users.
- OAuth/OIDC sign-in with validated issuer, audience, state, nonce, and redirect URI.
- Enterprise SSO, with the exact protocols and providers to be selected.
- Session expiry, revocation, and secure cookie/session handling.
- Protection against brute-force attempts and account enumeration.

The prototype may stage advanced identity-provider integrations, but its authentication architecture must not prevent adding them.

### 5.2 Tenant isolation

Organization-level data isolation is a critical requirement, not a UI feature.

- Every tenant-owned resource must have an explicit organization scope.
- Server-side authorization must validate both the user's role and the resource's organization.
- Background jobs, scheduled workflows, exports, webhooks, and search indexing must preserve tenant scope.
- Cache keys and object-storage paths must include appropriate tenant scope.
- Database queries must not rely on a client-provided organization ID without verifying access.
- Tests must cover cross-tenant reads, writes, exports, attachments, search results, and indirect object references.

Database-level row-level security may be used as defense in depth if compatible with the chosen stack. It does not replace application-level authorization.

### 5.3 Audit logs

Record security-sensitive and operationally important events, including:

- Sign-in and authentication changes.
- User, role, team, and workspace changes.
- Case assignment, status changes, and resolution.
- Workflow publication, configuration changes, and execution outcomes.
- Integration creation, changes, credential rotation, and revocation.
- Changes to security settings and data export/deletion requests.

Audit records should include actor, action, target, timestamp, organization, and relevant non-secret metadata. Do not log passwords, full tokens, secret keys, or unnecessary sensitive content. Retention and tamper-resistance requirements remain open.

### 5.4 API security

- Use TLS for network traffic.
- Scope credentials to the required permissions.
- Support credential revocation and rotation.
- Apply rate limits and abuse controls.
- Validate inputs and constrain payload size.
- Protect webhook endpoints and outbound network requests.
- Avoid returning internal stack traces or secret values.
- Keep administrative operations behind explicit authorization checks.

### 5.5 Privacy and data lifecycle

Privacy requirements must be completed before a production launch. At minimum, define data retention, deletion, export, backup expiry, attachment handling, and subprocessors. Self-hosted customers should have documented control over where their data is stored, subject to product capabilities.

Do not claim regulatory compliance or certification until the relevant controls have been implemented and independently assessed.

## 6. Deployment and operations

### 6.1 Hosted cloud

The hosted version should isolate organizations, support safe upgrades, and provide monitoring, backups, recovery procedures, and incident response.

Platform operators must have limited, documented access to customer data. Administrative access should be logged and protected.

### 6.2 Self-hosted

Self-hosted deployment is a confirmed product requirement, though production-grade packaging and support may follow the first prototype milestone.

The deployment approach should aim for:

- Documented installation and upgrade procedures.
- Environment-based configuration and secret management.
- Supported database and storage dependencies.
- Health checks and useful logs.
- Backup and restore instructions.
- Version compatibility and migration guidance.
- Clear responsibility boundaries between Ultrivly and the customer operating the deployment.

The exact packaging model, such as containers or a single-host bundle, is open. Keep configuration portable and avoid hard-coding cloud-vendor dependencies into business logic.

### 6.3 Reliability and observability

Proposed engineering requirements:

- Structured logs with correlation IDs.
- Health and readiness checks.
- Error reporting and metrics for core operations.
- Monitoring for failed background jobs and workflow executions.
- Database migration and rollback planning.
- Backups with tested restore procedures.
- Graceful handling of email, integration, and AI provider outages.
- Documented operational runbooks.

Specific availability targets, recovery time objectives, and recovery point objectives are open until hosting and support commitments are defined.

## 7. Recommended technical direction

The stack below is a **proposal**, not a confirmed user decision. Validate it with a short technical spike before committing.

### 7.1 Suggested architecture

Prefer a modular monolith for the first production-capable version, with clear internal boundaries and asynchronous workers where needed. Avoid premature microservices; split components only when deployment, scaling, security, or team ownership justifies it.

| Area | Proposed direction | Rationale |
|---|---|---|
| Web application | TypeScript with a React-based framework such as Next.js | Broad ecosystem, responsive web UI, mature tooling |
| API | TypeScript with a structured HTTP framework and OpenAPI generation | Consistent validation and documented integration contracts |
| Primary database | PostgreSQL | Transactions, relational case data, indexing, and mature operations |
| Data access | A typed ORM or query layer selected after schema/profiling tests | Maintainable data access and migrations |
| Background jobs | Durable job queue backed by PostgreSQL or a dedicated queue if justified | Email processing, workflow execution, webhooks, and reports |
| Cache/rate limiting | Add a dedicated cache only when required by scale | Avoid unnecessary operational complexity in the prototype |
| File storage | S3-compatible object storage abstraction | Supports hosted storage and self-hosted alternatives |
| Search | PostgreSQL search initially; dedicated search engine only if needed | Lower initial operational burden |
| Authentication | Established OIDC/OAuth-compatible library or identity component | Reduce custom security-sensitive code |
| API specification | OpenAPI | Supports integration development and generated clients |
| Deployment | Containerized services with documented configuration | Portability across hosted and self-hosted environments |
| Testing | Unit, integration, API-contract, and browser-level tests | Validate business rules and user workflows |

### 7.2 Architecture boundaries

Keep these modules logically separated even if they share a codebase:

- Identity and organization management.
- Cases and conversations.
- Teams, queues, and assignment.
- Knowledge.
- Workflow execution.
- Integrations, API credentials, and webhooks.
- Reporting.
- Channel adapters.
- AI provider adapters, introduced when AI enters scope.
- Audit and security events.

All modules must use shared authorization and tenant-context utilities. Do not create separate permission logic in each feature.

### 7.3 Technical principles

- Prefer simple, explicit designs over abstraction without a demonstrated need.
- Validate all untrusted inputs at boundaries.
- Use database transactions for multi-step changes that must remain consistent.
- Use asynchronous processing for operations that depend on external services.
- Make retried operations idempotent where possible.
- Version external contracts and provide migration guidance.
- Avoid storing secrets in source control or client-side bundles.
- Test organization isolation and permissions continuously.
- Keep hosted and self-hosted configuration separate from product logic.

## 8. UX and interface principles

### 8.1 Desktop web

The primary agent experience should make the case queue, current case, conversation, and key actions easy to scan. Common operations should require few steps. Administrative configuration should be separate from routine case handling.

### 8.2 Responsive mobile web

The interface must work on narrow screens without requiring a desktop viewport. Agents and requesters should be able to view cases, read and send messages, update permitted fields, and search knowledge content on mobile. Complex workflow editing may be optimized for desktop initially, but must remain usable or clearly marked as desktop-preferred.

### 8.3 UX principles

- Clear labels and predictable navigation.
- Distinguish public replies from internal notes.
- Make current case status, ownership, and priority visible.
- Provide useful empty, loading, success, and error states.
- Preserve unsaved input where practical.
- Confirm destructive or security-sensitive actions.
- Make keyboard navigation and accessible semantics part of implementation.
- Avoid overwhelming small teams with enterprise-only controls by default.

## 9. MVP definition and delivery phases

### Phase 0: Prototype validation

**Goal:** Validate the central case workflow and the proposed information architecture.

- Organization and workspace model.
- Authentication foundation.
- Basic role and permission model.
- Case creation, lists, details, assignment, replies, internal notes, and resolution.
- Responsive shell and primary navigation.
- Initial schema and API contract.
- A small set of representative end-to-end tests.

**Exit criteria:** A requester can submit a case, an agent can process it, and unauthorized users cannot access it.

### Phase 1: MVP core

- Complete core case management.
- Visual automation builder with a safe initial set of triggers, conditions, and actions.
- Public and private knowledge base.
- Secure API credentials, API documentation, and webhooks.
- Basic operational analytics.
- Audit events for critical operations.
- Tenant-isolation and authorization test suite.
- Initial deployment and backup documentation.

**Exit criteria:** A small pilot organization can configure its workspace, manage support cases, publish knowledge, automate a routine workflow, and inspect basic performance reports.

### Phase 2: Channel expansion and operational maturity

- Email intake and reply integration.
- Live chat, based on validation and channel scope.
- Improved workflow execution monitoring and controls.
- More built-in integrations.
- Improved reporting, exports, and saved views.
- Self-hosted installation and upgrade experience.
- Enterprise identity integrations and administration hardening.

The exact ordering of email, chat, and enterprise identity work should be finalized based on pilot requirements and operational risk.

### Phase 3: Optional AI and broader ecosystem

- Provider adapter framework and organization-level AI configuration.
- Agent-assist features and knowledge-grounded answers.
- Bounded autonomous resolution after evaluation and safety review.
- Selected social integrations.
- More advanced analytics and workflow features.
- Integration marketplace, if validated by developer and customer demand.

Phone/voice AI, native mobile apps, and complex ITSM modules remain future possibilities rather than commitments.

## 10. Quality attributes and acceptance gates

Before production release, the product must meet the following gates:

### Security

- Cross-tenant access tests pass for API, UI, background jobs, search, attachments, and exports.
- Authorization is enforced server-side for every protected action.
- Secrets are not exposed in logs, browser bundles, or API responses.
- Authentication, recovery, and session flows are tested.
- Dependency and application security checks are part of the release process.

### Correctness

- Case history remains consistent through updates, reassignment, resolution, and reopening.
- Workflow execution is bounded and failures are observable.
- Public and private knowledge visibility is enforced.
- Reporting calculations have documented definitions and repeatable tests.

### Reliability

- External provider outages do not corrupt case data.
- Failed background jobs can be inspected and safely retried.
- Backup restoration is tested, not merely configured.
- Database migrations are tested against representative data.

### Usability

- Core requester and agent journeys work on desktop and mobile web.
- Common actions provide clear feedback.
- Errors are actionable and do not leak implementation details.
- Keyboard and accessibility checks are included in UI testing.

### Performance

Exact numerical targets remain open. Establish measurable baselines for case list loading, case updates, search, API latency, and workflow processing before public launch. Test against a representative data volume and concurrency profile.

## 11. Product metrics

Start with metrics that indicate whether the core product is useful and reliable:

- Time from case creation to first response.
- Time from case creation to resolution.
- Backlog and overdue case count.
- Case volume and resolution volume by team.
- Requester satisfaction, if collected.
- Workflow success rate and failure rate.
- API error rate and webhook delivery success rate.
- Knowledge article search success and helpfulness, if collected.
- Availability and background job health for hosted deployments.

Metrics must be defined consistently. Do not optimize for automated resolution volume alone; measure reopens, escalations, requester outcomes, and errors alongside it.

## 12. Pricing and packaging

**Status: Open.** Pricing has not been decided.

Do not hard-code seat limits, usage caps, or plan names into the product architecture. Keep future entitlement checks centralized and configurable. Before implementing billing, decide whether pricing will be subscription-based, usage-based, or a combination, and define how self-hosted deployments will be licensed and supported.

## 13. Open decisions

These questions do not block the initial prototype, but should be resolved before the corresponding capabilities become production commitments.

1. **Initial channel order:** Which should launch first: email, live chat, or selected social channels?
2. **Built-in integrations:** Which one or two integrations would provide the most value to initial pilot users?
3. **Identity providers:** Which OAuth providers and enterprise SSO protocols must be supported first?
4. **Deployment packaging:** Containers, a single-host installer, or both?
5. **Custom fields:** How much field and status customization is needed in the MVP?
6. **Service targets:** What availability, backup, recovery, and support commitments will hosted customers receive?
7. **Audit retention:** How long should audit events be retained, and which events require stronger tamper resistance?
8. **Data lifecycle:** What retention, export, deletion, residency, and backup-expiry rules are required?
9. **Pricing and licensing:** How should cloud and self-hosted editions be packaged and monetized?
10. **AI release policy:** Which providers are supported first, and what evidence is required before autonomous resolution is enabled?
11. **Social channels:** Which specific platforms are worth supporting, given API access and policy constraints?
12. **Service management scope:** Are asset management, change management, and other ITSM features needed after the core helpdesk is validated?

## 14. Definition of done

A feature is not complete merely because its main screen works. It is complete when:

- Requirements and permission behavior are documented.
- Input validation and failure paths are implemented.
- Tenant isolation and authorization are tested.
- Relevant audit events are emitted.
- Loading, empty, success, and error states are handled.
- Automated tests cover core business logic and important user journeys.
- API or integration behavior is documented where applicable.
- Logs and metrics provide enough information to troubleshoot failures without exposing secrets.
- Responsive behavior is checked at desktop and mobile widths.
- Operational and migration implications are documented.

## 15. Guiding principle

Ultrivly should be one coherent support platform, not a collection of disconnected modules. Build a dependable case-management core first, make automation and integrations safe and extensible, and introduce AI as an optional capability that organizations can control. Every later feature should preserve clear permissions, tenant isolation, useful operational visibility, and a simple experience for both requesters and support teams.
