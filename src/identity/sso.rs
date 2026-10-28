


















use std::time::Duration;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::identity::accounts::{self, AuthError, SignIn};
use crate::identity::sessions::{AuthMethod, ClientInfo};
use crate::platform::authz::{self, AuthzError, Permission};
use crate::platform::net::HttpClient;
use crate::platform::secrets::Secrets;

const STATE_TTL: Duration = Duration::from_secs(10 * 60);

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;


#[derive(Debug, Clone)]
pub struct SocialProvider {
    
    pub key: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    
    
    pub trust_verified_email: bool,
}

impl SocialProvider {
    pub fn google(client_id: String, client_secret: String) -> Self {
        Self {
            key: "google".into(),
            issuer_url: "https://accounts.google.com".into(),
            client_id,
            client_secret,
            trust_verified_email: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider<'a> {
    
    Connection(Uuid),
    
    Social(&'a str),
}

#[derive(Debug)]
pub enum SsoOutcome {
    SignedIn {
        sign_in: SignIn,
        
        redirect_to: Option<String>,
    },
    
    Linked {
        user_id: Uuid,
        redirect_to: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SsoError {
    #[error("permission denied")]
    Forbidden,
    #[error("you cannot grant permissions you do not have: {}",
        .0.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", "))]
    CannotGrant(Vec<Permission>),
    #[error("{field} {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("a connection with this name already exists")]
    NameTaken,
    #[error("SSO connection not found")]
    NotFound,
    #[error("this sign-in method is not available")]
    Unavailable,
    #[error("this sign-in attempt is invalid or has expired; please try again")]
    InvalidState,
    #[error("the identity provider returned an error: {0}")]
    Provider(String),
    #[error("the identity provider did not share an email address")]
    EmailMissing,
    #[error("this email domain is not allowed to sign in here")]
    EmailDomainNotAllowed,
    
    #[error(
        "an account with this email already exists; sign in and link this provider from your account settings"
    )]
    AccountExists,
    
    #[error("you do not have access to this organization; ask an administrator to invite you")]
    NotProvisioned,
    #[error("this account is disabled")]
    AccountDisabled,
    #[error("this identity is already linked to a different account")]
    IdentityInUse,
    #[error("verify your email address before linking a sign-in provider")]
    EmailNotVerified,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<AuthzError> for SsoError {
    fn from(err: AuthzError) -> Self {
        match err {
            AuthzError::Forbidden => SsoError::Forbidden,
            AuthzError::Database(err) => SsoError::Database(err),
        }
    }
}

pub struct NewConnection<'a> {
    pub name: &'a str,
    
    
    pub issuer_url: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub email_domains: &'a [&'a str],
    pub jit_provisioning: bool,
    
    pub default_role_id: Option<Uuid>,
    pub enforced: bool,
}


#[derive(Default)]
pub struct ConnectionChanges<'a> {
    pub enabled: Option<bool>,
    pub enforced: Option<bool>,
    pub jit_provisioning: Option<bool>,
    
    pub default_role_id: Option<Option<Uuid>>,
    pub email_domains: Option<&'a [&'a str]>,
    pub client_secret: Option<&'a str>,
}


pub struct Sso {
    pub(crate) secrets: Secrets,
    pub(crate) http: HttpClient,
    pub(crate) public_url: String,
    redirect_url: RedirectUrl,
    social: Vec<SocialProvider>,
}

pub(crate) struct ProviderConfig {
    pub(crate) oidc: Option<OidcSettings>,
    pub(crate) kind: ProviderKind,
}

pub(crate) struct OidcSettings {
    issuer_url: String,
    client_id: String,
    client_secret: String,
}

pub(crate) enum ProviderKind {
    Connection {
        id: Uuid,
        org_id: Uuid,
        email_domains: Vec<String>,
        jit_provisioning: bool,
        default_role_id: Option<Uuid>,
    },
    Social {
        trust_verified_email: bool,
    },
}

pub(crate) struct Identity {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) email: Option<String>,
    pub(crate) email_verified: bool,
    pub(crate) name: Option<String>,
}

impl Sso {
    
    pub fn new(
        secrets: Secrets,
        http: HttpClient,
        public_url: &str,
        social: Vec<SocialProvider>,
    ) -> anyhow::Result<Self> {
        let redirect_url = RedirectUrl::new(format!(
            "{}/auth/oidc/callback",
            public_url.trim_end_matches('/')
        ))?;
        Ok(Self {
            secrets,
            http,
            public_url: public_url.trim_end_matches('/').to_string(),
            redirect_url,
            social,
        })
    }

    

    pub async fn create_connection(
        &self,
        conn: &mut PgConnection,
        org_id: Uuid,
        actor: Actor,
        new: NewConnection<'_>,
    ) -> Result<Uuid, SsoError> {
        authz::require(conn, org_id, actor, Permission::SecurityManage).await?;
        let name = new.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(SsoError::Invalid {
                field: "name",
                reason: "must be between 1 and 100 characters",
            });
        }
        if new.client_id.trim().is_empty() || new.client_secret.is_empty() {
            return Err(SsoError::Invalid {
                field: "client_id",
                reason: "and client secret are required",
            });
        }
        let email_domains = normalize_domains(new.email_domains)?;
        
        self.discover(new.issuer_url).await?;

        let mut tx = conn.begin().await?;
        if let Some(role_id) = new.default_role_id {
            check_default_role(&mut tx, org_id, actor, role_id).await?;
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO sso_connections (id, org_id, name, issuer_url, client_id,
                 client_secret_ciphertext, email_domains, enforced, jit_provisioning, default_role_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(org_id)
        .bind(name)
        .bind(new.issuer_url.trim())
        .bind(new.client_id.trim())
        .bind(self.secrets.encrypt(&secret_context(id), new.client_secret.as_bytes()))
        .bind(&email_domains)
        .bind(new.enforced)
        .bind(new.jit_provisioning)
        .bind(new.default_role_id)
        .execute(&mut *tx)
        .await
        .map_err(
            |err| match err.as_database_error().and_then(|e| e.constraint()) {
                Some("sso_connections_name_key") => SsoError::NameTaken,
                _ => err.into(),
            },
        )?;
        record_org(
            &mut tx,
            org_id,
            actor,
            "sso_connection.created",
            id,
            json!({
                "name": name,
                "issuer_url": new.issuer_url.trim(),
                "email_domains": email_domains,
                "enforced": new.enforced,
                "jit_provisioning": new.jit_provisioning,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn update_connection(
        &self,
        conn: &mut PgConnection,
        org_id: Uuid,
        connection_id: Uuid,
        actor: Actor,
        changes: ConnectionChanges<'_>,
    ) -> Result<(), SsoError> {
        let mut tx = conn.begin().await?;
        authz::require(&mut tx, org_id, actor, Permission::SecurityManage).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM sso_connections WHERE org_id = $1 AND id = $2)",
        )
        .bind(org_id)
        .bind(connection_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(SsoError::NotFound);
        }
        if let Some(Some(role_id)) = changes.default_role_id {
            check_default_role(&mut tx, org_id, actor, role_id).await?;
        }
        let email_domains = changes.email_domains.map(normalize_domains).transpose()?;
        let secret = changes.client_secret.map(|s| {
            self.secrets
                .encrypt(&secret_context(connection_id), s.as_bytes())
        });

        sqlx::query(
            "UPDATE sso_connections SET
                 enabled = coalesce($3, enabled),
                 enforced = coalesce($4, enforced),
                 jit_provisioning = coalesce($5, jit_provisioning),
                 default_role_id = CASE WHEN $6 THEN $7 ELSE default_role_id END,
                 email_domains = coalesce($8, email_domains),
                 client_secret_ciphertext = coalesce($9, client_secret_ciphertext)
             WHERE org_id = $1 AND id = $2",
        )
        .bind(org_id)
        .bind(connection_id)
        .bind(changes.enabled)
        .bind(changes.enforced)
        .bind(changes.jit_provisioning)
        .bind(changes.default_role_id.is_some())
        .bind(changes.default_role_id.flatten())
        .bind(&email_domains)
        .bind(secret)
        .execute(&mut *tx)
        .await?;

        record_org(
            &mut tx,
            org_id,
            actor,
            "sso_connection.updated",
            connection_id,
            json!({
                "enabled": changes.enabled,
                "enforced": changes.enforced,
                "jit_provisioning": changes.jit_provisioning,
                "default_role_id": changes.default_role_id,
                "email_domains": email_domains,
                "client_secret_rotated": changes.client_secret.is_some(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    
    pub async fn delete_connection(
        &self,
        conn: &mut PgConnection,
        org_id: Uuid,
        connection_id: Uuid,
        actor: Actor,
    ) -> Result<(), SsoError> {
        let mut tx = conn.begin().await?;
        authz::require(&mut tx, org_id, actor, Permission::SecurityManage).await?;
        let deleted = sqlx::query("DELETE FROM sso_connections WHERE org_id = $1 AND id = $2")
            .bind(org_id)
            .bind(connection_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if deleted == 0 {
            return Err(SsoError::NotFound);
        }
        record_org(
            &mut tx,
            org_id,
            actor,
            "sso_connection.deleted",
            connection_id,
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_connections(
        &self,
        conn: &mut PgConnection,
        org_id: Uuid,
        actor: Actor,
    ) -> Result<Vec<serde_json::Value>, SsoError> {
        authz::require(conn, org_id, actor, Permission::SecurityManage).await?;
        type Row = (
            Uuid,
            String,
            String,
            Option<String>,
            Option<String>,
            Vec<String>,
            bool,
            bool,
            bool,
            Option<Uuid>,
            chrono::DateTime<chrono::Utc>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, name, protocol, issuer_url, client_id, email_domains, enabled, enforced,
                    jit_provisioning, default_role_id, created_at
             FROM sso_connections WHERE org_id = $1 ORDER BY created_at",
        )
        .bind(org_id)
        .fetch_all(conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    protocol,
                    issuer_url,
                    client_id,
                    email_domains,
                    enabled,
                    enforced,
                    jit,
                    default_role_id,
                    created_at,
                )| {
                    let saml = (protocol == "saml").then(|| {
                        json!({
                            "entity_id": self.saml_entity_id(id),
                            "acs_url": self.saml_acs_url(id),
                        })
                    });
                    json!({
                        "id": id,
                        "name": name,
                        "protocol": protocol,
                        "issuer_url": issuer_url,
                        "client_id": client_id,
                        "email_domains": email_domains,
                        "enabled": enabled,
                        "enforced": enforced,
                        "jit_provisioning": jit,
                        "default_role_id": default_role_id,
                        "created_at": created_at,
                        "service_provider": saml,
                    })
                },
            )
            .collect())
    }

    pub async fn connection_protocol(
        conn: &mut PgConnection,
        connection_id: Uuid,
    ) -> sqlx::Result<Option<String>> {
        sqlx::query_scalar("SELECT protocol FROM sso_connections WHERE id = $1")
            .bind(connection_id)
            .fetch_optional(conn)
            .await
    }

    
    pub async fn connection_for_org(
        conn: &mut PgConnection,
        org_slug: &str,
    ) -> sqlx::Result<Option<(Uuid, String)>> {
        sqlx::query_as(
            "SELECT c.id, c.protocol FROM sso_connections c
             JOIN organizations o ON o.id = c.org_id AND o.deleted_at IS NULL
             WHERE o.slug = $1 AND c.enabled
             ORDER BY c.created_at LIMIT 1",
        )
        .bind(org_slug)
        .fetch_optional(conn)
        .await
    }

    

    
    
    
    pub async fn begin(
        &self,
        conn: &mut PgConnection,
        provider: Provider<'_>,
        redirect_to: Option<&str>,
        link_user_id: Option<Uuid>,
    ) -> Result<String, SsoError> {
        if let Some(path) = redirect_to
            && !is_safe_redirect(path)
        {
            return Err(SsoError::Invalid {
                field: "redirect_to",
                reason: "must be a path on this site",
            });
        }
        if let Some(user_id) = link_user_id {
            
            
            let verified: bool =
                sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&mut *conn)
                    .await?;
            if !verified {
                return Err(SsoError::EmailNotVerified);
            }
        }
        let config = self.load_provider(conn, provider).await?;
        let client = self.client(&config).await?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let (connection_id, social_key) = match (&config.kind, provider) {
            (ProviderKind::Connection { id, .. }, _) => (Some(*id), None),
            (ProviderKind::Social { .. }, Provider::Social(key)) => (None, Some(key)),
            (ProviderKind::Social { .. }, Provider::Connection(_)) => unreachable!(),
        };
        sqlx::query(
            "INSERT INTO oidc_login_states (state, nonce, pkce_verifier, sso_connection_id,
                 social_provider, link_user_id, redirect_to, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
        )
        .bind(state.secret())
        .bind(nonce.secret())
        .bind(pkce_verifier.secret())
        .bind(connection_id)
        .bind(social_key)
        .bind(link_user_id)
        .bind(redirect_to)
        .bind(STATE_TTL.as_secs_f64())
        .execute(conn)
        .await?;
        Ok(url.to_string())
    }

    
    pub async fn complete(
        &self,
        conn: &mut PgConnection,
        state: &str,
        code: &str,
        client_info: &ClientInfo,
    ) -> Result<SsoOutcome, SsoError> {
        
        
        type StateRow = (
            String,
            String,
            Option<Uuid>,
            Option<String>,
            Option<Uuid>,
            Option<String>,
        );
        let stored: Option<StateRow> = sqlx::query_as(
            "DELETE FROM oidc_login_states WHERE state = $1 AND expires_at > now()
                 RETURNING nonce, pkce_verifier, sso_connection_id, social_provider,
                           link_user_id, redirect_to",
        )
        .bind(state)
        .fetch_optional(&mut *conn)
        .await?;
        let (nonce, pkce_verifier, connection_id, social_key, link_user_id, redirect_to) =
            stored.ok_or(SsoError::InvalidState)?;
        let provider = match (connection_id, social_key.as_deref()) {
            (Some(id), _) => Provider::Connection(id),
            (None, Some(key)) => Provider::Social(key),
            (None, None) => return Err(SsoError::InvalidState),
        };
        let config = self.load_provider(conn, provider).await?;

        
        let identity = self.exchange(&config, code, &nonce, &pkce_verifier).await?;
        self.finish(
            conn,
            identity,
            &config,
            link_user_id,
            redirect_to,
            client_info,
        )
        .await
    }

    pub(crate) async fn finish(
        &self,
        conn: &mut PgConnection,
        identity: Identity,
        config: &ProviderConfig,
        link_user_id: Option<Uuid>,
        redirect_to: Option<String>,
        client_info: &ClientInfo,
    ) -> Result<SsoOutcome, SsoError> {
        if let ProviderKind::Connection { email_domains, .. } = &config.kind
            && !email_domains.is_empty()
        {
            let domain = identity
                .email
                .as_deref()
                .and_then(|e| e.rsplit_once('@'))
                .map(|(_, d)| d.to_ascii_lowercase())
                .ok_or(SsoError::EmailMissing)?;
            if !email_domains.contains(&domain) {
                return Err(SsoError::EmailDomainNotAllowed);
            }
        }

        let mut tx = conn.begin().await?;
        let linked_user: Option<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM auth_identities WHERE issuer = $1 AND subject = $2",
        )
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(link_user_id) = link_user_id {
            match linked_user {
                Some(existing) if existing != link_user_id => return Err(SsoError::IdentityInUse),
                Some(_) => {}
                None => insert_identity(&mut tx, link_user_id, &identity, config).await?,
            }
            accounts::record(
                &mut tx,
                link_user_id,
                "user.identity_linked",
                json!({ "issuer": identity.issuer }),
            )
            .await?;
            tx.commit().await?;
            return Ok(SsoOutcome::Linked {
                user_id: link_user_id,
                redirect_to,
            });
        }

        let user_id = match linked_user {
            Some(user_id) => user_id,
            None => self.first_sign_in(&mut tx, &identity, config).await?,
        };
        let disabled: bool =
            sqlx::query_scalar("SELECT disabled_at IS NOT NULL FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
        if disabled {
            return Err(SsoError::AccountDisabled);
        }
        sqlx::query(
            "UPDATE auth_identities SET last_used_at = now(), email = coalesce($3, email)
             WHERE issuer = $1 AND subject = $2",
        )
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(&identity.email)
        .execute(&mut *tx)
        .await?;

        let method = match &config.kind {
            ProviderKind::Connection {
                id,
                org_id,
                jit_provisioning,
                default_role_id,
                ..
            } => {
                ensure_membership(
                    &mut tx,
                    *org_id,
                    user_id,
                    *jit_provisioning,
                    *default_role_id,
                )
                .await?;
                AuthMethod::Sso { connection_id: *id }
            }
            ProviderKind::Social { .. } => AuthMethod::Social,
        };
        let sign_in = accounts::finish_sign_in(&mut tx, user_id, method, client_info).await?;
        tx.commit().await?;
        Ok(SsoOutcome::SignedIn {
            sign_in,
            redirect_to,
        })
    }

    
    async fn first_sign_in(
        &self,
        conn: &mut PgConnection,
        identity: &Identity,
        config: &ProviderConfig,
    ) -> Result<Uuid, SsoError> {
        let email = identity.email.as_deref().ok_or(SsoError::EmailMissing)?;
        let email = accounts::normalize_email(email).map_err(|_| SsoError::EmailMissing)?;
        let trusted_email = matches!(
            config.kind,
            ProviderKind::Social {
                trust_verified_email: true
            }
        ) && identity.email_verified;

        let existing: Option<(Uuid, bool)> = sqlx::query_as(
            "SELECT id, email_verified_at IS NOT NULL FROM users WHERE lower(email) = lower($1)",
        )
        .bind(email)
        .fetch_optional(&mut *conn)
        .await?;

        let user_id = match existing {
            Some((user_id, verified)) if trusted_email && verified => user_id,
            Some(_) => return Err(SsoError::AccountExists),
            None => {
                if let ProviderKind::Connection {
                    jit_provisioning: false,
                    ..
                } = config.kind
                {
                    return Err(SsoError::NotProvisioned);
                }
                let user_id = Uuid::now_v7();
                let display_name = identity
                    .name
                    .as_deref()
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or(email);
                sqlx::query(
                    "INSERT INTO users (id, email, display_name, email_verified_at)
                     VALUES ($1, $2, $3, CASE WHEN $4 THEN now() END)",
                )
                .bind(user_id)
                .bind(email)
                .bind(display_name.trim())
                .bind(trusted_email)
                .execute(&mut *conn)
                .await?;
                accounts::record(
                    conn,
                    user_id,
                    "user.signed_up",
                    json!({ "issuer": identity.issuer }),
                )
                .await?;
                user_id
            }
        };
        insert_identity(conn, user_id, identity, config).await?;
        Ok(user_id)
    }

    async fn load_provider(
        &self,
        conn: &mut PgConnection,
        provider: Provider<'_>,
    ) -> Result<ProviderConfig, SsoError> {
        match provider {
            Provider::Social(key) => {
                let social = self
                    .social
                    .iter()
                    .find(|p| p.key == key)
                    .ok_or(SsoError::Unavailable)?;
                Ok(ProviderConfig {
                    oidc: Some(OidcSettings {
                        issuer_url: social.issuer_url.clone(),
                        client_id: social.client_id.clone(),
                        client_secret: social.client_secret.clone(),
                    }),
                    kind: ProviderKind::Social {
                        trust_verified_email: social.trust_verified_email,
                    },
                })
            }
            Provider::Connection(id) => {
                type Row = (
                    Uuid,
                    Option<String>,
                    Option<String>,
                    Option<Vec<u8>>,
                    Vec<String>,
                    bool,
                    Option<Uuid>,
                );
                let row: Option<Row> = sqlx::query_as(
                    "SELECT c.org_id, c.issuer_url, c.client_id, c.client_secret_ciphertext,
                            c.email_domains, c.jit_provisioning, c.default_role_id
                     FROM sso_connections c
                     JOIN organizations o ON o.id = c.org_id AND o.deleted_at IS NULL
                     WHERE c.id = $1 AND c.enabled AND c.protocol = 'oidc'",
                )
                .bind(id)
                .fetch_optional(conn)
                .await?;
                let (
                    org_id,
                    issuer_url,
                    client_id,
                    ciphertext,
                    email_domains,
                    jit,
                    default_role_id,
                ) = row.ok_or(SsoError::Unavailable)?;
                let (Some(issuer_url), Some(client_id), Some(ciphertext)) =
                    (issuer_url, client_id, ciphertext)
                else {
                    return Err(SsoError::Unavailable);
                };
                let client_secret =
                    String::from_utf8(self.secrets.decrypt(&secret_context(id), &ciphertext)?)
                        .map_err(|_| anyhow::anyhow!("stored client secret is not UTF-8"))?;
                Ok(ProviderConfig {
                    oidc: Some(OidcSettings {
                        issuer_url,
                        client_id,
                        client_secret,
                    }),
                    kind: ProviderKind::Connection {
                        id,
                        org_id,
                        email_domains,
                        jit_provisioning: jit,
                        default_role_id,
                    },
                })
            }
        }
    }

    async fn discover(&self, issuer_url: &str) -> Result<CoreProviderMetadata, SsoError> {
        let issuer =
            IssuerUrl::new(issuer_url.trim().to_string()).map_err(|_| SsoError::Invalid {
                field: "issuer_url",
                reason: "must be a valid URL",
            })?;
        self.http
            .policy()
            .check_url(issuer.url())
            .map_err(|_| SsoError::Invalid {
                field: "issuer_url",
                reason: "must be a public https URL",
            })?;
        CoreProviderMetadata::discover_async(issuer, &self.http)
            .await
            .map_err(|e| SsoError::Provider(format!("discovery failed: {e}")))
    }

    async fn client(&self, config: &ProviderConfig) -> Result<OidcClient, SsoError> {
        let oidc = config.oidc.as_ref().ok_or(SsoError::Unavailable)?;
        let metadata = self.discover(&oidc.issuer_url).await?;
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(oidc.client_id.clone()),
            Some(ClientSecret::new(oidc.client_secret.clone())),
        )
        .set_redirect_uri(self.redirect_url.clone()))
    }

    async fn exchange(
        &self,
        config: &ProviderConfig,
        code: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<Identity, SsoError> {
        let client = self.client(config).await?;
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| SsoError::Provider(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| SsoError::Provider(format!("token exchange failed: {e}")))?;
        let id_token = response
            .id_token()
            .ok_or_else(|| SsoError::Provider("no ID token in response".into()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(nonce.to_string()))
            .map_err(|e| SsoError::Provider(format!("invalid ID token: {e}")))?;

        Ok(Identity {
            issuer: claims.issuer().to_string(),
            subject: claims.subject().to_string(),
            email: claims.email().map(|e| e.to_string()),
            email_verified: claims.email_verified() == Some(true),
            name: claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string()),
        })
    }
}

pub(crate) async fn insert_identity(
    conn: &mut PgConnection,
    user_id: Uuid,
    identity: &Identity,
    config: &ProviderConfig,
) -> sqlx::Result<()> {
    let connection_id = match config.kind {
        ProviderKind::Connection { id, .. } => Some(id),
        ProviderKind::Social { .. } => None,
    };
    sqlx::query(
        "INSERT INTO auth_identities (id, user_id, issuer, subject, email, sso_connection_id, last_used_at)
         VALUES ($1, $2, $3, $4, $5, $6, now())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(&identity.email)
    .bind(connection_id)
    .execute(conn)
    .await?;
    Ok(())
}



pub(crate) async fn ensure_membership(
    conn: &mut PgConnection,
    org_id: Uuid,
    user_id: Uuid,
    jit_provisioning: bool,
    default_role_id: Option<Uuid>,
) -> Result<(), SsoError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2)",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    if exists {
        return Ok(());
    }
    if !jit_provisioning {
        return Err(SsoError::NotProvisioned);
    }

    let membership_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(membership_id)
    .bind(org_id)
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    if let Some(role_id) = default_role_id {
        sqlx::query(
            "INSERT INTO membership_roles (org_id, membership_id, role_id) VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(membership_id)
        .bind(role_id)
        .execute(&mut *conn)
        .await?;
    }
    record_org(
        conn,
        org_id,
        Actor::System,
        "membership.provisioned",
        membership_id,
        json!({ "user_id": user_id, "role_id": default_role_id }),
    )
    .await?;
    Ok(())
}



pub(crate) async fn check_default_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    role_id: Uuid,
) -> Result<(), SsoError> {
    let permissions: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT coalesce((SELECT array_agg(permission) FROM role_permissions WHERE role_id = r.id), '{}')
         FROM roles r WHERE r.org_id = $1 AND r.id = $2",
    )
    .bind(org_id)
    .bind(role_id)
    .fetch_optional(&mut *conn)
    .await?;
    let permissions = permissions.ok_or(SsoError::Invalid {
        field: "default_role_id",
        reason: "is not a role in this organization",
    })?;
    let missing = authz::missing_permissions(
        conn,
        org_id,
        None,
        actor,
        permissions.iter().filter_map(|p| p.parse().ok()),
    )
    .await?;
    if missing.is_empty() {
        Ok(())
    } else {
        Err(SsoError::CannotGrant(missing))
    }
}

pub(crate) fn normalize_domains(domains: &[&str]) -> Result<Vec<String>, SsoError> {
    let mut out: Vec<String> = Vec::new();
    for domain in domains {
        let domain = domain.trim().trim_start_matches('@').to_ascii_lowercase();
        let valid = domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !valid {
            return Err(SsoError::Invalid {
                field: "email_domains",
                reason: "must be domain names like example.com",
            });
        }
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    Ok(out)
}


pub(crate) fn is_safe_redirect(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
}

fn secret_context(connection_id: Uuid) -> String {
    format!("sso_connection:{connection_id}")
}

pub(crate) async fn record_org(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    action: &str,
    target_id: Uuid,
    metadata: serde_json::Value,
) -> sqlx::Result<()> {
    audit::record(
        conn,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action,
            target_type: if action.starts_with("membership") {
                "membership"
            } else {
                "sso_connection"
            },
            target_id,
            metadata,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_same_site_redirects_are_allowed() {
        for ok in ["/", "/cases/42", "/search?q=a"] {
            assert!(is_safe_redirect(ok), "{ok}");
        }
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "cases",
            "/a\nb",
        ] {
            assert!(!is_safe_redirect(bad), "{bad}");
        }
    }

    #[test]
    fn normalizes_email_domains() {
        assert_eq!(
            normalize_domains(&["Example.com", "@example.com", " sub.example.org "]).unwrap(),
            ["example.com", "sub.example.org"]
        );
        for bad in ["example", "ex ample.com", "a@b.com", ".com"] {
            assert!(normalize_domains(&[bad]).is_err(), "{bad}");
        }
    }
}
